package intro

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/findy-network/findy-agent-auth/acator/enclave"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/cmds"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

var introDemoHTTPTCP = flag.Bool("intro-demo-http-tcp", false,
	"Opt in to a self-owned loopback TCP HTTP exchange")

func TestHTTPDemoRegistrationAndValidation(t *testing.T) {
	defer assert.PushTester(t)()

	for _, role := range []string{"root", "accept"} {
		registered, args, err := cmds.RootCmd().Find(
			[]string{"intro", "http-demo", role},
		)
		assert.NoError(err)
		assert.SEmpty(args)
		assert.Equal(registered.Name(), role)
		assert.Equal(registered.Parent().Name(), "http-demo")
		cmd := newHTTPDemoRoleCommand(role)
		assert.NoError(cmd.ValidateArgs(nil))
		assert.Error(cmd.ValidateArgs([]string{"extra"}))
		if role == "root" {
			assert.NoError(cmd.ValidateRequiredFlags())
			assert.Equal(
				try.To1(cmd.Flags().GetString("listen")),
				"127.0.0.1:0",
			)
		} else {
			assert.Error(cmd.ValidateRequiredFlags())
			assert.NoError(cmd.Flags().Set("url", "http://127.0.0.1:1234"))
			assert.Error(cmd.ValidateRequiredFlags())
			assert.NoError(cmd.Flags().Set("root", "selected-public-key"))
			assert.NoError(cmd.ValidateRequiredFlags())
			assert.Equal(try.To1(cmd.Flags().GetDuration("timeout")), 2*time.Minute)
		}
	}
	assert.Error(newHTTPDemoCommand().ValidateArgs([]string{"extra"}))
	assert.Equal(try.To1(httpDemoAddress("localhost:0", true)), "127.0.0.1:0")
	assert.Equal(try.To1(httpDemoEndpoint("http://localhost:1234/")),
		"http://127.0.0.1:1234")
	assert.Equal(try.To1(httpDemoEndpoint("http://[::1]:1234")),
		"http://[::1]:1234")
	for _, endpoint := range []string{
		"nats://127.0.0.1:4222", "https://127.0.0.1:1234",
		"http://user:secret@127.0.0.1:1234", "http://127.0.0.1:1234/path",
		"http://127.0.0.1:1234?", "http://127.0.0.1:1234#",
		"http://127.0.0.1", "http://127.0.0.1:0", "http://[::]:1234",
		"http://example.com:1234", "http://192.168.1.1:1234",
		"http://127.0.0.1:65536", "http://127.0.0.1:+1234",
	} {
		_, err := httpDemoEndpoint(endpoint)
		assert.Error(err, endpoint)
	}
}

// Counts generation while delegating to the real backend; no crypto is mocked.
type httpDemoEnclave struct {
	enclave.Secure
	created int
}

func (e *httpDemoEnclave) NewKeyHandle() (enclave.KeyHandle, error) {
	e.created++
	return e.Secure.NewKeyHandle()
}

func TestHTTPDemoInvalidInputsBeforeResources(t *testing.T) {
	defer assert.PushTester(t)()

	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	observed := &httpDemoEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()
	for _, tc := range []struct {
		role string
		args []string
	}{
		{"root", []string{"--listen", ":0"}},
		{"root", []string{"--listen", "0.0.0.0:0"}},
		{"root", []string{"--listen", "localhost:http"}},
		{"accept", nil},
		{"accept", []string{"--url", "http://127.0.0.1:1234"}},
		{"accept", []string{"--url", "http://127.0.0.1:1234", "--root", "xyz"}},
		{"accept", []string{"--url", "http://127.0.0.1:1234", "--root", "a0"}},
		{"accept", []string{"--url", "http://127.0.0.1:1234", "--timeout", "0s"}},
		{"accept", []string{"--url", "http://127.0.0.1:1234", "--timeout", "-1s"}},
	} {
		cmd := newHTTPDemoRoleCommand(tc.role)
		cmd.SetContext(t.Context())
		var output bytes.Buffer
		cmd.SetOut(&output)
		try.To(cmd.ParseFlags(tc.args))
		// Avoid process-wide legacy Cobra initializers; exercise the real RunE.
		assert.Error(cmd.RunE(cmd, nil))
		assert.Empty(output.String())
		assert.Equal(observed.created, 0)
		assert.SEmpty(try.To1(os.ReadDir(parent)))
	}
}

// Test-only http.Client transport. RoundTrip owns the original request body,
// checks cancellation on both sides of the synchronous handler, and returns
// recorder responses. It supplies client/handler evidence without sockets.
type httpDemoRoundTripper func(*http.Request) (*http.Response, error)

func (f httpDemoRoundTripper) RoundTrip(r *http.Request) (
	response *http.Response, err error,
) {
	body := r.Body
	defer func() {
		if body != nil {
			err = errors.Join(err, body.Close())
		}
	}()
	defer err2.Handle(&err)

	try.To(r.Context().Err())
	response = try.To1(f(r))
	if cause := r.Context().Err(); cause != nil {
		return nil, errors.Join(cause, response.Body.Close())
	}
	return response, nil
}

type httpDemoBody struct {
	io.ReadCloser
	closed, read int
	closeErr     error
}

func (b *httpDemoBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read += n
	return n, err
}

func (b *httpDemoBody) Close() error {
	b.closed++
	return errors.Join(b.closeErr, b.ReadCloser.Close())
}

func TestHTTPDemoExchange(t *testing.T) {
	for _, wrongRoot := range []bool{false, true} {
		name := "accepted"
		if wrongRoot {
			name = "wrong pinned root"
		}
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()

			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			root := &exchangeObservedHandle{Handle: key.New()}
			alice := &exchangeObservedHandle{Handle: key.New()}
			expected := key.Public(try.To1(root.CBORPublicKey()))
			if wrongRoot {
				expected = try.To1(key.New().CBORPublicKey())
			}
			handler := newHTTPExchangeHandler(root)
			var routes []string
			var bodies []*httpDemoBody
			var proposal coreintro.Path
			var submitted key.Signature
			client := newHTTPDemoClient()
			defer client.CloseIdleConnections()
			client.Transport = httpDemoRoundTripper(func(r *http.Request) (
				response *http.Response, err error,
			) {
				defer err2.Handle(&err)

				routes = append(routes, r.URL.Path)
				assert.Equal(r.Method, http.MethodPost)
				assert.Equal(r.Header.Get("Content-Type"), "application/cbor")
				var sent bytes.Buffer
				r.Body = io.NopCloser(io.TeeReader(r.Body, &sent))
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, r)
				if r.URL.Path == "/intro/offer" {
					var info key.Info
					try.To(wire.UnmarshalCanonical(&info, sent.Bytes()))
					assert.SNil(info.ID)
					assert.DeepEqual(sent.Bytes(), wire.TryMarshal(info))
					proposal = try.To1(
						coreintro.ParsePath(recorder.Body.Bytes()),
					)
				} else {
					try.To(wire.UnmarshalCanonical(&submitted, sent.Bytes()))
					assert.Equal(sent.Bytes()[0]>>5, byte(2))
					assert.DeepEqual(sent.Bytes(), wire.TryMarshal(submitted))
					assert.Equal(recorder.Code, http.StatusNoContent)
				}
				response = recorder.Result()
				body := &httpDemoBody{ReadCloser: response.Body}
				response.Body = body
				bodies = append(bodies, body)
				return response, nil
			})

			var out bytes.Buffer
			signature, err := runHTTPDemoAlice(t.Context(), client, alice,
				expected, "http://127.0.0.1:1234", &out)
			if wrongRoot {
				assert.ErrorIs(err, coreintro.ErrWrongRoot)
				assert.SNil(signature)
				assert.Equal(alice.signCalls, 0)
				assert.DeepEqual(routes, []string{"/intro/offer"})
			} else {
				assert.NoError(err)
				assert.NoError(proposal.VerifyAcceptance(signature))
				assert.DeepEqual(signature, submitted)
				assert.Equal(alice.signCalls, 1)
				assert.DeepEqual(routes, []string{"/intro/offer", "/intro/acceptance"})
				assert.Equal(out.String(), "proposal received: R -> Alice\n"+
					"choice and acceptance saved: true\n"+
					"local acceptance verifies: true\nissuer returned HTTP 204: true\n")
			}
			assert.Equal(root.signCalls, 1)
			for _, body := range bodies {
				assert.Equal(body.closed, 1)
			}
			assert.SEmpty(try.To1(os.ReadDir(parent)))
		})
	}
}

func TestHTTPDemoClientBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, operation, media, diagnostic string
		status                             int
		body                               []byte
	}{
		{"status", "offer", "", "offer returned HTTP 500", 500, []byte("private body")},
		{"redirect", "offer", "", "offer returned HTTP 307", 307, nil},
		{"media", "offer", "text/plain", "application/cbor", 200, nil},
		{"oversize", "offer", "application/cbor", "body too large", 200,
			make([]byte, exchangePayloadLimit+20)},
		{"malformed", "offer", "application/cbor", "parsing proposal", 200, []byte{0xff}},
		{"acceptance status", "acceptance", "", "acceptance returned HTTP 200", 200, nil},
		{"acceptance redirect", "acceptance", "", "acceptance returned HTTP 302", 302, nil},
		{"acceptance body", "acceptance", "", "must have no body", 204, []byte("private body")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			root := key.New()
			alice := &exchangeObservedHandle{Handle: key.New()}
			expected := key.Public(try.To1(root.CBORPublicKey()))
			handler := newHTTPExchangeHandler(root)
			var bodies []*httpDemoBody
			calls := 0
			client := newHTTPDemoClient()
			defer client.CloseIdleConnections()
			assert.That(client.Transport.(*http.Transport).Proxy == nil)
			client.Transport = httpDemoRoundTripper(func(r *http.Request) (
				response *http.Response, err error,
			) {
				defer err2.Handle(&err)

				calls++
				assert.That(
					calls <= 2,
					"redirect or retry must not send another request",
				)
				recorder := httptest.NewRecorder()
				if r.URL.Path == "/intro/"+tc.operation {
					recorder.Header().Set("Content-Type", tc.media)
					recorder.Header().
						Set("Location", "http://127.0.0.1:1234/elsewhere")
					recorder.WriteHeader(tc.status)
					// Deliberately permit a malformed 204-with-body fixture.
					try.To1(recorder.Body.Write(tc.body))
				} else {
					handler.ServeHTTP(recorder, r)
				}
				response = recorder.Result()
				response.ContentLength = 1 // Bound actual reads, not this claim.
				body := &httpDemoBody{ReadCloser: response.Body}
				response.Body = body
				bodies = append(bodies, body)
				return response, nil
			})

			signature, err := runHTTPDemoAlice(t.Context(), client, alice,
				expected, "http://127.0.0.1:1234", io.Discard)
			assert.Error(err)
			assert.That(strings.Contains(err.Error(), tc.diagnostic), err)
			assert.ThatNot(strings.Contains(err.Error(), "private body"))
			assert.SNil(signature)
			wantSigns := 0
			if tc.operation == "acceptance" {
				wantSigns = 1
			}
			assert.Equal(alice.signCalls, wantSigns)
			assert.Equal(calls, wantSigns+1)
			for _, body := range bodies {
				assert.Equal(body.closed, 1)
			}
			if tc.name == "oversize" {
				assert.Equal(bodies[0].read, exchangePayloadLimit+1)
			}
			assert.SEmpty(try.To1(os.ReadDir(parent)))
		})
	}
}

type httpDemoOutputFailure struct {
	text   string
	err    error
	cancel context.CancelFunc
}

func (w httpDemoOutputFailure) Write(data []byte) (int, error) {
	if strings.Contains(string(data), w.text) {
		if w.cancel != nil {
			w.cancel()
		}
		if w.err != nil {
			return 0, w.err
		}
	}
	return len(data), nil
}

func TestHTTPDemoCleanupAndCancellation(t *testing.T) {
	for _, scenario := range []string{
		"canceled", "cancel in transport", "cancel after saving", "close failure",
		"proposal received", "choice and acceptance saved", "issuer returned",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			root := key.New()
			alice := &exchangeObservedHandle{Handle: key.New()}
			expected := key.Public(try.To1(root.CBORPublicKey()))
			handler := newHTTPExchangeHandler(root)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			want := errors.New("local output or close failure")
			var out io.Writer = httpDemoOutputFailure{text: scenario, err: want}
			if strings.HasPrefix(scenario, "cancel") {
				want = context.Canceled
			}
			switch scenario {
			case "canceled":
				cancel()
			case "cancel after saving":
				out = httpDemoOutputFailure{text: "choice and acceptance saved", cancel: cancel}
			}
			client := newHTTPDemoClient()
			defer client.CloseIdleConnections()
			var bodies []*httpDemoBody
			calls := 0
			client.Transport = httpDemoRoundTripper(func(r *http.Request) (
				response *http.Response, err error,
			) {
				defer err2.Handle(&err)

				calls++
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, r)
				response = recorder.Result()
				body := &httpDemoBody{ReadCloser: response.Body}
				if scenario == "close failure" {
					body.closeErr = want
				}
				response.Body = body
				bodies = append(bodies, body)
				if scenario == "cancel in transport" {
					cancel()
				}
				return response, nil
			})

			signature, err := runHTTPDemoAlice(ctx, client, alice, expected,
				"http://127.0.0.1:1234", out)
			assert.ErrorIs(err, want)
			assert.SNil(signature)
			wantSigns, wantCalls := 0, 1
			switch scenario {
			case "canceled":
				wantCalls = 0
			case "cancel after saving", "choice and acceptance saved":
				wantSigns = 1
			case "issuer returned":
				wantSigns, wantCalls = 1, 2
			}
			assert.Equal(alice.signCalls, wantSigns)
			assert.Equal(calls, wantCalls)
			for _, body := range bodies {
				assert.Equal(body.closed, 1)
			}
			assert.SEmpty(try.To1(os.ReadDir(parent)))
		})
	}
}

func TestHTTPDemoAdapterOwnsRequestBody(t *testing.T) {
	defer assert.PushTester(t)()

	for _, canceled := range []bool{false, true} {
		ctx, cancel := context.WithCancel(t.Context())
		body := &httpDemoBody{
			ReadCloser: io.NopCloser(strings.NewReader("body")),
		}
		r := try.To1(http.NewRequestWithContext(ctx, http.MethodPost,
			"http://127.0.0.1:1234", body))
		if canceled {
			cancel()
		}
		transport := httpDemoRoundTripper(func(_ *http.Request) (
			response *http.Response, err error,
		) {
			defer err2.Handle(&err)

			return httptest.NewRecorder().Result(), nil
		})
		response, err := transport.RoundTrip(r)
		if canceled {
			assert.ErrorIs(err, context.Canceled)
		} else {
			assert.NoError(err)
			assert.NoError(response.Body.Close())
		}
		cancel()
		assert.Equal(body.closed, 1)
	}
}

// A socket-free listener exercises Serve ownership and error paths only.
type httpDemoListener struct {
	entered, closed chan struct{}
	closes          atomic.Int32
	acceptErr       error
	closeErr        error
}

func (l *httpDemoListener) Accept() (net.Conn, error) {
	close(l.entered)
	if l.acceptErr != nil {
		return nil, l.acceptErr
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *httpDemoListener) Close() error {
	if l.closes.Add(1) == 1 {
		close(l.closed)
		return l.closeErr
	}
	return net.ErrClosed
}

func (*httpDemoListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func TestHTTPDemoRootLifecycle(t *testing.T) {
	for _, scenario := range []string{
		"output", "serve", "server closed", "shutdown", "cancel",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			root := &exchangeObservedHandle{Handle: key.New()}
			listener := &httpDemoListener{
				entered: make(chan struct{}), closed: make(chan struct{}),
			}
			want := errors.New("local lifecycle failure")
			out := io.Discard
			switch scenario {
			case "output":
				out = failingWriter{err: want}
			case "serve":
				listener.acceptErr = want
			case "server closed":
				listener.acceptErr = http.ErrServerClosed
				want = http.ErrServerClosed
			case "shutdown":
				listener.closeErr = want
			default:
				want = nil
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			done := make(chan struct{})
			var result error
			go func() {
				result = runHTTPDemoRoot(ctx, listener, root, out)
				close(done)
			}()
			defer func() {
				cancel()
				waitHTTPDemoRoot(t, done)
			}()
			if scenario == "cancel" || scenario == "shutdown" {
				select {
				case <-listener.entered:
					cancel()
				case <-ctx.Done():
					t.Fatal("Serve did not start")
				}
			}
			waitHTTPDemoRoot(t, done)
			if want == nil {
				assert.NoError(result)
			} else {
				assert.ErrorIs(result, want)
			}
			assert.Equal(listener.closes.Load(), int32(1))
			assert.Equal(root.signCalls, 0)
		})
	}
}

func waitHTTPDemoRoot(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(7 * time.Second):
		t.Fatal("Root failed to stop within the shutdown bound")
	}
}

func TestHTTPDemoTCP(t *testing.T) {
	if !*introDemoHTTPTCP {
		t.Skip("requires -intro-demo-http-tcp; no socket opened")
	}
	defer assert.PushTester(t)()

	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	// Generate every handle before starting workers.
	root := &exchangeObservedHandle{Handle: key.New()}
	alice := &exchangeObservedHandle{Handle: key.New()}
	expected := key.Public(try.To1(root.CBORPublicKey()))
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	client := newHTTPDemoClient()
	defer client.CloseIdleConnections()
	listener := try.To1((&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0"))
	endpoint := "http://" + listener.Addr().String()
	rootOut := &exchangeReadyOutput{ready: make(chan struct{})}
	done := make(chan struct{})
	var rootErr error
	go func() {
		rootErr = runHTTPDemoRoot(ctx, listener, root, rootOut)
		close(done)
	}()
	// Join and check cleanup even when an assertion or Alice fails.
	t.Cleanup(func() {
		defer assert.PushTester(t)()

		cancel()
		client.CloseIdleConnections()
		waitHTTPDemoRoot(t, done)
		assert.NoError(rootErr)
		assert.SEmpty(try.To1(os.ReadDir(parent)))
	})
	select {
	case <-rootOut.ready:
	case <-done:
		t.Fatalf("Root stopped before readiness: %v", rootErr)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	var out bytes.Buffer
	signature := try.To1(runHTTPDemoAlice(ctx, client, alice, expected,
		endpoint, &out))
	assert.SNotEmpty(signature)
	assert.That(
		strings.HasSuffix(out.String(), "issuer returned HTTP 204: true\n"),
	)
	// Root still serves its one retained proposal after acceptance.
	_, err := postHTTPDemo(ctx, client, endpoint, "offer",
		wire.TryMarshal(try.To1(exchangePublicInfo(alice))), http.StatusOK)
	assert.Error(err)
	assert.That(strings.Contains(err.Error(), "offer returned HTTP 409"))
	cancel()
	waitHTTPDemoRoot(t, done)
	assert.NoError(rootErr)
	assert.Equal(root.signCalls, 1)
	assert.Equal(alice.signCalls, 1)
	assert.Equal(rootOut.String(), "root public key (hex): "+
		hex.EncodeToString(expected)+"\nHTTP endpoint: "+endpoint+"\n"+
		"ready for Alice\nstop with Ctrl+C\n")
}
