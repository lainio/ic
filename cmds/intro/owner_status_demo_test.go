package intro

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/findy-network/findy-agent-auth/acator/enclave"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/cmds"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestOwnerStatusDemoCommand(t *testing.T) {
	defer assert.PushTester(t)()

	registered, args, err := cmds.RootCmd().Find(
		[]string{"intro", "owner-status-demo"},
	)
	assert.NoError(err)
	assert.SEmpty(args)
	assert.Equal(registered.Use, "owner-status-demo CASE")
	assert.Equal(registered.Parent().Name(), "intro")
	cmd := newOwnerStatusDemoCommand()
	assert.DeepEqual(cmd.ValidArgs, []string{"unselected", "completed"})
	for _, fixture := range cmd.ValidArgs {
		assert.NoError(cmd.ValidateArgs([]string{fixture}))
	}
	assert.Equal(try.To1(cmd.Flags().GetString("listen")), "127.0.0.1:0")

	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	observed := &httpDemoEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()
	for _, tc := range []struct {
		args     []string
		listen   string
		canceled bool
	}{
		{nil, "127.0.0.1:0", false},
		{[]string{"pending"}, "127.0.0.1:0", false},
		{[]string{"completed", "unselected"}, "127.0.0.1:0", false},
		{[]string{"completed"}, "0.0.0.0:0", false},
		{[]string{"unselected"}, "127.0.0.1:0", true},
	} {
		cmd := newOwnerStatusDemoCommand()
		ctx, cancel := context.WithCancel(t.Context())
		if tc.canceled {
			cancel()
		}
		cmd.SetContext(ctx)
		var output bytes.Buffer
		cmd.SetOut(&output)
		try.To(cmd.Flags().Set("listen", tc.listen))
		// Avoid process-wide legacy Cobra initializers, as in the peer demos.
		err := cmd.RunE(cmd, tc.args)
		cancel()
		assert.Error(err)
		if tc.canceled {
			assert.ErrorIs(err, context.Canceled)
		}
		assert.Empty(output.String())
		assert.Equal(observed.created, 0)
		assert.SEmpty(try.To1(os.ReadDir(parent)))
	}
}

// Reuse the real signing backend and the handle that rejects private ID access.
type ownerStatusDemoEnclave struct {
	enclave.Secure
	handles []*exchangeObservedHandle
}

func (e *ownerStatusDemoEnclave) NewKeyHandle() (
	handle enclave.KeyHandle, err error,
) {
	defer err2.Handle(&err, nil)

	observed := &exchangeObservedHandle{
		Handle: try.To1(e.Secure.NewKeyHandle()),
	}
	e.handles = append(e.handles, observed)
	return observed, nil
}

func TestOwnerStatusDemoFixtures(t *testing.T) {
	for _, fixture := range []string{"unselected", "completed"} {
		t.Run(fixture, func(t *testing.T) {
			defer assert.PushTester(t)()

			observed := &ownerStatusDemoEnclave{Secure: key.Enclave}
			key.Enclave = observed
			defer func() { key.Enclave = observed.Secure }()
			demo := try.To1(setupOwnerStatusDemo(t.Context(), fixture))
			defer func() { try.Out(demo.close()).Logf() }()
			authorization := ownerStatusDemoHeader(t, demo)
			assert.SLen(observed.handles, 2)
			expectedRoot := try.To1(observed.handles[0].CBORPublicKey())
			expectedChild := try.To1(observed.handles[1].CBORPublicKey())
			before, found := try.To2(onboarding.ReadStoredChoice(
				demo.vault, expectedRoot, expectedChild,
			))
			assert.Equal(found, fixture == "completed")
			wantSigns := 0
			if found {
				wantSigns = 1
				assert.SLen(before.Proposal, 2)
				assert.NoError(
					before.Proposal.VerifyAcceptance(before.Acceptance),
				)
				for _, edge := range before.Proposal {
					assert.SNil(edge.Body.Child.ID)
				}
			}
			path := filepath.Join(demo.dir, "vault.db")
			contents := try.To1(os.ReadFile(path))
			remaining := demo.provider.remainingEncryptions
			assert.That(remaining < storedChoiceEncryptionBudget)
			assert.That(remaining > 0)

			for _, tc := range []struct {
				method, path, credential string
				status                   int
			}{
				{http.MethodGet, "/owner/status", "", http.StatusUnauthorized},
				{http.MethodGet, "/owner/status", authorization, http.StatusOK},
				{http.MethodGet, "/owner/status", authorization, http.StatusOK},
				{http.MethodPost, "/intro/offer", authorization, http.StatusNotFound},
				{http.MethodPost, "/owner/status", authorization, http.StatusMethodNotAllowed},
			} {
				request := httptest.NewRequest(tc.method, tc.path, nil)
				if tc.credential != "" {
					request.Header.Set("Authorization", tc.credential)
				}
				response := httptest.NewRecorder()
				demo.handler.ServeHTTP(response, request)
				assert.Equal(response.Code, tc.status)
				if tc.status == http.StatusOK {
					assert.Equal(response.Body.String(),
						"{\"choice\":\""+fixture+"\"}\n")
				}
			}
			after, foundAfter := try.To2(onboarding.ReadStoredChoice(
				demo.vault, expectedRoot, expectedChild,
			))
			assert.Equal(foundAfter, found)
			assert.DeepEqual(after, before)
			assert.DeepEqual(try.To1(os.ReadFile(path)), contents)
			assert.Equal(demo.provider.remainingEncryptions, remaining)
			for _, handle := range observed.handles {
				assert.Equal(handle.signCalls, wantSigns)
			}

			assert.NoError(demo.close())
			assertOwnerStatusDemoClosed(t, demo)
		})
	}
}

func ownerStatusDemoHeader(t *testing.T, demo *ownerStatusDemo) string {
	t.Helper()
	dir := try.To1(os.Stat(demo.dir))
	file := try.To1(os.Stat(demo.headerFile))
	assert.That(dir.IsDir())
	assert.Equal(dir.Mode().Perm()&0o077, os.FileMode(0))
	assert.That(file.Mode().IsRegular())
	assert.Equal(file.Mode().Perm()&0o177, os.FileMode(0))
	header := string(try.To1(os.ReadFile(demo.headerFile)))
	assert.That(regexp.MustCompile(
		`^Authorization: Bearer [0-9a-f]{64}\n$`,
	).MatchString(header), "private header file format")
	assert.ThatNot(strings.Contains(header,
		hex.EncodeToString(demo.provider.secret)), "separate credential")
	return strings.TrimSuffix(
		strings.TrimPrefix(header, "Authorization: "),
		"\n",
	)
}

func assertOwnerStatusDemoClosed(t *testing.T, demo *ownerStatusDemo) {
	t.Helper()
	_, err := os.Stat(demo.dir)
	assert.ErrorIs(err, os.ErrNotExist)
	assert.That(bytes.Equal(demo.provider.secret, make([]byte, 32)))
	assert.ErrorIs(demo.vault.View(func(_ storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		return nil
	}), storage.ErrClosed)
	_, err = demo.db.OpenVault(t.Context(), demo.provider.vault,
		demo.provider.id, demo.provider)
	assert.ErrorIs(err, storage.ErrClosed)
}

func TestOwnerStatusDemoLifecycle(t *testing.T) {
	for _, scenario := range []string{
		"output", "output and close", "serve", "server closed", "shutdown", "cancel",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			demo := try.To1(setupOwnerStatusDemo(t.Context(), "completed"))
			defer func() { try.Out(demo.close()).Logf() }()
			authorization := ownerStatusDemoHeader(t, demo)
			secret := hex.EncodeToString(demo.provider.secret)
			listener := &httpDemoListener{
				entered: make(chan struct{}), closed: make(chan struct{}),
			}
			want := errors.New("owner demo lifecycle failure")
			closeFailure := errors.New("listener close failure")
			output := &ownerStatusDemoReadyOutput{ready: make(chan struct{})}
			var out io.Writer = output
			switch scenario {
			case "output", "output and close":
				out = failingWriter{err: want}
				if scenario == "output and close" {
					listener.closeErr = closeFailure
				}
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
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			done := make(chan struct{})
			var result error
			go func() {
				result = runOwnerStatusDemo(ctx, listener, demo, out)
				close(done)
			}()
			defer func() {
				cancel()
				waitHTTPDemoRoot(t, done)
			}()
			if scenario == "cancel" || scenario == "shutdown" {
				select {
				case <-listener.entered:
					// Resources remain usable until HTTP shutdown starts.
					assert.That(
						try.To1(os.Stat(demo.headerFile)).
							Mode().
							IsRegular(),
					)
					request := httptest.NewRequest(
						http.MethodGet,
						"/owner/status",
						nil,
					)
					request.Header.Set("Authorization", authorization)
					response := httptest.NewRecorder()
					demo.handler.ServeHTTP(response, request)
					assert.Equal(response.Code, http.StatusOK)
					cancel()
				case <-ctx.Done():
					t.Fatal("owner Serve did not start")
				}
			}
			waitHTTPDemoRoot(t, done)
			if want == nil {
				assert.NoError(result)
			} else {
				assert.ErrorIs(result, want)
			}
			if scenario == "output and close" {
				assert.ErrorIs(result, closeFailure)
			}
			assert.Equal(listener.closes.Load(), int32(1))
			if !strings.HasPrefix(scenario, "output") {
				// Boolean assertion avoids printing secret material on failure.
				assert.ThatNot(strings.Contains(output.String(), secret))
				assert.ThatNot(strings.Contains(output.String(),
					strings.TrimPrefix(authorization, "Bearer ")))
				assert.Equal(output.String(), "fixture: completed\n"+
					"owner status URL: http://127.0.0.1:1234/owner/status\n"+
					"authorization header file: "+demo.headerFile+"\n"+
					"stop with Ctrl+C\n")
			}
			assertOwnerStatusDemoClosed(t, demo)
		})
	}
}

type ownerStatusDemoReadyOutput struct {
	bytes.Buffer
	ready chan struct{}
}

func (out *ownerStatusDemoReadyOutput) Write(data []byte) (int, error) {
	n, err := out.Buffer.Write(data)
	close(out.ready) // The runner writes its complete readiness message once.
	return n, err
}

func TestOwnerStatusDemoTCP(t *testing.T) {
	if !*introDemoHTTPTCP {
		t.Skip("requires -intro-demo-http-tcp; no socket opened")
	}
	defer assert.PushTester(t)()

	demo := try.To1(setupOwnerStatusDemo(t.Context(), "completed"))
	defer func() { try.Out(demo.close()).Logf() }()
	authorization := ownerStatusDemoHeader(t, demo)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	listener := try.To1(
		(&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0"),
	)
	endpoint := "http://" + listener.Addr().String() + "/owner/status"
	out := &ownerStatusDemoReadyOutput{ready: make(chan struct{})}
	done := make(chan struct{})
	var result error
	go func() {
		result = runOwnerStatusDemo(ctx, listener, demo, out)
		close(done)
	}()
	client := newHTTPDemoClient()
	defer func() {
		cancel()
		client.CloseIdleConnections()
		waitHTTPDemoRoot(t, done)
		assert.NoError(result)
		assertOwnerStatusDemoClosed(t, demo)
	}()
	select {
	case <-out.ready:
	case <-done:
		t.Fatalf("owner listener stopped before readiness: %v", result)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	for _, credential := range []string{"", authorization} {
		request := try.To1(http.NewRequestWithContext(ctx,
			http.MethodGet, endpoint, nil))
		if credential != "" {
			request.Header.Set("Authorization", credential)
		}
		response := try.To1(client.Do(request))
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		assert.NoError(errors.Join(readErr, closeErr))
		if credential == "" {
			assert.Equal(response.StatusCode, http.StatusUnauthorized)
		} else {
			assert.Equal(response.StatusCode, http.StatusOK)
			assert.Equal(string(body), "{\"choice\":\"completed\"}\n")
		}
	}
	cancel()
	waitHTTPDemoRoot(t, done)
	assert.NoError(result)
	assertOwnerStatusDemoClosed(t, demo)
}
