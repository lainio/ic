package intro

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
)

func TestHTTPOwnerCommand(t *testing.T) {
	defer assert.PushTester(t)()

	assert.Nil(newHTTPDemoRoleCommand("root").Flags().Lookup("owner-listen"))
	assert.Equal(try.To1(newHTTPDemoRoleCommand("accept").Flags().
		GetString("owner-listen")), "")
	rootHex := hex.EncodeToString(try.To1(key.New().CBORPublicKey()))
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	observed := &httpDemoEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()

	for _, address := range []string{
		"", ":0", "0.0.0.0:0", "localhost:http", "127.0.0.1:0",
	} {
		cmd := newHTTPDemoRoleCommand("accept")
		ctx, cancel := context.WithCancel(t.Context())
		if address == "127.0.0.1:0" {
			cancel() // Valid flags, cancellation before any resource or bind.
		}
		cmd.SetContext(ctx)
		var output bytes.Buffer
		cmd.SetOut(&output)
		try.To(cmd.ParseFlags([]string{
			"--url", "http://127.0.0.1:1234", "--root", rootHex,
			"--owner-listen", address,
		}))
		err := cmd.RunE(cmd, nil)
		cancel()
		assert.Error(err)
		if address == "127.0.0.1:0" {
			assert.ErrorIs(err, context.Canceled)
		}
		assert.Empty(output.String())
		assert.Equal(observed.created, 0)
		assert.SEmpty(try.To1(os.ReadDir(parent)))
	}
}

func TestHTTPOwnerExchange(t *testing.T) {
	defer assert.PushTester(t)()

	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	// Generate keys before workers; ID() access would panic in these handles.
	root := &exchangeObservedHandle{Handle: key.New()}
	alice := &exchangeObservedHandle{Handle: key.New()}
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	expectedChild := key.Public(try.To1(alice.CBORPublicKey()))
	observed := &httpDemoEnclave{Secure: key.Enclave}
	key.Enclave = observed
	defer func() { key.Enclave = observed.Secure }()
	demo := try.To1(
		setupOwnerStatusResources(t.Context(), expectedRoot, expectedChild),
	)
	defer func() { try.Out(demo.close()).Logf() }()
	authorization := ownerStatusDemoHeader(t, demo)
	secret := hex.EncodeToString(demo.provider.secret)
	assert.Equal(observed.created, 0)
	assert.Equal(alice.signCalls, 0)
	_, found := try.To2(
		onboarding.ReadStoredChoice(demo.vault, expectedRoot, expectedChild),
	)
	assert.ThatNot(found)
	request := httptest.NewRequest(http.MethodGet, "/owner/status", nil)
	response := httptest.NewRecorder()
	demo.handler.ServeHTTP(response, request)
	assert.Equal(response.Code, http.StatusUnauthorized)
	request.Header.Set("Authorization", authorization)
	response = httptest.NewRecorder()
	demo.handler.ServeHTTP(response, request)
	assert.Equal(response.Code, http.StatusOK)
	assert.Equal(response.Body.String(), "{\"choice\":\"unselected\"}\n")

	listener := &httpDemoListener{
		entered: make(chan struct{}), closed: make(chan struct{}),
	}
	peer := newHTTPExchangeHandler(root)
	var proposal coreintro.Path
	var submitted key.Signature
	var requests []*http.Request
	client := newHTTPDemoClient()
	defer client.CloseIdleConnections()
	client.Transport = httpDemoRoundTripper(func(r *http.Request) (
		response *http.Response, err error,
	) {
		defer err2.Handle(&err)

		select {
		case <-listener.entered:
			return nil, errors.New(
				"owner Serve started before exchange completed",
			)
		default:
		}
		requests = append(requests, r)
		var sent bytes.Buffer
		r.Body = io.NopCloser(io.TeeReader(r.Body, &sent))
		recorder := httptest.NewRecorder()
		peer.ServeHTTP(recorder, r)
		if r.URL.Path == "/intro/offer" {
			proposal = try.To1(coreintro.ParsePath(recorder.Body.Bytes()))
		} else {
			try.To(wire.UnmarshalCanonical(&submitted, sent.Bytes()))
			if recorder.Code != http.StatusNoContent {
				return nil, errors.New("peer did not verify acceptance")
			}
		}
		return recorder.Result(), nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	var output bytes.Buffer
	done := make(chan struct{})
	var result error
	go func() {
		result = runHTTPOwner(ctx, listener, demo, client, alice,
			expectedRoot, "http://127.0.0.1:1234", time.Second, &output)
		close(done)
	}()
	defer func() {
		cancel()
		waitHTTPDemoRoot(t, done)
	}()
	select {
	case <-listener.entered:
	case <-done:
		t.Fatalf("owner stopped before Serve: %v", result)
	case <-time.After(5 * time.Second):
		t.Fatal("owner Serve did not start")
	}

	assert.NoError(ctx.Err())
	assert.SLen(requests, 2)
	assert.Equal(requests[0].URL.Path, "/intro/offer")
	assert.Equal(requests[1].URL.Path, "/intro/acceptance")
	for _, r := range requests {
		assert.Empty(r.Header.Get("Authorization"))
		// Ending the exchange context has not stopped the owner service.
		assert.ErrorIs(r.Context().Err(), context.Canceled)
	}
	stored, found := try.To2(
		onboarding.ReadStoredChoice(demo.vault, expectedRoot, expectedChild),
	)
	assert.That(found)
	assert.DeepEqual(stored.Proposal.Bytes(), proposal.Bytes())
	assert.DeepEqual(stored.Acceptance, submitted)
	assert.NoError(proposal.VerifyAcceptance(submitted))
	for _, edge := range stored.Proposal {
		assert.SNil(edge.Body.Child.ID)
	}
	assert.Equal(root.signCalls, 1)
	assert.Equal(alice.signCalls, 1)
	remaining := demo.provider.remainingEncryptions
	for range 3 {
		response = httptest.NewRecorder()
		demo.handler.ServeHTTP(response, request)
		assert.Equal(response.Code, http.StatusOK)
		assert.Equal(response.Body.String(), "{\"choice\":\"completed\"}\n")
	}
	request = httptest.NewRequest(http.MethodPost, "/intro/offer", nil)
	request.Header.Set("Authorization", authorization)
	response = httptest.NewRecorder()
	demo.handler.ServeHTTP(response, request)
	assert.Equal(response.Code, http.StatusNotFound)
	after, found := try.To2(
		onboarding.ReadStoredChoice(demo.vault, expectedRoot, expectedChild),
	)
	assert.That(found)
	assert.DeepEqual(after, stored)
	assert.Equal(alice.signCalls, 1)
	assert.Equal(demo.provider.remainingEncryptions, remaining)
	assert.SLen(try.To1(os.ReadDir(parent)), 1)
	assert.Equal(observed.created, 0)

	cancel()
	waitHTTPDemoRoot(t, done)
	assert.NoError(result)
	assert.Equal(listener.closes.Load(), int32(1))
	assertOwnerStatusDemoClosed(t, demo)
	assert.SEmpty(try.To1(os.ReadDir(parent)))
	assert.ThatNot(strings.Contains(output.String(), secret))
	assert.ThatNot(strings.Contains(output.String(),
		strings.TrimPrefix(authorization, "Bearer ")))
	assert.Equal(output.String(), "proposal received: R -> Alice\n"+
		"choice and acceptance saved: true\nlocal acceptance verifies: true\n"+
		"issuer returned HTTP 204: true\n"+
		"owner status URL: http://127.0.0.1:1234/owner/status\n"+
		"authorization header file: "+demo.headerFile+"\nstop with Ctrl+C\n")
}

func TestHTTPOwnerFailures(t *testing.T) {
	for _, scenario := range []string{
		"wrong root", "acceptance status", "canceled", "cancel after saving",
		"readiness output", "serve",
	} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			root := key.New()
			alice := &exchangeObservedHandle{Handle: key.New()}
			expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
			expectedChild := key.Public(try.To1(alice.CBORPublicKey()))
			if scenario == "wrong root" {
				expectedRoot = try.To1(key.New().CBORPublicKey())
			}
			demo := try.To1(
				setupOwnerStatusResources(
					t.Context(),
					expectedRoot,
					expectedChild,
				),
			)
			defer func() { try.Out(demo.close()).Logf() }()
			listener := &httpDemoListener{
				entered: make(chan struct{}), closed: make(chan struct{}),
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			want := errors.New("owner startup failure")
			closeFailure := errors.New("listener close failure")
			var output bytes.Buffer
			var out io.Writer = &output
			wantSigns, wantCalls := 1, 2
			switch scenario {
			case "wrong root":
				want = coreintro.ErrWrongRoot
				listener.closeErr = closeFailure
				wantSigns, wantCalls = 0, 1
			case "canceled":
				want = context.Canceled
				wantSigns, wantCalls = 0, 0
				cancel()
			case "cancel after saving":
				want = context.Canceled
				wantCalls = 1
				out = httpDemoOutputFailure{
					text:   "choice and acceptance saved",
					cancel: cancel,
				}
			case "readiness output":
				out = httpDemoOutputFailure{
					text: "owner status URL",
					err:  want,
				}
			case "serve":
				listener.acceptErr = want
			}
			peer := newHTTPExchangeHandler(root)
			calls := 0
			client := newHTTPDemoClient()
			defer client.CloseIdleConnections()
			client.Transport = httpDemoRoundTripper(func(r *http.Request) (
				response *http.Response, err error,
			) {
				defer err2.Handle(&err)

				calls++
				recorder := httptest.NewRecorder()
				if scenario == "acceptance status" &&
					r.URL.Path == "/intro/acceptance" {
					recorder.WriteHeader(http.StatusServiceUnavailable)
				} else {
					peer.ServeHTTP(recorder, r)
				}
				return recorder.Result(), nil
			})

			err := runHTTPOwner(ctx, listener, demo, client, alice,
				expectedRoot, "http://127.0.0.1:1234", time.Second, out)
			if scenario == "acceptance status" {
				assert.Error(err)
				assert.That(
					strings.Contains(
						err.Error(),
						"acceptance returned HTTP 503",
					),
				)
			} else {
				assert.ErrorIs(err, want)
			}
			if scenario == "wrong root" {
				assert.ErrorIs(err, closeFailure)
			}
			if scenario != "serve" {
				select {
				case <-listener.entered:
					t.Fatal("owner Serve started on failure")
				default:
				}
				assert.ThatNot(
					strings.Contains(output.String(), "owner status URL"),
				)
			}
			assert.Equal(calls, wantCalls)
			assert.Equal(alice.signCalls, wantSigns)
			assert.Equal(listener.closes.Load(), int32(1))
			assertOwnerStatusDemoClosed(t, demo)
			assert.SEmpty(try.To1(os.ReadDir(parent)))
		})
	}
}
