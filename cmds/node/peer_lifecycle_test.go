package node

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
)

func TestPeerServeLifecycle(t *testing.T) {
	f := prepareServeFixture(t)
	before := saveServeChoice(t, f, "completed")
	for _, scenario := range []string{"cancel", "owner exit", "peer exit", "output failure", "already canceled"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()

			s := setupPeerServe(t, f)
			owner := &serveListener{entered: make(chan struct{}), closed: make(chan struct{})}
			peer := &serveListener{entered: make(chan struct{}), closed: make(chan struct{})}
			want := errors.New("simulated Serve failure")
			closeErr := errors.New("simulated peer close failure")
			var output bytes.Buffer
			var out io.Writer = &output
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			switch scenario {
			case "owner exit":
				owner.acceptErr = want
			case "peer exit":
				peer.acceptErr = want
			case "output failure":
				out = failingWriter{want}
				peer.closeErr = closeErr
			case "already canceled":
				cancel()
				want = context.Canceled
			default:
				want = nil
			}
			done := make(chan struct{})
			var result error
			go func() {
				result = runNodeServe(ctx, owner, peer, s, out)
				close(done)
			}()
			defer func() { cancel(); waitNodeServe(t, done) }()
			if scenario == "cancel" {
				waitNodeServe(t, owner.entered)
				waitNodeServe(t, peer.entered)
				cancel()
			}
			waitNodeServe(t, done)
			if want == nil {
				assert.NoError(result)
			} else {
				assert.ErrorIs(result, want)
			}
			if scenario == "output failure" {
				assert.ErrorIs(result, closeErr)
			}
			assert.Equal(owner.closes.Load(), int32(1))
			assert.Equal(peer.closes.Load(), int32(1))
			assertServeClosed(t, s, f, before)
		})
	}
}

func TestPeerBindFailureCleanup(t *testing.T) {
	defer assert.PushTester(t)()

	f := prepareServeFixture(t)
	before := saveServeChoice(t, f, "completed")
	credentials := t.TempDir()
	t.Setenv("TMPDIR", credentials)
	config := &net.ListenConfig{}
	occupied := try.To1(config.Listen(t.Context(), "tcp", "127.0.0.1:0"))
	defer func() { try.Out(occupied.Close()).Logf() }()
	// Reserve then release an explicit owner port so it can be checked after
	// the second bind fails. No HTTP goroutine starts until both binds succeed.
	probe := try.To1(config.Listen(t.Context(), "tcp", "127.0.0.1:0"))
	ownerAddress := probe.Addr().String()
	try.To(probe.Close())
	for _, firstFails := range []bool{false, true} {
		cmd := serveCommand(t, f)
		listenAddress := ownerAddress
		if firstFails {
			listenAddress = occupied.Addr().String()
		}
		try.To(cmd.Flags().Set("listen", listenAddress))
		try.To(cmd.Flags().Set("peer-listen", occupied.Addr().String()))
		if firstFails {
			try.To(cmd.Flags().Set("peer-listen", "127.0.0.1:0"))
		}
		var output bytes.Buffer
		cmd.SetOut(&output)
		assert.Error(cmd.RunE(cmd, nil))
		assert.Empty(output.String())
		assert.SEmpty(try.To1(os.ReadDir(credentials)))
		owner, peer := try.To2(bindNodeListeners(t.Context(), ownerAddress, ""))
		assert.INil(peer) // Disabled means exactly one socket, including port zero.
		try.To(owner.Close())
		// Reopening proves Store/usage locks were released and saved choice kept.
		s, _ := try.To2(setupNodeServe(t.Context(), serveCommand(t, f)))
		_, found := try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
		assert.ThatNot(found)
		try.To(s.close())
		assertServeClosed(t, s, f, before)
	}
}

type peerObservedListener struct {
	net.Listener
	closed chan struct{}
	once   sync.Once
}

func (l *peerObservedListener) Close() error {
	err := l.Listener.Close()
	l.once.Do(func() { close(l.closed) })
	return err
}

type peerHTTPResult struct {
	status int
	body   []byte
	err    error
}

func peerHTTPRequest(ctx context.Context, url, authorization string) <-chan peerHTTPResult {
	done := make(chan peerHTTPResult, 1)
	go func() {
		client := &http.Client{Timeout: 5 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: true}}
		defer client.CloseIdleConnections()
		r, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			done <- peerHTTPResult{err: err}
			return
		}
		r.Header.Set("Authorization", authorization)
		response, err := client.Do(r)
		if err != nil {
			done <- peerHTTPResult{err: err}
			return
		}
		body, err := io.ReadAll(response.Body)
		done <- peerHTTPResult{response.StatusCode, body, errors.Join(err, response.Body.Close())}
	}()
	return done
}

func waitPeerHTTP(t *testing.T, done <-chan peerHTTPResult) peerHTTPResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(7 * time.Second):
		t.Fatal("HTTP request did not finish")
		return peerHTTPResult{}
	}
}

func TestPeerSocketsJoinBeforeStoreClose(t *testing.T) {
	for _, tc := range []struct{ unexpected, ad, proof, challenge bool }{
		{false, false, false, false}, {true, false, false, false},
		{false, true, false, false}, {true, true, false, false},
		{false, true, true, false}, {true, true, true, false},
		{false, true, false, true}, {true, true, false, true},
	} {
		unexpected := tc.unexpected
		t.Run(fmt.Sprint("unexpected=", unexpected, "/ad=", tc.ad, "/proof=", tc.proof, "/challenge=", tc.challenge), func(t *testing.T) {
			defer assert.PushTester(t)()

			f := prepareServeFixture(t)
			before := saveServeChoice(t, f, "completed")
			s := setupPeerServe(t, f)
			owner, peer := try.To2(bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress))
			assert.NotEqual(owner.Addr().String(), peer.Addr().String())
			s.configurePublication(peer) // Install before wrapping or admitting requests.
			var current ads.Current
			var requester key.Public
			if tc.ad {
				auth := serveAuthorization(t, s)
				assert.Equal(serveDeviceRequest(s.handler, auth, "POST", "/owner/introductions", try.To1(onboarding.EncodeIntroduction(before))).Code, 200)
				assert.Equal(serveDeviceRequest(s.handler, auth, "POST", "/owner/introductions/verify", []byte("{}")).Code, 200)
				assert.Equal(serveDeviceRequest(s.handler, auth, "POST", ownerBootstrapPath, []byte("{}")).Code, 200)
				assert.Equal(serveDeviceRequest(s.handler, auth, "POST", ownerPublishPath, []byte("{}")).Code, 200)
				current, _ = try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
			}
			if tc.challenge {
				requester = saveChallengeRequester(t, s, f, true)
			}
			listeners := []*peerObservedListener{
				{Listener: owner, closed: make(chan struct{})},
				{Listener: peer, closed: make(chan struct{})},
			}
			release := make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			entered := []chan struct{}{make(chan struct{}), make(chan struct{})}
			reads := make(chan error, 2)
			gate := func(index int, next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					close(entered[index])
					<-release
					_, _, err := onboarding.ReadStoredChoice(s.store.Vault(), f.root, f.child)
					reads <- err
					next.ServeHTTP(w, r)
				})
			}
			s.handler, s.peerHandler = gate(0, s.handler), gate(1, s.peerHandler)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			var output bytes.Buffer
			done := make(chan struct{})
			var result error
			go func() {
				result = runNodeServe(ctx, listeners[0], listeners[1], s, &output)
				close(done)
			}()
			defer func() { cancel(); unblock(); waitNodeServe(t, done) }()
			header := string(try.To1(os.ReadFile(s.headerFile)))
			authorization := strings.TrimSpace(strings.TrimPrefix(header, "Authorization: "))
			ownerURL := "http://" + owner.Addr().String() + "/owner/status"
			peerURL := "http://" + peer.Addr().String() + "/peer/introduction"
			ownerResponse := peerHTTPRequest(t.Context(), ownerURL, authorization)
			readURL := peerURL
			if tc.ad {
				readURL = "http://" + peer.Addr().String() + "/peer/ad"
			}
			var peerResponse <-chan peerHTTPResult
			var proofAd, nonce []byte
			challengeStart := time.Now()
			if tc.proof || tc.challenge {
				proofAd = try.To1(wire.Marshal(current))
				nonce = peerProofNonce(t)
				body := peerProofBody(t, proofAd, nonce)
				path := peerProofPath
				if tc.challenge {
					body = peerChallengeBody(t, requester, proofAd)
					path = peerChallengePath
				}
				response := make(chan peerHTTPResult, 1)
				peerResponse = response
				go func() {
					response <- postPeerProofHTTP(t.Context(), "http://"+peer.Addr().String()+path, "", body, false)
				}()
			} else {
				peerResponse = peerHTTPRequest(t.Context(), readURL, "")
			}
			waitNodeServe(t, entered[0])
			waitNodeServe(t, entered[1])
			if unexpected {
				// Force Serve to fail with a handler still inside the failed server.
				try.To(owner.Close())
			} else {
				cancel()
			}
			for _, listener := range listeners {
				waitNodeServe(t, listener.closed)
			}
			select {
			case <-done:
				t.Fatal("service returned while handlers still used the Vault")
			default:
			}
			try.To2(onboarding.ReadStoredChoice(s.store.Vault(), f.root, f.child))
			unblock()
			waitNodeServe(t, done)
			for range 2 {
				select {
				case err := <-reads:
					assert.NoError(err)
				default:
					t.Fatal("service failed to join an admitted request")
				}
			}
			if unexpected {
				assert.ErrorIs(result, net.ErrClosed)
			} else {
				assert.NoError(result)
			}
			a, b := waitPeerHTTP(t, ownerResponse), waitPeerHTTP(t, peerResponse)
			if !unexpected {
				assert.NoError(a.err)
				assert.Equal(a.status, http.StatusOK)
			}
			assert.NoError(b.err)
			assert.Equal(b.status, http.StatusOK)
			if tc.challenge {
				assertPeerChallenge(t, b, challengeStart)
			} else if tc.proof {
				assertOnlineProof(t, b, f, proofAd, nonce)
			} else if tc.ad {
				assertPeerAd(t, b.body, before, current)
			} else {
				assert.DeepEqual(b.body, try.To1(onboarding.EncodeIntroduction(before)))
			}
			assert.That(strings.Contains(output.String(), "owner status URL: "+ownerURL))
			assert.That(strings.Contains(output.String(), "peer introduction URL: "+peerURL))
			assert.ThatNot(strings.Contains(output.String(), authorization))
			assertServeClosed(t, s, f, before)
		})
	}
}
