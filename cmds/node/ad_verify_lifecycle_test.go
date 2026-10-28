package node

import (
	"bytes"
	"context"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/nodevault"
	"github.com/lainio/ic/storage"
)

func TestServeAdVerificationReplacedReceipt(t *testing.T) {
	defer assert.PushTester(t)()
	a, b := newVerificationPair(t, false)
	assertAdVerification(t, b.verify(t.Context(), a.fixture.child), a.fixture.child, true)
	history := bytes.Clone(a.ad)
	a.publish(t)
	receiveVerificationAd(t, b, a)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	a.setResponse(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		recorded := httptest.NewRecorder()
		next.ServeHTTP(recorded, r) // Capture a genuine proof for the old receipt.
		close(entered)
		select {
		case <-release:
			maps.Copy(w.Header(), recorded.Header())
			w.WriteHeader(recorded.Code)
			_, _ = w.Write(recorded.Body.Bytes())
		case <-r.Context().Done():
		}
	})
	result := make(chan peerHTTPResult, 1)
	go func() { result <- b.verify(t.Context(), a.fixture.child) }()
	waitNodeServe(t, entered)
	a.publish(t)
	// Use the supported owner fetch path while verification is in flight. Its
	// mutation lock remains available; the unchanged Known binding stays valid.
	body := []byte(`{"peer_url":"` + a.peer.URL + `/peer/ad"}`)
	fetched := postPeerProofHTTP(t.Context(), b.owner.URL+ownerAdFetchPath, b.auth, body, false)
	assert.NoError(fetched.err)
	assert.Equal(fetched.status, 200)
	before := try.To1(verificationUnrelatedState(b.service.store.Vault()))
	vaultBytes := try.To1(os.ReadFile(filepath.Join(b.fixture.dir, "state", "vault.db")))
	unblock()
	got := waitPeerHTTP(t, result)
	assert.NoError(got.err)
	assert.Equal(got.status, 409)
	assert.Equal(string(got.body), "Conflict\n")
	assertHistoricalAd(t, b, a, history)
	receipt, found := try.To2(ads.ReadReceivedClaim(b.service.store.Vault(), b.fixture.root, a.fixture.child))
	assert.That(found)
	assert.DeepEqual(receipt, a.ad)
	assert.DeepEqual(try.To1(verificationUnrelatedState(b.service.store.Vault())), before)
	assert.DeepEqual(try.To1(os.ReadFile(filepath.Join(b.fixture.dir, "state", "vault.db"))), vaultBytes)
	assert.Equal(a.calls.Load(), int32(2))
}

func TestServeAdVerificationRemoteFailureKeepsHistory(t *testing.T) {
	for _, scenario := range []string{"refusal", "malformed", "invalid signature"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			a, b := newVerificationPair(t, false)
			assertAdVerification(t, b.verify(t.Context(), a.fixture.child), a.fixture.child, true)
			assertPeerFilesUnchanged(t, b.fixture)
			a.setResponse(func(w http.ResponseWriter, _ *http.Request, _ http.Handler) {
				w.Header().Set("Content-Type", "application/json")
				switch scenario {
				case "refusal":
					w.WriteHeader(409)
					_, _ = w.Write([]byte("private remote diagnostic"))
				case "malformed":
					_, _ = w.Write([]byte(`{"private":"remote diagnostic"}`))
				case "invalid signature":
					_, _ = w.Write([]byte(`{"version":1,"proof":"AQ=="}`))
				}
			})
			got := b.verify(t.Context(), a.fixture.child)
			assert.NoError(got.err)
			assert.Equal(got.status, 502)
			assert.Equal(string(got.body), "Bad Gateway\n")
			assertHistoricalAd(t, b, a, a.ad)
			assert.Equal(a.calls.Load(), int32(2))
		})
	}
}

func TestServeAdVerificationShutdownJoinsBeforeVaultClose(t *testing.T) {
	for _, unexpected := range []bool{false, true} {
		t.Run(map[bool]string{false: "shutdown", true: "connection cancellation"}[unexpected], func(t *testing.T) {
			defer assert.PushTester(t)()
			a, b := newVerificationPair(t, false)
			b.owner.Close() // Exercise the actual runNodeServe lifecycle below.
			proofEntered, proofRelease := make(chan struct{}), make(chan struct{})
			handlerReturned, handlerRelease := make(chan struct{}), make(chan struct{})
			var proofOnce, handlerOnce sync.Once
			unblockProof := func() { proofOnce.Do(func() { close(proofRelease) }) }
			unblockHandler := func() { handlerOnce.Do(func() { close(handlerRelease) }) }
			a.setResponse(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				close(proofEntered)
				select {
				case <-proofRelease:
					next.ServeHTTP(w, r)
				case <-r.Context().Done():
				}
			})
			reads := make(chan error, 1)
			canceled := make(chan error, 1)
			next := b.service.handler
			b.service.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(w, r)
				_, _, err := ads.ReadVerifiedClaim(b.service.store.Vault(), b.fixture.root, a.fixture.child)
				reads <- err
				canceled <- r.Context().Err()
				close(handlerReturned)
				<-handlerRelease // Test-owned gate released in bounded cleanup.
			})
			owner, peer := try.To2(bindNodeListeners(t.Context(), "127.0.0.1:0", ""))
			assert.INil(peer)
			listener := &peerObservedListener{Listener: owner, closed: make(chan struct{})}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			var serveErr error
			go func() { serveErr = runNodeServe(ctx, listener, nil, b.service, io.Discard); close(done) }()
			defer func() { cancel(); unblockProof(); unblockHandler(); waitNodeServe(t, done) }()
			response := make(chan peerHTTPResult, 1)
			go func() {
				response <- postPeerProofHTTP(t.Context(), "http://"+owner.Addr().String()+ownerAdVerifyPath,
					b.auth, ownerAdVerificationBody(a.fixture.child), false)
			}()
			waitNodeServe(t, proofEntered)
			if unexpected {
				try.To(owner.Close())
			} else {
				cancel()
			}
			waitNodeServe(t, listener.closed)
			select {
			case <-done:
				t.Fatal("service closed while verification was admitted")
			default:
			}
			try.To2(ads.ReadReceivedClaim(b.service.store.Vault(), b.fixture.root, a.fixture.child))
			if !unexpected {
				unblockProof()
			}
			waitNodeServe(t, handlerReturned)
			assert.NoError(<-reads)
			if unexpected {
				assert.ErrorIs(<-canceled, context.Canceled)
			} else {
				assert.NoError(<-canceled)
			}
			select {
			case <-done:
				t.Fatal("service failed to join the admitted handler")
			default:
			}
			unblockHandler()
			waitNodeServe(t, done)
			result := waitPeerHTTP(t, response)
			if unexpected {
				assert.ErrorIs(serveErr, net.ErrClosed)
				assert.Error(result.err)
			} else {
				assert.NoError(serveErr)
				assertAdVerification(t, result, a.fixture.child, true)
			}
			_, _, err := ads.ReadVerifiedClaim(b.service.store.Vault(), b.fixture.root, a.fixture.child)
			assert.ErrorIs(err, storage.ErrClosed)
			_, err = os.Stat(b.service.credentialDir)
			assert.ErrorIs(err, os.ErrNotExist)
			reopened := try.To1(nodevault.OpenForNode(t.Context(), b.fixture.dir, b.fixture.storageKey, b.fixture.root, b.fixture.child))
			defer func() { assert.NoError(reopened.Close()) }()
			history, found := try.To2(ads.ReadVerifiedClaim(reopened.Vault(), b.fixture.root, a.fixture.child))
			assert.Equal(found, !unexpected)
			if found {
				assert.DeepEqual(history, a.ad)
			}
			assert.Equal(a.calls.Load(), int32(1))
		})
	}
}

func waitVerificationExchange(t *testing.T, exchanges <-chan verificationExchange) verificationExchange {
	t.Helper()
	select {
	case exchange := <-exchanges:
		return exchange
	case <-time.After(2 * time.Second):
		t.Fatal("proof exchange was not observed")
		return verificationExchange{err: errors.New("missing exchange")}
	}
}
