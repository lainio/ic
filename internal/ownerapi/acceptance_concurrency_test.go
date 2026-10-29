package ownerapi

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func waitAcceptance(t *testing.T, done <-chan *httptest.ResponseRecorder,
) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case w := <-done:
		return w
	case <-time.After(5 * time.Second):
		t.Fatal("acceptance operation did not finish")
		return nil
	}
}

func TestAcceptanceSerializesWithOwnerAndPeerSigning(t *testing.T) {
	for _, blockAt := range []int32{1, 2} {
		for _, path := range []string{
			publishPath, bootstrapPath, "/owner/introductions/verify",
			"/owner/introductions", currentProofPath,
		} {
			t.Run(fmt.Sprint(path, "/sign=", blockAt), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newAcceptanceFixture(t)
				nonce := f.challenge(t)
				body := f.body(t, nonce, f.requesterProof(t, nonce))
				mutationBody, handler, auth := "{}", f.owner, f.auth
				switch path {
				case "/owner/introductions":
					choice, _ := try.To2(onboarding.ReadStoredChoice(f.vault, f.root, f.child))
					mutationBody = string(try.To1(onboarding.EncodeIntroduction(choice)))
				case currentProofPath:
					handler, auth = f.peer, ""
					mutationBody = currentProofBody(t, f.ad, currentProofNonce(t))
				}
				entered, release := make(chan struct{}), make(chan struct{})
				var once sync.Once
				unblock := func() { once.Do(func() { close(release) }) }
				defer unblock()
				f.signer.sign = func(data []byte) ([]byte, error) {
					if f.signer.signs.Load() == blockAt {
						close(entered)
						<-release
					}
					return f.signer.Handle.Sign(data)
				}
				done := make(chan *httptest.ResponseRecorder, 1)
				go func() { done <- deviceRequest(f.peer, "", "POST", acceptancePath, body) }()
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatal("acceptance did not enter signer")
				}
				// Ledger consumption is complete and its mutex released, even
				// while the publisher's signer is blocked.
				replay := make(chan *httptest.ResponseRecorder, 1)
				go func() { replay <- deviceRequest(f.peer, "", "POST", acceptancePath, body) }()
				assert.Equal(waitAcceptance(t, replay).Code, 409)
				f.challenge(t) // Issuance can still take the ledger lock.
				mutation := make(chan *httptest.ResponseRecorder, 1)
				go func() { mutation <- deviceRequest(handler, auth, "POST", path, mutationBody) }()
				select {
				case <-mutation:
					t.Fatal("operation escaped the acceptance mutation lock")
				case <-time.After(30 * time.Millisecond):
				}
				assert.Equal(f.signer.signs.Load(), blockAt)
				tx := make(chan error, 1)
				go func() { tx <- f.vault.Update(func(storage.WriteTx) error { return nil }) }()
				select {
				case err := <-tx:
					assert.NoError(err)
				case <-time.After(5 * time.Second):
					t.Fatal("acceptance held a Vault transaction while signing")
				}
				unblock()
				checkAcceptanceResponse(t, waitAcceptance(t, done),
					f.root, f.child, f.requester, nonce)
				want := 200
				if path == bootstrapPath {
					want = 409
				}
				assert.Equal(waitAcceptance(t, mutation).Code, want)
			})
		}
	}
}

func TestAcceptanceFinalGuardsAfterConsumption(t *testing.T) {
	for _, scenario := range []string{"publication", "denial", "Known", "authorization"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newAcceptanceFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			f.peer = peerapi.NewAcceptanceHandler(f.vault, f.root, f.child, f.endpoint,
				func(requester key.Public, ad, nonce []byte) (key.Signature, error) {
					close(entered)
					<-release // Consumed, but not yet inside the publisher lock.
					return f.prove(requester, ad, nonce)
				}, f.peer)
			nonce := f.challenge(t)
			body := f.body(t, nonce, f.requesterProof(t, nonce))
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- deviceRequest(f.peer, "", "POST", acceptancePath, body) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("did not consume challenge")
			}
			repair := func() {}
			f.publisher.mutations.Lock()
			switch scenario {
			case "publication":
				current := try.To1(ads.PublishLocal(f.vault, f.root, f.child,
					f.signer.Handle, f.endpoint, time.Now()))
				assert.That(len(try.To1(wire.Marshal(current))) > 0)
			case "denial":
				try.To1(policy.DenyLocal(f.vault, f.root, f.child, f.requester))
			case "Known":
				repair = replaceAcceptanceRecord(t, f.vault,
					"known-introductions-v1", f.requester, nil)
			case "authorization":
				repair = replaceAcceptanceRecord(t, f.vault, "local-device-auth-v1",
					[]byte("local-software-signer"), nil)
			}
			f.publisher.mutations.Unlock()
			unblock()
			w := waitAcceptance(t, done)
			assert.Equal(w.Code, 409)
			assert.Equal(w.Body.String(), "Conflict\n")
			assert.Equal(f.signer.signs.Load(), int32(0))
			repair()
			// No path restores a consumed nonce, regardless of callback failure.
			assert.Equal(deviceRequest(f.peer, "", "POST", acceptancePath, body).Code, 409)
		})
	}
}

func TestAcceptanceRechecksAdAfterSignerCallback(t *testing.T) {
	for _, scenario := range []string{"replaced", "expired while signing"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newAcceptanceFixture(t)
			var until time.Time
			if scenario == "expired while signing" {
				// Shorten this authentic ad's lifetime without changing the API's clock.
				until = time.Now().Add(200 * time.Millisecond)
				current := try.To1(ads.PublishLocal(f.vault, f.root, f.child,
					f.signer.Handle, f.endpoint, until.Add(-ads.TTL)))
				f.ad = try.To1(wire.Marshal(current))
			}
			nonce := f.challenge(t)
			body := f.body(t, nonce, f.requesterProof(t, nonce))
			f.signer.sign = func(data []byte) ([]byte, error) {
				if f.signer.signs.Load() == 2 {
					if scenario == "replaced" {
						// Simulate a faulty reentrant provider bypassing the service
						// lock. No Vault transaction is held; the final read catches it.
						_, err := ads.PublishLocal(f.vault, f.root, f.child,
							f.signer.Handle, f.endpoint, time.Now())
						if err != nil {
							return nil, err
						}
					} else {
						time.Sleep(time.Until(until) + time.Millisecond)
					}
				}
				return f.signer.Handle.Sign(data)
			}
			w := deviceRequest(f.peer, "", "POST", acceptancePath, body)
			assert.Equal(w.Code, 409)
			assert.Equal(w.Body.String(), "Conflict\n")
			assert.Equal(f.signer.signs.Load(), int32(2))
			// Restore the exact original ad for the replacement case, solely to
			// observe that the spent nonce still cannot produce a second proof.
			if scenario == "replaced" {
				replaceAcceptanceRecord(t, f.vault, "local-current-ad-v1",
					[]byte("slot-1"), f.ad)
			}
			assert.Equal(deviceRequest(f.peer, "", "POST", acceptancePath, body).Code, 409)
			assert.Equal(f.signer.signs.Load(), int32(2))
		})
	}
}

type acceptanceWriteCheck struct {
	*httptest.ResponseRecorder
	write func()
}

func (w acceptanceWriteCheck) Write([]byte) (int, error) {
	w.write()
	return 0, errors.New("simulated lost response")
}

func TestAcceptanceReleasesLocksBeforeResponseIO(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAcceptanceFixture(t)
	nonce := f.challenge(t)
	body := f.body(t, nonce, f.requesterProof(t, nonce))
	writes := 0
	w := acceptanceWriteCheck{httptest.NewRecorder(), func() {
		writes++
		assert.That(f.publisher.mutations.TryLock())
		f.publisher.mutations.Unlock()
		f.challenge(t) // Reenter the same ledger while the response is writing.
	}}
	r := httptest.NewRequest(http.MethodPost, acceptancePath, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	f.peer.ServeHTTP(w, r)
	assert.Equal(writes, 1)
	assert.Equal(deviceRequest(f.peer, "", "POST", acceptancePath, body).Code, 409)
	assert.Equal(f.signer.signs.Load(), int32(2))
}
