package ownerapi

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/storage"
)

func TestDenySerializedWithBobOperations(t *testing.T) {
	for _, phase := range []string{"BobAccept", "BobReply", "BobFirstUse"} {
		for _, denyFirst := range []bool{false, true} {
			t.Run(
				phase+map[bool]string{false: "/operation first", true: "/deny first"}[denyFirst],
				func(t *testing.T) {
					defer assert.PushTester(t)()
					var f establishmentOwnerFixture
					var target *firstUseHandler
					path, body := establishmentPath, ""
					if phase == "BobFirstUse" {
						f, target, body = firstUseOwnerTarget(t)
						path = "/peer/pw/first-use"
					} else {
						f = newEstablishmentOwner(t)
						target = heldOwnerTarget(t, &f)
						body = f.body
						if phase == "BobReply" {
							assert.Equal(deviceRequest(f.peer, "", "POST", path, body).Code, 200)
						}
					}
					if denyFirst {
						before := f.records(t)
						w := deviceRequest(
							target,
							"",
							"POST",
							denyPath,
							denyBody(f.requester),
						)
						assert.Equal(w.Code, 200)
						want := 409
						assert.Equal(w.Body.String(), `{"changed":true}`)
						assert.Equal(
							deviceRequest(f.peer, "", "POST", path, body).Code,
							want,
						)
						assert.DeepEqual(f.records(t), before)
						return
					}
					entered, release := make(chan struct{}), make(chan struct{})
					var once sync.Once
					unblock := func() { once.Do(func() { close(release) }) }
					defer unblock()
					blockAt := f.signer.signs.Load() + 1
					f.signer.sign = func(data []byte) ([]byte, error) {
						if f.signer.signs.Load() == blockAt {
							close(entered)
							<-release
						}
						return f.signer.Handle.Sign(data)
					}
					done := make(chan *httptest.ResponseRecorder, 1)
					go func() { done <- deviceRequest(f.peer, "", "POST", path, body) }()
					select {
					case <-entered:
					case <-time.After(5 * time.Second):
						t.Fatal("operation did not reach signer")
					}
					locked := target.mutations.TryLock()
					if locked {
						target.mutations.Unlock()
					}
					assert.ThatNot(locked)
					denied := make(chan *httptest.ResponseRecorder, 1)
					go func() { denied <- deviceRequest(target, "", "POST", denyPath, denyBody(f.requester)) }()
					unblock()
					assert.Equal(waitAcceptance(t, done).Code, 200)
					w := waitAcceptance(t, denied)
					assert.Equal(w.Code, 200)
					assert.Equal(w.Body.String(), `{"changed":true}`)
					assert.SNotEmpty(f.records(t)[2])
					assert.Equal(
						deviceRequest(f.peer, "", "POST", path, body).Code,
						409,
					)
				},
			)
		}
	}
}

func TestDenyHoldsOwnerLockUntilDurableCommit(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	target := heldOwnerTarget(t, &f)
	assert.Equal(
		deviceRequest(f.peer, "", "POST", establishmentPath, f.body).Code,
		200,
	)
	inTx, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	txDone := make(chan error, 1)
	go func() {
		txDone <- f.vault.Update(func(storage.WriteTx) error {
			close(inTx)
			<-release
			return nil
		})
	}()
	<-inTx
	entered := make(chan struct{})
	r := httptest.NewRequest(
		"POST",
		denyPath,
		strings.NewReader(denyBody(f.requester)),
	)
	r = r.WithContext(deleteEnteredContext{r.Context(), entered})
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", f.auth)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); f.owner.ServeHTTP(w, r); done <- w }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("deny did not acquire owner lock")
	}
	locked := target.mutations.TryLock()
	if locked {
		target.mutations.Unlock()
	}
	assert.ThatNot(locked)
	select {
	case <-done:
		t.Fatal("deny replied before Vault admitted its transaction")
	default:
	}
	// BobReply queues behind the denial already holding the owner lock.
	reply := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		reply <- deviceRequest(f.peer, "", "POST", establishmentPath, f.body)
	}()
	unblock()
	assert.NoError(<-txDone)
	w := waitAcceptance(t, done)
	assert.Equal(w.Code, 200)
	assert.Equal(w.Body.String(), `{"changed":true}`)
	assert.SNotEmpty(f.records(t)[2])
	assert.Equal(waitAcceptance(t, reply).Code, 409)
}

func TestDenyCannotRecallAlreadyAuthorizedResponse(t *testing.T) {
	for _, phase := range []string{"BobAccept", "BobReply", "BobFirstUse"} {
		t.Run(phase, func(t *testing.T) {
			defer assert.PushTester(t)()
			var f establishmentOwnerFixture
			var target *firstUseHandler
			path, body := establishmentPath, ""
			if phase == "BobFirstUse" {
				f, target, body = firstUseOwnerTarget(t)
				path = "/peer/pw/first-use"
			} else {
				f = newEstablishmentOwner(t)
				target = heldOwnerTarget(t, &f)
				body = f.body
				if phase == "BobReply" {
					assert.Equal(deviceRequest(f.peer, "", "POST", path, body).Code, 200)
				}
			}
			w := &establishmentWriter{ResponseRecorder: httptest.NewRecorder(),
				onHeader: func() {
					// Authorization and any commit precede response I/O. A new
					// local Deny here cannot retract those authorized bytes.
					assert.That(target.mutations.TryLock())
					target.mutations.Unlock()
					before := f.records(t)
					denied := deviceRequest(target, "", "POST", denyPath,
						denyBody(f.requester))
					assert.Equal(denied.Code, 200)
					assert.Equal(denied.Body.String(), `{"changed":true}`)
					assert.DeepEqual(f.records(t), before)
				}}
			r := httptest.NewRequest("POST", path, strings.NewReader(body))
			r.Header.Set("Content-Type", "application/json")
			f.peer.ServeHTTP(w, r)
			assert.Equal(w.Code, 200)
			assert.SNotEmpty(w.Body.Bytes())
			defer f.unchanged(t)()
			assert.Equal(
				deviceRequest(f.peer, "", "POST", path, body).Code,
				409,
			)
		})
	}
}
