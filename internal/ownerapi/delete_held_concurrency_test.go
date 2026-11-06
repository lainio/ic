package ownerapi

import (
	"context"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/storage"
)

func TestDeleteHeldSerializedWithBobOperations(t *testing.T) {
	for _, phase := range []string{"BobAccept", "BobReply", "BobFirstUse"} {
		for _, deleteFirst := range []bool{false, true} {
			t.Run(
				phase+map[bool]string{false: "/operation first", true: "/delete first"}[deleteFirst],
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
					if deleteFirst {
						w := deviceRequest(
							target,
							"",
							"POST",
							deleteHeldPath,
							"{}",
						)
						assert.Equal(w.Code, 200)
						want := 409
						if phase == "BobAccept" {
							assert.Equal(w.Body.String(), `{"deleted":false}`)
							want = 200 // A no-op never preemptively burns acceptance.
						} else {
							assert.Equal(w.Body.String(), `{"deleted":true}`)
						}
						assert.Equal(
							deviceRequest(f.peer, "", "POST", path, body).Code,
							want,
						)
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
					deleted := make(chan *httptest.ResponseRecorder, 1)
					go func() { deleted <- deviceRequest(target, "", "POST", deleteHeldPath, "{}") }()
					unblock()
					assert.Equal(waitAcceptance(t, done).Code, 200)
					w := waitAcceptance(t, deleted)
					assert.Equal(w.Code, 200)
					assert.Equal(w.Body.String(), `{"deleted":true}`)
					assert.SNil(f.records(t)[2])
					assert.Equal(
						deviceRequest(f.peer, "", "POST", path, body).Code,
						409,
					)
				},
			)
		}
	}
}

// Err is sampled inside deleteHeld's owner lock, before its Vault.Update.
type deleteEnteredContext struct {
	context.Context
	entered chan struct{}
}

func (c deleteEnteredContext) Err() error {
	close(c.entered)
	return c.Context.Err()
}

func TestDeleteHeldHoldsOwnerLockUntilDurableCommit(t *testing.T) {
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
	r := httptest.NewRequest("POST", deleteHeldPath, strings.NewReader("{}"))
	r = r.WithContext(deleteEnteredContext{r.Context(), entered})
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", f.auth)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); f.owner.ServeHTTP(w, r); done <- w }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("delete did not acquire owner lock")
	}
	locked := target.mutations.TryLock()
	if locked {
		target.mutations.Unlock()
	}
	assert.ThatNot(locked)
	select {
	case <-done:
		t.Fatal("delete replied before Vault admitted its transaction")
	default:
	}
	unblock()
	assert.NoError(<-txDone)
	w := waitAcceptance(t, done)
	assert.Equal(w.Code, 200)
	assert.Equal(w.Body.String(), `{"deleted":true}`)
	assert.SNil(f.records(t)[2])
}

func TestDeleteHeldSerializedWithRequesterAcceptance(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	_, _, bind := try.To3(NewFirstUseCredentials(t.Context(), f.vault,
		f.root, f.child, f.signer, t.TempDir()))
	prove, _, establish, _, message := bind(server.Listener)
	assert.That(message != nil)
	endpoint := "http://" + server.Listener.Addr().
		String() +
		"/peer/introduction"
	server.Config.Handler = peerapi.NewEstablishmentHandler(establish,
		peerapi.NewProofHandler(f.vault, f.root, f.child, endpoint, prove))
	server.Start()
	ad := try.To1(wire.Marshal(try.To1(ads.PublishLocal(f.vault, f.root,
		f.child, f.signer, endpoint, time.Now()))))
	v := f.requesterVault.vault
	try.To1(ads.ReceiveClaim(v, f.root, f.child, ad))
	try.To1(
		ads.VerifyReceivedRemote(t.Context(), v, f.root, f.requester, f.child),
	)
	signer := &deviceProbe{Handle: f.requesterKey}
	h, _ := deleteHeldCredential(t, v, f.root, f.requester, signer)
	target := h.(*authenticatedStatusHandler).next.(*firstUseHandler)
	row, _ := try.To2(pw.ReadInvitation(f.vault, f.root, f.child))
	saved := try.To1(
		target.saveRedemption(
			t.Context(),
			redemptionInput{f.child, row.ID, row.Audience},
		),
	)
	response := try.To1(pw.SendEstablish(t.Context(), saved))
	// Delete first observes only the pending attempt. Later acceptance remains
	// eligible; the same immutable history then makes deletion irreversible.
	assert.ThatNot(try.To1(target.deleteHeld(t.Context())))
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	signer.sign = func(data []byte) ([]byte, error) {
		close(entered)
		<-release
		return signer.Handle.Sign(data)
	}
	type result struct {
		held bool
		err  error
	}
	accepted := make(chan result, 1)
	go func() { held, err := target.receiveRedemption(response); accepted <- result{held, err} }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("acceptance did not reach signer")
	}
	locked := target.mutations.TryLock()
	if locked {
		target.mutations.Unlock()
	}
	assert.ThatNot(locked)
	deleted := make(chan *httptest.ResponseRecorder, 1)
	go func() { deleted <- deviceRequest(target, "", "POST", deleteHeldPath, "{}") }()
	unblock()
	r := <-accepted
	assert.NoError(r.err)
	assert.That(r.held)
	w := waitAcceptance(t, deleted)
	assert.Equal(w.Code, 200)
	assert.Equal(w.Body.String(), `{"deleted":true}`)
	signer.sign = nil
	defer f.requesterVault.unchanged(t)()
	assert.ThatNot(try.To1(target.receiveRedemption(response)))
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		_, held := try.To2(tx.Get([]byte("local-pw-held-v1")))
		assert.ThatNot(held)
		return nil
	}))
}
