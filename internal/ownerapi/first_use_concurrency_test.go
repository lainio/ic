package ownerapi

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func firstUseOwnerTarget(
	t *testing.T,
) (establishmentOwnerFixture, *firstUseHandler, string) {
	t.Helper()
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	assert.Equal(
		deviceRequest(f.peer, "", "POST", establishmentPath, f.body).Code,
		200,
	)
	var accepted pw.SignedAccepted
	try.To(wire.UnmarshalCanonical(&accepted, f.savedResponse(t)))
	h, _, bind := try.To3(
		NewFirstUseCredentials(
			t.Context(),
			f.vault,
			f.root,
			f.child,
			f.signer,
			t.TempDir(),
		),
	)
	target := h.(*authenticatedStatusHandler).next.(*firstUseHandler)
	prove, accept, establish, use, _ := bind(f.listener)
	assert.That(prove != nil && accept != nil && establish != nil && use != nil)
	f.peer = peerapi.NewFirstUseHandler(use, http.NotFoundHandler())
	now := time.Now().UTC().UnixNano()
	p := pw.FirstUse{Version: 1, Established: accepted.Payload,
		SessionID: bytes.Repeat([]byte{48}, 32), IssuedUnixNano: now,
		ExpiresUnixNano: now + int64(pw.FirstUseLifetime), HeldEvidence: true}
	digest := key.HashTagged(pw.FirstUsePurpose, try.To1(wire.Marshal(p)))
	raw := try.To1(
		wire.Marshal(
			pw.SignedFirstUse{
				Payload:   p,
				Signature: try.To1(f.requesterKey.Sign(digest[:])),
			},
		),
	)
	return f, target, establishmentBody(t, raw)
}

func TestFirstUseBobConcurrentRequestsOnlyOneReceipt(t *testing.T) {
	defer assert.PushTester(t)()
	f, _, body := firstUseOwnerTarget(t)
	before, signs := f.lease.remaining.Load(), f.signer.signs.Load()
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 8)
	for range 8 {
		go func() { <-start; results <- deviceRequest(f.peer, "", "POST", "/peer/pw/first-use", body) }()
	}
	close(start)
	successes := 0
	for range 8 {
		r := waitAcceptance(t, results)
		if r.Code == 200 {
			successes++
		} else {
			assert.Equal(r.Code, 409)
			assert.Equal(r.Body.String(), "Conflict\n")
		}
	}
	assert.Equal(successes, 1)
	assert.Equal(before-f.lease.remaining.Load(), int64(1))
	assert.Equal(f.signer.signs.Load()-signs, int32(2))
}

func TestFirstUseBobProbeAndSignHoldOwnerLockOutsideVault(t *testing.T) {
	for _, step := range []int32{1, 2} {
		t.Run(fmt.Sprint(step), func(t *testing.T) {
			defer assert.PushTester(t)()
			f, target, body := firstUseOwnerTarget(t)
			blockAt := f.signer.signs.Load() + step
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			f.signer.sign = func(d []byte) ([]byte, error) {
				if f.signer.signs.Load() == blockAt {
					close(entered)
					<-release
				}
				return f.signer.Handle.Sign(d)
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- deviceRequest(f.peer, "", "POST", "/peer/pw/first-use", body) }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("first use did not reach signer")
			}
			locked := target.mutations.TryLock()
			if locked {
				target.mutations.Unlock()
			}
			assert.ThatNot(locked)
			txDone := make(chan error, 1)
			go func() { txDone <- f.vault.Update(func(storage.WriteTx) error { return nil }) }()
			select {
			case err := <-txDone:
				assert.NoError(err)
			case <-time.After(5 * time.Second):
				t.Fatal("signer inside Vault transaction")
			}
			unblock()
			assert.Equal(waitAcceptance(t, done).Code, 200)
			// The response writer also sees the receipt after the capability releases
			// its lock; no Alice ACK is awaited. A repeated call cannot sign again.
			before := f.signer.signs.Load()
			r := httptest.NewRequest(
				"POST",
				"/peer/pw/first-use",
				strings.NewReader(body),
			)
			r.Header.Set("Content-Type", "application/json")
			w := &establishmentWriter{
				ResponseRecorder: httptest.NewRecorder(),
				onHeader: func() {
					assert.That(target.mutations.TryLock())
					target.mutations.Unlock()
				},
			}
			f.peer.ServeHTTP(w, r)
			assert.Equal(w.Code, 409)
			assert.Equal(f.signer.signs.Load(), before)
		})
	}
}
