package ownerapi

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestEstablishmentConcurrentExactRequests(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	before := f.lease.remaining.Load()
	results := make(chan *httptest.ResponseRecorder, 12)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 12 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- deviceRequest(f.peer, "", "POST", establishmentPath, f.body)
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	var first string
	for result := range results {
		assert.Equal(result.Code, 200)
		if first == "" {
			first = result.Body.String()
		}
		assert.Equal(result.Body.String(), first)
	}
	f.savedResponse(t)
	assert.Equal(before-f.lease.remaining.Load(), 3)
	assert.Equal(
		f.signer.signs.Load(),
		int32(14),
	) // 1 probe + 1 accept + 12 replies.
}

func TestEstablishmentConcurrentContenders(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	carol := key.New()
	public := key.Public(try.To1(carol.CBORPublicKey()))
	choice, _ := try.To2(onboarding.ReadStoredChoice(f.vault, f.root, f.child))
	path := choice.Proposal.Introduce(f.signer.Handle, key.Info{Public: public})
	try.To2(onboarding.SaveIntroduction(f.vault, f.root, path.Bytes(),
		try.To1(path.SignAcceptance(carol))))
	try.To1(onboarding.VerifyReceived(f.vault, f.root))
	request := f.request
	request.Payload.Requester, request.Payload.Device = public, public
	request.Payload.AttemptID = bytes.Repeat([]byte{54}, 32)
	other := signOwnerEstablishment(t, request, carol)
	before := f.lease.remaining.Load()
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	for _, body := range []string{f.body, establishmentBody(t, other)} {
		go func() {
			<-start
			results <- deviceRequest(f.peer, "", "POST", establishmentPath, body)
		}()
	}
	close(start)
	a, b := waitAcceptance(t, results), waitAcceptance(t, results)
	assert.That((a.Code == 200 && b.Code == 409) ||
		(a.Code == 409 && b.Code == 200))
	assert.Equal(before-f.lease.remaining.Load(), 3)
	assert.Equal(f.signer.signs.Load(), int32(4)) // Losing retry only probes.
	records := f.records(t)
	var history struct {
		_                 struct{} `cbor:",toarray"`
		Version           uint8
		Request, Response []byte
	}
	try.To(wire.UnmarshalCanonical(&history, records[1]))
	assert.That(bytes.Equal(history.Request, f.raw) ||
		bytes.Equal(history.Request, other))
}

func TestEstablishmentProbeAndAcceptanceShareOwnerLock(t *testing.T) {
	for _, blockAt := range []int32{1, 2, 3, 4} {
		t.Run(fmt.Sprint(blockAt), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishmentOwner(t)
			if blockAt == 4 {
				assert.Equal(
					deviceRequest(f.peer, "", "POST", establishmentPath,
						f.body).Code,
					200,
				)
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
			go func() {
				done <- deviceRequest(f.peer, "", "POST", establishmentPath, f.body)
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("establishment did not reach signer")
			}
			// Deterministic observation of the exact publisher/owner mutex,
			// shared by issuance, revocation, Known and acceptance proof signing.
			locked := f.publisher.mutations.TryLock()
			if locked {
				f.publisher.mutations.Unlock()
			}
			assert.ThatNot(locked)
			txDone := make(chan error, 1)
			go func() {
				txDone <- f.vault.Update(func(storage.WriteTx) error { return nil })
			}()
			select {
			case err := <-txDone:
				assert.NoError(err)
			case <-time.After(5 * time.Second):
				t.Fatal("signing inside a Vault transaction")
			}
			revoke := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				revoke <- deviceRequest(f.owner, f.auth, "POST", invitationRevokePath,
					revokeInvitationBody(f.request.Payload.InvitationID))
			}()
			unblock()
			assert.Equal(waitAcceptance(t, done).Code, 200)
			w := waitAcceptance(t, revoke)
			assert.Equal(w.Code, 200)
			assert.Equal(w.Body.String(), `{"revoked":false}`)
			f.savedResponse(t)
		})
	}
}

func TestEstablishmentHostileRetryNeverAcceptsAgain(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	assert.Equal(
		deviceRequest(f.peer, "", "POST", establishmentPath, f.body).Code,
		200,
	)
	defer f.unchanged(t)()
	saved := f.savedResponse(t)
	var response pw.SignedAccepted
	try.To(wire.UnmarshalCanonical(&response, saved))
	acceptDigest := key.HashTagged(pw.AcceptedPurpose,
		try.To1(wire.Marshal(response.Payload)))
	f.signer.sign = func(data []byte) ([]byte, error) {
		assert.ThatNot(bytes.Equal(data, acceptDigest[:]))
		return f.signer.Handle.Sign(data)
	}
	other := f.request
	other.Payload.InvitationID = bytes.Repeat([]byte{9}, 32)
	for _, raw := range [][]byte{
		signOwnerEstablishment(t, f.request, f.requesterKey),
		signOwnerEstablishment(t, other, f.requesterKey),
		signOwnerEstablishment(t, f.request, f.signer.Handle),
		append(bytes.Clone(f.raw), 0), append([]byte{0x98, 2}, f.raw[1:]...),
	} {
		w := deviceRequest(f.peer, f.auth, "POST", establishmentPath,
			establishmentBody(t, raw))
		assert.Equal(w.Code, 409)
		assert.Equal(w.Body.String(), "Conflict\n")
	}
	assert.Equal(
		f.signer.signs.Load(),
		int32(5),
	) // Two authenticated retry probes.
}
