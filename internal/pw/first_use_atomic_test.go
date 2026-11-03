package pw

import (
	"errors"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func TestFirstUseCallbackAndEncryptionRollback(t *testing.T) {
	for _, phase := range []string{"Await", "useSeen", "Ready"} {
		for _, failure := range []string{"callback", "encryption"} {
			t.Run(phase+"/"+failure, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUse(t)
				saved := try.To1(f.startUse())
				response := try.To1(f.bobUse(saved.request, f.local.handle))
				fixture := &f.alice
				// Arrange the pre-transition state, keeping signed inputs for callbacks.
				if phase == "useSeen" {
					fixture = &f.f
				}
				if phase != "Ready" {
					name := firstUseKey
					if phase == "useSeen" {
						name = useSeenKey
					}
					try.To(
						fixture.vault.Update(
							func(tx storage.WriteTx) error { return tx.Delete([]byte(name)) },
						),
					)
				}
				before := useRecords(t, fixture.vault)
				history := requesterRecords(t, fixture.vault)
				if failure == "encryption" {
					fixture.lease.remaining.Store(0)
					var err error
					switch phase {
					case "Await":
						var result SavedFirstUse
						result, err = f.startUse()
						assert.SNil(result.request)
					case "useSeen":
						var result []byte
						result, err = f.bobUse(saved.request, f.local.handle)
						assert.SNil(result)
					case "Ready":
						var ready bool
						ready, err = f.receiveUse(response)
						assert.ThatNot(ready)
					}
					assert.Equal(err, ErrFirstUse)
				} else {
					cause := errors.New("callback after first-use write")
					err := fixture.vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						tx = &failingAcceptanceTx{WriteTx: tx, failAfter: 1, cause: cause}
						switch phase {
						case "Await":
							return commitFirstUseAwait(tx, f.root.public, f.peer.public, saved.request, f.useClock)
						case "useSeen":
							return commitFirstUseReceipt(tx, f.root.public, f.local.public, saved.request, response, f.useClock)
						default:
							return commitFirstUseReady(tx, f.root.public, f.peer.public, response, f.useClock)
						}
					})
					assert.ErrorIs(err, cause)
				}
				assert.DeepEqual(useRecords(t, fixture.vault), before)
				assert.DeepEqual(requesterRecords(t, fixture.vault), history)
				fixture.reopen(t)
				assert.DeepEqual(useRecords(t, fixture.vault), before)
			})
		}
	}
}

func TestFirstUseNoRevivalOfDeletedAwaitAndReady(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "Await", true: "Ready"}[ready],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUse(t)
				saved := try.To1(f.startUse())
				response := try.To1(f.bobUse(saved.request, f.local.handle))
				if ready {
					try.To1(f.receiveUse(response))
				}
				try.To(
					f.alice.vault.Update(
						func(tx storage.WriteTx) error { return tx.Delete([]byte(heldKey)) },
					),
				)
				before := requesterRecords(t, f.alice.vault)
				f.alice.unchanged(
					t,
					func() { _, err := f.receiveUse(response); assert.Equal(err, ErrFirstUse) },
				)
				assert.That(try.To1(f.expireUse(true)))
				assert.Equal(useRecord(t, f).State, useExpired)
				assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
			},
		)
	}
}

func TestFirstUseChangedSavedRequestCannotUseOldResponse(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUse(t)
	saved := try.To1(f.startUse())
	response := try.To1(f.bobUse(saved.request, f.local.handle))
	record := useRecord(t, f)
	var request SignedFirstUse
	try.To(wire.UnmarshalCanonical(&request, record.Request))
	request.Payload.SessionID[0] ^= 1
	record.Request = signUse(t, request.Payload, f.peer.handle)
	try.To(f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return tx.Put([]byte(firstUseKey), try.To1(wire.Marshal(record)))
	}))
	f.alice.unchanged(
		t,
		func() { _, err := f.receiveUse(response); assert.Equal(err, ErrFirstUse) },
	)
}
