package pw

import (
	"errors"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func TestFirstUseCallbackAndEncryptionRollbackV2(t *testing.T) {
	for _, phase := range []string{"Await", "useSeen", "Ready", "Expired"} {
		for _, failure := range []string{"callback", "encryption"} {
			t.Run(phase+"/"+failure, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUseV2(t)
				saved := try.To1(f.startUseV2())
				response := try.To1(f.bobUseV2(saved.request, f.local.handle))
				fixture := &f.alice
				// Arrange the pre-transition state, keeping signed inputs for callbacks.
				if phase == "useSeen" {
					fixture = &f.f
				}
				if phase == "Expired" {
					assert.That(try.To1(f.receiveUseV2(response)))
				}
				if phase == "Await" || phase == "useSeen" {
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
						var result SavedFirstUseV2
						result, err = f.startUseV2()
						assert.SNil(result.request)
					case "useSeen":
						var result []byte
						result, err = f.bobUseV2(saved.request, f.local.handle)
						assert.SNil(result)
					case "Ready":
						var ready bool
						ready, err = f.receiveUseV2(response)
						assert.ThatNot(ready)
					case "Expired":
						var expired bool
						expired, err = f.expireUseV2(true)
						assert.ThatNot(expired)
					}
					assert.Equal(err, ErrFirstUse)
				} else {
					cause := errors.New("callback after first-use write")
					err := fixture.vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						tx = &failingAcceptanceTx{WriteTx: tx, failAfter: 1, cause: cause}
						switch phase {
						case "Await":
							return commitFirstUseAwaitV2(tx, f.root.public, f.peer.public, f.aliceRuntime, saved.request, f.useClock)
						case "useSeen":
							return commitFirstUseReceiptV2(tx, f.root.public, f.local.public, f.bobRuntime, saved.request, response, f.useClock)
						case "Ready":
							return commitFirstUseReadyV2(tx, f.root.public, f.peer.public, f.aliceRuntime, response, f.useClock)
						default:
							return commitFirstUseExpiredV2(tx, f.root.public,
								f.peer.public, true, f.useClock)
						}
					})
					assert.ErrorIs(err, cause)
				}
				assert.DeepEqual(useRecords(t, fixture.vault), before)
				assert.DeepEqual(requesterRecords(t, fixture.vault), history)
				fixture.reopen(t)
				assert.DeepEqual(useRecords(t, fixture.vault), before)
				assert.DeepEqual(requesterRecords(t, fixture.vault), history)
				fixture.lease.remaining.Store(10)
				switch phase {
				case "Await":
					try.To1(f.startUseV2())
				case "useSeen":
					try.To1(f.bobUseV2(saved.request, f.local.handle))
				case "Ready":
					assert.That(try.To1(f.receiveUseV2(response)))
				case "Expired":
					assert.That(try.To1(f.expireUseV2(true)))
				}
				assert.DeepEqual(requesterRecords(t, fixture.vault), history)
			})
		}
	}
}

func TestFirstUseOwnerSerializationV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	var owner sync.Mutex
	results := make(chan error, 4)
	for range 4 {
		go func() {
			owner.Lock()
			defer owner.Unlock()
			_, err := f.startUseV2()
			results <- err
		}()
	}
	successes := 0
	for range 4 {
		if err := <-results; err == nil {
			successes++
		} else {
			assert.Equal(err, ErrFirstUse)
		}
	}
	assert.Equal(successes, 1)
	request := useRecordV2(t, f).Request
	for range 4 {
		go func() {
			owner.Lock()
			defer owner.Unlock()
			_, err := f.bobUseV2(request, f.local.handle)
			results <- err
		}()
	}
	successes = 0
	for range 4 {
		if err := <-results; err == nil {
			successes++
		} else {
			assert.Equal(err, ErrFirstUse)
		}
	}
	assert.Equal(successes, 1)
	var receipt firstUseReceipt
	try.To(wire.UnmarshalCanonical(&receipt, useRecords(t, f.f.vault)[1]))
	remaining := f.alice.lease.remaining.Load()
	for range 4 {
		go func() {
			owner.Lock()
			defer owner.Unlock()
			_, err := f.receiveUseV2(receipt.Response)
			results <- err
		}()
	}
	for range 4 {
		assert.NoError(<-results)
	}
	assert.Equal(f.alice.lease.remaining.Load(), remaining-1)
	assert.Equal(useRecordV2(t, f).State, useReady)
}

func TestFirstUseNoRevivalOfDeletedAwaitAndReadyV2(t *testing.T) {
	for _, ready := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "Await", true: "Ready"}[ready],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUseV2(t)
				saved := try.To1(f.startUseV2())
				response := try.To1(f.bobUseV2(saved.request, f.local.handle))
				if ready {
					try.To1(f.receiveUseV2(response))
				}
				try.To(
					f.alice.vault.Update(
						func(tx storage.WriteTx) error { return tx.Delete([]byte(heldKey)) },
					),
				)
				before := requesterRecords(t, f.alice.vault)
				f.alice.unchanged(
					t,
					func() { _, err := f.receiveUseV2(response); assert.Equal(err, ErrFirstUse) },
				)
				assert.That(try.To1(f.expireUseV2(true)))
				assert.Equal(useRecordV2(t, f).State, useExpired)
				assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
			},
		)
	}
}

func TestFirstUseChangedSavedRequestCannotUseOldResponseV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	saved := try.To1(f.startUseV2())
	response := try.To1(f.bobUseV2(saved.request, f.local.handle))
	record := useRecordV2(t, f)
	var request SignedFirstUseV2
	try.To(wire.UnmarshalCanonical(&request, record.Request))
	request.Payload.SessionID[0] ^= 1
	record.Request = signUseV2(t, request.Payload, f.peer.handle)
	try.To(f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return tx.Put([]byte(firstUseKey), try.To1(wire.Marshal(record)))
	}))
	f.alice.unchanged(
		t,
		func() { _, err := f.receiveUseV2(response); assert.Equal(err, ErrFirstUse) },
	)
}
