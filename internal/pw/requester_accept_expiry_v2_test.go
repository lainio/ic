package pw

import (
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func TestReceiveAcceptanceV2AdExpiry(t *testing.T) {
	for _, phase := range []string{"before", "probe", "duplicate",
		"duplicate probe", "reopen"} {
		t.Run(phase, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, true)
			// Move this uncommitted fixture to the wall clock. The ad expires
			// before the still-active invitation, independently of its TTL.
			f.now = time.Now()
			f.invitation.ExpiresUnixNano = f.now.Add(InvitationTTL).UnixNano()
			try.To(f.f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				return tx.Put([]byte(invitationKey),
					try.To1(wire.Marshal(f.invitation)))
			}))
			ad := try.To1(ads.PublishLocal(f.f.vault, f.root.public,
				f.local.public, f.local.handle, establishmentEndpoint,
				f.now.Add(-ads.TTL+time.Second)))
			raw := try.To1(wire.Marshal(ad))
			try.To1(ads.ReceiveClaim(f.alice.vault, f.root.public,
				f.local.public, raw))
			// Same test-only VerifiedAd admission as newRequester.
			try.To(f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				return tx.Put([]byte("verified-ad-claims-v1"),
					try.To1(wire.Marshal([]any{uint8(1),
						[]any{[]any{f.local.public, raw}}})))
			}))
			response := f.responseV2(t)
			deadline := time.Unix(0, ad.Payload.ExpiresUnixNano)
			assert.That(invitationBeforeExpiry(f.invitation, deadline))
			duplicate := phase == "duplicate" || phase == "duplicate probe"
			if duplicate {
				assert.That(try.To1(f.receiveV2(response)))
			}
			try.To(f.alice.vault.View(func(tx storage.ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				assert.DeepEqual(try.To1(ads.ReadEstablishmentAdInTx(tx,
					f.root.public, f.local.public, time.Now())), raw)
				return nil
			}))

			expire := func() {
				assert.That(time.Now().Before(deadline))
				timer := time.NewTimer(time.Until(deadline))
				defer timer.Stop()
				<-timer.C
				assert.ThatNot(time.Now().Before(deadline))
			}
			if phase == "probe" || phase == "duplicate probe" {
				f.signer.sign = func(d []byte) ([]byte, error) {
					expire() // Actual expiry between preflight and TX-A/View.
					return f.peer.handle.Sign(d)
				}
			} else {
				expire()
			}
			if phase == "reopen" {
				f.alice.reopen(t)
			}

			before := heldTestState(t, f.alice.vault)
			calls := f.signer.signCalls.Load()
			allowance := int64(2)
			if duplicate {
				allowance = 0
			}
			f.alice.lease.remaining.Store(allowance)
			f.f.unchanged(t, func() {
				if duplicate {
					f.alice.unchanged(t, func() {
						assert.That(try.To1(f.receiveV2(response)))
					})
				} else {
					assert.That(try.To1(f.receiveV2(response)))
				}
			})
			assert.Equal(f.signer.signCalls.Load()-calls, 1)
			assert.Equal(f.alice.lease.remaining.Load(), 0)
			f.signer.sign = nil
			f.now = deadline

			committed := requesterRecords(t, f.alice.vault)
			_, bobHistory, bobHeld := f.records(t)
			assert.DeepEqual(committed[0], before["root"][attemptKey])
			assert.DeepEqual(committed[1], bobHistory)
			assert.DeepEqual(committed[2], bobHeld)
			after := heldTestState(t, f.alice.vault)
			if !duplicate {
				delete(after["root"], acceptedKey)
				delete(after["root"], heldKey)
			}
			assert.DeepEqual(after, before)
			assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
				f.root.public, f.peer.public)), "http://127.0.0.1:12345")
			assert.DeepEqual(useRecords(t, f.alice.vault), [2][]byte{})

			// The fresh reader and saved-attempt retrieval retain their guards.
			f.alice.unchanged(t, func() {
				err := f.alice.vault.View(func(tx storage.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					try.To1(ads.ReadEstablishmentAdInTx(tx, f.root.public,
						f.local.public, deadline))
					return nil
				})
				assert.ErrorIs(err, ads.ErrInvalidRecord)
				_, err = f.saveV2(aliceServiceOrigin)
				assert.Equal(err, ErrEstablishment)
			})

			f.alice.reopen(t)
			f.alice.unchanged(t, func() {
				assert.That(try.To1(f.receiveV2(response)))
			})
			assert.DeepEqual(requesterRecords(t, f.alice.vault), committed)

			// Expired retained history cannot resurrect a deleted holding.
			f.alice.lease.remaining.Store(1)
			assert.That(try.To1(DeleteHeldLocal(f.alice.vault,
				f.root.public, f.peer.public)))
			f.alice.lease.remaining.Store(0)
			f.alice.reopen(t)
			f.alice.unchanged(t, func() {
				assert.ThatNot(try.To1(f.receiveV2(response)))
			})
			assert.DeepEqual(requesterRecords(t, f.alice.vault),
				[3][]byte{committed[0], committed[1], nil})
		})
	}
}
