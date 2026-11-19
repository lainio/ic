package pw

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestContactV2AdExpiry(t *testing.T) {
	for _, alice := range []bool{false, true} {
		t.Run(fmt.Sprint(alice), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			response := f.responseV2(t)
			assert.That(try.To1(f.receiveV2(response)))
			var accepted SignedAcceptedV2
			try.To(wire.UnmarshalCanonical(&accepted, response))
			var ad ads.Current
			try.To(wire.UnmarshalCanonical(&ad, accepted.Payload.Binding.Ad))
			deadline := time.Unix(0, ad.Payload.ExpiresUnixNano)
			requestDigest := key.HashTagged(EstablishPurposeV2,
				try.To1(wire.Marshal(accepted.Payload.Binding)))
			responseDigest := key.HashTagged(AcceptedPurposeV2,
				try.To1(wire.Marshal(accepted.Payload)))

			node, identity, read, usable := &f.f, f.local,
				BobContactV2, BobUsableContactV2
			origin, want := "http://127.0.0.1:12345", aliceServiceOrigin
			if alice {
				node, identity, read, usable = &f.alice, f.peer,
					RequesterContactV2, RequesterUsableContactV2
				origin, want = want, origin
			}
			runtime := ContactRuntimeV2{true, origin}
			signer := &probeSigner{Handle: identity.handle}
			history := try.To1(read(node.vault, f.root.public, identity.public))
			assert.Equal(history, want)
			bobBefore := heldTestState(t, f.f.vault)
			aliceBefore := heldTestState(t, f.alice.vault)
			f.f.lease.remaining.Store(0)
			f.alice.lease.remaining.Store(0)

			for _, phase := range []string{"before", "probe", "at", "after",
				"reopen"} {
				t.Run(phase, func(t *testing.T) {
					defer assert.PushTester(t)()
					f.now = deadline.Add(-time.Nanosecond)
					switch phase {
					case "at":
						f.now = deadline
					case "after", "reopen":
						f.now = deadline.Add(time.Nanosecond)
					}
					if phase == "reopen" {
						node.reopen(t)
						signer.Handle = try.To1(nodeidentity.OpenDirectory(
							identity.dir, identity.unlock))
					}
					signer.sign = func(d []byte) ([]byte, error) {
						if bytes.Equal(d, requestDigest[:]) ||
							bytes.Equal(d, responseDigest[:]) {
							return nil, errors.New("must not re-sign establishment")
						}
						if phase == "probe" {
							f.now = deadline // Expiry before the final contact View.
						}
						return signer.Handle.Sign(d)
					}
					calls := signer.signCalls.Load()
					f.f.unchanged(t, func() {
						f.alice.unchanged(t, func() {
							assert.Equal(try.To1(read(node.vault, f.root.public,
								identity.public)), history)
							assert.Equal(signer.signCalls.Load(), calls)
							assert.Equal(try.To1(usable(node.vault, f.root.public,
								identity.public, signer, runtime)), history)

							// A timeless projection must not make bootstrap fresh.
							_, fresh := try.To2(ads.ReadCurrentLocal(f.f.vault,
								f.root.public, f.local.public, f.now))
							assert.Equal(fresh, phase == "before")
							err := f.alice.vault.View(
								func(tx storage.ReadTx) (err error) {
									defer err2.Handle(&err, nil)
									try.To1(ads.ReadEstablishmentAdInTx(tx,
										f.root.public, f.local.public, f.now))
									return nil
								})
							if fresh {
								assert.NoError(err)
							} else {
								assert.ErrorIs(err, ads.ErrInvalidRecord)
							}
						})
					})
					assert.Equal(signer.signCalls.Load()-calls, 1) // Probe only.
					assert.DeepEqual(heldTestState(t, f.f.vault), bobBefore)
					assert.DeepEqual(heldTestState(t, f.alice.vault), aliceBefore)
				})
			}
		})
	}
}
