package pw

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func TestBobV2SharedSlotsAndVersionIsolation(t *testing.T) {
	for _, firstV2 := range []bool{false, true} {
		for _, deleted := range []bool{false, true} {
			t.Run(fmt.Sprint(firstV2, deleted), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				saved := try.To1(f.saveV2(aliceServiceOrigin))
				if firstV2 {
					try.To(f.acceptV2(saved.request, f.local.handle))
				} else {
					try.To(f.accept(f.raw, f.local.handle))
				}
				_, history, _ := f.records(t)
				if deleted {
					try.To(f.invalidateBobV2("held"))
				}
				f.f.reopen(t)
				f.f.unchanged(t, func() {
					var response []byte
					var err error
					if firstV2 {
						assert.Equal(f.accept(f.raw, f.local.handle), ErrEstablishment)
						response, err = f.reply(f.raw, f.local.handle)
					} else {
						assert.Equal(f.acceptV2(saved.request, f.local.handle),
							ErrEstablishment)
						response, err = f.replyV2(saved.request, f.local.handle)
					}
					assert.Equal(err, ErrEstablishment)
					assert.SNil(response)
				})
				_, retained, _ := f.records(t)
				assert.DeepEqual(retained, history)
			})
		}
	}
}

func TestBobV2MixedVersionCommitOrders(t *testing.T) {
	for _, firstV2 := range []bool{false, true} {
		t.Run(fmt.Sprint(firstV2), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			saved := try.To1(f.saveV2(aliceServiceOrigin))
			signer := &probeSigner{Handle: f.local.handle}
			var history []byte
			signer.sign = func(d []byte) ([]byte, error) {
				if signer.signCalls.Load() == 2 {
					var err error
					if firstV2 {
						err = f.acceptV2(saved.request, f.local.handle)
					} else {
						err = f.accept(f.raw, f.local.handle)
					}
					if err != nil {
						return nil, err
					}
					_, history, _ = f.records(t)
				}
				return f.local.handle.Sign(d)
			}
			var err error
			if firstV2 {
				err = f.accept(f.raw, signer)
			} else {
				err = f.acceptV2(saved.request, signer)
			}
			assert.Equal(err, ErrEstablishment)
			assert.SNotEmpty(history)
			f.f.reopen(t)
			_, retained, held := f.records(t)
			assert.DeepEqual(retained, history)
			assert.SNotEmpty(held)
		})
	}
}

func TestBobAcceptV2ExistingSlotsBeforeCommit(t *testing.T) {
	for _, name := range []string{attemptKey, acceptedKey, heldKey} {
		for _, namespace := range []bool{false, true} {
			t.Run(fmt.Sprint(name, namespace), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				saved := try.To1(f.saveV2(aliceServiceOrigin))
				signer := &probeSigner{Handle: f.local.handle}
				signer.sign = func(d []byte) ([]byte, error) {
					if signer.signCalls.Load() == 2 {
						err := f.f.vault.Update(func(tx storage.WriteTx) (err error) {
							defer err2.Handle(&err, nil)
							if namespace {
								try.To1(tx.EnsureChild([]byte(name)))
								return nil
							}
							return tx.Put([]byte(name), []byte{0xff})
						})
						if err != nil {
							return nil, err
						}
					}
					return f.local.handle.Sign(d)
				}
				assert.Equal(f.acceptV2(saved.request, signer), ErrEstablishment)
				row, found := try.To2(ReadInvitation(f.f.vault,
					f.root.public, f.local.public))
				assert.That(found)
				assert.DeepEqual(row, f.invitation)
				f.f.unchanged(t, func() {
					response, err := f.replyV2(saved.request, f.local.handle)
					assert.Equal(err, ErrEstablishment)
					assert.SNil(response)
				})
			})
		}
	}
}

func TestBobV2PinnedInputsAndSigner(t *testing.T) {
	for _, phase := range []string{"accept", "reply"} {
		for _, fault := range []string{"nil vault", "root", "target", "endpoint",
			"nil signer", "typed nil signer", "wrong signer", "sign error",
			"bad signature", "lying signer"} {
			t.Run(phase+"/"+fault, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				saved := try.To1(f.saveV2(aliceServiceOrigin))
				if phase == "reply" {
					try.To(f.acceptV2(saved.request, f.local.handle))
				}
				vault, root, local := f.f.vault, f.root.public, f.local.public
				endpoint, signer := establishmentEndpoint, f.local.handle
				switch fault {
				case "nil vault":
					vault = nil
				case "root":
					root = f.peer.public
				case "target":
					local = f.peer.public
				case "endpoint":
					endpoint = "http://127.0.0.1:12346/peer/introduction"
				case "nil signer":
					signer = nil
				case "typed nil signer":
					signer = (*probeSigner)(nil)
				case "wrong signer":
					signer = f.peer.handle
				default:
					probe := &probeSigner{Handle: f.local.handle}
					probe.sign = func(d []byte) ([]byte, error) {
						if phase == "reply" || probe.signCalls.Load() == 2 {
							switch fault {
							case "sign error":
								return []byte{1}, errors.New("private diagnostic")
							case "bad signature":
								return []byte{1}, nil
							case "lying signer":
								return f.peer.handle.Sign(d)
							}
						}
						return f.local.handle.Sign(d)
					}
					signer = probe
				}
				f.f.unchanged(t, func() {
					now := func() time.Time { return f.now }
					if phase == "accept" {
						assert.Equal(bobAcceptV2(vault, root, local, signer,
							endpoint, saved.request, now), ErrEstablishment)
					} else {
						response, err := bobReplyV2(vault, root, local, signer,
							endpoint, saved.request, now)
						assert.Equal(err, ErrEstablishment)
						assert.SNil(response)
					}
				})
			})
		}
	}
}

func TestBobV2PublicLocalEntryPoints(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, true)
	// Replace only the unused fixture invitation/ad with current-clock inputs.
	try.To(f.f.vault.Update(func(tx storage.WriteTx) error {
		return tx.Delete([]byte(invitationKey))
	}))
	f.invitation = try.To1(IssueInvitation(f.f.vault, f.root.public,
		f.local.public, f.peer.public))
	endpoint := "http://[::1]:12345/peer/introduction"
	ad := try.To1(ads.PublishLocal(f.f.vault, f.root.public, f.local.public,
		f.local.handle, endpoint, time.Now()))
	raw := try.To1(wire.Marshal(ad))
	try.To1(ads.ReceiveClaim(f.alice.vault, f.root.public, f.local.public, raw))
	// Same test-only VerifiedAd admission as newRequester, using the exact ad.
	try.To(f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return tx.Put([]byte("verified-ad-claims-v1"), try.To1(wire.Marshal(
			[]any{uint8(1), []any{[]any{f.local.public, raw}}})))
	}))
	saved := try.To1(SaveAttemptV2(f.alice.vault, f.root.public,
		f.peer.public, f.local.public, f.peer.handle, f.invitation.ID,
		f.invitation.Audience, aliceServiceOrigin))
	f.alice.unchanged(t, func() {
		try.To(BobAcceptV2(f.f.vault, f.root.public, f.local.public,
			f.local.handle, endpoint, saved.request))
		response := try.To1(BobReplyV2(f.f.vault, f.root.public, f.local.public,
			f.local.handle, endpoint, saved.request))
		var result SignedAcceptedV2
		try.To(wire.UnmarshalCanonical(&result, response))
		assert.Equal(result.Payload.Binding.TargetContact, "http://[::1]:12345")
	})
}
