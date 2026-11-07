package pw

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const aliceServiceOrigin = "http://127.0.0.1:4040"

func (f *requesterFixture) saveV2(origin string) (SavedAttemptV2, error) {
	return saveAttemptV2(f.alice.vault, f.root.public, f.peer.public,
		f.local.public, f.signer, f.invitation.ID, f.invitation.Audience,
		origin, func() time.Time { return f.now })
}

func TestRequesterV2ContactsAndExactReopen(t *testing.T) {
	for _, origin := range []string{aliceServiceOrigin, "http://[::1]:4040"} {
		for _, directed := range []bool{false, true} {
			t.Run(fmt.Sprint(origin, directed), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, directed)
				var saved SavedAttemptV2
				f.f.unchanged(t, func() {
					saved = try.To1(f.saveV2(origin))
				})
				request := try.To1(decodeEstablishmentV2(saved.request,
					f.root.public, f.local.public))
				p := request.Payload
				assert.Equal(p.Version, 2)
				assert.Equal(p.RequesterContact, origin)
				assert.Equal(p.TargetContact, "http://127.0.0.1:12345")
				assert.DeepEqual(p.Root, f.root.public)
				assert.DeepEqual(p.Requester, f.peer.public)
				assert.DeepEqual(p.Target, f.local.public)
				assert.DeepEqual(p.InvitationID, f.invitation.ID)
				assert.Equal(p.Audience, f.invitation.Audience)
				assert.DeepEqual(p.Recipient, f.invitation.Recipient)
				assert.Equal(len(p.AttemptID), 32)
				assert.DeepEqual(p.Device, f.peer.public)
				assert.Equal(p.Epoch, uint64(0))
				assert.DeepEqual(p.Ad, f.request.Payload.Ad)
				digest := key.HashTagged(EstablishPurposeV2,
					try.To1(wire.Marshal(p)))
				assert.That(request.Signature.Verify(f.peer.public, digest[:]))
				assert.ThatNot(request.Signature.Verify(f.local.public, digest[:]))
				assert.DeepEqual(requesterRecords(t, f.alice.vault),
					[3][]byte{saved.request, nil, nil})
				assert.Equal(f.signer.signCalls.Load(), 2)

				f.alice.reopen(t)
				f.signer.Handle = try.To1(nodeidentity.OpenDirectory(
					f.peer.dir, f.peer.unlock))
				f.signer.sign = func(d []byte) ([]byte, error) {
					if bytes.Equal(d, digest[:]) {
						return nil, errors.New("attempt must not be re-signed")
					}
					return f.signer.Handle.Sign(d)
				}
				f.alice.lease.remaining.Store(0)
				f.alice.unchanged(t, func() {
					again := try.To1(f.saveV2(origin))
					assert.DeepEqual(again, saved)
					assert.Equal(f.signer.signCalls.Load(), 3) // Probe only.

					// Returned bytes do not alias storage.
					again.request[0] ^= 1
					assert.DeepEqual(requesterRecords(t, f.alice.vault),
						[3][]byte{saved.request, nil, nil})
				})
			})
		}
	}
}

func TestRequesterV2RejectsOwnConfiguration(t *testing.T) {
	for _, origin := range []string{
		"", "http://127.0.0.1:0", "http://localhost:4040",
		"http://127.0.0.1:04040", "http://127.0.0.1:65536",
		"http://127.0.0.1:4040/", "http://127.0.0.1:4040/peer/introduction",
		"http://127.0.0.1:4040?x", "http://127.0.0.1:4040#x",
		"http://user@127.0.0.1:4040", "http://127.0.0.1:4040\\x",
		"https://127.0.0.1:4040", "HTTP://127.0.0.1:4040",
		"http://192.0.2.1:4040", "http://0.0.0.0:4040",
		"http://[0:0:0:0:0:0:0:1]:4040", "http://[::ffff:127.0.0.1]:4040",
		"http://[::1%lo]:4040", "http://[::]:4040",
		" http://127.0.0.1:4040", "http://127.0.0.1:4040\n",
		"http://" + strings.Repeat("1", 257),
	} {
		t.Run(origin, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			f.alice.unchanged(t, func() {
				saved, err := f.saveV2(origin)
				assert.Equal(err, ErrEstablishment)
				assert.DeepEqual(saved, SavedAttemptV2{})
			})
			assert.Equal(f.signer.signCalls.Load(), 0)
			assert.DeepEqual(requesterRecords(t, f.alice.vault), [3][]byte{})
		})
	}
}

func TestRequesterV2SignerAndIdentity(t *testing.T) {
	for _, mode := range []string{
		"wrong signer", "wrong identity", "nil signer", "sign failure",
		"wrong signature", "lying signer",
	} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			local, signer := f.peer.public, key.Handle(f.signer)
			switch mode {
			case "wrong signer":
				signer = f.local.handle
			case "wrong identity":
				local = f.root.public
			case "nil signer":
				signer = nil
			default:
				f.signer.sign = func(d []byte) ([]byte, error) {
					if f.signer.signCalls.Load() == 2 {
						switch mode {
						case "sign failure":
							return nil, errors.New("private signer diagnostic")
						case "wrong signature":
							return []byte{1}, nil
						case "lying signer":
							return f.local.handle.Sign(d)
						}
					}
					return f.peer.handle.Sign(d)
				}
			}
			f.alice.unchanged(t, func() {
				saved, err := saveAttemptV2(f.alice.vault, f.root.public,
					local, f.local.public, signer, f.invitation.ID,
					f.invitation.Audience, aliceServiceOrigin,
					func() time.Time { return f.now })
				assert.Equal(err, ErrEstablishment)
				assert.DeepEqual(saved, SavedAttemptV2{})
			})
		})
	}
}

func TestRequesterV2DescriptorConflicts(t *testing.T) {
	for _, field := range []string{"origin", "target", "invitation", "audience"} {
		t.Run(field, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			saved := try.To1(f.saveV2(aliceServiceOrigin))
			f.alice.reopen(t)
			origin := aliceServiceOrigin
			switch field {
			case "origin":
				origin = "http://127.0.0.1:4041" // A new :0 listener's port.
			case "target":
				f.local.public = f.root.public
			case "invitation":
				f.invitation.ID[0] ^= 1
			case "audience":
				f.invitation.Audience = InvitationDirected
			}
			f.alice.unchanged(t, func() {
				_, err := f.saveV2(origin)
				assert.Equal(err, ErrEstablishment)
			})
			assert.Equal(f.signer.signCalls.Load(), 2)
			assert.DeepEqual(requesterRecords(t, f.alice.vault),
				[3][]byte{saved.request, nil, nil})
		})
	}
}

// Replace both local ad collections with a correctly signed new fixture ad.
// This is fixture admission, not a production shortcut around online proof.
func replaceRequesterAd(t *testing.T, f *requesterFixture, endpoint string) {
	t.Helper()
	defer assert.PushTester(t)()
	var ad ads.Current
	try.To(wire.UnmarshalCanonical(&ad, f.request.Payload.Ad))
	ad.Payload.Token[0] ^= 1
	ad.Payload.PeerIntroductionURL = endpoint
	digest := key.HashTagged(ads.SignaturePurpose,
		try.To1(wire.Marshal(ad.Payload)))
	ad.Signature = try.To1(f.local.handle.Sign(digest[:]))
	raw := try.To1(wire.Marshal(ad))
	try.To1(ads.ReceiveClaim(f.alice.vault, f.root.public, f.local.public, raw))
	claims := []any{uint8(1), []any{[]any{f.local.public, raw}}}
	try.To(f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return tx.Put([]byte("verified-ad-claims-v1"),
			try.To1(wire.Marshal(claims)))
	}))
}

func TestRequesterV2ChangedAdConflicts(t *testing.T) {
	for _, endpoint := range []string{establishmentEndpoint,
		"http://127.0.0.1:12346/peer/introduction"} {
		t.Run(endpoint, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			saved := try.To1(f.saveV2(aliceServiceOrigin))
			f.alice.reopen(t)
			replaceRequesterAd(t, f, endpoint)
			f.alice.unchanged(t, func() {
				_, err := f.saveV2(aliceServiceOrigin)
				assert.Equal(err, ErrEstablishment)
			})
			assert.Equal(f.signer.signCalls.Load(), 2)
			assert.DeepEqual(requesterRecords(t, f.alice.vault),
				[3][]byte{saved.request, nil, nil})
		})
	}
}

func TestRequesterV2CurrentGuards(t *testing.T) {
	for _, phase := range []string{"before", "probe", "sign", "retry"} {
		for _, guard := range []string{"known self", "known peer", "device",
			"deny", "received", "verified", "expiry"} {
			t.Run(phase+"/"+guard, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				if phase == "retry" {
					try.To1(f.saveV2(aliceServiceOrigin))
				}
				before := requesterRecords(t, f.alice.vault)
				invalidate := func() (err error) {
					defer err2.Handle(&err, nil)
					switch guard {
					case "known self", "known peer", "device":
						ns, subject := knownNS, []byte(f.peer.public)
						switch guard {
						case "known peer":
							subject = f.local.public
						case "device":
							ns, subject = authNS, []byte(authKey)
						}
						return f.alice.vault.Update(func(tx storage.WriteTx,
						) (err error) {
							defer err2.Handle(&err, nil)
							return try.To1(tx.ChildForUpdate([]byte(ns))).
								Delete(subject)
						})
					case "deny":
						try.To1(policy.DenyLocal(f.alice.vault, f.root.public,
							f.peer.public, f.local.public))
					case "received", "verified":
						return f.alice.vault.Update(func(tx storage.WriteTx) error {
							return tx.Delete([]byte(guard + "-ad-claims-v1"))
						})
					case "expiry":
						f.now = f.now.Add(2 * ads.TTL)
					}
					return nil
				}
				if phase == "before" || phase == "retry" {
					try.To(invalidate())
				} else {
					at := int64(1)
					if phase == "sign" {
						at = 2
					}
					f.signer.sign = func(d []byte) ([]byte, error) {
						if f.signer.signCalls.Load() == at {
							if err := invalidate(); err != nil {
								return nil, err
							}
						}
						return f.peer.handle.Sign(d)
					}
				}
				saved, err := f.saveV2(aliceServiceOrigin)
				assert.Equal(err, ErrEstablishment)
				assert.DeepEqual(saved, SavedAttemptV2{})
				assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
				if phase == "before" {
					assert.Equal(f.signer.signCalls.Load(), 0)
				}
			})
		}
	}
}

func TestRequesterV2SaveFailureAndRollback(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	f.alice.lease.remaining.Store(0)
	saved, err := f.saveV2(aliceServiceOrigin)
	assert.Equal(err, ErrEstablishment)
	assert.DeepEqual(saved, SavedAttemptV2{})
	assert.DeepEqual(requesterRecords(t, f.alice.vault), [3][]byte{})
	f.alice.reopen(t)
	assert.DeepEqual(requesterRecords(t, f.alice.vault), [3][]byte{})

	f.alice.lease.remaining.Store(10)
	saved = try.To1(f.saveV2(aliceServiceOrigin))
	try.To(f.alice.vault.Update(func(tx storage.WriteTx) error {
		return tx.Delete([]byte(attemptKey)) // Test-only uncommitted fixture.
	}))
	cause := errors.New("failure after encrypted attempt write")
	err = f.alice.vault.Update(func(tx storage.WriteTx) error {
		return commitAttemptV2(&failingAcceptanceTx{WriteTx: tx,
			failAfter: 1, cause: cause}, f.root.public, f.peer.public,
			aliceServiceOrigin, saved.request, func() time.Time { return f.now })
	})
	assert.ErrorIs(err, cause)
	assert.DeepEqual(requesterRecords(t, f.alice.vault), [3][]byte{})
	f.alice.reopen(t)
	assert.DeepEqual(requesterRecords(t, f.alice.vault), [3][]byte{})
}

func TestRequesterV2VersionIsolation(t *testing.T) {
	for _, phase := range []string{"v1 attempt", "v1 accepted", "v1 deleted",
		"v2 attempt"} {
		t.Run(phase, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			switch phase {
			case "v2 attempt":
				try.To1(f.saveV2(aliceServiceOrigin))
			case "v1 attempt":
				try.To1(f.save())
			default:
				try.To1(f.receive(f.response(t)))
				if phase == "v1 deleted" {
					try.To(f.alice.vault.Update(func(tx storage.WriteTx) error {
						return tx.Delete([]byte(heldKey))
					}))
				}
			}
			before := requesterRecords(t, f.alice.vault)
			f.alice.reopen(t)
			calls := f.signer.signCalls.Load()
			f.alice.unchanged(t, func() {
				var err error
				if phase == "v2 attempt" {
					_, err = f.save()
				} else {
					_, err = f.saveV2(aliceServiceOrigin)
				}
				assert.Equal(err, ErrEstablishment)
			})
			assert.Equal(f.signer.signCalls.Load(), calls)
			assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
		})
	}
}

func TestRequesterV2PublicPreparationFromVerifiedIPv6Ad(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, true)
	f.now = time.Now()
	ad := try.To1(ads.PublishLocal(f.f.vault, f.root.public, f.local.public,
		f.local.handle, "http://[::1]:12345/peer/introduction", f.now))
	f.request.Payload.Ad = try.To1(wire.Marshal(ad))
	replaceRequesterAd(t, f, ad.Payload.PeerIntroductionURL)
	f.f.unchanged(t, func() {
		saved := try.To1(SaveAttemptV2(f.alice.vault, f.root.public,
			f.peer.public, f.local.public, f.signer, f.invitation.ID,
			f.invitation.Audience, aliceServiceOrigin))
		p := try.To1(decodeEstablishmentV2(saved.request,
			f.root.public, f.local.public)).Payload
		assert.Equal(p.RequesterContact, aliceServiceOrigin)
		assert.Equal(p.TargetContact, "http://[::1]:12345")
		f.alice.reopen(t)
		again := try.To1(SaveAttemptV2(f.alice.vault, f.root.public,
			f.peer.public, f.local.public, f.signer, f.invitation.ID,
			f.invitation.Audience, aliceServiceOrigin))
		assert.DeepEqual(again, saved)
	})
}

func TestRequesterV2AdReplacementDuringSigning(t *testing.T) {
	for _, endpoint := range []string{establishmentEndpoint,
		"http://127.0.0.1:12346/peer/introduction"} {
		t.Run(endpoint, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			f.signer.sign = func(d []byte) ([]byte, error) {
				if f.signer.signCalls.Load() == 2 {
					replaceRequesterAd(t, f, endpoint)
				}
				return f.peer.handle.Sign(d)
			}
			saved, err := f.saveV2(aliceServiceOrigin)
			assert.Equal(err, ErrEstablishment)
			assert.DeepEqual(saved, SavedAttemptV2{})
			assert.DeepEqual(requesterRecords(t, f.alice.vault), [3][]byte{})
		})
	}
}

func TestRequesterV2MixedVersionCommitOrders(t *testing.T) {
	for _, firstV2 := range []bool{false, true} {
		t.Run(fmt.Sprint(firstV2), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			var committed []byte
			f.signer.sign = func(d []byte) (_ []byte, err error) {
				defer err2.Handle(&err, nil)
				if f.signer.signCalls.Load() == 2 {
					// Inject an independent durable writer after preflight.
					// Use the real signer directly to avoid callback recursion.
					if firstV2 {
						committed = try.To1(saveAttemptV2(f.alice.vault,
							f.root.public, f.peer.public, f.local.public,
							f.peer.handle, f.invitation.ID, f.invitation.Audience,
							aliceServiceOrigin, func() time.Time { return f.now },
						)).request
					} else {
						committed = try.To1(saveAttempt(f.alice.vault,
							f.root.public, f.peer.public, f.local.public,
							f.peer.handle, f.invitation.ID, f.invitation.Audience,
							func() time.Time { return f.now },
						)).request
					}
				}
				return f.peer.handle.Sign(d)
			}
			var err error
			if firstV2 {
				_, err = f.save()
			} else {
				_, err = f.saveV2(aliceServiceOrigin)
			}
			assert.Equal(err, ErrEstablishment)
			assert.SNotEmpty(committed)
			f.alice.reopen(t)
			assert.DeepEqual(requesterRecords(t, f.alice.vault),
				[3][]byte{committed, nil, nil})
		})
	}
}

func TestRequesterV2CorruptSavedAttemptIsNotRepaired(t *testing.T) {
	for _, mode := range []string{"contact", "noncanonical", "accepted", "held"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			saved := try.To1(f.saveV2(aliceServiceOrigin))
			name, raw := attemptKey, saved.request
			switch mode {
			case "contact":
				p := try.To1(decodeEstablishmentV2(raw,
					f.root.public, f.local.public))
				p.Payload.RequesterContact = "http://127.0.0.1:4041"
				raw = try.To1(wire.Marshal(p))
			case "noncanonical":
				raw = append([]byte{0x98, 2}, raw[1:]...)
			case "accepted":
				name, raw = acceptedKey, []byte{0xff}
			case "held":
				name, raw = heldKey, []byte{0xff}
			}
			try.To(f.alice.vault.Update(func(tx storage.WriteTx) error {
				return tx.Put([]byte(name), raw)
			}))
			before := requesterRecords(t, f.alice.vault)
			f.alice.reopen(t)
			f.alice.unchanged(t, func() {
				_, err := f.saveV2(aliceServiceOrigin)
				assert.Equal(err, ErrEstablishment)
			})
			assert.Equal(f.signer.signCalls.Load(), 2)
			assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
		})
	}
}
