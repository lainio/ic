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
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

type requesterFixture struct {
	establishmentFixture
	alice  vaultFixture
	signer *probeSigner
}

func newRequester(t *testing.T, directed bool) *requesterFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := &requesterFixture{establishmentFixture: newEstablishment(t, directed),
		alice: newVault(t)}
	f.signer = &probeSigner{Handle: f.peer.handle}
	base := intro.New(key.Info{Public: f.root.public})
	for _, subject := range []savedSigner{f.local, f.peer} {
		savePath(
			t,
			f.alice.vault,
			f.root.public,
			base.Introduce(
				f.root.handle,
				key.Info{Public: subject.public},
			),
			subject,
		)
	}
	try.To1(onboarding.VerifyReceived(f.alice.vault, f.root.public))
	try.To1(device.BootstrapLocal(f.alice.vault, f.root.public, f.peer.public,
		f.peer.handle))
	try.To1(ads.ReceiveClaim(f.alice.vault, f.root.public, f.local.public,
		f.request.Payload.Ad))
	// Unit fixture only: online admission is exercised by the two-Store HTTP tests.
	claims := struct {
		_       struct{} `cbor:",toarray"`
		Version uint8
		Entries []struct {
			_       struct{} `cbor:",toarray"`
			Subject key.Public
			Ad      []byte
		}
	}{Version: 1}
	claims.Entries = append(claims.Entries, struct {
		_       struct{} `cbor:",toarray"`
		Subject key.Public
		Ad      []byte
	}{Subject: f.local.public, Ad: f.request.Payload.Ad})
	try.To(f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return tx.Put(
			[]byte("verified-ad-claims-v1"),
			try.To1(wire.Marshal(claims)),
		)
	}))
	return f
}

func (f *requesterFixture) save() (SavedAttempt, error) {
	return saveAttempt(f.alice.vault, f.root.public, f.peer.public,
		f.local.public, f.signer, f.invitation.ID, f.invitation.Audience,
		func() time.Time { return f.now })
}

func (f *requesterFixture) receive(response []byte) (bool, error) {
	return receiveAcceptance(f.alice.vault, f.root.public, f.peer.public,
		f.signer, response, func() time.Time { return f.now })
}

func (f *requesterFixture) response(t *testing.T) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	saved := try.To1(f.save())
	try.To(f.accept(saved.request, f.local.handle))
	return try.To1(bobReply(f.f.vault, f.root.public, f.local.public,
		f.local.handle, establishmentEndpoint, saved.request,
		func() time.Time { return f.now }))
}

func requesterRecords(t *testing.T, v *storage.Vault) (result [3][]byte) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for i, name := range []string{attemptKey, acceptedKey, heldKey} {
			result[i], _ = try.To2(tx.Get([]byte(name)))
		}
		return nil
	}))
	return result
}

func TestRequesterSavedExactAndDuplicate(t *testing.T) {
	for _, directed := range []bool{false, true} {
		t.Run(fmt.Sprint(directed), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, directed)
			saved := try.To1(f.save())
			request := try.To1(decodeEstablishment(saved.request, f.root.public,
				f.local.public))
			assert.DeepEqual(request.Payload.Requester, f.peer.public)
			assert.Equal(len(request.Payload.AttemptID), 32)
			assert.DeepEqual(request.Payload.Ad, f.request.Payload.Ad)
			assert.Equal(f.signer.signCalls.Load(), 2)
			assert.DeepEqual(requesterRecords(t, f.alice.vault),
				[3][]byte{saved.request, nil, nil})
			f.alice.reopen(t)
			f.alice.unchanged(t, func() {
				again := try.To1(f.save())
				assert.DeepEqual(again, saved)
				assert.Equal(
					f.signer.signCalls.Load(),
					3,
				) // Discarded probe only.
				f.invitation.ID = bytes.Repeat([]byte{7}, 32)
				_, err := f.save()
				assert.Equal(err, ErrEstablishment)
				assert.Equal(f.signer.signCalls.Load(), 3)
			})
		})
	}
}

func TestRequesterIndependentAcceptanceAndDeletion(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, true)
	response := f.response(t)
	try.To1(policy.DenyLocal(f.f.vault, f.root.public, f.local.public,
		f.peer.public)) // Response already sent: Alice must not consult this.
	f.f.unchanged(t, func() { assert.That(try.To1(f.receive(response))) })
	history := requesterRecords(t, f.alice.vault)
	assert.SNotEmpty(history[1])
	assert.SNotEmpty(history[2])
	f.alice.lease.remaining.Store(0)
	f.alice.unchanged(t, func() { assert.That(try.To1(f.receive(response))) })
	// Test-only local deletion requires no encryption and must not be repaired.
	try.To(f.alice.vault.Update(func(tx storage.WriteTx) error {
		return tx.Delete([]byte(heldKey))
	}))
	f.alice.unchanged(t, func() {
		assert.ThatNot(try.To1(f.receive(response)))
		saved := try.To1(f.save())
		assert.That(saved.Accepted && !saved.Held)
	})
	after := requesterRecords(t, f.alice.vault)
	assert.DeepEqual(after, [3][]byte{history[0], history[1], nil})
}

func TestRequesterRejectsResponseBindings(t *testing.T) {
	changes := map[string]func(*Accepted){
		"digest":     func(p *Accepted) { p.RequestDigest[0] ^= 1 },
		"root":       func(p *Accepted) { p.Binding.Root = p.Binding.Target },
		"requester":  func(p *Accepted) { p.Binding.Requester = p.Binding.Root },
		"target":     func(p *Accepted) { p.Binding.Target = p.Binding.Root },
		"invitation": func(p *Accepted) { p.Binding.InvitationID[0] ^= 1 },
		"attempt":    func(p *Accepted) { p.Binding.AttemptID[0] ^= 1 },
		"recipient":  func(p *Accepted) { p.Binding.Recipient = p.Binding.Root },
		"audience":   func(p *Accepted) { p.Binding.Audience = InvitationAny },
		"device":     func(p *Accepted) { p.Binding.Device = p.Binding.Root },
		"epoch":      func(p *Accepted) { p.Binding.Epoch++ },
		"ad":         func(p *Accepted) { p.Binding.Ad[0] ^= 1 },
	}
	f := newRequester(t, true)
	response := f.response(t)
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			var result SignedAccepted
			try.To(wire.UnmarshalCanonical(&result, response))
			change(&result.Payload)
			digest := key.HashTagged(
				AcceptedPurpose,
				try.To1(wire.Marshal(result.Payload)),
			)
			result.Signature = try.To1(f.local.handle.Sign(digest[:]))
			f.alice.unchanged(t, func() {
				_, err := f.receive(try.To1(wire.Marshal(result)))
				assert.Equal(err, ErrEstablishment)
			})
		})
	}
	for i, raw := range [][]byte{nil, {0xff}, response[:len(response)-1],
		append(bytes.Clone(response), 0), append([]byte{0x98, 2}, response[1:]...),
		append([]byte{0xc0}, response...), make([]byte, MaxEstablishmentBytes+1)} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			defer assert.PushTester(t)()
			f.alice.unchanged(t, func() {
				_, err := f.receive(raw)
				assert.Equal(err, ErrEstablishment)
			})
		})
	}
}

func TestRequesterCurrentGuards(t *testing.T) {
	for _, phase := range []string{"save", "receive", "duplicate"} {
		for _, guard := range []string{"deny", "known self", "known peer", "device",
			"received", "verified", "expiry", "unusable"} {
			for _, duringProbe := range []bool{false, true} {
				t.Run(
					fmt.Sprint(phase, "/", guard, "/", duringProbe),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f := newRequester(t, false)
						var response []byte
						if phase != "save" {
							response = f.response(t)
						}
						if phase == "duplicate" {
							try.To1(f.receive(response))
						}
						before := requesterRecords(t, f.alice.vault)
						invalidate := func() (err error) {
							defer err2.Handle(&err, nil)
							switch guard {
							case "deny":
								try.To1(
									policy.DenyLocal(
										f.alice.vault,
										f.root.public,
										f.peer.public,
										f.local.public,
									),
								)
							case "known self", "known peer":
								subject := f.peer.public
								if guard == "known peer" {
									subject = f.local.public
								}
								return f.alice.vault.Update(
									func(tx storage.WriteTx) (err error) {
										defer err2.Handle(&err, nil)
										return try.To1(tx.ChildForUpdate([]byte(knownNS))).
											Delete(subject)
									},
								)
							case "device":
								return f.alice.vault.Update(
									func(tx storage.WriteTx) (err error) {
										defer err2.Handle(&err, nil)
										return try.To1(tx.ChildForUpdate([]byte(authNS))).
											Delete([]byte(authKey))
									},
								)
							case "received", "verified":
								return f.alice.vault.Update(
									func(tx storage.WriteTx) error {
										return tx.Delete(
											[]byte(guard + "-ad-claims-v1"),
										)
									},
								)
							case "expiry":
								f.now = f.now.Add(2 * ads.TTL)
							case "unusable":
								return errors.New("unusable signer")
							}
							return nil
						}
						if duringProbe || guard == "unusable" {
							f.signer.sign = func(d []byte) ([]byte, error) {
								if err := invalidate(); err != nil {
									return nil, err
								}
								return f.peer.handle.Sign(d)
							}
						} else {
							try.To(invalidate())
						}
						signs := f.signer.signCalls.Load()
						if phase == "save" {
							_, err := f.save()
							assert.Equal(err, ErrEstablishment)
						} else {
							_, err := f.receive(response)
							assert.Equal(err, ErrEstablishment)
						}
						assert.That(f.signer.signCalls.Load()-signs <= 1)
						assert.DeepEqual(
							requesterRecords(t, f.alice.vault),
							before,
						)
					},
				)
			}
		}
	}
}

func TestRequesterAtomicWriteRollback(t *testing.T) {
	for index := range 2 {
		boundary := index + 1
		t.Run(fmt.Sprint(boundary), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			response := f.response(t)
			before := requesterRecords(t, f.alice.vault)
			f.f.unchanged(t, func() {
				cause := errors.New("Alice write failure")
				err := f.alice.vault.Update(
					func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						try.To1(
							commitRequesterAcceptance(
								&failingAcceptanceTx{WriteTx: tx,
									failAfter: boundary, cause: cause},
								f.root.public,
								f.peer.public,
								response,
								func() time.Time { return f.now },
							),
						)
						return nil
					},
				)
				assert.ErrorIs(err, cause)
			})
			assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
			f.alice.reopen(t)
			assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
		})
	}
}

func TestRequesterEncryptionFailure(t *testing.T) {
	for _, phase := range []string{"save", "receive"} {
		for allowance := range int64(2) {
			if phase == "save" && allowance == 1 {
				continue
			}
			t.Run(fmt.Sprint(phase, allowance), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				var response []byte
				if phase == "receive" {
					response = f.response(t)
				}
				before := requesterRecords(t, f.alice.vault)
				f.alice.lease.remaining.Store(allowance)
				var err error
				if phase == "save" {
					_, err = f.save()
				} else {
					_, err = f.receive(response)
				}
				assert.Equal(err, ErrEstablishment)
				assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
				f.alice.reopen(t)
				assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
			})
		}
	}
}

func TestRequesterConflictingRecords(t *testing.T) {
	for _, name := range []string{attemptKey, acceptedKey, heldKey} {
		for _, namespace := range []bool{false, true} {
			t.Run(fmt.Sprint(name, namespace), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				response := f.response(t)
				try.To(
					f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						if namespace {
							try.To(tx.Delete([]byte(name)))
							try.To1(tx.EnsureChild([]byte(name)))
							return nil
						}
						return tx.Put([]byte(name), []byte{0xff})
					}),
				)
				signs := f.signer.signCalls.Load()
				f.alice.unchanged(t, func() {
					_, err := f.save()
					assert.Equal(err, ErrEstablishment)
					_, err = f.receive(response)
					assert.Equal(err, ErrEstablishment)
				})
				assert.Equal(f.signer.signCalls.Load(), signs)
			})
		}
	}
}

func TestRequesterExactDescriptorAndRoleConflicts(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	saved := try.To1(f.save())
	for _, descriptor := range []struct {
		target   key.Public
		id       []byte
		audience string
	}{
		{f.root.public, f.invitation.ID, InvitationAny},
		{f.local.public, f.invitation.ID, InvitationDirected},
		{f.local.public, bytes.Repeat([]byte{17}, 32), InvitationAny},
	} {
		f.alice.unchanged(t, func() {
			_, err := saveAttempt(f.alice.vault, f.root.public, f.peer.public,
				descriptor.target, f.signer, descriptor.id, descriptor.audience,
				func() time.Time { return f.now })
			assert.Equal(err, ErrEstablishment)
		})
	}
	assert.Equal(f.signer.signCalls.Load(), 2)
	// A valid Bob-role history cannot be repurposed as Alice's history.
	try.To(f.accept(f.raw, f.local.handle))
	_, history, holding := f.records(t)
	try.To(f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(tx.Put([]byte(acceptedKey), history))
		return tx.Put([]byte(heldKey), holding)
	}))
	f.alice.unchanged(t, func() {
		_, err := f.save()
		assert.Equal(err, ErrEstablishment)
	})
	assert.Equal(f.signer.signCalls.Load(), 2)
	assert.DeepEqual(requesterRecords(t, f.alice.vault)[0], saved.request)
}

func TestBobCannotOverwriteRequesterAttempt(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishment(t, false)
	try.To(f.f.vault.Update(func(tx storage.WriteTx) error {
		return tx.Put([]byte(attemptKey), []byte{1})
	}))
	signer := &probeSigner{Handle: f.local.handle}
	f.f.unchanged(t, func() {
		assert.Equal(f.accept(f.raw, signer), ErrEstablishment)
	})
	assert.Equal(signer.signCalls.Load(), 0)
	f.unconsumed(t)
}

func TestRequesterSigningAndFinalSaveGuard(t *testing.T) {
	for _, mode := range []string{"sign failure", "wrong signature", "deny during signing"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			f.signer.sign = func(d []byte) ([]byte, error) {
				if f.signer.signCalls.Load() == 2 {
					switch mode {
					case "sign failure":
						return nil, errors.New("private signer diagnostic")
					case "wrong signature":
						return []byte{1}, nil
					case "deny during signing":
						if _, err := policy.DenyLocal(f.alice.vault, f.root.public,
							f.peer.public, f.local.public); err != nil {
							return nil, err
						}
					}
				}
				return f.peer.handle.Sign(d)
			}
			_, err := f.save()
			assert.Equal(err, ErrEstablishment)
			assert.DeepEqual(requesterRecords(t, f.alice.vault), [3][]byte{})
		})
	}
}

func TestRequesterRejectsChangedLocalAdAtCommit(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	response := f.response(t)
	before := requesterRecords(t, f.alice.vault)
	var ad ads.Current
	try.To(wire.UnmarshalCanonical(&ad, f.request.Payload.Ad))
	ad.Payload.Token[0] ^= 1
	digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(ad.Payload)))
	ad.Signature = try.To1(f.local.handle.Sign(digest[:]))
	replacement := try.To1(wire.Marshal(ad))
	f.signer.sign = func(d []byte) ([]byte, error) {
		if _, err := ads.ReceiveClaim(f.alice.vault, f.root.public, f.local.public, replacement); err != nil {
			return nil, err
		}
		return f.peer.handle.Sign(d)
	}
	f.f.unchanged(t, func() {
		_, err := f.receive(response)
		assert.Equal(err, ErrEstablishment)
	})
	assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
}

func TestRequesterRejectsInvalidAndDifferentAcceptanceSignatures(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	response := f.response(t)
	var accepted SignedAccepted
	try.To(wire.UnmarshalCanonical(&accepted, response))
	accepted.Signature = []byte{1}
	f.alice.unchanged(t, func() {
		_, err := f.receive(try.To1(wire.Marshal(accepted)))
		assert.Equal(err, ErrEstablishment)
	})
	assert.That(try.To1(f.receive(response)))
	digest := key.HashTagged(AcceptedPurpose, try.To1(wire.Marshal(accepted.Payload)))
	accepted.Signature = try.To1(f.local.handle.Sign(digest[:]))
	other := try.To1(wire.Marshal(accepted))
	assert.ThatNot(bytes.Equal(response, other))
	// A second valid signature for the same payload is not an exact duplicate.
	f.alice.unchanged(t, func() {
		_, err := f.receive(other)
		assert.Equal(err, ErrEstablishment)
	})
}
