package pw

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const establishmentEndpoint = "http://127.0.0.1:12345/peer/introduction"

type establishmentFixture struct {
	scenario
	invitation Invitation
	request    SignedEstablishment
	raw        []byte
	now        time.Time
}

func newEstablishment(t *testing.T, directed bool) establishmentFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := establishmentFixture{scenario: ready(t), now: invitationNow}
	var recipient key.Public
	if directed {
		recipient = f.peer.public
	}
	f.invitation = try.To1(issueInvitation(f.f.vault, f.root.public,
		f.local.public, recipient, f.now))
	ad := try.To1(ads.PublishLocal(f.f.vault, f.root.public, f.local.public,
		f.local.handle, establishmentEndpoint, f.now.Add(time.Minute)))
	f.request = SignedEstablishment{Payload: Establishment{
		Version: 1, Root: f.root.public, Requester: f.peer.public,
		Target: f.local.public, InvitationID: f.invitation.ID,
		Audience: f.invitation.Audience, Recipient: recipient,
		AttemptID: bytes.Repeat([]byte{42}, 32), Device: f.peer.public,
		Ad: try.To1(wire.Marshal(ad)),
	}}
	f.raw = signEstablishment(t, f.request, f.peer.handle)
	return f
}

func signEstablishment(t *testing.T, request SignedEstablishment,
	signer key.Handle,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(EstablishPurpose,
		try.To1(wire.Marshal(request.Payload)))
	request.Signature = try.To1(signer.Sign(digest[:]))
	return try.To1(wire.Marshal(request))
}

func (f establishmentFixture) accept(raw []byte, signer key.Handle) error {
	return bobAccept(f.f.vault, f.root.public, f.local.public, signer,
		establishmentEndpoint, raw, func() time.Time { return f.now })
}

func (f establishmentFixture) records(
	t *testing.T,
) (Invitation, []byte, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	var row Invitation
	var accepted, held []byte
	try.To(f.f.vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		row, _ = try.To2(readInvitation(tx, f.root.public, f.local.public))
		accepted, _ = try.To2(tx.Get([]byte(acceptedKey)))
		held, _ = try.To2(tx.Get([]byte(heldKey)))
		return nil
	}))
	return row, accepted, held
}

func (f establishmentFixture) unconsumed(t *testing.T) {
	t.Helper()
	defer assert.PushTester(t)()
	row, accepted, held := f.records(t)
	assert.DeepEqual(row, f.invitation)
	assert.SNil(accepted)
	assert.SNil(held)
}

func TestBobAcceptAtomicBinding(t *testing.T) {
	for _, directed := range []bool{false, true} {
		t.Run(map[bool]string{false: "Any", true: "Directed"}[directed],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newEstablishment(t, directed)
				before := f.f.lease.remaining.Load()
				try.To(f.accept(f.raw, f.local.handle))
				assert.Equal(before-f.f.lease.remaining.Load(), 3)
				row, history, held := f.records(t)
				assert.Equal(row.State, InvitationConsumed)
				row.State = InvitationActive
				assert.DeepEqual(row, f.invitation)
				var accepted acceptedRecord
				try.To(wire.UnmarshalCanonical(&accepted, history))
				assert.Equal(accepted.Version, 1)
				assert.DeepEqual(accepted.Request, f.raw)
				payload := acceptedPayload(f.request.Payload, f.raw)
				try.To(verifyAccepted(accepted.Response, payload))
				assert.DeepEqual(held, try.To1(wire.Marshal(heldRecord{
					Version: 1, RequestDigest: payload.RequestDigest,
				})))
				f.f.unchanged(t, func() {
					assert.Equal(
						f.accept(f.raw, f.local.handle),
						ErrEstablishment,
					)
				})
			})
	}
}

func TestBobAcceptRejectsAuthenticatedBadBindings(t *testing.T) {
	for name, change := range map[string]func(*Establishment){
		"root":           func(p *Establishment) { p.Root = p.Requester },
		"requester":      func(p *Establishment) { p.Requester = p.Root },
		"target":         func(p *Establishment) { p.Target = p.Root },
		"invitation":     func(p *Establishment) { p.InvitationID = bytes.Repeat([]byte{9}, 32) },
		"recipient":      func(p *Establishment) { p.Recipient = p.Root },
		"audience":       func(p *Establishment) { p.Audience, p.Recipient = InvitationAny, nil },
		"attempt length": func(p *Establishment) { p.AttemptID = p.AttemptID[:31] },
		"device":         func(p *Establishment) { p.Device = p.Root },
		"epoch":          func(p *Establishment) { p.Epoch = 1 },
		"version":        func(p *Establishment) { p.Version = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishment(t, true)
			change(&f.request.Payload)
			raw := signEstablishment(t, f.request, f.peer.handle)
			f.f.unchanged(t, func() {
				assert.Equal(f.accept(raw, f.local.handle), ErrEstablishment)
			})
			f.unconsumed(t)
		})
	}
}

func TestBobAcceptRejectsWireAndSignatureChanges(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishment(t, false)
	request := try.To1(
		decodeEstablishment(f.raw, f.root.public, f.local.public),
	)
	request.Payload.AttemptID[0] ^= 1 // No second signature authorizes this change.
	cases := [][]byte{
		nil, {0xa0}, f.raw[:len(f.raw)-1], append(bytes.Clone(f.raw), 0),
		append([]byte{0x98, 2}, f.raw[1:]...), append([]byte{0xc0}, f.raw...),
		make([]byte, MaxEstablishmentBytes+1),
		try.To1(wire.Marshal(request)),
		signEstablishment(t, f.request, f.local.handle),
	}
	for _, raw := range cases {
		f.f.unchanged(t, func() {
			assert.Equal(f.accept(raw, f.local.handle), ErrEstablishment)
		})
	}
	f.unconsumed(t)
}

func TestBobAcceptRejectsAdVariants(t *testing.T) {
	for name, change := range map[string]func(*ads.Payload){
		"slot":   func(p *ads.Payload) { p.Slot = 2 },
		"device": func(p *ads.Payload) { p.Device = p.Root },
		"epoch":  func(p *ads.Payload) { p.Epoch = 1 },
		"root":   func(p *ads.Payload) { p.Root = p.Node },
		"target": func(p *ads.Payload) { p.Node = p.Root },
		"token":  func(p *ads.Payload) { p.Token[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishment(t, false)
			var ad ads.Current
			try.To(wire.UnmarshalCanonical(&ad, f.request.Payload.Ad))
			change(&ad.Payload)
			digest := key.HashTagged(ads.SignaturePurpose,
				try.To1(wire.Marshal(ad.Payload)))
			ad.Signature = try.To1(f.local.handle.Sign(digest[:]))
			f.request.Payload.Ad = try.To1(wire.Marshal(ad))
			raw := signEstablishment(t, f.request, f.peer.handle)
			f.f.unchanged(t, func() {
				assert.Equal(f.accept(raw, f.local.handle), ErrEstablishment)
			})
			f.unconsumed(t)
		})
	}
}

func TestBobAcceptExpiry(t *testing.T) {
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishment(t, false)
			f.now = time.Unix(0, f.invitation.ExpiresUnixNano).Add(offset)
			err := f.accept(f.raw, f.local.handle)
			if offset < 0 {
				assert.NoError(err)
			} else {
				assert.Equal(err, ErrEstablishment)
				f.unconsumed(t)
			}
		})
	}
}

func TestBobAcceptFinalGuards(t *testing.T) {
	for _, stage := range []string{"before", "after preflight"} {
		for _, invalidation := range []string{"deny", "known self", "known peer", "device", "ad", "expiry"} {
			t.Run(stage+"/"+invalidation, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newEstablishment(t, false)
				invalidate := func() (err error) {
					defer err2.Handle(&err, nil)
					switch invalidation {
					case "deny":
						try.To1(
							policy.DenyLocal(
								f.f.vault,
								f.root.public,
								f.local.public,
								f.peer.public,
							),
						)
					case "known self", "known peer":
						subject := f.local.public
						if invalidation == "known peer" {
							subject = f.peer.public
						}
						return f.f.vault.Update(
							func(tx storage.WriteTx) (err error) {
								defer err2.Handle(&err, nil)
								return try.To1(tx.ChildForUpdate([]byte(knownNS))).
									Delete(subject)
							},
						)
					case "device":
						return f.f.vault.Update(
							func(tx storage.WriteTx) (err error) {
								defer err2.Handle(&err, nil)
								return try.To1(tx.ChildForUpdate([]byte(authNS))).
									Delete([]byte(authKey))
							},
						)
					case "ad":
						try.To1(
							ads.PublishLocal(
								f.f.vault,
								f.root.public,
								f.local.public,
								f.local.handle,
								establishmentEndpoint,
								f.now,
							),
						)
					case "expiry":
						f.now = time.Unix(0, f.invitation.ExpiresUnixNano)
					}
					return nil
				}
				signer := &probeSigner{Handle: f.local.handle}
				if stage == "before" {
					try.To(invalidate())
				} else {
					signer.sign = func(d []byte) ([]byte, error) {
						// The second Sign is the acceptance, after the usability probe.
						if signer.signCalls.Load() == 2 {
							if err := invalidate(); err != nil {
								return nil, err
							}
						}
						return f.local.handle.Sign(d)
					}
				}
				assert.Equal(bobAccept(
					f.f.vault,
					f.root.public,
					f.local.public,
					signer,
					establishmentEndpoint,
					f.raw,
					func() time.Time { return f.now },
				),
					ErrEstablishment)
				f.unconsumed(t)
			})
		}
	}
}

func TestBobAcceptSigningFailure(t *testing.T) {
	for _, mode := range []string{"probe", "acceptance", "wrong signature"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishment(t, false)
			signer := &probeSigner{Handle: f.local.handle}
			signer.sign = func(d []byte) ([]byte, error) {
				if mode == "probe" || signer.signCalls.Load() == 2 {
					if mode == "wrong signature" {
						return []byte{1}, nil
					}
					return nil, errors.New("private signing diagnostic")
				}
				return f.local.handle.Sign(d)
			}
			f.f.unchanged(t, func() {
				assert.Equal(f.accept(f.raw, signer), ErrEstablishment)
			})
			f.unconsumed(t)
		})
	}
}
