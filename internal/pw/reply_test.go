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

func (f establishmentFixture) reply(
	raw []byte,
	signer key.Handle,
) ([]byte, error) {
	return bobReply(f.f.vault, f.root.public, f.local.public, signer,
		establishmentEndpoint, raw, func() time.Time { return f.now })
}

func TestBobReplyReadOnlyAndExpiry(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishment(t, false)
	try.To(f.accept(f.raw, f.local.handle))
	_, history, _ := f.records(t)
	var accepted acceptedRecord
	try.To(wire.UnmarshalCanonical(&accepted, history))
	digest := key.HashTagged(AcceptedPurpose,
		try.To1(wire.Marshal(acceptedPayload(f.request.Payload, f.raw))))
	var probes [][]byte
	signer := &probeSigner{Handle: f.local.handle}
	signer.sign = func(data []byte) ([]byte, error) {
		assert.ThatNot(
			bytes.Equal(data, digest[:]),
			"must not re-sign acceptance",
		)
		probes = append(probes, bytes.Clone(data))
		return f.local.handle.Sign(data)
	}
	f.f.lease.remaining.Store(0) // Reply works even with exhausted encryption.
	for _, restart := range []bool{false, true} {
		if restart {
			f.f.reopen(t)
		}
		// The fixture's ad expires one minute after the invitation. Expiry of
		// the consumed invitation alone must not change reply authorization.
		f.now = time.Unix(0, f.invitation.ExpiresUnixNano)
		f.f.unchanged(t, func() {
			assert.DeepEqual(try.To1(f.reply(f.raw, signer)), accepted.Response)
		})
	}
	assert.Equal(len(probes), 2)
	assert.ThatNot(bytes.Equal(probes[0], probes[1]), "probe must be fresh")

	f.now = f.now.Add(time.Minute)
	f.f.unchanged(t, func() {
		response, err := f.reply(f.raw, signer)
		assert.Equal(err, ErrEstablishment) // Current ad expiry still blocks.
		assert.SNil(response)
	})
}

func TestBobReplySignerRequired(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishment(t, false)
	try.To(f.accept(f.raw, f.local.handle))
	for _, signer := range []key.Handle{nil, (*probeSigner)(nil), f.peer.handle,
		&probeSigner{Handle: f.local.handle,
			signErr: errors.New("private probe diagnostic")},
		&probeSigner{Handle: f.local.handle,
			sign: func([]byte) ([]byte, error) { return []byte{1}, nil }},
	} {
		f.f.unchanged(t, func() {
			response, err := f.reply(f.raw, signer)
			assert.Equal(err, ErrEstablishment)
			assert.SNil(response)
		})
	}
}

func TestBobReplyCurrentGuardsAfterProbe(t *testing.T) {
	for _, stage := range []string{"before", "during probe"} {
		for _, fault := range []string{
			"deny", "held", "known self", "known peer", "device", "ad",
		} {
			t.Run(stage+"/"+fault, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newEstablishment(t, false)
				try.To(f.accept(f.raw, f.local.handle))
				row, history, holding := f.records(t)
				invalidate := func() (err error) {
					defer err2.Handle(&err, nil)
					switch fault {
					case "deny":
						try.To1(policy.DenyLocal(f.f.vault, f.root.public,
							f.local.public, f.peer.public))
					case "ad":
						try.To1(ads.PublishLocal(f.f.vault, f.root.public,
							f.local.public, f.local.handle,
							establishmentEndpoint, f.now))
					default:
						return f.f.vault.Update(
							func(tx storage.WriteTx) (err error) {
								defer err2.Handle(&err, nil)
								switch fault {
								case "held":
									return tx.Delete([]byte(heldKey))
								case "device":
									return try.To1(tx.ChildForUpdate([]byte(authNS))).
										Delete([]byte(authKey))
								default:
									subject := f.peer.public
									if fault == "known self" {
										subject = f.local.public
									}
									return try.To1(tx.ChildForUpdate([]byte(knownNS))).
										Delete(subject)
								}
							},
						)
					}
					return nil
				}
				signer := &probeSigner{Handle: f.local.handle}
				if stage == "before" {
					try.To(invalidate())
				} else {
					signer.sign = func(data []byte) ([]byte, error) {
						// A real Update here also detects signing inside View.
						if err := invalidate(); err != nil {
							return nil, err
						}
						return f.local.handle.Sign(data)
					}
				}
				response, err := f.reply(f.raw, signer)
				assert.Equal(err, ErrEstablishment)
				assert.SNil(response)
				gotRow, gotHistory, gotHeld := f.records(t)
				assert.DeepEqual(gotRow, row)
				assert.DeepEqual(gotHistory, history)
				if fault == "held" {
					assert.SNil(gotHeld)
				} else {
					assert.DeepEqual(gotHeld, holding)
				}
				f.f.unchanged(t, func() {
					_, err := f.reply(f.raw, f.local.handle)
					assert.Equal(
						err,
						ErrEstablishment,
					) // No automatic restoration.
				})
			})
		}
	}
}

func TestBobReplyHostileRequests(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishment(t, false)
	try.To(f.accept(f.raw, f.local.handle))
	changed := f.request
	changed.Payload.InvitationID = bytes.Repeat([]byte{7}, 32)
	other := f.request
	other.Payload.Requester, other.Payload.Device = f.root.public, f.root.public
	attempt := f.request
	attempt.Payload.AttemptID = bytes.Repeat([]byte{8}, 32)
	for _, raw := range [][]byte{
		nil, append(bytes.Clone(f.raw), 0),
		append([]byte{0x98, 2}, f.raw[1:]...),
		signEstablishment(t, f.request, f.peer.handle), // Same payload, new signature.
		signEstablishment(t, changed, f.peer.handle),   // Same attempt, different ID.
		signEstablishment(t, other, f.root.handle),
		signEstablishment(t, attempt, f.peer.handle),
		signEstablishment(t, f.request, f.local.handle), // Invalid proof.
	} {
		f.f.unchanged(t, func() {
			response, err := f.reply(raw, f.local.handle)
			assert.Equal(err, ErrEstablishment)
			assert.SNil(response)
		})
	}
	f.f.unchanged(t, func() {
		_, err := bobReply(f.f.vault, f.root.public, f.local.public,
			f.local.handle, establishmentEndpoint+"/other", f.raw,
			func() time.Time { return f.now })
		assert.Equal(err, ErrEstablishment)
	})
}
