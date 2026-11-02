package pw

import (
	"bytes"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestBobReplyRejectsStoredConflictsWithoutRepair(t *testing.T) {
	for _, name := range []string{invitationKey, acceptedKey, heldKey} {
		for _, mode := range []string{
			"absent", "namespace", "malformed", "version", "noncanonical",
			"conflict", "extra", "oversize",
		} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newEstablishment(t, false)
				try.To(f.accept(f.raw, f.local.handle))
				try.To(f.f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					if mode == "absent" || mode == "namespace" {
						try.To(tx.Delete([]byte(name)))
						if mode == "namespace" {
							try.To1(tx.EnsureChild([]byte(name)))
						}
						return nil
					}
					raw, _ := try.To2(tx.Get([]byte(name)))
					switch mode {
					case "malformed":
						raw = []byte{0xff}
					case "oversize":
						raw = make([]byte, 2*MaxEstablishmentBytes+17)
					case "extra":
						raw = append(raw, 0)
					case "noncanonical":
						raw = append([]byte{0x98, raw[0] & 0x1f}, raw[1:]...)
					default:
						switch name {
						case invitationKey:
							var row Invitation
							try.To(wire.UnmarshalCanonical(&row, raw))
							if mode == "version" {
								row.Version++
							} else {
								row.State = InvitationActive
							}
							raw = try.To1(wire.Marshal(row))
						case acceptedKey:
							var row acceptedRecord
							try.To(wire.UnmarshalCanonical(&row, raw))
							if mode == "version" {
								row.Version++
							} else {
								row.Request = bytes.Clone(f.raw)
								row.Request[len(row.Request)-1] ^= 1
							}
							raw = try.To1(wire.Marshal(row))
						case heldKey:
							var row heldRecord
							try.To(wire.UnmarshalCanonical(&row, raw))
							if mode == "version" {
								row.Version++
							} else {
								row.RequestDigest[0] ^= 1
							}
							raw = try.To1(wire.Marshal(row))
						}
					}
					return tx.Put([]byte(name), raw)
				}))
				f.f.unchanged(t, func() {
					response, err := f.reply(f.raw, f.local.handle)
					assert.Equal(err, ErrEstablishment)
					assert.SNil(response)
				})
			})
		}
	}
}

func TestBobReplyValidatesEntireSavedAcceptance(t *testing.T) {
	for _, field := range []string{
		"signature", "digest", "version", "attempt", "requester", "invitation",
		"device", "epoch", "ad", "root", "target", "audience", "recipient",
	} {
		t.Run(field, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishment(t, true)
			try.To(f.accept(f.raw, f.local.handle))
			_, raw, _ := f.records(t)
			var history acceptedRecord
			try.To(wire.UnmarshalCanonical(&history, raw))
			var response SignedAccepted
			try.To(wire.UnmarshalCanonical(&response, history.Response))
			p := &response.Payload.Binding
			switch field {
			case "signature":
				response.Signature[0] ^= 1
			case "digest":
				response.Payload.RequestDigest[0] ^= 1
			case "version":
				response.Payload.Version++
			case "attempt":
				p.AttemptID[0] ^= 1
			case "requester":
				p.Requester = f.root.public
			case "invitation":
				p.InvitationID[0] ^= 1
			case "device":
				p.Device = f.root.public
			case "epoch":
				p.Epoch++
			case "ad":
				p.Ad[0] ^= 1
			case "root":
				p.Root = f.peer.public
			case "target":
				p.Target = f.peer.public
			case "audience":
				p.Audience, p.Recipient = InvitationAny, nil
			case "recipient":
				p.Recipient = f.root.public
			}
			if field != "signature" {
				// A valid Bob signature over conflicting authenticated contents
				// must still fail exact-binding/digest validation. Prepare it
				// outside the transaction, just like production signing.
				digest := key.HashTagged(AcceptedPurpose,
					try.To1(wire.Marshal(response.Payload)))
				response.Signature = try.To1(f.local.handle.Sign(digest[:]))
			}
			history.Response = try.To1(wire.Marshal(response))
			try.To(f.f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				return tx.Put(
					[]byte(acceptedKey),
					try.To1(wire.Marshal(history)),
				)
			}))
			f.f.unchanged(t, func() {
				response, err := f.reply(f.raw, f.local.handle)
				assert.Equal(err, ErrEstablishment)
				assert.SNil(response)
			})
		})
	}
}
