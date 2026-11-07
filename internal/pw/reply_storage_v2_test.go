package pw

import (
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func TestBobReplyV2RejectsStoredConflicts(t *testing.T) {
	for _, name := range []string{invitationKey, acceptedKey, heldKey} {
		for _, mode := range []string{"absent", "namespace", "malformed",
			"version", "noncanonical", "conflict", "extra", "oversize"} {
			t.Run(name+"/"+mode, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, true)
				saved := try.To1(f.saveV2(aliceServiceOrigin))
				try.To(f.acceptV2(saved.request, f.local.handle))
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
					case "extra":
						raw = append(raw, 0)
					case "oversize":
						raw = make([]byte, 2*MaxEstablishmentBytes+17)
					case "noncanonical":
						raw = append([]byte{0x98, raw[0] & 0x1f}, raw[1:]...)
					default:
						switch name {
						case invitationKey:
							var row Invitation
							try.To(wire.UnmarshalCanonical(&row, raw))
							if mode == "version" {
								row.Version = 2 // Invitation storage remains v1.
							} else {
								row.ID[0] ^= 1
							}
							raw = try.To1(wire.Marshal(row))
						case acceptedKey:
							var row acceptedRecord
							try.To(wire.UnmarshalCanonical(&row, raw))
							if mode == "version" {
								row.Version = 1
							} else {
								row.Request[len(row.Request)-1] ^= 1
							}
							raw = try.To1(wire.Marshal(row))
						case heldKey:
							var row heldRecord
							try.To(wire.UnmarshalCanonical(&row, raw))
							if mode == "version" {
								row.Version = 1
							} else {
								row.RequestDigest[0] ^= 1
							}
							raw = try.To1(wire.Marshal(row))
						}
					}
					return tx.Put([]byte(name), raw)
				}))
				f.f.unchanged(t, func() {
					response, err := f.replyV2(saved.request, f.local.handle)
					assert.Equal(err, ErrEstablishment)
					assert.SNil(response)
				})
			})
		}
	}
}
