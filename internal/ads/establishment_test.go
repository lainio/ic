package ads

import (
	"bytes"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestRetainedEstablishmentAdExpiry(t *testing.T) {
	defer assert.PushTester(t)()
	f := newVault(t)
	root, peer := newSigner(t), newSigner(t)
	ad := historicalClaim(t, root.public, peer.handle)
	try.To1(ReceiveClaim(f.vault, root.public, peer.public, ad))
	try.To(f.vault.Update(func(tx storage.WriteTx) error {
		return replaceVerifiedClaim(tx, root.public, peer.public, ad)
	}))
	f.lease.remaining = 0
	for _, reopened := range []bool{false, true} {
		if reopened {
			f.Reopen(t)
		}
		for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Hour} {
			f.unchanged(t, func() {
				try.To(f.vault.View(func(tx storage.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					got := try.To1(ReadRetainedEstablishmentAdInTx(tx,
						root.public, peer.public))
					assert.DeepEqual(got, ad)
					clear(got) // Returned bytes cannot alter retained evidence.
					assert.DeepEqual(try.To1(ReadRetainedEstablishmentAdInTx(tx,
						root.public, peer.public)), ad)
					return nil
				}))
				err := f.vault.View(func(tx storage.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					got := try.To1(ReadEstablishmentAdInTx(tx,
						root.public, peer.public, time.Unix(0, int64(TTL)+int64(offset))))
					assert.DeepEqual(got, ad)
					return nil
				})
				if offset < 0 {
					assert.NoError(err)
				} else {
					assert.ErrorIs(err, ErrInvalidRecord)
				}
			})
		}
	}
}

func TestRetainedEstablishmentAdEvidence(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer, other := newSigner(t), newSigner(t), newSigner(t)
	ad := historicalClaim(t, root.public, peer.handle)
	replacement := changeClaim(t, ad, func(c *Current) {
		c.Payload.Token[0] ^= 1
		resignAd(t, c, peer.handle)
	})
	for _, fault := range []string{"missing received", "missing verified",
		"changed received", "changed verified", "signature", "malformed received",
		"malformed verified", "other corrupt received", "other corrupt verified",
		"received namespace", "verified namespace", "root", "subject"} {
		t.Run(fault, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			try.To1(ReceiveClaim(f.vault, root.public, peer.public, ad))
			try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				try.To(replaceVerifiedClaim(tx, root.public, peer.public, ad))
				for _, collection := range []string{"received", "verified"} {
					name := []byte(collection + "-ad-claims-v1")
					switch fault {
					case "missing " + collection:
						try.To(tx.Delete(name))
					case "changed " + collection, "signature":
						raw := replacement
						if fault == "signature" {
							raw = changeClaim(t, ad, func(c *Current) {
								c.Signature[0] ^= 1
							})
						}
						try.To(tx.Put(name, try.To1(wire.Marshal([]any{uint8(1),
							[]any{[]any{peer.public, raw}}}))))
					case "malformed " + collection:
						try.To(tx.Put(name, []byte{0xff}))
					case "other corrupt " + collection:
						// The requested subject is sound, but the whole table must
						// validate, including entries beyond the requested subject.
						claims := []any{[]any{peer.public, ad},
							[]any{other.public, []byte{0xff}}}
						if bytes.Compare(peer.public, other.public) > 0 {
							claims[0], claims[1] = claims[1], claims[0]
						}
						try.To(tx.Put(name,
							try.To1(wire.Marshal([]any{uint8(1), claims}))))
					case collection + " namespace":
						try.To(tx.Delete(name))
						try.To1(tx.EnsureChild(name))
					}
				}
				return nil
			}))
			r, subject := root.public, peer.public
			switch fault {
			case "root":
				r = key.Public{1}
			case "subject":
				subject = key.Public{1}
			}
			f.lease.remaining = 0
			f.unchanged(t, func() {
				for _, retained := range []bool{false, true} {
					var got []byte
					err := f.vault.View(func(tx storage.ReadTx) (err error) {
						defer err2.Handle(&err, nil)
						if retained {
							got = try.To1(ReadRetainedEstablishmentAdInTx(tx, r, subject))
						} else {
							got = try.To1(ReadEstablishmentAdInTx(tx, r, subject,
								time.Unix(0, int64(TTL)-1)))
						}
						return nil
					})
					assert.Error(err)
					assert.SNil(got)
				}
			})
		})
	}
}
