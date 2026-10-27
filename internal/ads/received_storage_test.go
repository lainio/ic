package ads

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestReceivedClaimCorruptStorageNeverReadsOrRepairs(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer, other := newSigner(t), newSigner(t), newSigner(t)
	ad := claimBytes(t, root.public, peer.public)
	good := receivedClaims{Version: 1, Entries: []receivedClaim{{Subject: peer.public, Ad: ad}}}
	raw := try.To1(wire.Marshal(good))
	cases := map[string][]byte{
		"empty record": nil, "truncated": raw[:len(raw)-1],
		"trailing":              append(bytes.Clone(raw), 0),
		"noncanonical":          append([]byte{0x98, 0x02}, raw[1:]...),
		"oversize":              make([]byte, maxReceivedBytes+1),
		"inner ad is not table": ad, "map": {0xa0},
		"extra table field":   try.To1(wire.Marshal([]any{1, good.Entries, "slot-2"})),
		"extra slot field":    try.To1(wire.Marshal([]any{1, []any{[]any{peer.public, ad, ad}}})),
		"missing entry field": try.To1(wire.Marshal([]any{1, []any{[]any{peer.public}}})),
	}
	for name, change := range map[string]func(*receivedClaims){
		"wrong version":         func(c *receivedClaims) { c.Version = 2 },
		"empty table":           func(c *receivedClaims) { c.Entries = []receivedClaim{} },
		"null entries":          func(c *receivedClaims) { c.Entries = nil },
		"duplicate subject":     func(c *receivedClaims) { c.Entries = append(c.Entries, c.Entries[0]) },
		"too many subjects":     func(c *receivedClaims) { c.Entries = slices.Repeat(c.Entries, maxReceivedClaims+1) },
		"bad subject binding":   func(c *receivedClaims) { c.Entries[0].Subject = other.public },
		"truncated subject key": func(c *receivedClaims) { c.Entries[0].Subject = peer.public[:14] },
		"stray slot key":        func(c *receivedClaims) { c.Entries[0].Subject = []byte("slot-2") },
		"malformed inner ad":    func(c *receivedClaims) { c.Entries[0].Ad = []byte{0xff} },
		"wrong Root binding":    func(c *receivedClaims) { c.Entries[0].Ad = claimBytes(t, other.public, peer.public) },
		"wrong slot": func(c *receivedClaims) {
			c.Entries[0].Ad = changeClaim(t, ad, func(a *Current) { a.Payload.Slot = 2 })
		},
		"unsorted subjects": func(c *receivedClaims) {
			c.Entries = append(c.Entries, receivedClaim{Subject: other.public, Ad: claimBytes(t, root.public, other.public)})
			slices.SortFunc(c.Entries, func(a, b receivedClaim) int { return -bytes.Compare(a.Subject, b.Subject) })
		},
		"corrupt other subject": func(c *receivedClaims) {
			c.Entries = append(c.Entries, receivedClaim{Subject: other.public, Ad: []byte{0xff}})
			slices.SortFunc(c.Entries, func(a, b receivedClaim) int { return bytes.Compare(a.Subject, b.Subject) })
		},
	} {
		var changed receivedClaims
		try.To(wire.UnmarshalCanonical(&changed, raw))
		change(&changed)
		cases[name] = try.To1(wire.Marshal(changed))
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			assert.That(try.To1(ReceiveClaim(f.vault, root.public, peer.public, ad)))
			try.To(f.vault.Update(func(tx storage.WriteTx) error {
				return tx.Put([]byte(receivedClaimsKey), corrupt)
			}))
			assertCorruptClaims(t, f, root.public, peer.public, other.public, ad, ErrInvalidReceivedClaims)
			assert.That(bytes.Equal(rawClaims(t, f.vault), corrupt))
		})
	}
}

func assertCorruptClaims(t *testing.T, f vaultFixture, root, peer, other key.Public,
	ad []byte, wantErr error,
) {
	t.Helper()
	defer assert.PushTester(t)()
	f.lease.remaining = 0
	f.unchanged(t, func() {
		for _, subject := range []key.Public{peer, other} {
			got, found, err := ReadReceivedClaim(f.vault, root, subject)
			assert.SNil(got)
			assert.ThatNot(found)
			assert.ErrorIs(err, wantErr)
		}
		for _, candidate := range [][]byte{ad, changeClaim(t, ad, func(c *Current) { c.Payload.Token[0] ^= 1 })} {
			changed, err := ReceiveClaim(f.vault, root, peer, candidate)
			assert.ThatNot(changed)
			assert.ErrorIs(err, wantErr)
		}
	})
}

func TestReceivedClaimRejectsNamespaceInsteadOfRecord(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer, other := newSigner(t), newSigner(t), newSigner(t)
	ad := claimBytes(t, root.public, peer.public)
	for _, name := range []string{"empty", "subject record", "slot record", "stray child"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(tx.EnsureChild([]byte(receivedClaimsKey)))
				switch name {
				case "subject record":
					try.To(ns.Put(peer.public, ad))
				case "slot record":
					try.To(ns.Put([]byte("slot-2"), ad))
				case "stray child":
					try.To1(ns.EnsureChild([]byte("unexpected")))
				}
				return nil
			}))
			assertCorruptClaims(t, f, root.public, peer.public, other.public, ad, storage.ErrConflict)
		})
	}
}

func TestReceivedClaimFailedUpdatesPreservePreviousBytes(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer := newSigner(t), newSigner(t)
	ad := claimBytes(t, root.public, peer.public)
	replacement := changeClaim(t, ad, func(c *Current) { c.Signature = []byte{2} })
	cause := errors.New("injected claim write failure")
	for _, existing := range []bool{false, true} {
		for _, failure := range []string{"exhaustion", "seal failure", "rollback after Put"} {
			t.Run(failure+map[bool]string{false: "/absent", true: "/present"}[existing], func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newVault(t)
				var want []byte
				if existing {
					assert.That(try.To1(ReceiveClaim(f.vault, root.public, peer.public, ad)))
					want = ad
				}
				if failure == "rollback after Put" {
					before, remaining := try.To1(os.ReadFile(f.path)), f.lease.remaining
					err := f.vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						try.To(replaceReceivedClaim(tx, root.public, peer.public, replacement))
						return cause
					})
					assert.ErrorIs(err, cause)
					assert.Equal(f.lease.remaining, remaining-1) // Failed writes do not refund usage.
					assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
				} else {
					wantErr := cause
					if failure == "exhaustion" {
						f.lease.remaining = 0
						wantErr = storage.ErrKeyUsageExhausted
					} else {
						f.lease.sealErr = cause
					}
					f.unchanged(t, func() {
						changed, err := ReceiveClaim(f.vault, root.public, peer.public, replacement)
						assert.ThatNot(changed)
						assert.ErrorIs(err, wantErr)
					})
				}
				f.unchanged(t, func() { readClaim(t, f.vault, root.public, peer.public, want) })
			})
		}
	}
}

func TestReceivedClaimReopenOwnershipAndZeroEncryptions(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer := newSigner(t), newSigner(t)
	f := newVault(t)
	ad := claimBytes(t, root.public, peer.public)
	r, subject, input := bytes.Clone(root.public), bytes.Clone(peer.public), bytes.Clone(ad)
	assert.That(try.To1(ReceiveClaim(f.vault, r, subject, input)))
	clear(r)
	clear(subject)
	clear(input)
	try.To(f.db.Close())
	f.lease.remaining = 0
	f.db = try.To1(storage.OpenBolt(f.path))
	t.Cleanup(func() { assert.NoError(f.db.Close()) })
	f.vault = try.To1(f.db.OpenVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, f.lease))
	f.unchanged(t, func() {
		readClaim(t, f.vault, root.public, peer.public, ad)
		got, found := try.To2(ReadReceivedClaim(f.vault, root.public, peer.public))
		assert.That(found)
		clear(got)
		readClaim(t, f.vault, root.public, peer.public, ad)
		assert.ThatNot(try.To1(ReceiveClaim(f.vault, root.public, peer.public, ad)))
		candidate := changeClaim(t, ad, func(c *Current) { c.Payload.Token[0] ^= 1 })
		changed, err := ReceiveClaim(f.vault, root.public, peer.public, candidate)
		assert.ThatNot(changed)
		assert.ErrorIs(err, storage.ErrKeyUsageExhausted)
		readClaim(t, f.vault, root.public, peer.public, ad)
		assert.Equal(len(try.To1(records(f.vault, claimBoundaryNames...))), 0)
	})
	try.To(f.vault.Close())
	f.unchanged(t, func() {
		changed, err := ReceiveClaim(f.vault, root.public, peer.public, ad)
		assert.ThatNot(changed)
		assert.ErrorIs(err, storage.ErrVaultClosed)
		got, found, err := ReadReceivedClaim(f.vault, root.public, peer.public)
		assert.SNil(got)
		assert.ThatNot(found)
		assert.ErrorIs(err, storage.ErrVaultClosed)
	})
}
