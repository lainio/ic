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

func historicalClaim(t *testing.T, root key.Public, peer key.Handle) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	subject := key.Public(try.To1(peer.CBORPublicKey()))
	ad := claimBytes(t, root, subject)
	return changeClaim(t, ad, func(c *Current) {
		c.Payload.ExpiresUnixNano = int64(TTL) // Long expired, but still historical evidence.
		resignAd(t, c, peer)
	})
}

func rawVerified(t *testing.T, v *storage.Vault) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	var raw []byte
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		raw, _ = try.To2(tx.Get([]byte(verifiedClaimsKey)))
		return nil
	}))
	return raw
}

func TestVerifiedCorruptionNeverReadsOrRepairs(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer, other := newSigner(t), newSigner(t), newSigner(t)
	ad := historicalClaim(t, root.public, peer.handle)
	good := verifiedClaims{Version: 1, Entries: []verifiedClaim{{Subject: peer.public, Ad: ad}}}
	raw := try.To1(wire.Marshal(good))
	cases := map[string][]byte{
		"empty": nil, "truncated": raw[:len(raw)-1], "trailing": append(bytes.Clone(raw), 0),
		"noncanonical": append([]byte{0x98, 2}, raw[1:]...), "oversized": make([]byte, maxVerifiedBytes+1),
		"map": {0xa0}, "inner ad is not a verified table": ad,
		"extra table field": try.To1(wire.Marshal([]any{1, good.Entries, "extra record"})),
		"extra slot":        try.To1(wire.Marshal([]any{1, []any{[]any{peer.public, ad, ad}}})),
		"missing ad":        try.To1(wire.Marshal([]any{1, []any{[]any{peer.public}}})),
	}
	for name, change := range map[string]func(*verifiedClaims){
		"version":         func(c *verifiedClaims) { c.Version = 2 },
		"empty entries":   func(c *verifiedClaims) { c.Entries = []verifiedClaim{} },
		"null entries":    func(c *verifiedClaims) { c.Entries = nil },
		"duplicate":       func(c *verifiedClaims) { c.Entries = append(c.Entries, c.Entries[0]) },
		"too many":        func(c *verifiedClaims) { c.Entries = slices.Repeat(c.Entries, maxVerifiedClaims+1) },
		"foreign subject": func(c *verifiedClaims) { c.Entries[0].Subject = other.public },
		"bad key":         func(c *verifiedClaims) { c.Entries[0].Subject = []byte{1} },
		"foreign Root":    func(c *verifiedClaims) { c.Entries[0].Ad = historicalClaim(t, other.public, peer.handle) },
		"malformed ad":    func(c *verifiedClaims) { c.Entries[0].Ad = []byte{0xff} },
		"forged signature": func(c *verifiedClaims) {
			c.Entries[0].Ad = changeClaim(t, ad, func(a *Current) { a.Signature = []byte{1} })
		},
		"mismatched signed payload": func(c *verifiedClaims) {
			c.Entries[0].Ad = changeClaim(t, ad, func(a *Current) { a.Payload.Token[0] ^= 1 })
		},
		"noncanonical inner": func(c *verifiedClaims) { c.Entries[0].Ad = append([]byte{0x98, 2}, ad[1:]...) },
		"wrong slot": func(c *verifiedClaims) {
			c.Entries[0].Ad = changeClaim(t, ad, func(a *Current) { a.Payload.Slot = 2; resignAd(t, a, peer.handle) })
		},
		"corrupt other subject": func(c *verifiedClaims) {
			c.Entries = append(c.Entries, verifiedClaim{Subject: other.public, Ad: []byte{0xff}})
			slices.SortFunc(c.Entries, func(a, b verifiedClaim) int { return bytes.Compare(a.Subject, b.Subject) })
		},
		"unsorted": func(c *verifiedClaims) {
			c.Entries = append(c.Entries, verifiedClaim{Subject: other.public, Ad: historicalClaim(t, root.public, other.handle)})
			slices.SortFunc(c.Entries, func(a, b verifiedClaim) int { return -bytes.Compare(a.Subject, b.Subject) })
		},
	} {
		var altered verifiedClaims
		try.To(wire.UnmarshalCanonical(&altered, raw))
		change(&altered)
		cases[name] = try.To1(wire.Marshal(altered))
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			try.To(f.vault.Update(func(tx storage.WriteTx) error { return tx.Put([]byte(verifiedClaimsKey), corrupt) }))
			f.lease.remaining = 0
			f.unchanged(t, func() {
				for _, subject := range []key.Public{peer.public, other.public} {
					got, found, err := ReadVerifiedClaim(f.vault, root.public, subject)
					assert.SNil(got)
					assert.ThatNot(found)
					assert.ErrorIs(err, ErrInvalidVerifiedClaims)
				}
				err := f.vault.Update(func(tx storage.WriteTx) error { return replaceVerifiedClaim(tx, root.public, peer.public, ad) })
				assert.ErrorIs(err, ErrInvalidVerifiedClaims)
			})
			assert.That(bytes.Equal(rawVerified(t, f.vault), corrupt))
		})
	}
}

func TestVerifiedNamespaceConflict(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer := newSigner(t), newSigner(t)
	ad := historicalClaim(t, root.public, peer.handle)
	f := newVault(t)
	try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.EnsureChild([]byte(verifiedClaimsKey)))
		return ns.Put([]byte("extra"), ad)
	}))
	f.unchanged(t, func() {
		got, found, err := ReadVerifiedClaim(f.vault, root.public, peer.public)
		assert.SNil(got)
		assert.ThatNot(found)
		assert.ErrorIs(err, storage.ErrConflict)
		assert.ErrorIs(f.vault.Update(func(tx storage.WriteTx) error {
			return replaceVerifiedClaim(tx, root.public, peer.public, ad)
		}), storage.ErrConflict)
	})
}

func TestVerifiedCapacityReplacementExpiryAndOwnership(t *testing.T) {
	defer assert.PushTester(t)()
	root := newSigner(t)
	f := newVault(t)
	want := make(map[string][]byte)
	var first key.Public
	var signer key.Handle
	for i := range maxVerifiedClaims {
		peer := key.New()
		subject := key.Public(try.To1(peer.CBORPublicKey()))
		ad := historicalClaim(t, root.public, peer)
		try.To(f.vault.Update(func(tx storage.WriteTx) error { return replaceVerifiedClaim(tx, root.public, subject, ad) }))
		want[string(subject)] = ad
		if i == 0 {
			first, signer = subject, peer
		}
	}
	f.unchanged(t, func() {
		peer := key.New()
		subject := key.Public(try.To1(peer.CBORPublicKey()))
		ad := historicalClaim(t, root.public, peer)
		err := f.vault.Update(func(tx storage.WriteTx) error { return replaceVerifiedClaim(tx, root.public, subject, ad) })
		assert.ErrorIs(err, ErrVerifiedClaimsFull)
	})
	// Replacing one subject at capacity leaves all other historical bytes alone.
	replacement := changeClaim(t, want[string(first)], func(c *Current) { c.Payload.Token[0] ^= 1; resignAd(t, c, signer) })
	try.To(f.vault.Update(func(tx storage.WriteTx) error { return replaceVerifiedClaim(tx, root.public, first, replacement) }))
	want[string(first)] = replacement
	try.To1(ReceiveClaim(f.vault, root.public, first, claimBytes(t, root.public, first)))
	f.lease.remaining = 0
	f.unchanged(t, func() {
		for subject, ad := range want {
			got, found := try.To2(ReadVerifiedClaim(f.vault, root.public, key.Public(subject)))
			assert.That(found)
			assert.DeepEqual(got, ad)
			clear(got)
		}
	})
	f.Reopen(t)
	f.unchanged(t, func() {
		got, found := try.To2(ReadVerifiedClaim(f.vault, root.public, first))
		assert.That(found)
		assert.DeepEqual(got, replacement)
		assert.ErrorIs(f.vault.Update(func(tx storage.WriteTx) error {
			return replaceVerifiedClaim(tx, root.public, first, replacement)
		}), errVerifiedClaimUnchanged)
	})
}

func TestVerifiedRollbackAfterSeal(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer := newSigner(t), newSigner(t)
	f := newVault(t)
	ad := historicalClaim(t, root.public, peer.handle)
	try.To(f.vault.Update(func(tx storage.WriteTx) error { return replaceVerifiedClaim(tx, root.public, peer.public, ad) }))
	replacement := changeClaim(t, ad, func(c *Current) { c.Payload.Token[0] ^= 1; resignAd(t, c, peer.handle) })
	cause := errors.New("rollback after seal")
	before, remaining := try.To1(os.ReadFile(f.path)), f.lease.remaining
	err := f.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(replaceVerifiedClaim(tx, root.public, peer.public, replacement))
		return cause
	})
	assert.ErrorIs(err, cause)
	assert.Equal(f.lease.remaining, remaining-1)
	assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
	got, found := try.To2(ReadVerifiedClaim(f.vault, root.public, peer.public))
	assert.That(found)
	assert.DeepEqual(got, ad)
}
