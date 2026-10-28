package ads_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

func TestVerifyRemoteFullHistoricalCollection(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRemote(t)
	entries := make([][]any, 32)
	for i := range entries {
		peer := remoteKey(t)
		ad := mutateRemoteAd(t, f.ad, func(c *ads.Current) {
			c.Payload.Node, c.Payload.Device = peer.public, peer.public
			c.Payload.ExpiresUnixNano = int64(ads.TTL)
		}, peer.handle)
		entries[i] = []any{peer.public, ad}
	}
	slices.SortFunc(entries, func(a, b []any) int { return bytes.Compare(a[0].(key.Public), b[0].(key.Public)) })
	table := try.To1(wire.Marshal([]any{1, entries}))
	setRemoteRecord(t, f.receiver.Vault(), verifiedKey, table)
	f.receiver.Unchanged(t, func() {
		changed, err := f.verify(t.Context())
		assert.ThatNot(changed)
		assert.ErrorIs(err, ads.ErrVerifiedClaimsFull)
		f.readVerified(t, nil)
		for _, entry := range entries {
			got, found := try.To2(ads.ReadVerifiedClaim(f.receiver.Vault(), f.root.public, entry[0].(key.Public)))
			assert.That(found)
			assert.DeepEqual(got, entry[1].([]byte))
		}
	})
	assert.Equal(f.calls.Load(), int32(1))
}

func TestVerifyRemoteCorruptVerifiedCollectionNeverRepaired(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRemote(t)
	good := try.To1(wire.Marshal([]any{1, []any{[]any{f.peer.public, f.ad}}}))
	cases := map[string][]byte{
		"empty": nil, "truncated": good[:len(good)-1], "noncanonical": append([]byte{0x98, 2}, good[1:]...),
		"extra record": try.To1(wire.Marshal([]any{1, []any{[]any{f.peer.public, f.ad}}, "extra"})),
		"foreign key":  try.To1(wire.Marshal([]any{1, []any{[]any{f.reader.public, f.ad}}})),
		"mismatched signature": try.To1(wire.Marshal([]any{1, []any{[]any{f.peer.public,
			mutateRemoteAd(t, f.ad, func(c *ads.Current) { c.Signature = []byte{1} }, nil)}}})),
	}
	for name, corrupt := range cases {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			setRemoteRecord(t, f.receiver.Vault(), verifiedKey, corrupt)
			before := try.To1(remoteState(f.receiver.Vault(), false))
			f.receiver.Unchanged(t, func() {
				changed, err := f.verify(t.Context())
				assert.ThatNot(changed)
				assert.ErrorIs(err, ads.ErrInvalidVerifiedClaims)
				got, found, err := ads.ReadVerifiedClaim(f.receiver.Vault(), f.root.public, f.peer.public)
				assert.SNil(got)
				assert.ThatNot(found)
				assert.ErrorIs(err, ads.ErrInvalidVerifiedClaims)
				assert.DeepEqual(try.To1(remoteState(f.receiver.Vault(), false)), before)
			})
		})
	}
}
