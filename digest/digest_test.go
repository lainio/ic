package digest

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/key"
)

var (
	hand = key.NewHand()

	testDigest = Digest{
		IDK: hand.Public,
		Roots: []RootInfo{
			{
				IDK:  hand.Public,
				Hops: 0, // value is used as testing index as well!!!
			},
			{
				IDK:  hand.Public,
				Hops: 1, // value is used as testing index as well!!!
			},
		},
	}
)

func TestNewFromString(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name   string
		args   args
		wantDi Digest
	}{
		{"simple", args{testDigest.Base58()}, testDigest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			gotDi := NewFromString(tt.args.s)
			assert.DeepEqual(gotDi, testDigest)
			assert.ThatNot(gotDi.EmptyRoot())
		})
	}
}

func TestDigestDigest(t *testing.T) {
	defer assert.PushTester(t)()

	digest := testDigest.Digest()
	digestStr := string(digest)
	assert.Len(digestStr, key.PKLen+1+key.PKLen+2+1+key.PKLen+2)

	s := digest.PKStringIDK()
	assert.Len(s, key.PKLen)

	ref := digest.Build()
	for i := range 2 {
		root := ref.PKDigest(i)
		pkstr, hop := root.PKStringIDK, root.Hop
		assert.Len(pkstr, key.PKLen)
		assert.Equal(int(hop), i)
	}
}

func TestDigestV2(t *testing.T) {
	defer assert.PushTester(t)()

	dig1 := "Y8BuDe2owZEoJL:TJtNVsFBQBynnV.1:TtAH5vqJCt92CQ.1:UvgVsZVianpbQP.1"
	dig2 := "XxQiDfBTbtHCWe:UvgVsZVianpbQP.1:VcbUYNGZYvBPn5.1:XtfNVtLjehn5cu.1"
	dig3 := "Ywxfen9vBSycH3:UMbgKVuafnPZoj.1"
	dig4 := "UZBViGmKMehipP:UZBViGmKMehipP.0"

	digest1 := DigestV2(dig1).Build()
	digest2 := DigestV2(dig2).Build()
	digest3 := DigestV2(dig3).Build()
	digest4 := DigestV2(dig4).Build()

	isEmptyRoot := digest4.EmptyRoot()
	assert.That(isEmptyRoot)
	isEmptyRoot = digest1.EmptyRoot()
	assert.ThatNot(isEmptyRoot)
	isEmptyRoot = digest3.EmptyRoot()
	assert.ThatNot(isEmptyRoot)

	isWot := digest1.WoT(digest3)
	assert.ThatNot(isWot, "not common root")

	isWot = digest1.WoT(digest2)
	assert.That(isWot)

	isWot = digest1.WoT(digest1)
	assert.That(isWot)
}
