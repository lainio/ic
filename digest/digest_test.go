package digest

import (
	"reflect"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/key"
)

var (
	hand = key.NewHand()
	d    = Digest{
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
		{"simple", args{d.Base58()}, d},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotDi := NewFromString(tt.args.s); !reflect.DeepEqual(gotDi, tt.wantDi) {
				t.Errorf("NewFromString() = %v, want %v", gotDi, tt.wantDi)
			}
		})
	}
}

func TestDigestDigest(t *testing.T) {
	defer assert.PushTester(t)()

	digest := d.Digest()
	digestStr := string(digest)
	assert.Len(digestStr, key.PKLen+1+key.PKLen+2+1+key.PKLen+2)

	s := digest.PKStringIDK()
	assert.Len(s, key.PKLen)

	for i := range 2 {
		pkstr, hop := digest.PKDigest(i)
		assert.Len(pkstr, key.PKLen)
		assert.Equal(int(hop), i)
	}
}
