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
				Hops: 0,
			},
			{
				IDK:  hand.Public,
				Hops: 0,
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

	digestStr := d.Digest()
	assert.Len(digestStr, 14+1+14+2+1+14+2)
}
