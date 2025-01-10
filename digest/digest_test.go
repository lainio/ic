package digest

import (
	"reflect"
	"testing"

	"github.com/lainio/ic/key"
)

func TestNewFromString(t *testing.T) {
	hand := key.NewHand()
	d := Digest{
		IDK:     hand.Public,
		RootIDK: hand.Public,
		Hops:    0,
	}

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
