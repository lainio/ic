package chain

import (
	"testing"

	"github.com/lainio/err2/assert"
)

func TestNewVerifyBlock(t *testing.T) {
	type args struct {
		pinCode int
	}
	tests := []struct {
		name string
		args args
		want int // length of Block
	}{
		{"nil pincode", args{0}, 294},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//t.Skip("Not until Block is about ready again")

			defer assert.PushTester(t)()

			cb, _ := NewVerifyBlock(tt.args.pinCode)
			assert.SLen(cb.Bytes(), tt.want)
		})
	}
}
