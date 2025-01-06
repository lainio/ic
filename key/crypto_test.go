// Package crypto implemets need helpers for invitation chain use. We haven't
// yet thought about interface or other stuff. We just build the minimum for the
// PoC.
package key

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestNewPublicCBOR(t *testing.T) {
	defer assert.PushTester(t)()

	kHand := NewHand()
	pk := try.To1(kHand.Handle.CBORPublicKey())
	str := kHand.Info.PKString()
	msg := []byte("here we are and testing")
	sig := try.To1(kHand.Sign(msg))

	type args struct {
		s   string
		msg []byte
		sig Signature
	}
	tests := []struct {
		name   string
		args   args
		wantPk PublicCBOR
	}{
		{"success", args{str, msg, sig}, pk},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Skip("not needed")

			defer assert.PushTester(t)()

			gotPk := NewPublicCBOR(tt.args.s)
			assert.That(gotPk.Equal(tt.wantPk))

			verified := tt.args.sig.Verify(gotPk, tt.args.msg)
			assert.That(verified)
		})
	}
}

func BenchmarkNewPublicCBOR(b *testing.B) {
	run := func(n int) {
		defer assert.PushTester(b)()

		kHand := NewHand()
		str := kHand.Info.PKString()
		//msg := []byte("here we are and testing")
		//sig := Signature(try.To1(kHand.Sign(msg)))

		gotPk := NewPublicCBOR(str)
		assert.That(
			gotPk.Equal(try.To1(kHand.CBORPublicKey())),
			"run %d", n,
		)

		//verified := sig.Verify(gotPk, msg)
		//verified := sig.Verify(try.To1(kHand.CBORPublicKey()), msg)
		//assert.That(verified, "run %d", n)
	}

	for n := 0; n < b.N; n++ {
		run(n)
	}
}
