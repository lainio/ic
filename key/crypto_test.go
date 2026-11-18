// Package crypto implemets need helpers for invitation chain use. We haven't
// yet thought about interface or other stuff. We just build the minimum for the
// PoC.
package key

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/fxamacker/cbor/v2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestSignatureVerifyCoordinates(t *testing.T) {
	for _, fixture := range []struct {
		name   string
		scalar uint16
	}{
		{"short X", 379},
		{"short Y", 43},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			var raw [32]byte
			raw[30], raw[31] = byte(fixture.scalar>>8), byte(fixture.scalar)
			private := try.To1(
				ecdsa.ParseRawPrivateKey(elliptic.P256(), raw[:]),
			)
			point := try.To1(private.PublicKey.Bytes())
			x, y := point[1:33], point[33:]
			shortX := bytes.TrimLeft(x, "\x00")
			shortY := bytes.TrimLeft(y, "\x00")
			assert.That(len(shortX) < 32 || len(shortY) < 32)

			msg := []byte("verify coordinate encodings")
			hash := sha256.Sum256(msg)
			sig := Signature(
				try.To1(ecdsa.SignASN1(rand.Reader, private, hash[:])),
			)

			for _, tc := range []struct {
				name string
				x, y []byte
				want bool
			}{
				{"fixed width", x, y, true},
				{"minimal width", shortX, shortY, true},
				{
					"leading zeros",
					append([]byte{0}, x...), append([]byte{0}, y...), true,
				},
				{"oversized X", append([]byte{1}, x...), y, false},
				{"oversized Y", x, append([]byte{1}, y...), false},
				{"out of range X", bytes.Repeat([]byte{0xff}, 32), y, false},
				{"out of range Y", x, bytes.Repeat([]byte{0xff}, 32), false},
				{"missing X", nil, y, false},
				{"missing Y", x, nil, false},
				{"off curve", make([]byte, 32), make([]byte, 32), false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					defer assert.PushTester(t)()

					public := try.To1(
						cbor.Marshal(webauthncose.EC2PublicKeyData{
							PublicKeyData: webauthncose.PublicKeyData{
								KeyType:   2,
								Algorithm: -7,
							},
							Curve: 1, XCoord: tc.x, YCoord: tc.y,
						}),
					)
					assert.Equal(sig.Verify(public, msg), tc.want)
					assert.ThatNot(
						sig.Verify(public, []byte("changed message")),
					)
					assert.ThatNot(Signature{0}.Verify(public, msg))
				})
			}
		})
	}
}

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

			verified := tt.args.sig.Verify([]byte(gotPk), tt.args.msg)
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
