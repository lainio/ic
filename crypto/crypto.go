// Package crypto implements need helpers for invitation chain use. We haven't
// yet thought about interface or other stuff. We just build the minimum for the
// PoC.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/findy-network/findy-agent-auth/acator/enclave"
	"github.com/fxamacker/cbor/v2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

// TODO: from where we get the key!
var myStore = enclave.New("aa5cb4215d4fc1f9912f094a6fdc1f263c124854f59b8b889b50ac2f32856844")

type PubKey = []byte
type ID = []byte

func VerifySign(pubKey PubKey, msg []byte, sig Signature) bool {
	var pubK webauthncose.EC2PublicKeyData
	try.To(cbor.Unmarshal(pubKey, &pubK))

	hash := crypto.SHA256.New()
	try.To1(hash.Write(msg))

	pk := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(pubK.XCoord),
		Y:     big.NewInt(0).SetBytes(pubK.YCoord),
	}

	return ecdsa.VerifyASN1(pk, hash.Sum(nil), sig)
}

type Key = enclave.KeyHandle

func NewKey() Key {
	return try.To1(myStore.NewKeyHandle())
}

func RandSlice(n int) []byte {
	b := make([]byte, n)
	r := try.To1(rand.Read(b))
	assert.Equal(r, n)
	return b
}

type Signature = []byte

func EqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
