// Package crypto implements need helpers for invitation chain use. We haven't
// yet thought about interface or other stuff. We just build the minimum for the
// PoC.
package key

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

type Public = []byte
type ID = []byte

// Handle is key.Handle that has secure access to private key as well. But
// private key is always hided. And that's why we have only Handle to key pair.
type Handle = enclave.KeyHandle

// Info is key.Info that binds and transport both key's ID and its public key
// together. TODO: start to use this in Chain?
type Info struct {
	ID
	Public
}

func InfoFromHandle(h Handle) Info {
	pubK := try.To1(h.CBORPublicKey())
	return Info{ID: h.ID(), Public: pubK}
}

func VerifySign(pubKey Public, msg []byte, sig Signature) bool {
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

func NewKey() Handle {
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
