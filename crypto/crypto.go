// Package crypto implements need helpers for invitation chain use. We haven't
// yet thought about interface or other stuff. We just build the minimum for the
// PoC.
package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"

	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/findy-network/findy-agent-auth/acator/enclave"
	"github.com/fxamacker/cbor/v2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var myStore = enclave.New("aa5cb4215d4fc1f9912f094a6fdc1f263c124854f59b8b889b50ac2f32856844") // TODO: from where we get the key!

type PubKey = []byte

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
	//return ed25519.Verify(pubK, msg, sig)
}

// TODO: we need a KeyHandle
// TODO: this is a problem now. We need a design to separate Priv and PubKeys:
// - let's try to find where privkey is in use and just separate them to API
// -
type Key = enclave.KeyHandle

func NewKey() Key {
	return try.To1(myStore.NewKeyHandle())
}

// KeyOld is a struct for full key.
type KeyOld struct {
	PrivKey []byte
	PubKey
}

func NewKeyB() KeyOld {
	pub, priv := try.To2(ed25519.GenerateKey(nil))
	return KeyOld{PrivKey: priv, PubKey: pub}
}

func (k KeyOld) PubKeyEqual(pubKey PubKey) bool {
	return EqualBytes(k.PubKey, pubKey)
}

func (k KeyOld) Sign(h []byte) Signature {
	return ed25519.Sign(k.PrivKey, h)
}

func (k KeyOld) VerifySign(msg []byte, sig Signature) bool {
	return VerifySign(k.PubKey, msg, sig)
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
