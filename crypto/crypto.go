// Package crypto implements need helpers for invitation chain use. We haven't
// yet thought about interface or other stuff. We just build the minimum for the
// PoC.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

type PubKey = []byte

func VerifySign(pubKey PubKey, msg []byte, sig Signature) bool {
	return ed25519.Verify(pubKey, msg, sig)
}

// TODO: we need a KeyHandle

// Key is a struct for full key.
type Key struct {
	PrivKey []byte
	PubKey
}

func NewKey() Key {
	pub, priv := try.To2(ed25519.GenerateKey(nil))
	return Key{PrivKey: priv, PubKey: pub}
}

func (k Key) PubKeyEqual(pubKey PubKey) bool {
	return EqualBytes(k.PubKey, pubKey)
}

func (k Key) Sign(h []byte) Signature {
	return ed25519.Sign(k.PrivKey, h)
}

func (k Key) VerifySign(msg []byte, sig Signature) bool {
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
