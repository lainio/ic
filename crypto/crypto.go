package crypto

import (
	"crypto/ed25519"

	"github.com/lainio/err2"
)

type PubKey = []byte
type Key struct {
	PrivKey []byte
	PubKey
}

func NewKey() *Key {
	pub, priv, err := ed25519.GenerateKey(nil)
	err2.Check(err)
	return &Key{PrivKey: priv, PubKey: pub}
}

func (k Key) PubKeyEqual(pubKey PubKey) bool {
	return byteEqual(k.PubKey, pubKey)
}

func (k Key) Sign(h []byte) Signature {
	return ed25519.Sign(k.PrivKey, h)
}

func (k Key) VerifySign(msg []byte, sig Signature) bool {
	return ed25519.Verify(k.PubKey, msg, sig)
}

type Signature = []byte

func byteEqual(a, b []byte) bool {
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
