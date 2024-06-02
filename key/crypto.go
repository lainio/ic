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

// TODO: from where we get the key! In the server this is ordinary secret. We
// can still think this when we have our UI app ready.
// TODO: how we should handle and store these keys! this solves so much!
var myStore = enclave.New("aa5cb4215d4fc1f9912f094a6fdc1f263c124854f59b8b889b50ac2f32856844")

type Public = []byte
type ID = []byte

// Hand is hand holding a full [Handle] or key [Info]. This structure allows us
// to abstract easily ours and theirs.
type Hand struct {
	Handle // is interface, so it can be nil
	*Info  // can be nil, that's why we need pointer
}

func NewHand(h Handle) Hand {
	info := InfoFromHandle(h)
	return Hand{Handle: h, Info: &info}
}

func NewHandInfo(i *Info) Hand {
	return Hand{Info: i}
}

func (h Hand) Valid() bool {
	return h.Handle != nil || h.Info != nil
}

// Handle is key.Handle that has secure access to private key as well. But
// private key is always hided. And that's why we have only Handle to key pair.
//
// NOTE: Handle is stateless as well, which means that we don't need to persist
// them, i.e., if we have created the Handle, we can use it thru its ID.
//
// Handle also allows us decided what kind of key storage we are using and it
// simplifies key management A LOT.
type Handle = enclave.KeyHandle

// Info is key.Info that binds and transport both key's ID and its public key
// together.
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

func New() Handle {
	return try.To1(myStore.NewKeyHandle())
}

func NewFromInfo(info Info) Handle {
	yes, kh := myStore.IsKeyHandle(info.ID)
	assert.That(yes)
	return kh
}

func RandInfo(n int) Info {
	return Info{
		ID:     RandSlice(32),
		Public: RandSlice(32),
	}
}

func RandSlice(n int) []byte {
	b := make([]byte, n)
	r := try.To1(rand.Read(b))
	assert.Equal(r, n)
	return b
}

type Signature = []byte
type Hash = []byte // TODO: [32]byte! we are using SHA256

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
