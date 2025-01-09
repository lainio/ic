// Package crypto implemets need helpers for invitation chain use. We haven't
// yet thought about interface or other stuff. We just build the minimum for the
// PoC.
package key

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcutil/base58"
	"github.com/duo-labs/webauthn/protocol/webauthncose"
	"github.com/findy-network/findy-agent-auth/acator/enclave"
	"github.com/fxamacker/cbor/v2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

// TODO: from where we get the key! In the server this is ordinary secret. We
// can still think this when we have our UI app ready.
var Enclave enclave.Secure = enclave.New(
	"bad0bad1bad0bad1bad0bad1bad0bad1bad0bad1bad0bad1bad0bad1bad0bad1",
)

type Public []byte
type ID = []byte

// Hand is hand holding a key pair: a full [Handle] or key [Info]. This
// structure allows us to abstract key pairs to ours and theirs. We always have
// a key pair in our hand, and the Hand decides is it a full key pair that is
// capable signing or is it a public key pair only for challenging and
// verifying.
type Hand struct {
	Handle // is interface, so it can be nil already. TODO: should this be
	// Maybe/Option/... to make this Hand to real enum type?

	// can be nil, that's why we need pointer. TODO: better would be to have
	// private info and accessor to info or to use somekind of Maybe, Option
	// type. TODO: or should we make interface of Info, or then Hand?
	*Info
}

func NewHand() Hand {
	h := New()
	info := InfoFromHandle(h)
	return Hand{Handle: h, Info: &info}
}

// NewHandFromHandle creates a hand holding a [Handle] and [Info].
func NewHandFromHandle(h Handle) Hand {
	info := InfoFromHandle(h)
	return Hand{Handle: h, Info: &info}
}

// NewHandInfo creates a hand holding only a [Info].
func NewHandInfo(i *Info) Hand {
	return Hand{Info: i}
}

func (h Hand) ValidHandle() bool {
	return h.Handle != nil
}

func (h Hand) ValidInfo() bool {
	return h.Info != nil
}

func (h Hand) Valid() bool {
	return h.ValidHandle() || h.ValidInfo()
}

// PubKey returns pubkey. If error occurs it panics. See err2.Handle and Catch.
func (h Hand) PubKey() Public {
	if h.ValidInfo() {
		return h.Public
	}
	assert.That(h.ValidHandle())

	return try.To1(h.CBORPublicKey())
}

// Handle is key.Handle that has secure access to private key as well. But
// private key is always hided. And that's why we have only Handle to key pair.
//
// NOTE: Handle is stateless as well, which means that we don't need to persist
// them, i.e., if we have created the Handle, we can use it thru its ID.
//
// Handle also allows us decided what kind of key storage we are using and it
// simplifies key management A LOT.
//
// TODO: if this would not be an alias, we could have better API like kh.Info()
// TODO: if this would not be an alias, we could have better API like kh.Info()
// TODO: if this would not be an alias, we could have better API like kh.Info()
type Handle = enclave.KeyHandle

// Info is key.Info that binds and transport both key's ID and its public key
// together. Info is like a public version of key pair.
type Info struct {
	ID     // The key ID
	Public // The Public Key
}

const (
	byteCount       = 8
	publicByteCount = 77
	prefixLenOfCBOR = 14
)

func (i Info) String() string {
	id := base58.Encode(i.ID[:byteCount])
	pk := base58.Encode(i.Public[publicByteCount-byteCount:])
	//id := hex.EncodeToString(i.ID[:byteCount])
	//pk := hex.EncodeToString(i.Public[publicByteCount-byteCount:])

	return fmt.Sprintf("ID: '%v', Public: '%v'", id, pk)
}

func (i Info) PKString() string {
	pk := base58.Encode(i.Public)
	return pk[prefixLenOfCBOR : 2*prefixLenOfCBOR]
}

func InfoFromHandle(h Handle) Info {
	pubK := try.To1(h.CBORPublicKey())
	return Info{ID: h.ID(), Public: pubK}
}

// New creates a new [Handle] by using current [Enclave].
func New() Handle {
	return try.To1(Enclave.NewKeyHandle())
}

func NewFromInfo(info Info) Handle {
	yes, kh := Enclave.IsKeyHandle(info.ID)
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

type Signature []byte

func (sig Signature) Verify(pubKey Public, msg []byte) bool {
	var pubK webauthncose.EC2PublicKeyData // TODO: copy&paste no module ref!
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

const HashSize = 32

type Hash = [HashSize]byte

const prefixCBOR = "2DLtZ9GymDo1pt"

type PublicCBOR []byte

func (pk PublicCBOR) Equal(rhs PublicCBOR) bool {
	return bytes.Equal(pk, rhs)
}

func (pk PublicCBOR) String() string {
	p := base58.Encode(pk)
	return p[prefixLenOfCBOR:]
}

func NewPublicCBOR(s string) (pk PublicCBOR) {
	s = prefixCBOR + s
	b := base58.Decode(s)
	return b
}
