package chain

import (
	"bytes"
	"encoding/gob"

	"github.com/lainio/err2/try"
	"github.com/lainio/ic/crypto"
)

type Block struct {
	HashToPrev        []byte           // check the size later
	InviteePubKey     crypto.PubKey    // TODO: check the type later?
	InvitersSignature crypto.Signature // TODO: check the type
	Position          int
}

// NewVerifyBlock returns two randomized Blocks that can be used for
// verification or challenges, etc. First block is for challenge, i.e. pinCode
// is unknown aka 0, and second block is for actual signing where pincode is set
// to Position field. By this we can send pincode by other, safe channel.
func NewVerifyBlock(pinCode int) (Block, Block) {
	challengeBlock := Block{
		HashToPrev:    crypto.RandSlice(32),
		InviteePubKey: crypto.RandSlice(32),
	}
	return challengeBlock, Block{
		HashToPrev:    challengeBlock.HashToPrev,
		InviteePubKey: challengeBlock.InviteePubKey,
		Position:      pinCode,
	}
}

func NewBlockFromData(d []byte) (b Block) {
	r := bytes.NewReader(d)
	dec := gob.NewDecoder(r)
	try.To(dec.Decode(&b))
	return b
}

func (b Block) Bytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	try.To(enc.Encode(b))
	return buf.Bytes()
}

func (b Block) ExcludeSign() Block {
	newBlock := Block{
		HashToPrev:    b.HashToPrev,
		InviteePubKey: b.InviteePubKey,
		Position:      b.Position,
	}
	return newBlock
}

func EqualBlocks(b1, b2 Block) bool {
	return crypto.EqualBytes(b1.HashToPrev, b2.HashToPrev) &&
		crypto.EqualBytes(b1.InviteePubKey, b2.InviteePubKey) &&
		crypto.EqualBytes(b1.InvitersSignature, b2.InvitersSignature) &&
		b1.Position == b2.Position
}

func (b Block) VerifySign(invitersPubKey crypto.PubKey) bool {
	return crypto.VerifySign(
		invitersPubKey,
		b.ExcludeSign().Bytes(),
		b.InvitersSignature,
	)
}
