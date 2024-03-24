package chain

import (
	"bytes"
	"encoding/gob"

	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

type Block struct {
	HashToPrev        []byte        // check the size later
	InviteePubKey     key.Public    // TODO: check the type later?
	InviteeID         key.ID        // Makes stateless key management possible
	InvitersSignature key.Signature // TODO: check the type
	Position          int
}

// NewVerifyBlock returns two randomized Blocks that can be used for
// verification or challenges, etc. First block is for challenge, i.e. pinCode
// is unknown aka 0, and second block is for actual signing where pincode is set
// to Position field. By this we can send pincode by other, safe channel.
func NewVerifyBlock(pinCode int) (Block, Block) {
	challengeBlock := Block{
		HashToPrev:    key.RandSlice(32),
		InviteePubKey: key.RandSlice(32),
	}
	return challengeBlock, Block{
		HashToPrev:    challengeBlock.HashToPrev,
		InviteePubKey: challengeBlock.InviteePubKey,
		Position:      pinCode, // TODO: move to InviteeID
	}
}

// NewBlockFromData constructor from raw gob data block.
// TODO: start to use CBOR? for everything, all add as format?
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
	return key.EqualBytes(b1.HashToPrev, b2.HashToPrev) &&
		key.EqualBytes(b1.InviteePubKey, b2.InviteePubKey) &&
		key.EqualBytes(b1.InvitersSignature, b2.InvitersSignature) &&
		b1.Position == b2.Position
}

func (b Block) VerifySign(invitersPubKey key.Public) bool {
	return key.VerifySign(
		invitersPubKey,
		b.ExcludeSign().Bytes(),
		b.InvitersSignature,
	)
}
