package chain

import (
	"bytes"
	"encoding/gob"

	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

// Block is the block in our invitation Chain (IC). Note that Invitee is an
// important field, because its data must be same at the node level. They tell
// that otherwise separated ICs belong to the same node. [Invitee.Public] is the
// identity ID, we call it in the docs IDK.
type Block struct {
	HashToPrev key.Hash
	Invitee    key.Info
	Options

	InvitersSignature key.Signature
}

// NewVerifyBlock returns two randomized Blocks that can be used for
// verification or challenges, etc. First block is for challenge, i.e. pinCode
// is unknown aka 0, and second block is for actual signing where pincode is set
// to Position field. By this we can send pincode by other, thru safe channel
// and out-of-band.
func NewVerifyBlock(pinCode int) (Block, Block) {
	challengeBlock := Block{
		HashToPrev: key.RandSlice(32),
		Invitee:    key.RandInfo(32),
	}
	return challengeBlock, Block{
		HashToPrev: challengeBlock.HashToPrev,
		Invitee:    challengeBlock.Invitee,
		Options: Options{
			Position: pinCode,
		},
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

// Bytes return marshallel bytes of the Block.
// TODO: start to use CBOR? for everything, all add as format?
func (b Block) Bytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	try.To(enc.Encode(b))
	return buf.Bytes()
}

func (b Block) ExcludeBytes() []byte {
	return b.excludeSign().Bytes()
}

func (b Block) excludeSign() Block {
	newBlock := Block{
		HashToPrev: b.HashToPrev,
		Invitee:    b.Invitee,
		Options: Options{
			Position: b.Position,
			Rotation: b.Rotation,
		},
	}
	return newBlock
}

func EqualBlocks(b1, b2 Block) bool {
	return key.EqualBytes(b1.HashToPrev, b2.HashToPrev) &&
		key.EqualBytes(b1.ID(), b2.ID()) &&
		key.EqualBytes(b1.Public(), b2.Public()) &&
		key.EqualBytes(b1.InvitersSignature, b2.InvitersSignature) &&
		b1.Position == b2.Position &&
		b1.Rotation == b2.Rotation
}

func (b Block) VerifySign(invitersPubKey key.Public) bool {
	return b.InvitersSignature.Verify(
		invitersPubKey,
		b.ExcludeBytes(),
	)
}

func (b Block) ID() key.ID {
	return b.Invitee.ID
}

func (b Block) Public() key.Public {
	return b.Invitee.Public
}
