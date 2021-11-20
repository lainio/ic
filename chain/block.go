package chain

import (
	"bytes"
	"encoding/gob"

	"github.com/findy-network/ic/crypto"
	"github.com/lainio/err2"
)

type Block struct {
	HashToPrev        []byte           // check the size later
	InviteePubKey     crypto.PubKey    // TODO: check the type later?
	InvitersSignature crypto.Signature // TODO: check the type
	Position          int
}

// NewVerifyBlock returns new randomized Block that can be used for verification
// or challenges, etc.
func NewVerifyBlock() Block {
	return Block{
		HashToPrev:    crypto.RandSlice(32),
		InviteePubKey: crypto.RandSlice(32),
	}
}

func (b Block) Bytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err2.Check(enc.Encode(b))
	return buf.Bytes()
}

func (b Block) ExludeSign() Block {
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
		b.ExludeSign().Bytes(),
		b.InvitersSignature,
	)
}
