package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"

	"github.com/findy-network/ic/crypto"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
)

type Block struct {
	HashToPrev        []byte           // check the size later
	InviteePubKey     crypto.PubKey    // TODO: check the type later?
	InvitersSignature crypto.Signature // TODO: check the type
	Position          int
}

func (b Block) Bytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err2.Check(enc.Encode(b))
	return buf.Bytes()
}

func (b Block) NoSign() Block {
	newBlock := Block{
		HashToPrev:    b.HashToPrev,
		InviteePubKey: b.InviteePubKey,
		Position:      b.Position,
	}
	return newBlock
}

func (b Block) VerifySign(invitersPubKey crypto.PubKey) bool {
	return crypto.VerifySign(invitersPubKey, b.NoSign().Bytes(), b.InvitersSignature)
}

// Chain is the data type for Invitation Chain, it's ID is rootPubKey. TODO:
type Chain struct {
	blocks []Block
}

func NewChain(rootPubKey crypto.PubKey) Chain {
	chain := Chain{blocks: make([]Block, 1, 12)}
	chain.blocks[0] = Block{
		HashToPrev:        nil,
		InviteePubKey:     rootPubKey,
		InvitersSignature: nil,
	}
	return chain
}

func (c *Chain) AddBlock(
	invitersKey *crypto.Key,
	inviteesPubKey crypto.PubKey,
	position int,
) {
	assert.D.True(invitersKey.PubKeyEqual(c.LeafPubKey()))

	newBlock := Block{
		HashToPrev:    c.HashToLeaf(),
		InviteePubKey: inviteesPubKey,
		Position:      position,
	}
	newBlock.InvitersSignature = invitersKey.Sign(newBlock.Bytes())

	c.blocks = append(c.blocks, newBlock)
}

func (c Chain) LeafPubKey() crypto.PubKey {
	assert.D.True(len(c.blocks) > 0)

	return c.blocks[len(c.blocks)-1].InviteePubKey
}

func (c Chain) HashToLeaf() []byte {
	if c.blocks == nil {
		return nil
	}
	lastBlockBytes := c.blocks[len(c.blocks)-1].Bytes()
	ha := sha256.Sum256(lastBlockBytes)
	return ha[:]
}

func (c Chain) Verify() bool {
	assert.D.True(len(c.blocks) > 1, "cannot verify empty chain")

	var invitersPubKey crypto.PubKey
	// start with the root key
	invitersPubKey = c.blocks[0].InviteePubKey

	for _, b := range c.blocks[1:] {
		if !b.VerifySign(invitersPubKey) {
			return false
		}
		// the next block is signed with this blocks pub key i.e. this is
		// chain
		invitersPubKey = b.InviteePubKey
	}
	return true
}
