package chain

import "github.com/lainio/err2/assert"

type Block struct {
	HashToPrev        []byte    // check the size later
	InviteePubKey     PubKey    // TODO: check the type later?
	InvitersSignature Signature // TODO: check the type
	Position          int
}

type Chain struct {
	blocks []Block
}

type PubKey = []byte
type Key = []byte
type Signature = []byte

func NewChain(rootPubKey PubKey) Chain {
	chain = Chain{blocks: make(Chain, 1, 12)}
	chain.blocks[0] = Block{
		HashToPrev: nil,
		InviteePubKey: rootPubKey,
		InvitersSignature: nil,
	}
}

func (c *Chain) AddBlock(invitersKey Key, inviteesPubKey PubKey, position int) {
	assert.D.True(invitersKey.PubKey == c.LeafPubKey())

	newBlock := Block{
		HashToPrev:    c.HashToLeaf(),
		InviteePubKey: inviteesPubKey,
		Position:      position,
	}
	h := newBlock.Hash()
	newBlock.InvitersSignature = invitersKey.Sign(h)

	c.blocks = append(c.blocks, newBlock)
}

func (c Chain) LeafPubKey() PubKey {
	assert.D.True(len(c.blocks) > 0)

	return c.blocks[len(c.blocks)-1].InviteePubKey
}
