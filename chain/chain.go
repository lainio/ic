package chain

import "github.com/lainio/err2/assert"

type Block struct {
	HashToPrev        []byte    // check the size later
	InviteePubKey     PubKey    // TODO: check the type later?
	InvitersSignature Signature // TODO: check the type
	Position          int
}

func (b Block) Hash() []byte {
	return nil // TODO: 
}

type Chain struct {
	blocks []Block
}

type PubKey = []byte
type Key struct {
	PrivKey []byte
	PubKey
}

func (k Key) PubKeyEqual( pubKey PubKey) bool {
	return byteEqual(k.PubKey, pubKey)
}

func (k Key) Sign(h []byte) Signature {
	return nil // TODO: 
}

type Signature = []byte

func NewChain(rootPubKey PubKey) Chain {
	chain := Chain{blocks: make([]Block, 1, 12)}
	chain.blocks[0] = Block{
		HashToPrev: nil,
		InviteePubKey: rootPubKey,
		InvitersSignature: nil,
	}
	return chain
}

func (c *Chain) AddBlock(invitersKey Key, inviteesPubKey PubKey, position int) {
	assert.D.True(invitersKey.PubKeyEqual(c.LeafPubKey()))

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

func (c Chain) HashToLeaf() []byte {
	return nil // TODO:
}

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
