package chain

import "github.com/lainio/err2/assert"

type Block struct {
	HashToPrev        []byte    // check the size later
	InviteePubKey     PubKey    // TODO: check the type later?
	InvitersSignature Signature // TODO: check the type
	Position          int
}

type Chain struct {
	blocks []Block // first is leaf and last is the root block, always
}

type PubKey = []byte
type Key = []byte
type Signature = []byte

func NewRoot(rootPubKey PubKey) Block {
	return Block{HashToPrev: nil, InviteePubKey: rootPubKey, InvitersSignature: nil}
}

func (c Chain) AddBlock(invitersKey Key, inviteesPubKey PubKey, position int) {
	assert.D.True(invitersKey.PubKey == c.LeafPubKey())

	newBlock := Block{
		HashToPrev:    c.HashToLeaf(),
		InviteePubKey: inviteesPubKey,
		Position:      position,
	}
	h := newBlock.Hash()
	newBloc.InvitersSignature = invitersKey.Sign(h)
}

func (c Chain) LeafPubKey() PubKey {
	assert.D.True(len(c.blocks) > 0)

	return c.blocks[0].InviteePubKey
}
