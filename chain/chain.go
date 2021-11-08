// package chain present Invitation Chain and its Block and other methods.
// Invitation Chain is meant to be used as part of a communication protocol. At
// this level we don't think where chains are stored either.
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

func (b Block) NoSign() Block {
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
		b.NoSign().Bytes(),
		b.InvitersSignature,
	)
}

// Chain is the data type for Invitation Chain, it's ID is rootPubKey
type Chain struct {
	Blocks []Block // Blocks is exported variable for serialization
}

func SameRoot(c1, c2 Chain) bool {
	if !c1.Verify() || !c2.Verify() {
		return false
	}
	return EqualBlocks(c1.firstBlock(), c2.firstBlock())
}

func SameInviter(c1, c2 Chain) bool {
	if !c1.Verify() || !c2.Verify() {
		return false
	}
	return EqualBlocks(
		c1.secondLastBlock(),
		c2.secondLastBlock(),
	)
}

// CommonInviter returns distance (current level) from chain's root if it
// exists.  If not it returns -1
func CommonInviter(c1, c2 Chain) (level int) {
	if !SameRoot(c1, c2) {
		return -1
	}
	c := c1
	if len(c1.Blocks) > len(c2.Blocks) {
		c = c2
	}
	for i := range c.Blocks[1:] {
		if !EqualBlocks(c1.Blocks[i], c2.Blocks[i]) {
			return i - 1
		}
		level = i
	}
	return level
}

func NewChain(rootPubKey crypto.PubKey) Chain {
	chain := Chain{Blocks: make([]Block, 1, 12)}
	chain.Blocks[0] = Block{
		HashToPrev:        nil,
		InviteePubKey:     rootPubKey,
		InvitersSignature: nil,
	}
	return chain
}

func NewChainFromData(d []byte) (c Chain) {
	r := bytes.NewReader(d)
	dec := gob.NewDecoder(r)
	err2.Check(dec.Decode(&c))
	return c
}

func (c Chain) Bytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err2.Check(enc.Encode(c))
	return buf.Bytes()
}

func (c Chain) Invite(
	invitersKey *crypto.Key,
	inviteesPubKey crypto.PubKey,
	position int,
) (nc Chain) {
	assert.D.True(invitersKey.PubKeyEqual(c.LeafPubKey()))

	newBlock := Block{
		HashToPrev:    c.hashToLeaf(),
		InviteePubKey: inviteesPubKey,
		Position:      position,
	}
	newBlock.InvitersSignature = invitersKey.Sign(newBlock.Bytes())

	nc = c.Clone()
	nc.Blocks = append(nc.Blocks, newBlock)
	return nc
}

func (c Chain) LeafPubKey() crypto.PubKey {
	assert.D.True(len(c.Blocks) > 0)

	return c.lastBlock().InviteePubKey
}

func (c Chain) hashToLeaf() []byte {
	if c.Blocks == nil {
		return nil
	}
	ha := sha256.Sum256(c.lastBlock().Bytes())
	return ha[:]
}

func (c Chain) Verify() bool {
	assert.D.True(len(c.Blocks) > 1, "cannot verify empty chain")

	var invitersPubKey crypto.PubKey
	// start with the root key
	invitersPubKey = c.firstBlock().InviteePubKey

	for _, b := range c.Blocks[1:] {
		if !b.VerifySign(invitersPubKey) {
			return false
		}
		// the next block is signed with this block's pub key
		invitersPubKey = b.InviteePubKey
	}
	return true
}

func (c Chain) Clone() Chain {
	return NewChainFromData(c.Bytes())
}

func (c Chain) IsInviterFor(invitee Chain) bool {
	if !invitee.Verify() {
		return false
	}

	return EqualBlocks(
		c.lastBlock(),
		invitee.secondLastBlock(),
	)
}

// Challenge offers a method and placeholder for challenging leaf holder. Most
// common cases is that caller of the function implements the closure where it
// calls other party over the network to sign the challenge which is readily
// build and randomized.
func (c Chain) Challenge(f func(d []byte) crypto.Signature) bool {
	pubKey := c.lastBlock().InviteePubKey
	cb := NewVerifyBlock().Bytes()
	sig := f(cb)
	return crypto.VerifySign(pubKey, cb, sig)
}

func (c Chain) firstBlock() Block {
	return c.Blocks[0]
}

func (c Chain) lastBlock() Block {
	return c.Blocks[len(c.Blocks)-1]
}

func (c Chain) secondLastBlock() Block {
	return c.Blocks[len(c.Blocks)-2]
}
