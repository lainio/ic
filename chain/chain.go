// package chain present Invitation Chain and its Block and other methods.
// Invitation Chain is meant to be used as part of a communication protocol. At
// this level we don't think where chains are stored either.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

// NotConnected tells that chains aren't connected at all, i.e. we don't have
// any route to other.
const NotConnected = -1

// Chain is the data type for Invitation Chain, it's ID is rootPubKey
type Chain struct {
	Blocks []Block // Blocks is exported variable for serialization
}

// Pair is helper struct to handle chain pairs. It offers helper methods to
// calculate hops between two chains. Pair and Chain are summetric.
type Pair struct {
	Chain1, Chain2 Chain
}

func (p Pair) Hops() (int, int) {
	return Hops(p.Chain1, p.Chain2)
}

func (p Pair) OneHop() bool {
	return p.Chain1.IsInviterFor(p.Chain2) ||
		p.Chain2.IsInviterFor(p.Chain1)
}

func (p Pair) CommonInviter() int {
	return CommonInviter(p.Chain1, p.Chain2)
}

var Nil = Chain{Blocks: nil}

func SameRoot(c1, c2 Chain) bool {
	if !c1.VerifySign() || !c2.VerifySign() {
		return false
	}
	return EqualBlocks(c1.firstBlock(), c2.firstBlock())
}

func SameInviter(c1, c2 Chain) bool {
	if !c1.VerifySign() || !c2.VerifySign() {
		return false
	}
	return EqualBlocks(
		c1.secondLastBlock(),
		c2.secondLastBlock(),
	)
}

// CommonInviter returns inviter's distance (current level) from chain's root if
// inviter exists.  If not it returns NotConnected
func CommonInviter(c1, c2 Chain) (level int) {
	if !SameRoot(c1, c2) {
		return NotConnected
	}

	// pickup the shorter of the chains for the compare loop below
	c := c1
	if c1.Len() > c2.Len() {
		c = c2
	}

	// root is the same, start from next until difference is found
	for i := range c.Blocks[1:] {
		if !EqualBlocks(c1.Blocks[i], c2.Blocks[i]) {
			return i - 1
		}
		level = i
	}
	return level
}

func Hops(lhs, rhs Chain) (int, int) {
	return lhs.Hops(rhs)
}

// NewRootChain construts a new root chain.
func NewRootChain(rootPubKey key.Info) Chain {
	chain := Chain{Blocks: make([]Block, 1, 12)}
	chain.Blocks[0] = Block{
		HashToPrev:        nil,
		Invitee:           rootPubKey,
		InvitersSignature: nil,
	}
	return chain
}

func NewChainFromData(d []byte) (c Chain) {
	r := bytes.NewReader(d)
	dec := gob.NewDecoder(r)
	try.To(dec.Decode(&c))
	return c
}

func (c Chain) IsNil() bool {
	return c.Blocks == nil
}

func (c Chain) Bytes() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	try.To(enc.Encode(c))
	return buf.Bytes()
}

// Invite is called for the inviter's chain. Inviter's key is needed for signing
// the new link/block which includes inviteesPubKey and position in the chain.
// A new chain is returned. The chain will be given for the invitee.
func (c Chain) Invite(
	invitersKey key.Handle,
	invitee key.Info,
	position int,
) (nc Chain) {
	assert.That(c.isLeaf(invitersKey), "only leaf can invite")

	newBlock := Block{
		HashToPrev: c.hashToLeaf(),
		Invitee:    invitee,
		Position:   position,
	}
	newBlock.InvitersSignature = try.To1(invitersKey.Sign(newBlock.Bytes()))

	nc = c.Clone()
	nc.Blocks = append(nc.Blocks, newBlock)
	return nc
}

// Hops returns hops and common inviter's level if that exists. If not both
// return values are NotConnected.
func (c Chain) Hops(their Chain) (int, int) {
	common := CommonInviter(c, their)
	if common == NotConnected {
		return NotConnected, NotConnected
	}

	if c.OneHop(their) {
		return 1, common
	}

	// both chain lengths without self, minus "tail" to common inviter
	hops := c.Len() - 1 + their.Len() - 1 - 2*common

	return hops, common
}

func (c Chain) OneHop(their Chain) bool {
	return c.IsInviterFor(their) ||
		their.IsInviterFor(c)
}

func (c Chain) Len() int {
	return len(c.Blocks)
}

func (c Chain) isLeaf(invitersKey key.Handle) bool {
	return key.EqualBytes(c.LeafPubKey(), try.To1(invitersKey.CBORPublicKey()))
}

func (c Chain) LeafPubKey() key.Public {
	assert.That(c.Len() > 0, "chain cannot be empty")

	return c.lastBlock().Invitee.Public
}

func (c Chain) hashToLeaf() []byte {
	if c.Blocks == nil {
		return nil
	}
	ha := sha256.Sum256(c.lastBlock().Bytes())
	return ha[:]
}

// VerifySign verifies chains signatures, from root to the leaf.
func (c Chain) VerifySign() bool {
	if c.Len() == 1 {
		return true // root block is valid always
	}

	var invitersPubKey key.Public
	// start with the root key
	invitersPubKey = c.firstBlock().Invitee.Public

	for _, b := range c.Blocks[1:] {
		if !b.VerifySign(invitersPubKey) {
			return false
		}
		// the next block is signed with this block's pub key
		invitersPubKey = b.Invitee.Public
	}
	return true
}

func (c Chain) Clone() Chain {
	return NewChainFromData(c.Bytes())
}

func (c Chain) IsInviterFor(invitee Chain) bool {
	if !invitee.VerifySign() {
		return false
	}

	return EqualBlocks(
		c.lastBlock(),
		invitee.secondLastBlock(),
	)
}

// Challenge offers a method and placeholder for challenging other chain holder.
// Most common cases is that caller of the function implements the closure where
// it calls other party over the network to sign the challenge which is readily
// build and randomized.
func (c Chain) Challenge(pinCode int, f func(d []byte) key.Signature) bool {
	pubKey := c.lastBlock().Invitee.Public
	challengeBlock, sigBlock := NewVerifyBlock(pinCode)
	sig := f(challengeBlock.Bytes())
	return key.VerifySign(pubKey, sigBlock.Bytes(), sig)
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
