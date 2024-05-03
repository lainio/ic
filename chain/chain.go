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
// TODO: should be add some information about chains type? The current
// imlementation doesn't have specific chains for the ID keys. the key handle is
// just transported as an argument to the functions like Invite
type Chain struct {
	// TODO: We have to refer these chains outside, so should we have following
	// fields: ID (: string, UUID), Type (enum: ID, Invitation),
	//
	// We might need to have some sort of chain management, but let's be
	// careful here! We don't want to make this to complicated. However, we
	// want to courage people to use only one chain as long as possible. That
	// would mean that the have only on structure e.g. family. and they should
	// try to use that same chain to connect to government, work place, etc.
	// NOTE: ^ that's bullshit, we cannot do that! People won't want to think
	// that kind of things, the just want to connect to other people, my job is
	// to make it automatic as possible. I must find out what are the use cases
	// people need when the use the SW. They install app, they start with the
	// empty app, they create needed keys (this might happen automatically, but
	// is depending the used authenticator), they meet a people (later we might
	// build a service) and other one invites other: who invites and who's
	// invitee is calculated the trust-level
	// TODO: calculate identity's trust
	// level

	Blocks []Block // Blocks is exported variable for serialization
}

// Pair is helper type to keep two related chains together. Related chains means
// that two chains have common inviter even the actual chains are different. It
// also means that chains have some ancestor that they share.
//
// Pair type offers helper methods to calculate hops between two chains. Pair
// and Chain are symmetric.
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

// CommonInviterLevel is stupid helper that's more a precondition than actual method.
// The implementation asserts that common inviter really exists.
func (p Pair) CommonInviterLevel() int { // TODO: not used!
	common := CommonInviterLevel(p.Chain1, p.Chain2)
	assert.NotEqual(common, NotConnected)
	return common
}

var Nil = Chain{Blocks: nil}

func SameRoot(c1, c2 Chain) bool {
	// TODO: maybe we should check validity of chains earlier than until here?
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

// CommonInviterLevel returns inviter's distance (current level) from chain's root if
// inviter exists.  If not it returns NotConnected
func CommonInviterLevel(c1, c2 Chain) (level int) {
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

// NewRoot constructs a new root chain.
// NOTE: NewRoot is important part of key rotation and everything where we will
// construct our key concepts from key pair.
func NewRoot(rootPubKey key.Info, flags ...bool) Chain {
	chain := Chain{Blocks: make([]Block, 1, 12)}
	chain.Blocks[0] = Block{
		HashToPrev:        nil,
		Invitee:           rootPubKey,
		InvitersSignature: nil,
		Rotation:          flagOn(flags),
	}
	return chain
}

func flagOn(flags []bool) bool {
	if len(flags) > 0 {
		return flags[0] // TODO: only rotation flag is supported now
	}
	return false
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
	// TODO: CBOR type
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	try.To(enc.Encode(c))
	return buf.Bytes()
}

// Invite is called for the inviter's chain. Inviter's key is needed for signing
// the new link/block which includes inviteesPubKey and position in the chain.
// A new chain is returned. The chain will be given for the invitee.
func (c Chain) Invite(
	inviter key.Handle,
	invitee key.Info,
	position int,
) (nc Chain) {
	assert.That(c.isLeaf(inviter), "only leaf can invite")

	newBlock := Block{
		HashToPrev: c.hashToLeaf(),
		Invitee:    invitee,
		Position:   position,
	}
	newBlock.InvitersSignature = try.To1(inviter.Sign(newBlock.ExcludeBytes()))

	nc = c.Clone()
	nc.Blocks = append(nc.Blocks, newBlock)
	return nc
}

// rotationInvite used for unit testing only!
func (c Chain) rotationInvite(
	inviter key.Handle,
	invitee key.Info,
	position int,
) (nc Chain) {
	assert.That(c.isLeaf(inviter), "only leaf can invite")

	newBlock := Block{
		HashToPrev: c.hashToLeaf(),
		Invitee:    invitee,
		Position:   position,
		Rotation:   true,
	}
	newBlock.InvitersSignature = try.To1(inviter.Sign(newBlock.ExcludeBytes()))

	nc = c.Clone()
	nc.Blocks = append(nc.Blocks, newBlock)
	return nc
}

// Hops returns hops and common inviter's level if that exists. If not both
// return values are NotConnected.
func (c Chain) Hops(their Chain) (hops int, rootLvl int) {
	common := CommonInviterLevel(c, their)
	if common == NotConnected {
		return NotConnected, NotConnected
	}

	if c.OneHop(their) {
		return 1, common
	}

	// both chain lengths without self, minus "tail" to common inviter
	hops = c.AbsLen() - 1 + their.AbsLen() - 1 - 2*common

	return hops, common
}

func (c Chain) OneHop(their Chain) bool {
	return c.IsInviterFor(their) ||
		their.IsInviterFor(c)
}

func (c Chain) AbsLen() int {
	return c.Len()
	//return c.Len() - c.KeyRotationsLen()
}

func (c Chain) Len() int {
	return len(c.Blocks)
}

func (c Chain) KeyRotationsLen() (count int) {
	for _, b := range c.Blocks {
		if b.Rotation {
			count += 1
		}
	}
	return
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

	// start with the root key
	invitersPubKey := c.firstBlock().Invitee.Public

	for _, b := range c.Blocks[1:] {
		if !b.VerifySign(invitersPubKey) {
			return false
		}
		// the next block is signed with this block's pub key
		invitersPubKey = b.Invitee.Public
	}
	return true
}

// VerifyIDChain is tool to verify whole ID chain, i.e., chain sipnatures hold
// and Rotation flag is true in every Block.
func (c Chain) VerifyIDChain() bool {
	if c.Len() == 1 {
		return c.firstBlock().Rotation // root block is valid always
	}

	// start with the root key
	invitersPubKey := c.firstBlock().Invitee.Public

	for _, b := range c.Blocks[1:] {
		if !b.Rotation || !b.VerifySign(invitersPubKey) {
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
