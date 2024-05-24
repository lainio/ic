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
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

// Chain is the data type for Invitation Chain.
type Chain struct {
	Blocks []Block // Blocks is exported variable for serialization
}

var Nil = Chain{Blocks: nil}

func SameRoot(c1, c2 Chain) bool {
	b1, b2 := c1.firstBlock(), c2.firstBlock()
	return EqualBlocks(b1, b2)
}

func SameInviter(c1, c2 Chain) bool {
	return EqualBlocks(
		c1.secondLastBlock(),
		c2.secondLastBlock(),
	)
}

// CommonInviterLevel returns inviter's distance (current level) from chain's
// root if inviter exists, and same if Inviter is in the same IC. If the Common
// Inviter doesn't exist, it returns [hop.NotConnected] and false.
func CommonInviterLevel(c1, c2 Chain) (level hop.Distance, same bool) {
	if !SameRoot(c1, c2) {
		return hop.NotConnected, false
	}

	// pickup the shorter of the chains for the compare loop below
	c := c1
	if c1.Len() > c2.Len() {
		c = c2
	}

	// we can find only IC branch, so default is the that they are same:
	same = true

	// root is the same, start from next until difference is found
	startBlock := 1
	for i := range c.Blocks[startBlock:] {
		i += startBlock
		if !EqualBlocks(c1.Blocks[i], c2.Blocks[i]) {
			same = false
			return hop.Distance(i - 1), same
		}
		level = hop.Distance(i)
	}
	return level, same
}

// Hops returns hops and common inviter's level if that exists. If not both
// return values are NotConnected.
func Hops(lhs, rhs Chain) (hop.Distance, hop.Distance) {
	return lhs.Hops(rhs)
}

// New constructs a new chain. It's a genesis block. We can start our identity
// chain with this. If it's a rotation block, the first one, we are creating
// backup chain for several keys.
//
// NOTE: New is important part of key rotation and everything where we will
// construct our key concepts from key pair.
func New(keyInfo key.Info, flags ...Opts) Chain {
	chain := Chain{Blocks: make([]Block, 1, 12)}
	chain.Blocks[0] = Block{
		HashToPrev:        nil,
		Invitee:           keyInfo,
		InvitersSignature: nil,
	}
	opts := NewOptions(flags...)
	chain.Blocks[0].Options = *opts
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
	opts ...Opts,
) (nc Chain) {
	// We have backup keys which cannot handle this assert!
	//	assert.That(c.isLeaf(inviter), "only leaf can invite")

	newBlock := Block{
		HashToPrev: c.hashToLeaf(),
		Invitee:    invitee,
	}
	newBlock.Options = *NewOptions(opts...)
	newBlock.InvitersSignature = try.To1(inviter.Sign(newBlock.ExcludeBytes()))

	nc = c.Clone()
	nc.Blocks = append(nc.Blocks, newBlock)
	return nc
}

// Hops returns hops and common inviter's level if that exists. If not both
// return values are NotConnected.
func (c Chain) Hops(their Chain) (hops hop.Distance, rootLvl hop.Distance) {
	common, _ := CommonInviterLevel(c, their)
	if common == hop.NotConnected {
		return hop.NotConnected, hop.NotConnected
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

func (c Chain) AbsLen() hop.Distance {
	return c.Len()
	//return c.Len() - c.KeyRotationsLen()
}

func (c Chain) Len() hop.Distance {
	return hop.Distance(len(c.Blocks))
}

func (c Chain) KeyRotationsLen() (count hop.Distance) {
	for _, b := range c.Blocks {
		if b.Rotation {
			count += 1
		}
	}
	return
}

// isLeaf
func (c Chain) _(invitersKey key.Handle) bool {
	return key.EqualBytes(c.LeafPubKey(), try.To1(invitersKey.CBORPublicKey()))
}

func (c Chain) LeafPubKey() key.Public {
	assert.That(c.Len() > 0, "chain cannot be empty")

	return c.LastBlock().Invitee.Public
}

func (c Chain) hashToLeaf() []byte {
	if c.Blocks == nil {
		return nil
	}
	ha := sha256.Sum256(c.LastBlock().Bytes())
	return ha[:]
}

type getBackupKey func(int) key.Public

func (c Chain) VerifySignExtended(getBKID getBackupKey) bool {
	if c.Len() == 1 {
		return true // root block is valid always
	}

	// start with the root key
	invitersPubKey := c.firstBlock().Invitee.Public

	for _, b := range c.Blocks[1:] {
		if b.BackupKeyIndex != 0 {
			invitersPubKey = getBKID(b.BackupKeyIndex)
		}
		if !b.VerifySign(invitersPubKey) {
			return false
		}
		// the next block is signed with this block's pub key
		invitersPubKey = b.Invitee.Public
	}
	return true
}

// VerifySign verifies chains signatures, from root to the leaf.
// TODO: merge with the next, refactoring.
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
	// if we are a root or too near of a root we cannot be inviter
	if c.Len() < 1 || invitee.Len() < 2 {
		return false
	}

	return EqualBlocks(
		c.LastBlock(),
		invitee.secondLastBlock(),
	)
}

// Find finds Block from Chain if it exists.
func (c Chain) Find(IDK key.Public) (b Block, found bool) {
	for _, block := range c.Blocks {
		if key.EqualBytes(block.Invitee.Public, IDK) {
			return block, true
		}
	}
	return
}

// Resolver returns first found Resolver or empty string.
func (c Chain) Resolver() (endpoint string) {
	for _, block := range c.Blocks {
		if block.Resolver {
			return block.Endpoint
		}
	}
	return
}

func (c Chain) FindLevel(IDK key.Public) (lvl hop.Distance) {
	for i, block := range c.Blocks {
		if key.EqualBytes(block.Invitee.Public, IDK) {
			return hop.Distance(i)
		}
	}
	return hop.NewNotConnected()
}

// Challenge offers a method and placeholder for challenging other chain holder.
// Most common cases is that caller of the function implements the closure where
// it calls other party over the network to sign the challenge which is readily
// build and randomized.
func (c Chain) Challenge(pinCode int, f func(d []byte) key.Signature) bool {
	pubKey := c.LastBlock().Invitee.Public
	challengeBlock, sigBlock := NewVerifyBlock(pinCode)
	sig := f(challengeBlock.Bytes())
	return key.VerifySign(pubKey, sigBlock.Bytes(), sig)
}

func (c Chain) firstBlock() Block {
	return c.Blocks[0]
}

func (c Chain) LastBlock() Block {
	l := len(c.Blocks)
	assert.That(l > 0, "Blocks is too short")
	return c.Blocks[l-1]
}

func (c Chain) secondLastBlock() Block {
	l := len(c.Blocks)
	assert.That(l > 1, "Blocks is too short")
	return c.Blocks[l-2]
}
