// package path present Invitation Path and its Edge and other methods.
// Invitation Path is meant to be used as part of a communication protocol. At
// this level we don't think where paths are stored either.
package intro

import (
	"bytes"

	"github.com/btcsuite/btcutil/base58"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

const (
	ProfileVersion uint64 = 1

	AnchorVersion uint64 = 1
	EdgeVersion   uint64 = 1
	PathVersion   uint64 = 1
)

type Anchor struct {
	Version uint64     `cbor:"0,keyasint"`
	Profile uint64     `cbor:"1,keyasint"`
	Root    key.Public `cbor:"2,keyasint"`
}

func (a Anchor) Digest() key.Hash {
	return key.HashTagged("v1/anchor", wire.TryMarshal(a))
}

var (
	anchorKey key.Public = base58.Decode(
		"2DLtZ9GymDo1ptTVMjXQCfjvLCzDd65eZAu9JDa3tqYLeHaCuQRY4ph4AhCz4UeEXgFQGtcJ8J6PvUodSwta45Grp7r9KHgAQeiSqt6fzf",
	)

	anchor = Anchor{
		Version: AnchorVersion,
		Profile: ProfileVersion,

		Root: anchorKey,
	}
)

func AnchorDigest() key.Hash {
	return anchor.Digest()
}

type Path []Edge

// TODO: used in Node, not needed here any more.
var Nil = Path{}

func SameRoot(c1, c2 Path) bool {
	b1, b2 := c1.FirstEdge(), c2.FirstEdge()
	return EqualEdges(b1, b2)
}

func SameParent(c1, c2 Path) bool {
	return EqualEdges(
		c1.secondLastEdge(),
		c2.secondLastEdge(),
	)
}

// CommonParentLevel returns parent's distance (current level) from path's root
// if parent exists, and [same] is true if Parent is in the same IC. If the
// Common Parent doesn't exist, it returns [hop.NotConnected] and false.
// TODO: remove [same] it's not needed when we have only one chain.
func CommonParentLevel(c1, c2 Path) (level hop.Distance, same bool) {
	if !SameRoot(c1, c2) {
		return hop.NotConnected, false
	}

	// pickup the shorter of the paths for the compare loop below
	c := c1
	if c1.Len() > c2.Len() {
		c = c2
	}

	// we can find only IC branch, so default is the that they are same:
	same = true

	// root is the same, start from next until difference is found
	startEdge := 1
	for i := range c[startEdge:] {
		i += startEdge
		if !EqualEdges(c1[i], c2[i]) {
			same = false
			return hop.Distance(i - 1), same
		}
		level = hop.Distance(i)
	}
	return level, same
}

// Hops returns hops and common parent's level if that exists. If not both
// return values are NotConnected.
func Hops(lhs, rhs Path) (hop.Distance, hop.Distance) {
	return lhs.Hops(rhs)
}

// New constructs a new path ROOT.
// This happens only once for whole introduction tree.
// The rest of the paths are created through [Path.Intoduce] function.
// TODO: refactoring idea or questions who owns the root key and is able to
// onboard level 2 enties to the tree.
func New(keyInfo key.Info, flags ...Opts) Path {
	path := Path(make([]Edge, 1, 12))
	path[0] = Edge{Body: EdgeBody{
		Version: EdgeVersion,
		Prev:    AnchorDigest(),
		Child:   keyInfo,
	},
		ParentSig: nil,
	}
	opts := NewOptions(flags...)
	path[0].Body.Options = *opts
	return path
}

// NewPathFromData creates a new Path from byte data.
//
// NOTE that [NewEdgeFromData] creates a new Edge.
func NewPathFromData(d []byte) Path {
	return wire.FromData[Path](d)
}

func (p Path) Bytes() []byte {
	return wire.TryMarshal(p)
}

// Introduce is called for the parent's path. Parent's key is needed for signing
// the new link/block which includes childsPubKey and position in the path.
// A new path is returned. The path will be given for the child.
func (c Path) Introduce(
	parent key.Handle,
	child key.Info,
	opts ...Opts,
) (nc Path) {
	// We have *now* backup keys which cannot handle this assert!
	//	assert.That(c.isLeaf(parent), "only leaf can invite")

	newEdge := Edge{Body: EdgeBody{
		Version: EdgeVersion,
		Prev:    c.leafHash(),
		Child:   child,
	}}
	newEdge.Body.Options = *NewOptions(opts...)
	newEdge.ParentSig = try.To1(parent.Sign(newEdge.Bytes()))

	//pubK := try.To1(parent.CBORPublicKey())
	//assert.That(newEdge.VerifySignature2(pubK))

	nc = c.Clone()
	nc = append(nc, newEdge)
	return nc
}

// Hops returns hops and common parent's level if that exists. If not both
// return values are NotConnected.
func (c Path) Hops(their Path) (hops hop.Distance, rootLvl hop.Distance) {
	common, _ := CommonParentLevel(c, their)
	if common == hop.NotConnected {
		return hop.NotConnected, hop.NotConnected
	}

	if c.OneHop(their) {
		return 1, common
	}

	// both path lengths without self, minus "tail" to common parent
	hops = c.AbsLen() - 1 + their.AbsLen() - 1 - 2*common

	return hops, common
}

func (c Path) OneHop(their Path) bool {
	return c.IsParentFor(their) ||
		their.IsParentFor(c)
}

func (c Path) AbsLen() hop.Distance {
	return c.Len()
	//return c.Len() - c.KeyRotationsLen()
}

func (c Path) Len() hop.Distance {
	return hop.Distance(len(c))
}

func (c Path) KeyRotationsLen() (count hop.Distance) {
	for _, b := range c {
		if b.Body.Options.Rotation {
			count += 1
		}
	}
	return
}

// isLeaf
func (c Path) _(parentsKey key.Handle) bool {
	return bytes.Equal(c.LeafPubKey(), try.To1(parentsKey.CBORPublicKey()))
}

func (c Path) LeafPubKey() key.Public {
	assert.That(c.Len() > 0, "path cannot be empty")

	return c.LastEdge().Public()
}

func (c Path) leafHash() key.Hash {
	if c == nil {
		return key.Hash{}
	}
	ha := key.HashTagged("v1/signed-hash", c.LastEdge().Bytes())
	return ha
}

type getBackupKey func(int) key.Public

func (p Path) VerifySignaturesWithGetBKID(getBKID getBackupKey) bool {
	if p.Len() == 1 {
		return true // root block is valid always
	}

	assert.Equal(p.FirstEdge().Body.Version, PathVersion, "Unsupported path version")
	assert.Equal(p.FirstEdge().Body.Prev, AnchorDigest(), "Wrong anchor")

	// start with the root key
	parentsPubKey := p.FirstEdge().Public()

	for _, edge := range p[1:] {
		if edge.Body.Options.BackupKeyIndex != 0 {
			parentsPubKey = getBKID(edge.Body.Options.BackupKeyIndex)
		}
		if !edge.VerifySignature(parentsPubKey) {
			return false
		}
		// the next block is signed with this block's pub key
		parentsPubKey = edge.Public()
	}
	return true
}

func emptyBKImpl(int) key.Public {
	assert.NotImplemented()
	return nil
}

// VerifySignatures verifies paths signatures, from root to the leaf.
func (c Path) VerifySignatures() bool {
	return c.VerifySignaturesWithGetBKID(emptyBKImpl)
}

func (c Path) Clone() Path {
	return NewPathFromData(c.Bytes())
}

func (c Path) IsParentFor(child Path) bool {
	// if we are a root or too near of a root we cannot be parent
	if c.Len() < 1 || child.Len() < 2 {
		return false
	}

	return EqualEdges(
		c.LastEdge(),
		child.secondLastEdge(),
	)
}

// Find finds Edge from Path if it exists. If block not found the returned
// 'found' is [hop.NotConnected].
func (c Path) Find(IDK key.Public) (b Edge, found hop.Distance) {
	found = hop.NewNotConnected()
	for i, block := range c {
		if block.Public().Equal(IDK) {
			return block, hop.Distance(i)
		}
	}
	return
}

// Resolver returns first found Resolver or empty string.
func (c Path) Resolver() (endpoint string) {
	for _, block := range c {
		if block.Body.Options.Resolver {
			return block.Body.Options.Endpoint
		}
	}
	return
}

func (c Path) FindLevel(IDK key.Public) (lvl hop.Distance) {
	for i, block := range c {
		if bytes.Equal(block.Public(), IDK) {
			return hop.Distance(i)
		}
	}
	return hop.NewNotConnected()
}

// Challenge offers a method and placeholder for challenging other path holder.
// Most common cases is that caller of the function implements the closure where
// it calls other party over the network to sign the challenge which is readily
// build and randomized.
func (c Path) Challenge(pinCode int, f func(d []byte) key.Signature) bool {
	pubKey := c.LastEdge().Public()
	challengeEdge, sigEdge := NewVerifyEdge(pinCode)
	signature := f(challengeEdge.Bytes())
	return signature.Verify(pubKey, sigEdge.Bytes())
}

func (c Path) FirstEdge() Edge {
	return c[0]
}

func (c Path) LastEdge() Edge {
	l := len(c)
	assert.That(l > 0, "Edges is too short")
	return c[l-1]
}

func (c Path) secondLastEdge() Edge {
	l := len(c)
	assert.That(l > 1, "Edges is too short")
	return c[l-2]
}
