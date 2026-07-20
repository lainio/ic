// package path present Invitation Path and its Edge and other methods.
// Invitation Path is meant to be used as part of a communication protocol. At
// this level we don't think where paths are stored either.
package intro

import (
	"bytes"
	"errors"

	"github.com/btcsuite/btcutil/base58"
	"github.com/lainio/err2"
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
// TODO: remove [same] it's not needed when we have only one intro tree.
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
// the new link/edge which includes childsPubKey and position in the path.
// A new path is returned. The path will be given for the child.
func (p Path) Introduce(
	parent key.Handle,
	child key.Info,
	opts ...Opts,
) (newP Path) {
	// We have *now* backup keys which cannot handle this assert!
	//	assert.That(c.isLeaf(parent), "only leaf can invite")

	newEdge := Edge{Body: EdgeBody{
		Version: EdgeVersion,
		Prev:    p.leafHash(),
		Child:   child,
	}}
	newEdge.Body.Options = *NewOptions(opts...)
	newEdge.ParentSig = try.To1(parent.Sign(newEdge.Bytes()))

	//pubK := try.To1(parent.CBORPublicKey())
	//assert.That(newEdge.VerifySignature2(pubK))

	newP = p.Clone()
	newP = append(newP, newEdge)
	return newP
}

// Hops returns hops and common parent's level if that exists. If not both
// return values are NotConnected.
func (p Path) Hops(their Path) (hops hop.Distance, rootLvl hop.Distance) {
	common, _ := CommonParentLevel(p, their)
	if common == hop.NotConnected {
		return hop.NotConnected, hop.NotConnected
	}

	if p.OneHop(their) {
		return 1, common
	}

	// both path lengths without self, minus "tail" to common parent
	hops = p.AbsLen() - 1 + their.AbsLen() - 1 - 2*common

	return hops, common
}

func (p Path) OneHop(their Path) bool {
	return p.IsParentFor(their) ||
		their.IsParentFor(p)
}

func (p Path) AbsLen() hop.Distance {
	return p.Len()
	//return c.Len() - c.KeyRotationsLen()
}

func (p Path) Len() hop.Distance {
	// TODO: the Anchor is calculated now
	return hop.Distance(len(p))
}

func (p Path) KeyRotationsLen() (count hop.Distance) {
	for _, b := range p {
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

func (p Path) LeafPubKey() key.Public {
	assert.That(p.Len() > 0, "path cannot be empty")

	return p.LastEdge().Public()
}

func (p Path) leafHash() key.Hash {
	if p == nil {
		return key.Hash{}
	}
	ha := key.HashTagged("v1/signed-hash", p.LastEdge().Bytes())
	return ha
}

type getBackupKey func(int) key.Public

var (
	ErrUnsupportedVersion = errors.New("Unsupported edge version")
	ErrWrongAnchor        = errors.New("Wrong anchor")
	ErrBrokenPath         = errors.New("Broken path")
	ErrCycleOrDuplicate   = errors.New("Cycle or dublicate")
	ErrBadSignature       = errors.New("Bad signature")
)

func (p Path) ProveWithGetBKID(getBKID getBackupKey) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.Equal(p.FirstEdge().Body.Version, EdgeVersion, ErrUnsupportedVersion)
	assert.Equal(p.FirstEdge().Body.Prev, AnchorDigest(), ErrWrongAnchor)

	if p.Len() == 1 {
		return nil // root edge is valid, see the previous asserts
	}

	// start with the root key
	parentsPubKey := p.FirstEdge().Public()
	prev := parentsPubKey.Hash()
	seen := map[key.Hash]bool{}

	for _, edge := range p[1:] {
		assert.Equal(edge.Body.Version, EdgeVersion, ErrUnsupportedVersion)

		edgeIDK := edge.Public()
		edgeDigest := edgeIDK.Hash()
		assert.NotEqual(edgeDigest, prev, ErrBrokenPath)            // tested
		assert.MKeyNotExists(seen, edgeDigest, ErrCycleOrDuplicate) // tested

		if edge.Body.Options.BackupKeyIndex != 0 {
			parentsPubKey = getBKID(edge.Body.Options.BackupKeyIndex)
		}
		assert.That(edge.VerifySignature(parentsPubKey), ErrBadSignature)

		// the next edge is signed with this edge's pub key
		parentsPubKey = edgeIDK
		prev = parentsPubKey.Hash()
		seen[prev] = true
	}
	return nil
}

func emptyBKImpl(int) key.Public {
	assert.NotImplemented()
	return nil
}

// Prove verifies the whole path, from root to the leaf.
func (p Path) Prove() (err error) {
	defer err2.Handle(&err, nil)

	return p.ProveWithGetBKID(emptyBKImpl)
}

func (p Path) Clone() Path {
	return NewPathFromData(p.Bytes())
}

func (p Path) IsParentFor(child Path) bool {
	// if we are a root or too near of a root we cannot be parent
	if p.Len() < 1 || child.Len() < 2 {
		return false
	}

	return EqualEdges(
		p.LastEdge(),
		child.secondLastEdge(),
	)
}

// Find finds Edge from Path if it exists. If edge not found the returned
// 'found' is [hop.NotConnected].
func (p Path) Find(IDK key.Public) (e Edge, found hop.Distance) {
	found = hop.NewNotConnected()
	for i, edge := range p {
		if edge.Public().Equal(IDK) {
			return edge, hop.Distance(i)
		}
	}
	return
}

// Resolver returns first found Resolver or empty string.
func (p Path) Resolver() (endpoint string) {
	for _, edge := range p {
		if edge.Body.Options.Resolver {
			return edge.Body.Options.Endpoint
		}
	}
	return
}

func (p Path) FindLevel(IDK key.Public) (lvl hop.Distance) {
	for i, edge := range p {
		if bytes.Equal(edge.Public(), IDK) {
			return hop.Distance(i)
		}
	}
	return hop.NewNotConnected()
}

// Challenge offers a method and placeholder for challenging other path holder.
// Most common cases is that caller of the function implements the closure where
// it calls other party over the network to sign the challenge which is readily
// build and randomized.
func (p Path) Challenge(pinCode int, f func(d []byte) key.Signature) bool {
	pubKey := p.LastEdge().Public()
	challengeEdge, sigEdge := NewVerifyEdge(pinCode)
	signature := f(challengeEdge.Bytes())
	return signature.Verify(pubKey, sigEdge.Bytes())
}

func (p Path) FirstEdge() Edge {
	return p[0]
}

func (p Path) LastEdge() Edge {
	l := len(p)
	assert.That(l > 0, "Edges is too short")
	return p[l-1]
}

func (p Path) secondLastEdge() Edge {
	l := len(p)
	assert.That(l > 1, "Edges is too short")
	return p[l-2]
}
