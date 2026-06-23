package intro

import (
	"bytes"

	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

// Edge is the graph edge in our introduction tree (IT). [Child.Public] is the
// identity ID, we call it in the docs IDK. [child.ID] is more a data storage
// used to handle key pair state.
type EdgeBody struct {
	Version uint64   `cbor:"0,keyasint"`
	Prev    key.Hash `cbor:"1,keyasint"`
	Child   key.Info `cbor:"2,keyasint"`

	Options Options `cbor:"3,keyasint,omitempty"`
}

type Edge struct {
	Body      EdgeBody      `cbor:"0,keyasint"`
	ParentSig key.Signature `cbor:"1,keyasint"`
}

// NewVerifyEdge returns two randomized Edges that can be used for
// verification or challenges, etc. [theirs] is for challenge, i.e. pinCode
// is unknown aka 0, and [ours] is for actual signing where pincode is set
// to Position field. By this we can send pincode by other, thru safe channel
// and out-of-band.
func NewVerifyEdge(pinCode int) (theirs Edge, ours Edge) {
	challengeEdge := Edge{Body: EdgeBody{
		Version: EdgeVersion,
		Prev:    key.Hash(key.RandSlice(32)),
		Child:   key.RandInfo(32),
	}}
	return challengeEdge, Edge{Body: EdgeBody{
		Version: EdgeVersion,
		Prev:    challengeEdge.Body.Prev,
		Child:   challengeEdge.Body.Child,
		Options: Options{
			Position: pinCode,
		},
	}}
}

// NewEdgeFromData constructor from raw CBOR data block.
func NewEdgeFromData(d []byte) (b Edge) {
	return wire.FromData[Edge](d)
}

// Bytes return marshallel bytes of the Edge.
func (e Edge) Bytes() []byte {
	return wire.TryMarshal(e)
}

func (e Edge) ExcludeBytes() []byte {
	return e.excludeSign().Bytes()
}

func (e Edge) excludeSign() Edge {
	newEdge := Edge{Body: EdgeBody{
		Version: EdgeVersion,
		Prev:    e.Body.Prev,
		Child:   e.Body.Child,
		Options: Options{
			Position: e.Body.Options.Position,
			Rotation: e.Body.Options.Rotation,
		},
	}}
	return newEdge
}

func EqualEdges(b1, b2 Edge) bool {
	return b1.Body.Prev == b2.Body.Prev &&
		bytes.Equal(b1.ID(), b2.ID()) &&
		bytes.Equal(b1.Public(), b2.Public()) &&
		bytes.Equal(b1.ParentSig, b2.ParentSig) &&
		b1.Body.Options.Position == b2.Body.Options.Position &&
		b1.Body.Options.Rotation == b2.Body.Options.Rotation &&
		b1.Body.Version == b2.Body.Version
}

func (e Edge) VerifySignature2(invitersPubKey key.Public) bool {
	return e.ParentSig.Verify(
		invitersPubKey,
		e.Bytes(),
	)
}

func (e Edge) VerifySignature(invitersPubKey key.Public) bool {
	return e.ParentSig.Verify(
		invitersPubKey,
		e.ExcludeBytes(),
	)
}

func (e Edge) ID() key.ID {
	return e.Body.Child.ID
}

func (e Edge) Public() key.Public {
	return e.Body.Child.Public
}
