package intro

import (
	"bytes"

	"github.com/fxamacker/cbor/v2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

// Edge is the graph edge in our introduction tree (IT). [Child.Public] is the
// identity ID, we call it in the docs IDK. [child.ID] is more a data storage
// used to handle key pair state.
type EdgeBody struct {
	Version uint64   `cbor:"0,keyasint"`
	Prev    key.Hash `cbor:"1,keyasint"`
	Child   key.Info `cbor:"2,keyasint"`

	Options `cbor:"3,keyasint,omitempty"`
}

type Edge struct {
	EdgeBody  `cbor:"0,keyasint"`
	ParentSig key.Signature `cbor:"1,keyasint"`
}

// NewVerifyEdge returns two randomized Edges that can be used for
// verification or challenges, etc. [theirs] is for challenge, i.e. pinCode
// is unknown aka 0, and [ours] is for actual signing where pincode is set
// to Position field. By this we can send pincode by other, thru safe channel
// and out-of-band.
func NewVerifyEdge(pinCode int) (theirs Edge, ours Edge) {
	challengeEdge := Edge{EdgeBody: EdgeBody{
		Prev:  key.Hash(key.RandSlice(32)),
		Child: key.RandInfo(32),
	}}
	return challengeEdge, Edge{EdgeBody: EdgeBody{
		Prev:  challengeEdge.Prev,
		Child: challengeEdge.Child,
		Options: Options{
			Position: pinCode,
		},
	}}
}

// NewEdgeFromData constructor from raw CBOR data block.
func NewEdgeFromData(d []byte) (b Edge) {
	r := bytes.NewReader(d)
	dec := cbor.NewDecoder(r)
	try.To(dec.Decode(&b))
	return b
}

// Bytes return marshallel bytes of the Edge.
func (b Edge) Bytes() []byte {
	var buf bytes.Buffer
	enc := cbor.NewEncoder(&buf)
	try.To(enc.Encode(b))
	return buf.Bytes()
}

func (b Edge) ExcludeBytes() []byte {
	return b.excludeSign().Bytes()
}

func (b Edge) excludeSign() Edge {
	newEdge := Edge{EdgeBody: EdgeBody{
		Prev:  b.Prev,
		Child: b.Child,
		Options: Options{
			Position: b.Position,
			Rotation: b.Rotation,
		},
	}}
	return newEdge
}

func EqualEdges(b1, b2 Edge) bool {
	return b1.Prev == b2.Prev &&
		bytes.Equal(b1.ID(), b2.ID()) &&
		bytes.Equal(b1.Public(), b2.Public()) &&
		bytes.Equal(b1.ParentSig, b2.ParentSig) &&
		b1.Position == b2.Position &&
		b1.Rotation == b2.Rotation
}

func (b Edge) VerifySignature(invitersPubKey key.Public) bool {
	return b.ParentSig.Verify(
		invitersPubKey,
		b.ExcludeBytes(),
	)
}

func (b Edge) ID() key.ID {
	return b.Child.ID
}

func (b Edge) Public() key.Public {
	return b.Child.Public
}
