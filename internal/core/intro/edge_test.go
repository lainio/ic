package intro

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

func TestEdge_all(t *testing.T) {
	defer assert.PushTester(t)()
	t.Run("test new verify edge construction", testNewVerifyEdge)
	t.Run("test signing", testSigning)
}

func testNewVerifyEdge(t *testing.T) {
	const (
		pincode = 1234
		size    = 194 // TODO: can be wrong quite soon
	)
	defer assert.PushTester(t)()

	cb, ours := NewVerifyEdge(pincode)
	assert.Equal(cb.Position, 0)
	assert.Equal(ours.Position, pincode)
	assert.SLen(cb.Bytes(), size)

}

func testSigning(t *testing.T) {
	defer assert.PushTester(t)()

	parent, child := key.New(), key.New()

	newEdge := Edge{EdgeBody: EdgeBody{
		Version: EdgeVersion,
		Prev:    AnchorDigest(),
		Child:   key.InfoFromHandle(child),
	}}
	// TODO: these options are only ones that work now! Fix with the 
	newEdge.Options = *NewOptions(WithRotation(), WithPosition(1))
	newEdge.ParentSig = try.To1(parent.Sign(newEdge.Bytes()))

	pubK := try.To1(parent.CBORPublicKey())

	ok := newEdge.ParentSig.Verify(
		pubK,
		newEdge.ExcludeBytes(), // TODO: use edge EdgeBody!
	)
	assert.That(ok)
}
