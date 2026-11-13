package intro_test

import (
	"bytes"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

func init() {
	// Suppress all the panic and error-handling logging noiee from this
	// package we don't want them especially with the benchmar.
	err2.SetTracers(nil)
}

// One operation encodes one signed introduction edge as deterministic CBOR.
// Key generation, introduction signing and fixture checks are outside timing;
// each timed operation includes comparing its complete bytes to the fixture.
func BenchmarkEdgeCanonicalEncoding(b *testing.B) {
	defer assert.PushTester(b)()
	parent, child := key.New(), key.New()
	parentPublic := key.Public(try.To1(parent.CBORPublicKey()))
	path := intro.New(key.Info{Public: parentPublic}).Introduce(
		parent, key.Info{Public: try.To1(child.CBORPublicKey())},
	)
	assert.NoError(path.ProveFromRoot(parentPublic))
	edge := path.LastEdge()
	want := edge.Bytes()
	var decoded intro.Edge
	try.To(wire.UnmarshalCanonical(&decoded, want))
	assert.DeepEqual(decoded, edge)

	b.ReportAllocs()

	for b.Loop() {
		assert.That(bytes.Equal(edge.Bytes(), want))
	}
	b.StopTimer()
}

// One operation verifies the parent signature on an introduction edge.
// This includes unsigned-edge encoding, public-key decoding and hashing;
// key generation, signing and positive/negative fixture checks are excluded.
func BenchmarkEdgeVerifySignature(b *testing.B) {
	defer assert.PushTester(b)()
	parent, child := key.New(), key.New()
	parentPublic := key.Public(try.To1(parent.CBORPublicKey()))
	path := intro.New(key.Info{Public: parentPublic}).Introduce(
		parent, key.Info{Public: try.To1(child.CBORPublicKey())},
	)
	assert.NoError(path.ProveFromRoot(parentPublic))
	edge := path.LastEdge()
	assert.That(edge.VerifySignature(parentPublic))
	modified := intro.NewEdgeFromData(edge.Bytes())
	modified.Body.Options.Position++
	assert.ThatNot(modified.VerifySignature(parentPublic))

	b.ReportAllocs()

	for b.Loop() {
		assert.That(edge.VerifySignature(parentPublic))
	}
	b.StopTimer()
}
