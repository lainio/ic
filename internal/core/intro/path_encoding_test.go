package intro_test

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

func TestPathEncodingAlternateArrayHead(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := try.To1(root.CBORPublicKey())
	expectedBefore := append([]byte(nil), expectedRoot...)
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	assert.SLen(path, 2)
	for _, edge := range path {
		assert.DeepEqual(edge.Body.Options, intro.Options{})
	}
	encoded := path.Bytes()
	encodedBefore := append([]byte(nil), encoded...)
	assert.SLonger(encoded, 0)
	assert.Equal(encoded[0], byte(0x82))

	var canonical intro.Path
	assert.NoError(wire.UnmarshalCanonical(&canonical, encoded))
	assert.DeepEqual(canonical, path)

	// Same two-entry array, but with a nonminimal length encoding.
	// Only the array head changes; all signed content stays intact.
	alternate := append([]byte{0x98, 0x02}, encoded[1:]...)
	alternateBefore := append([]byte(nil), alternate...)
	assert.SLen(alternate, len(encoded)+1)
	assert.DeepEqual(alternate[2:], encoded[1:])

	var decoded, decodedAlternate intro.Path
	assert.NoError(wire.Unmarshal(&decoded, encoded))
	assert.NoError(wire.Unmarshal(&decodedAlternate, alternate))
	assert.DeepEqual(decoded, path)
	assert.DeepEqual(decodedAlternate, decoded)
	// Both reproduce the original bytes, which are shorter than alternate.
	assert.DeepEqual(decoded.Bytes(), encoded)
	assert.DeepEqual(decodedAlternate.Bytes(), encoded)
	assert.NoError(decoded.ProveFromRoot(expectedRoot))
	assert.NoError(decodedAlternate.ProveFromRoot(expectedRoot))

	// Discard the fresh destination: strict decoding may populate it on error.
	err := wire.UnmarshalCanonical(new(intro.Path), alternate)
	assert.ErrorIs(err, wire.ErrNonCanonicalCBOR)
	assert.DeepEqual(encoded, encodedBefore)
	assert.DeepEqual(alternate, alternateBefore)
	assert.DeepEqual(expectedRoot, expectedBefore)
	assert.DeepEqual(path.Bytes(), encodedBefore)
}

func TestPathEncodingMalformedInput(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	encoded := path.Bytes()
	encodedBefore := append([]byte(nil), encoded...)
	trailing := append(append([]byte(nil), encoded...), 0x00)

	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"empty input", nil},
		{"truncated input", encoded[:len(encoded)-1]},
		{"trailing CBOR item", trailing},
		{"wrong top-level type", []byte{0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			before := append([]byte(nil), tc.data...)
			assert.Error(wire.Unmarshal(new(intro.Path), tc.data))
			assert.Error(wire.UnmarshalCanonical(new(intro.Path), tc.data))

			assert.DeepEqual(tc.data, before)
		})
	}
	assert.DeepEqual(encoded, encodedBefore)
	assert.DeepEqual(path.Bytes(), encodedBefore)
}

func TestPathEncodingCanonicalIsNotProof(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := try.To1(root.CBORPublicKey())
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	assert.NoError(path.ProveFromRoot(expectedRoot))
	encoded := path.Bytes()
	encodedBefore := append([]byte(nil), encoded...)

	modified := intro.NewPathFromData(encoded)
	modified[1].Body.Options.Position++
	modifiedBytes := modified.Bytes()
	modifiedBefore := append([]byte(nil), modifiedBytes...)
	var decoded intro.Path
	assert.NoError(wire.UnmarshalCanonical(&decoded, modifiedBytes))
	assert.DeepEqual(decoded, modified)
	assert.DeepEqual(decoded[1].ParentSig, path[1].ParentSig)

	assert.ErrorIs(decoded.ProveFromRoot(expectedRoot), intro.ErrBadSignature)
	assert.DeepEqual(modifiedBytes, modifiedBefore)
	assert.DeepEqual(encoded, encodedBefore)
	assert.DeepEqual(path.Bytes(), encodedBefore)
}
