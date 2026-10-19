package intro_test

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

func TestParsePathRoundTrip(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := try.To1(root.CBORPublicKey())
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	encoded := path.Bytes()
	before := append([]byte(nil), encoded...)

	decoded, err := intro.ParsePath(encoded)
	assert.NoError(err)
	assert.SLen(decoded, 2)
	assert.DeepEqual(decoded, path)
	assert.DeepEqual(decoded.Bytes(), before)
	assert.NoError(decoded.ProveFromRoot(expectedRoot))

	assert.DeepEqual(encoded, before)
	assert.DeepEqual(path.Bytes(), before)
}

func TestParsePathRejectedResult(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	encoded := path.Bytes()
	assert.SLonger(encoded, 0)
	assert.Equal(encoded[0], byte(0x82))
	alternate := append([]byte{0x98, 0x02}, encoded[1:]...)
	before := append([]byte(nil), alternate...)

	// The generic strict decoder populates its destination before rejection.
	var temporary intro.Path
	err := wire.UnmarshalCanonical(&temporary, alternate)
	assert.ErrorIs(err, wire.ErrNonCanonicalCBOR)
	assert.DeepEqual(temporary, path)

	decoded, err := intro.ParsePath(alternate)
	assert.ErrorIs(err, wire.ErrNonCanonicalCBOR)
	assert.SNil(decoded)
	assert.DeepEqual(alternate, before)
}

func TestParsePathMalformedInput(t *testing.T) {
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
			decoded, err := intro.ParsePath(tc.data)
			assert.Error(err)
			assert.ErrorIsNot(err, wire.ErrNonCanonicalCBOR)
			assert.SNil(decoded)

			assert.DeepEqual(tc.data, before)
		})
	}
	assert.DeepEqual(encoded, encodedBefore)
}

func TestParsePathBadSignature(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := try.To1(root.CBORPublicKey())
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	assert.NoError(path.ProveFromRoot(expectedRoot))

	path[1].Body.Options.Position++
	encoded := path.Bytes()
	before := append([]byte(nil), encoded...)
	decoded, err := intro.ParsePath(encoded)
	assert.NoError(err)
	assert.DeepEqual(decoded, path)

	assert.ErrorIs(decoded.ProveFromRoot(expectedRoot), intro.ErrBadSignature)
	assert.DeepEqual(encoded, before)
}

func TestParsePathEmptyPath(t *testing.T) {
	defer assert.PushTester(t)()

	expectedRoot := try.To1(key.New().CBORPublicKey())
	path := intro.Path{}
	encoded := path.Bytes()
	before := append([]byte(nil), encoded...)

	decoded, err := intro.ParsePath(encoded)
	assert.NoError(err)
	assert.DeepEqual(decoded, path)
	assert.DeepEqual(decoded.Bytes(), before)

	assert.ErrorIs(decoded.ProveFromRoot(expectedRoot), intro.ErrWrongAnchor)
	assert.DeepEqual(encoded, before)
}
