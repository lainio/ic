package intro_test

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

func TestPathRootForeignRoot(t *testing.T) {
	defer assert.PushTester(t)()

	root, otherRoot, alice := key.New(), key.New(), key.New()
	rootInfo := key.InfoFromHandle(root)
	otherRootInfo := key.InfoFromHandle(otherRoot)
	aliceInfo := key.InfoFromHandle(alice)
	expectedRoot := rootInfo.Public
	assert.ThatNot(expectedRoot.Equal(otherRootInfo.Public))

	path := intro.New(rootInfo).Introduce(root, aliceInfo)
	otherPath := intro.New(otherRootInfo).Introduce(otherRoot, aliceInfo)
	assert.DeepEqual(path[1].Body.Child, otherPath[1].Body.Child)
	assert.Equal(path[0].Body.Prev, intro.AnchorDigest())
	assert.Equal(otherPath[0].Body.Prev, intro.AnchorDigest())
	assert.NoError(path.Prove())
	assert.NoError(otherPath.Prove())
	encoded, otherEncoded := path.Bytes(), otherPath.Bytes()
	expectedBefore := append(key.Public(nil), expectedRoot...)

	assert.NoError(path.ProveFromRoot(expectedRoot))
	err := otherPath.ProveFromRoot(expectedRoot)
	assert.Error(err,
		"a valid path from X must be rejected when the expected root is R")
	assert.ErrorIs(err, intro.ErrWrongRoot)
	assert.ErrorIsNot(err, intro.ErrWrongAnchor)
	assert.DeepEqual(path.Bytes(), encoded)
	assert.DeepEqual(otherPath.Bytes(), otherEncoded)
	assert.DeepEqual(expectedRoot, expectedBefore)
}

func TestPathRootMatching(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	rootInfo := key.InfoFromHandle(root)
	expectedRoot := append(key.Public(nil), rootInfo.Public...)
	expectedBefore := append(key.Public(nil), expectedRoot...)
	assert.DeepEqual(expectedRoot, rootInfo.Public)
	assert.NotEqual(&expectedRoot[0], &rootInfo.Public[0])

	rootPath := intro.New(rootInfo)
	path := rootPath.Introduce(root, key.InfoFromHandle(alice))
	path = path.Introduce(alice, key.InfoFromHandle(bob))
	for _, tc := range []struct {
		name string
		path intro.Path
	}{
		{"root only", rootPath},
		{"descendants", path},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			encoded := tc.path.Bytes()
			decoded := intro.NewPathFromData(encoded)
			assert.NoError(tc.path.ProveFromRoot(expectedRoot))
			assert.NoError(decoded.ProveFromRoot(expectedRoot))

			assert.DeepEqual(tc.path.Bytes(), encoded)
			assert.DeepEqual(decoded.Bytes(), encoded)
			assert.DeepEqual(expectedRoot, expectedBefore)
		})
	}
}

func TestPathRootEmptyExpectedRoot(t *testing.T) {
	defer assert.PushTester(t)()

	path := intro.New(key.InfoFromHandle(key.New()))
	encoded := path.Bytes()
	for _, tc := range []struct {
		name string
		root key.Public
	}{
		{"nil", nil},
		{"empty", key.Public{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			err := path.ProveFromRoot(tc.root)
			assert.Error(err)
			assert.ErrorIs(err, intro.ErrWrongRoot)
			assert.ErrorIsNot(err, intro.ErrWrongAnchor)
			assert.DeepEqual(path.Bytes(), encoded)
			assert.SEmpty(tc.root)
		})
	}
}

func TestPathRootEmptyPath(t *testing.T) {
	defer assert.PushTester(t)()

	expectedRoot := key.InfoFromHandle(key.New()).Public
	expectedBefore := append(key.Public(nil), expectedRoot...)
	for _, tc := range []struct {
		name string
		path intro.Path
	}{
		{"nil", nil},
		{"empty", intro.Path{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			encoded := tc.path.Bytes()
			for _, root := range []key.Public{expectedRoot, nil, {}} {
				err := tc.path.ProveFromRoot(root)
				assert.Error(err)
				assert.ErrorIs(err, intro.ErrWrongAnchor)
				assert.ErrorIsNot(err, intro.ErrWrongRoot)
			}

			assert.DeepEqual(tc.path.Bytes(), encoded)
			assert.DeepEqual(expectedRoot, expectedBefore)
		})
	}
}

func TestPathRootStructuralErrors(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	rootInfo := key.InfoFromHandle(root)
	expectedRoot := rootInfo.Public
	expectedBefore := append(key.Public(nil), expectedRoot...)
	path := intro.New(rootInfo).Introduce(root, key.InfoFromHandle(alice))
	assert.NoError(path.ProveFromRoot(expectedRoot))
	encoded := path.Bytes()

	wrongLink := intro.NewPathFromData(encoded)
	wrongLink[1].Body.Prev[0] ^= 1
	wrongLink[1].ParentSig = try.T1(root.Sign(wrongLink[1].ExcludeBytes()))(
		"signing a wrong predecessor under the expected root",
	)
	assert.That(wrongLink[1].VerifySignature(expectedRoot))

	badSignature := intro.NewPathFromData(encoded)
	sig := badSignature[1].ParentSig
	sig[len(sig)-1] ^= 1
	assert.ThatNot(badSignature[1].VerifySignature(expectedRoot))

	for _, tc := range []struct {
		name string
		path intro.Path
		want error
	}{
		{"signed wrong predecessor", wrongLink, intro.ErrBrokenPath},
		{"altered signature", badSignature, intro.ErrBadSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			before := tc.path.Bytes()
			structuralErr := tc.path.Prove()
			assert.Error(structuralErr)
			assert.ErrorIs(structuralErr, tc.want)
			err := tc.path.ProveFromRoot(expectedRoot)
			assert.Error(err)
			assert.ErrorIs(err, tc.want)
			assert.ErrorIsNot(err, intro.ErrWrongRoot)

			assert.DeepEqual(tc.path.Bytes(), before)
			assert.DeepEqual(expectedRoot, expectedBefore)
		})
	}
	assert.DeepEqual(path.Bytes(), encoded)
}
