package intro_test

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

func TestPathSignAcceptanceForWrongParent(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPath := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(bob),
	)
	indirect := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	assert.NoError(indirect.ProveFromRoot(expectedRoot))
	before, rootBefore := indirect.Bytes(), slices.Clone(expectedRoot)

	for _, tc := range []struct {
		name   string
		parent key.Public
	}{
		{"root instead of Bob", expectedRoot},
		{"empty parent", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			signer := &acceptanceHandle{Handle: alice}
			parentBefore := slices.Clone(tc.parent)

			acceptance, err := indirect.SignAcceptanceFor(
				signer, expectedRoot, tc.parent,
			)
			assert.ErrorIs(err, intro.ErrWrongParent)
			assert.SNil(acceptance)
			assert.Equal(signer.signCalls, 0)
			assert.DeepEqual(indirect.Bytes(), before)
			assert.DeepEqual(expectedRoot, rootBefore)
			assert.DeepEqual(tc.parent, parentBefore)
		})
	}
}

func TestPathSignAcceptanceForCorrectProposals(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, key.InfoFromHandle(alice))

	for _, tc := range []struct {
		name   string
		path   intro.Path
		parent key.Public
	}{
		{"root parent", direct, expectedRoot},
		{"descendant parent", indirect, bobPublic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			assert.NoError(tc.path.ProveFromRoot(expectedRoot))
			before := tc.path.Bytes()
			rootBefore := slices.Clone(expectedRoot)
			parentBefore := slices.Clone(tc.parent)
			signer := &acceptanceHandle{Handle: alice}

			acceptance, err := tc.path.SignAcceptanceFor(
				signer, expectedRoot, tc.parent,
			)
			assert.NoError(err)
			assert.Equal(signer.signCalls, 1)
			assert.NoError(tc.path.VerifyAcceptance(acceptance))
			assert.DeepEqual(tc.path.Bytes(), before)
			assert.DeepEqual(expectedRoot, rootBefore)
			assert.DeepEqual(tc.parent, parentBefore)
		})
	}
}

func TestPathSignAcceptanceForInvalidProof(t *testing.T) {
	defer assert.PushTester(t)()

	root, otherRoot, alice := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	otherPublic := key.Public(try.To1(otherRoot.CBORPublicKey()))
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	assert.NoError(path.ProveFromRoot(expectedRoot))
	wrongLink := try.To1(intro.ParsePath(path.Bytes()))
	last := &wrongLink[len(wrongLink)-1]
	last.Body.Prev[0] ^= 1
	last.ParentSig = try.To1(root.Sign(last.ExcludeBytes()))
	assert.That(wrongLink.LastEdge().VerifySignature(expectedRoot))
	assert.ErrorIs(wrongLink.ProveFromRoot(expectedRoot), intro.ErrBrokenPath)

	foreign := intro.New(key.InfoFromHandle(otherRoot)).Introduce(
		otherRoot, key.InfoFromHandle(alice),
	)
	assert.NoError(foreign.ProveFromRoot(otherPublic))
	assert.That(foreign.LastEdge().VerifySignature(otherPublic))
	assert.ErrorIs(foreign.ProveFromRoot(expectedRoot), intro.ErrWrongRoot)
	rootBefore := slices.Clone(expectedRoot)

	for _, tc := range []struct {
		name string
		path intro.Path
		want error
	}{
		{"signed wrong predecessor", wrongLink, intro.ErrBrokenPath},
		{"valid foreign root", foreign, intro.ErrWrongRoot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			before := tc.path.Bytes()
			signer := &acceptanceHandle{Handle: alice}

			acceptance, err := tc.path.SignAcceptanceFor(
				signer, expectedRoot, expectedRoot,
			)
			assert.ErrorIs(err, tc.want)
			assert.SNil(acceptance)
			assert.Equal(signer.signCalls, 0)
			assert.DeepEqual(tc.path.Bytes(), before)
			assert.DeepEqual(expectedRoot, rootBefore)
		})
	}
}

func TestPathSignAcceptanceForMissingShape(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	rootBefore := slices.Clone(expectedRoot)

	for _, tc := range []struct {
		name string
		path intro.Path
	}{
		{"nil path", nil},
		{"root only", intro.New(key.InfoFromHandle(root))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			before := tc.path.Bytes()
			signer := &acceptanceHandle{Handle: alice}

			acceptance, err := tc.path.SignAcceptanceFor(
				signer, expectedRoot, expectedRoot,
			)
			assert.ErrorIs(err, intro.ErrBadAcceptance)
			assert.SNil(acceptance)
			assert.Equal(signer.signCalls, 0)
			assert.DeepEqual(tc.path.Bytes(), before)
			assert.DeepEqual(expectedRoot, rootBefore)
		})
	}
}

func TestPathSignAcceptanceForDelegatedFailures(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	assert.NoError(path.ProveFromRoot(expectedRoot))
	before, rootBefore := path.Bytes(), slices.Clone(expectedRoot)
	cause := errors.New("key unavailable")

	for _, tc := range []struct {
		name      string
		signer    acceptanceHandle
		want      error
		signCalls int
	}{
		{"wrong child", acceptanceHandle{Handle: bob}, intro.ErrBadAcceptance, 0},
		{"public key access", acceptanceHandle{
			Handle: alice, publicErr: fmt.Errorf("public key: %w", cause),
		}, cause, 0},
		{"partial signature and error", acceptanceHandle{
			Handle: alice, signErr: fmt.Errorf("sign: %w", cause),
		}, cause, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			acceptance, err := path.SignAcceptanceFor(
				&tc.signer, expectedRoot, expectedRoot,
			)
			assert.ErrorIs(err, tc.want)
			assert.ErrorIsNot(err, intro.ErrWrongParent)
			assert.SNil(acceptance)
			assert.Equal(tc.signer.signCalls, tc.signCalls)
			assert.DeepEqual(path.Bytes(), before)
			assert.DeepEqual(expectedRoot, rootBefore)
		})
	}
}
