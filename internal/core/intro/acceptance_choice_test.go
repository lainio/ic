package intro_test

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

var errDifferentAcceptance = errors.New("another introduction is selected")

// localAcceptanceChoice is test scaffolding used serially through one instance.
// It remembers an exact signed proposal before asking the child to sign, even
// if signing fails. It has no change-of-mind, persistence, or recovery policy.
// Another instance or direct key use bypasses it; it changes no modeled state
// and receiving its acceptance must not automatically create Known.
type localAcceptanceChoice struct {
	child        key.Handle
	expectedRoot key.Public
	selected     intro.Path
	acceptance   key.Signature
}

func newLocalAcceptanceChoice(
	child key.Handle, expectedRoot key.Public,
) *localAcceptanceChoice {
	return &localAcceptanceChoice{
		child: child, expectedRoot: slices.Clone(expectedRoot),
	}
}

func (c *localAcceptanceChoice) accept(
	offered intro.Path, expectedParent key.Public,
) (acceptance key.Signature, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err)

	candidate := offered.Clone()
	if c.selected != nil &&
		!bytes.Equal(candidate.Bytes(), c.selected.Bytes()) {
		return nil, errDifferentAcceptance
	}

	assert.SLonger(candidate, 1, intro.ErrBadAcceptance)
	try.To(candidate.ProveFromRoot(c.expectedRoot))
	assert.SNotEmpty(expectedParent, intro.ErrWrongParent)
	assert.That(
		candidate.SecondLastEdge().Public().Equal(expectedParent),
		intro.ErrWrongParent,
	)

	if c.selected == nil {
		assert.INotNil(c.child, intro.ErrBadAcceptance)
		public := candidate.LastEdge().Public()
		assert.SNotEmpty(public, intro.ErrBadAcceptance)
		signerPublic := try.To1(c.child.CBORPublicKey())
		assert.That(public.Equal(signerPublic), intro.ErrBadAcceptance)

		c.selected = candidate
	}
	if c.acceptance != nil {
		return slices.Clone(c.acceptance), nil
	}

	// Keep the selection on error: the signer may already have performed work.
	signed := try.To1(c.selected.SignAcceptanceFor(
		c.child, c.expectedRoot, expectedParent,
	))
	c.acceptance = slices.Clone(signed)

	return slices.Clone(c.acceptance), nil
}

func TestLocalAcceptanceChoiceSelection(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	assert.NoError(direct.ProveFromRoot(expectedRoot))
	assert.NoError(indirect.ProveFromRoot(expectedRoot))
	signer := &acceptanceHandle{Handle: alice}
	choice := newLocalAcceptanceChoice(signer, expectedRoot)

	acceptance := try.To1(choice.accept(direct, expectedRoot))
	assert.Equal(signer.signCalls, 1)
	assert.NoError(direct.VerifyAcceptance(acceptance))
	retry := try.To1(choice.accept(direct.Clone(), expectedRoot))
	assert.DeepEqual(retry, acceptance)
	assert.Equal(signer.signCalls, 1)

	rejected, err := choice.accept(direct, bobPublic)
	assert.ErrorIs(err, intro.ErrWrongParent)
	assert.SNil(rejected)
	assert.Equal(signer.signCalls, 1)
	rejected, err = choice.accept(indirect, bobPublic)
	assert.ErrorIs(err, errDifferentAcceptance)
	assert.ErrorIsNot(err, intro.ErrWrongParent)
	assert.SNil(rejected)
	assert.Equal(signer.signCalls, 1)

	revised := direct.Clone()
	last := &revised[len(revised)-1]
	last.Body.Options.Position++
	last.ParentSig = try.To1(root.Sign(last.ExcludeBytes()))
	assert.NoError(revised.ProveFromRoot(expectedRoot))
	assert.DeepEqual(
		revised.LastEdge().Body.Child,
		direct.LastEdge().Body.Child,
	)
	assert.That(revised.SecondLastEdge().Public().Equal(expectedRoot))
	assert.ThatNot(bytes.Equal(revised.Bytes(), direct.Bytes()))

	rejected, err = choice.accept(revised, expectedRoot)
	assert.ErrorIs(err, errDifferentAcceptance)
	assert.SNil(rejected)
	assert.Equal(signer.signCalls, 1)
	assert.DeepEqual(choice.selected.Bytes(), direct.Bytes())
	assert.NoError(choice.selected.VerifyAcceptance(choice.acceptance))
	assert.DeepEqual(choice.acceptance, acceptance)
}

func TestLocalAcceptanceChoiceInvalidFirstOffer(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	cause := errors.New("key unavailable")

	for _, tc := range []struct {
		name   string
		signer acceptanceHandle
		parent key.Public
		want   error
	}{
		{"wrong parent", acceptanceHandle{Handle: alice},
			bobPublic, intro.ErrWrongParent},
		{"wrong child", acceptanceHandle{Handle: bob},
			expectedRoot, intro.ErrBadAcceptance},
		{"key access", acceptanceHandle{
			Handle: alice, publicErr: fmt.Errorf("public key: %w", cause),
		}, expectedRoot, cause},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			choice := newLocalAcceptanceChoice(&tc.signer, expectedRoot)
			rejected, err := choice.accept(direct, tc.parent)
			assert.ErrorIs(err, tc.want)
			assert.SNil(rejected)
			assert.SNil(choice.selected)
			assert.SNil(choice.acceptance)
			assert.Equal(tc.signer.signCalls, 0)

			tc.signer.Handle, tc.signer.publicErr = alice, nil
			acceptance := try.To1(choice.accept(indirect, bobPublic))
			assert.Equal(tc.signer.signCalls, 1)
			assert.NoError(indirect.VerifyAcceptance(acceptance))
		})
	}
}

func TestLocalAcceptanceChoiceSigningErrorRetry(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	assert.NoError(direct.ProveFromRoot(expectedRoot))
	assert.NoError(indirect.ProveFromRoot(expectedRoot))
	cause := errors.New("signing unavailable")
	// Fault injection exercises this policy; it is not a current signer defect.
	signer := &acceptanceHandle{
		Handle: alice, signErr: fmt.Errorf("sign: %w", cause),
	}
	choice := newLocalAcceptanceChoice(signer, expectedRoot)

	failed, err := choice.accept(direct, expectedRoot)
	assert.ErrorIs(err, cause)
	assert.SNil(failed)
	assert.Equal(signer.signCalls, 1)
	assert.DeepEqual(choice.selected.Bytes(), direct.Bytes())
	assert.SNil(choice.acceptance) // Partial error bytes must not be cached.

	rejected, err := choice.accept(indirect, bobPublic)
	assert.ErrorIs(err, errDifferentAcceptance)
	assert.SNil(rejected)
	assert.Equal(signer.signCalls, 1)
	assert.DeepEqual(choice.selected.Bytes(), direct.Bytes())
	assert.SNil(choice.acceptance)

	signer.signErr = nil
	acceptance := try.To1(choice.accept(direct.Clone(), expectedRoot))
	assert.Equal(signer.signCalls, 2)
	assert.NoError(direct.VerifyAcceptance(acceptance))
	retry := try.To1(choice.accept(direct.Clone(), expectedRoot))
	assert.Equal(signer.signCalls, 2)
	assert.DeepEqual(retry, acceptance)
	assert.NoError(choice.selected.VerifyAcceptance(retry))
}

func TestLocalAcceptanceChoiceOwnership(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	expectedParent := slices.Clone(expectedRoot)
	direct := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	original := direct.Clone()
	signer := &acceptanceHandle{Handle: alice}
	choice := newLocalAcceptanceChoice(signer, expectedRoot)
	expectedRoot[0] ^= 1

	acceptance := try.To1(choice.accept(direct, expectedParent))
	saved := slices.Clone(acceptance)
	direct[1].ParentSig[0] ^= 1
	acceptance[0] ^= 1
	assert.DeepEqual(choice.selected.Bytes(), original.Bytes())

	rejected, err := choice.accept(direct, expectedParent)
	assert.ErrorIs(err, errDifferentAcceptance)
	assert.SNil(rejected)
	retry := try.To1(choice.accept(original, expectedParent))
	assert.DeepEqual(retry, saved)
	assert.NoError(original.VerifyAcceptance(retry))
	retry[0] ^= 1
	assert.DeepEqual(try.To1(choice.accept(original, expectedParent)), saved)
	assert.Equal(signer.signCalls, 1)
}
