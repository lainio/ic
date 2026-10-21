package intro_test

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

func TestAcceptanceChoiceSelection(t *testing.T) {
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
	choice := intro.NewAcceptanceChoice(signer, expectedRoot)

	acceptance := try.To1(choice.Accept(direct, expectedRoot))
	assert.Equal(signer.signCalls, 1)
	assert.NoError(direct.VerifyAcceptance(acceptance))
	retry := try.To1(choice.Accept(direct.Clone(), expectedRoot))
	assert.DeepEqual(retry, acceptance)
	assert.Equal(signer.signCalls, 1)

	rejected, err := choice.Accept(direct, bobPublic)
	assert.ErrorIs(err, intro.ErrWrongParent)
	assert.SNil(rejected)
	assert.Equal(signer.signCalls, 1)
	rejected, err = choice.Accept(indirect, bobPublic)
	assert.ErrorIs(err, intro.ErrDifferentAcceptance)
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

	rejected, err = choice.Accept(revised, expectedRoot)
	assert.ErrorIs(err, intro.ErrDifferentAcceptance)
	assert.SNil(rejected)
	assert.Equal(signer.signCalls, 1)

	retry = try.To1(choice.Accept(direct.Clone(), expectedRoot))
	assert.DeepEqual(retry, acceptance)
	assert.NoError(direct.VerifyAcceptance(retry))
	assert.Equal(signer.signCalls, 1)
}

func TestAcceptanceChoiceInvalidFirstOffer(t *testing.T) {
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

			choice := intro.NewAcceptanceChoice(&tc.signer, expectedRoot)
			rejected, err := choice.Accept(direct, tc.parent)
			assert.ErrorIs(err, tc.want)
			assert.SNil(rejected)
			assert.Equal(tc.signer.signCalls, 0)

			// A different valid offer proves the failed attempt chose nothing.
			tc.signer.Handle, tc.signer.publicErr = alice, nil
			acceptance := try.To1(choice.Accept(indirect, bobPublic))
			assert.Equal(tc.signer.signCalls, 1)
			assert.NoError(indirect.VerifyAcceptance(acceptance))
		})
	}
}

func TestAcceptanceChoiceSigningErrorRetry(t *testing.T) {
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
	choice := intro.NewAcceptanceChoice(signer, expectedRoot)

	failed, err := choice.Accept(direct, expectedRoot)
	assert.ErrorIs(err, cause)
	assert.SNil(failed)
	assert.Equal(signer.signCalls, 1)

	rejected, err := choice.Accept(indirect, bobPublic)
	assert.ErrorIs(err, intro.ErrDifferentAcceptance)
	assert.SNil(rejected)
	assert.Equal(signer.signCalls, 1)

	// Explicit retry must sign again, not reuse the partial error bytes.
	signer.signErr = nil
	acceptance := try.To1(choice.Accept(direct.Clone(), expectedRoot))
	assert.Equal(signer.signCalls, 2)
	assert.NoError(direct.VerifyAcceptance(acceptance))
	retry := try.To1(choice.Accept(direct.Clone(), expectedRoot))
	assert.Equal(signer.signCalls, 2)
	assert.DeepEqual(retry, acceptance)
	assert.NoError(direct.VerifyAcceptance(retry))
}

func TestAcceptanceChoiceOwnership(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	expectedParent := slices.Clone(expectedRoot)
	direct := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	original := direct.Clone()
	signer := &acceptanceHandle{Handle: alice}
	choice := intro.NewAcceptanceChoice(signer, expectedRoot)
	expectedRoot[0] ^= 1

	acceptance := try.To1(choice.Accept(direct, expectedParent))
	saved := slices.Clone(acceptance)
	direct[1].ParentSig[0] ^= 1
	acceptance[0] ^= 1

	rejected, err := choice.Accept(direct, expectedParent)
	assert.ErrorIs(err, intro.ErrDifferentAcceptance)
	assert.SNil(rejected)
	retry := try.To1(choice.Accept(original, expectedParent))
	assert.DeepEqual(retry, saved)
	assert.NoError(original.VerifyAcceptance(retry))
	retry[0] ^= 1
	assert.DeepEqual(try.To1(choice.Accept(original, expectedParent)), saved)
	assert.Equal(signer.signCalls, 1)
}
