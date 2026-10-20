package intro_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

func TestPathAcceptanceSignatureTransfer(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	aliceInfo := key.InfoFromHandle(alice)
	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, aliceInfo)
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, aliceInfo)
	assert.NoError(direct.ProveFromRoot(expectedRoot))
	assert.NoError(indirect.ProveFromRoot(expectedRoot))
	directBytes, indirectBytes := direct.Bytes(), indirect.Bytes()

	acceptance := try.To1(direct.SignAcceptance(alice))
	assert.NoError(direct.VerifyAcceptance(acceptance))
	assert.ErrorIs(
		indirect.VerifyAcceptance(acceptance),
		intro.ErrBadAcceptance,
	)

	revised := try.To1(intro.ParsePath(directBytes))
	last := &revised[len(revised)-1]
	last.Body.Options.Position++
	last.ParentSig = try.To1(root.Sign(last.ExcludeBytes()))
	assert.NoError(revised.ProveFromRoot(expectedRoot))
	revisedBytes := revised.Bytes()
	assert.ErrorIs(
		revised.VerifyAcceptance(acceptance),
		intro.ErrBadAcceptance,
	)
	fresh := try.To1(revised.SignAcceptance(alice))
	assert.NoError(revised.VerifyAcceptance(fresh))

	// Alice can deliberately sign both valid proposals; no one-time enrollment.
	otherAcceptance := try.To1(indirect.SignAcceptance(alice))
	assert.NoError(indirect.VerifyAcceptance(otherAcceptance))
	assert.NoError(direct.VerifyAcceptance(acceptance))
	assert.DeepEqual(direct.Bytes(), directBytes)
	assert.DeepEqual(indirect.Bytes(), indirectBytes)
	assert.DeepEqual(revised.Bytes(), revisedBytes)
}

func TestPathAcceptanceRoundTrip(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := try.To1(root.CBORPublicKey())
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	assert.NoError(path.ProveFromRoot(expectedRoot))
	before := path.Bytes()
	signer := &acceptanceHandle{Handle: alice}

	acceptance := try.To1(path.SignAcceptance(signer))
	assert.Equal(signer.signCalls, 1)
	assert.SNotEmpty(acceptance)
	digest := key.HashTagged("intro-acceptance/v1", before)
	assert.That(acceptance.Verify(path.LastEdge().Public(), digest[:]))
	assert.NoError(path.VerifyAcceptance(acceptance))

	copied := try.To1(intro.ParsePath(before))
	assert.NoError(copied.ProveFromRoot(expectedRoot))
	assert.NoError(copied.VerifyAcceptance(acceptance))
	assert.NoError(copied.VerifyAcceptance(acceptance))
	assert.DeepEqual(copied.Bytes(), before)
	assert.DeepEqual(path.Bytes(), before)
}

func TestPathAcceptanceRejectedSignatures(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	aliceInfo := key.InfoFromHandle(alice)
	// A storage ID is not the signer's identity; public-key bytes decide.
	aliceInfo.ID = bob.ID()
	path := intro.New(key.InfoFromHandle(root)).Introduce(root, aliceInfo)
	assert.NoError(path.ProveFromRoot(try.To1(root.CBORPublicKey())))
	before := path.Bytes()
	acceptance := try.To1(path.SignAcceptance(alice))
	assert.NoError(path.VerifyAcceptance(acceptance))

	assert.ErrorIs(path.VerifyAcceptance(nil), intro.ErrBadAcceptance)
	digest := key.HashTagged("intro-acceptance/v1", before)
	bobsSignature := key.Signature(try.To1(bob.Sign(digest[:])))
	assert.ErrorIs(
		path.VerifyAcceptance(bobsSignature),
		intro.ErrBadAcceptance,
	)

	signer := &acceptanceHandle{Handle: bob}
	rejected, err := path.SignAcceptance(signer)
	assert.ErrorIs(err, intro.ErrBadAcceptance)
	assert.SNil(rejected)
	assert.Equal(signer.signCalls, 0)

	oldDigest := key.HashTagged("test/intro-acceptance/v1", before)
	oldAcceptance := key.Signature(try.To1(alice.Sign(oldDigest[:])))
	assert.That(oldAcceptance.Verify(path.LastEdge().Public(), oldDigest[:]))
	assert.ErrorIs(
		path.VerifyAcceptance(oldAcceptance),
		intro.ErrBadAcceptance,
	)
	assert.DeepEqual(path.Bytes(), before)
}

func TestPathAcceptanceMissingShape(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	rootPath := intro.New(key.InfoFromHandle(root))
	path := rootPath.Introduce(root, key.InfoFromHandle(alice))
	acceptance := try.To1(path.SignAcceptance(alice))
	emptyPublic := try.To1(intro.ParsePath(path.Bytes()))
	last := &emptyPublic[len(emptyPublic)-1]
	last.Body.Child.Public = nil

	for _, tc := range []struct {
		name string
		path intro.Path
	}{
		{"nil path", nil},
		{"empty path", intro.Path{}},
		{"root only", rootPath},
		{"empty child public key", emptyPublic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			before := tc.path.Bytes()
			rejected, err := tc.path.SignAcceptance(alice)
			assert.ErrorIs(err, intro.ErrBadAcceptance)
			assert.SNil(rejected)
			err = tc.path.VerifyAcceptance(acceptance)
			assert.ErrorIs(err, intro.ErrBadAcceptance)
			assert.DeepEqual(tc.path.Bytes(), before)
		})
	}

	before := path.Bytes()
	rejected, err := path.SignAcceptance(nil)
	assert.ErrorIs(err, intro.ErrBadAcceptance)
	assert.SNil(rejected)
	assert.DeepEqual(path.Bytes(), before)
}

func TestPathAcceptanceHandleErrors(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	before := path.Bytes()
	cause := errors.New("key unavailable")

	for _, tc := range []struct {
		name      string
		publicErr error
		signErr   error
		signCalls int
	}{
		{"public key access", fmt.Errorf("public key: %w", cause), nil, 0},
		{"signing", nil, fmt.Errorf("sign: %w", cause), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			signer := &acceptanceHandle{
				Handle: alice, publicErr: tc.publicErr, signErr: tc.signErr,
			}
			acceptance, err := path.SignAcceptance(signer)
			assert.ErrorIs(err, cause)
			assert.ErrorIsNot(err, intro.ErrBadAcceptance)
			assert.SNil(acceptance)
			assert.Equal(signer.signCalls, tc.signCalls)
			assert.DeepEqual(path.Bytes(), before)
		})
	}
}

func TestPathAcceptanceSeparateProof(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := try.To1(root.CBORPublicKey())
	path := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	assert.NoError(path.ProveFromRoot(expectedRoot))
	wrongLink := try.To1(intro.ParsePath(path.Bytes()))
	last := &wrongLink[len(wrongLink)-1]
	last.Body.Prev[0] ^= 1
	last.ParentSig = try.To1(root.Sign(last.ExcludeBytes()))
	assert.That(last.VerifySignature(expectedRoot))
	assert.ErrorIs(wrongLink.ProveFromRoot(expectedRoot), intro.ErrBrokenPath)
	before := wrongLink.Bytes()

	// Signature checking does not grant permission to enroll this proposal.
	acceptance := try.To1(wrongLink.SignAcceptance(alice))
	assert.NoError(wrongLink.VerifyAcceptance(acceptance))
	assert.ErrorIs(wrongLink.ProveFromRoot(expectedRoot), intro.ErrBrokenPath)
	assert.DeepEqual(wrongLink.Bytes(), before)
}

type acceptanceHandle struct {
	key.Handle
	publicErr error
	signErr   error
	signCalls int
}

func (h *acceptanceHandle) CBORPublicKey() ([]byte, error) {
	if h.publicErr != nil {
		return nil, h.publicErr
	}
	return h.Handle.CBORPublicKey()
}

func (h *acceptanceHandle) Sign(data []byte) ([]byte, error) {
	h.signCalls++
	if h.signErr != nil {
		return []byte("partial signature"), h.signErr
	}
	return h.Handle.Sign(data)
}
