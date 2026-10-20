package intro_test

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
)

func TestAcceptanceBinding(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	aliceInfo, bobInfo := key.InfoFromHandle(alice), key.InfoFromHandle(bob)

	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, aliceInfo)
	bobPath := rootPath.Introduce(root, bobInfo)
	indirect := bobPath.Introduce(bob, aliceInfo)
	directBytes, indirectBytes := direct.Bytes(), indirect.Bytes()
	direct = try.To1(intro.ParsePath(directBytes))
	indirect = try.To1(intro.ParsePath(indirectBytes))
	assert.SLen(direct, 2)
	assert.SLen(indirect, 3)
	assert.NoError(direct.ProveFromRoot(expectedRoot))
	assert.NoError(indirect.ProveFromRoot(expectedRoot))
	assert.DeepEqual(indirect.LastEdge().Body.Child, aliceInfo)
	assert.DeepEqual(indirect.SecondLastEdge().Public(), bobInfo.Public)
	assert.ThatNot(expectedRoot.Equal(bobInfo.Public))

	offered := direct
	assert.DeepEqual(offered.LastEdge().Body.Child, aliceInfo)
	assert.DeepEqual(offered.SecondLastEdge().Public(), expectedRoot)

	// Experimental transcript; bind the entire signed representation.
	acceptanceDigest := func(proposal intro.Path) key.Hash {
		return key.HashTagged("test/intro-acceptance/v1", proposal.Bytes())
	}
	digest := acceptanceDigest(offered)
	acceptance := key.Signature(try.To1(alice.Sign(digest[:])))

	t.Run("chosen direct proposal", func(t *testing.T) {
		defer assert.PushTester(t)()

		digest := acceptanceDigest(direct)
		assert.That(
			acceptance.Verify(direct.LastEdge().Public(), digest[:]),
		)
	})

	t.Run("serialization round trip", func(t *testing.T) {
		defer assert.PushTester(t)()

		copied := try.To1(intro.ParsePath(direct.Bytes()))
		assert.SLen(copied, 2)
		assert.NoError(copied.ProveFromRoot(expectedRoot))
		assert.DeepEqual(copied.Bytes(), directBytes)

		digest := acceptanceDigest(copied)
		assert.That(
			acceptance.Verify(copied.LastEdge().Public(), digest[:]),
		)
		assert.DeepEqual(copied.Bytes(), directBytes)
	})

	t.Run("no signature", func(t *testing.T) {
		defer assert.PushTester(t)()

		var absent key.Signature
		digest := acceptanceDigest(direct)
		assert.ThatNot(
			absent.Verify(direct.LastEdge().Public(), digest[:]),
		)
	})

	t.Run("Bob cannot accept for Alice", func(t *testing.T) {
		defer assert.PushTester(t)()

		digest := acceptanceDigest(direct)
		bobsSignature := key.Signature(try.To1(bob.Sign(digest[:])))

		digest = acceptanceDigest(direct)
		assert.ThatNot(bobsSignature.Verify(
			direct.LastEdge().Public(), digest[:],
		))
	})

	t.Run("signature transfer rejected", func(t *testing.T) {
		defer assert.PushTester(t)()

		assert.NoError(indirect.ProveFromRoot(expectedRoot))
		digest := acceptanceDigest(indirect)
		assert.ThatNot(acceptance.Verify(
			indirect.LastEdge().Public(), digest[:],
		))
	})

	t.Run("changed signed option", func(t *testing.T) {
		defer assert.PushTester(t)()

		revised := try.To1(intro.ParsePath(directBytes))
		assert.SLen(revised, 2)
		last := &revised[len(revised)-1]
		last.Body.Options.Position++

		last.ParentSig = try.To1(root.Sign(last.ExcludeBytes()))
		assert.NoError(revised.ProveFromRoot(expectedRoot))
		assert.DeepEqual(revised[0], direct[0])
		assert.DeepEqual(last.Body.Child, aliceInfo)
		assert.Equal(last.Body.Prev, direct[1].Body.Prev)
		revisedBytes := revised.Bytes()

		digest := acceptanceDigest(revised)
		assert.ThatNot(acceptance.Verify(last.Public(), digest[:]))
		assert.DeepEqual(revised.Bytes(), revisedBytes)
	})

	t.Run("different purpose tag", func(t *testing.T) {
		defer assert.PushTester(t)()

		otherDigest := key.HashTagged("test/other-purpose/v1", direct.Bytes())
		otherSignature := key.Signature(try.To1(alice.Sign(otherDigest[:])))

		digest := acceptanceDigest(direct)
		assert.ThatNot(otherSignature.Verify(
			direct.LastEdge().Public(), digest[:],
		))
	})

	t.Run("deliberate double sign limitation", func(t *testing.T) {
		defer assert.PushTester(t)()

		// Alice can sign both; this does not authorize two enrollments.
		for _, proposal := range []intro.Path{direct, indirect} {
			assert.SLonger(proposal, 1)
			assert.NoError(proposal.ProveFromRoot(expectedRoot))
			before := proposal.Bytes()
			digest := acceptanceDigest(proposal)
			ownAcceptance := key.Signature(try.To1(alice.Sign(digest[:])))

			digest = acceptanceDigest(proposal)
			assert.That(ownAcceptance.Verify(
				proposal.LastEdge().Public(), digest[:],
			))
			assert.DeepEqual(proposal.Bytes(), before)
		}
	})

	assert.DeepEqual(direct.Bytes(), directBytes)
	assert.DeepEqual(indirect.Bytes(), indirectBytes)
}
