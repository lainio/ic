package chain

import (
	"os"
	"testing"

	"github.com/findy-network/ic/crypto"
	"github.com/stretchr/testify/assert"
)

var (
	root, alice, bob struct {
		*crypto.Key
		Chain
	}
	c                   Chain
	rootKey, inviteeKey *crypto.Key
)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
}

func setup() {
	// general chain for tests
	rootKey = crypto.NewKey()
	c = NewChain(rootKey.PubKey)
	inviteeKey = crypto.NewKey()
	level := 1
	c = c.Invite(rootKey, inviteeKey.PubKey, level)

	// root, alice, bob setup
	root.Key = crypto.NewKey()
	alice.Key = crypto.NewKey()
	bob.Key = crypto.NewKey()

	root.Chain = NewChain(root.Key.PubKey)

	// root invites alice and bod but the have no invitation between
	alice.Chain = root.Invite(root.Key, alice.Key.PubKey, 1)
	bob.Chain = root.Invite(root.Key, bob.Key.PubKey, 1)
}

func TestNewChain(t *testing.T) {
	assert.Len(t, c.Blocks, 2)
}

func TestRead(t *testing.T) {
	c2 := c.Clone()
	assert.Len(t, c2.Blocks, 2)
	assert.True(t, c2.Verify())
}

func TestVerifyChainFail(t *testing.T) {
	c2 := c.Clone()
	assert.Len(t, c2.Blocks, 2)
	assert.True(t, c2.Verify())

	b2 := c2.Blocks[1]
	b2.InvitersSignature[len(b2.InvitersSignature)-1] += 0x01

	assert.False(t, c2.Verify())
}

func TestVerifyChain(t *testing.T) {
	assert.Len(t, c.Blocks, 2)
	assert.True(t, c.Verify())

	newInvitee := crypto.NewKey()
	level := 3
	c = c.Invite(inviteeKey, newInvitee.PubKey, level)

	assert.Len(t, c.Blocks, 3)
	assert.True(t, c.Verify())
}

func TestInvitation(t *testing.T) {
	assert.Len(t, alice.Blocks, 2)
	assert.True(t, alice.Verify())
	assert.Len(t, bob.Blocks, 2)
	assert.True(t, bob.Verify())

	cecilia := struct {
		*crypto.Key
		Chain
	}{
		Key: crypto.NewKey(),
	}
	cecilia.Chain = bob.Invite(bob.Key, cecilia.Key.PubKey, 1)
	assert.Len(t, cecilia.Blocks, 3)
	assert.True(t, cecilia.Verify())
	assert.False(t, SameRoot(c, cecilia.Chain), "we have two different roots")
	assert.True(t, SameRoot(alice.Chain, cecilia.Chain))
}

// common root : my distance, her distance

// TestCommonInviter tests that Chain owners have one common inviter
func TestCommonInviter(t *testing.T) {
	// alice and bod have common root
	cecilia := struct {
		*crypto.Key
		Chain
	}{
		Key: crypto.NewKey(),
	}
	// bob intives cecilia
	cecilia.Chain = bob.Invite(bob.Key, cecilia.Key.PubKey, 1)
	assert.Len(t, cecilia.Blocks, 3)
	assert.True(t, cecilia.Verify())

	david := struct {
		*crypto.Key
		Chain
	}{
		Key: crypto.NewKey(),
	}
	// alice invites david
	david.Chain = alice.Invite(alice.Key, david.Key.PubKey, 1)

	assert.Equal(t, 0, CommonInviter(cecilia.Chain, david.Chain),
		"cecilia and david have only common root")
	edvin := struct {
		*crypto.Key
		Chain
	}{
		Key: crypto.NewKey(),
	}
	edvin.Chain = alice.Invite(alice.Key, edvin.Key.PubKey, 1)
	assert.Equal(t, 1, CommonInviter(edvin.Chain, david.Chain),
		"alice is at level 1 and inviter of both")

	edvin2Chain := alice.Chain.Invite(alice.Key, crypto.NewKey().PubKey, 1)
	assert.Equal(t, 1, CommonInviter(edvin2Chain, david.Chain),
		"alice is at level 1 and inviter of both")

	fred1Chain := edvin.Invite(edvin.Key, crypto.NewKey().PubKey, 1)
	fred2Chain := edvin.Invite(edvin.Key, crypto.NewKey().PubKey, 1)
	assert.Equal(t, 2, CommonInviter(fred2Chain, fred1Chain),
		"edvin is at level 2")
}

// TestSameInviter test that two chain holders have same inviter.
func TestSameInviter(t *testing.T) {
	assert.True(t, SameInviter(alice.Chain, bob.Chain))
	assert.False(t, SameInviter(c, bob.Chain))

	cecilia := struct {
		*crypto.Key
		Chain
	}{
		Key: crypto.NewKey(),
	}
	cecilia.Chain = bob.Invite(bob.Key, cecilia.Key.PubKey, 1)
	assert.Len(t, cecilia.Blocks, 3)
	assert.True(t, cecilia.Verify())
	assert.True(t, bob.IsInviterFor(cecilia.Chain))
	assert.False(t, alice.IsInviterFor(cecilia.Chain))
}

// TestChallengeInvitee test shows how we can challenge the party who presents
// us the chain. Chains are present as full! At least for now. They don't
// include any personal data, and we try to make sure that they won't include
// any data which could be used to correlate the use of the chain. Chain is only
// for the proofing the position in the Invitation Chain.
func TestChallengeInvitee(t *testing.T) {
	// chain leaf is the only part who has the private key for the leaf, so
	// it can response the challenge properly.

	// Challenge is needed that we can be sure that the party who presents the
	// chain is the actual owner of the chain.

	// When let's say Bob have received Alice's chain he can use Challenge
	// method for Alice's Chain to let Alice proof that she controls the chain
	assert.True(t, alice.Challenge(
		func(d []byte) crypto.Signature {
			// In realtime usage here we would send the d for Alice's signing
			// over the network.
			return alice.Sign(d)
		},
	))
	assert.False(t, bob.Challenge(
		func(d []byte) crypto.Signature {
			return alice.Sign(d)
		},
	))
	assert.True(t, bob.Challenge(
		func(d []byte) crypto.Signature {
			return bob.Sign(d)
		},
	))
}

// Issuer adds her own chain to every credential it's issuing, I haven't solved
// the correlation yet. Is it an issue because chain doesn't include any
// identifiers. PubKey is identifier, if we don't use PubKey as an identifier,
// it the only option to use some other identifier and behind it similar to
// DIDDoc concept. How about if chain holder creates new sub chains just to hide
// it's actual identity?
// For what purpose we could use them?
