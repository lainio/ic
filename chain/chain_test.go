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
	c.AddBlock(rootKey, inviteeKey.PubKey, level)

	// root, alice, bob setup
	root.Key = crypto.NewKey()
	alice.Key = crypto.NewKey()
	bob.Key = crypto.NewKey()

	root.Chain = NewChain(root.Key.PubKey)

	// root invites alice and bod but the have no invitation between
	alice.Chain = root.Chain.Invite(root.Key, alice.Key.PubKey, 1)
	bob.Chain = root.Chain.Invite(root.Key, bob.Key.PubKey, 1)
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
	c.AddBlock(inviteeKey, newInvitee.PubKey, level)

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
	cecilia.Chain = bob.Chain.Invite(bob.Key, cecilia.Key.PubKey, 1)
	assert.Len(t, cecilia.Chain.Blocks, 3)
	assert.True(t, cecilia.Chain.Verify())
	assert.False(t, SameRoot(c, cecilia.Chain), "we have two different roots")
	assert.True(t, SameRoot(alice.Chain, cecilia.Chain))
}

// common root : my distance, her distance

// common inviter
func TestCommonInviter(t *testing.T) {
	// alice and bod have common root
	cecilia := struct {
		*crypto.Key
		Chain
	}{
		Key: crypto.NewKey(),
	}
	// bob intives cecilia
	cecilia.Chain = bob.Chain.Invite(bob.Key, cecilia.Key.PubKey, 1)
	assert.Len(t, cecilia.Chain.Blocks, 3)
	assert.True(t, cecilia.Chain.Verify())

	david := struct {
		*crypto.Key
		Chain
	}{
		Key: crypto.NewKey(),
	}
	// alice invites david
	david.Chain = alice.Chain.Invite(alice.Key, david.Key.PubKey, 1)

	assert.Equal(t, 0, CommonInviter(cecilia.Chain, david.Chain),
		"cecilia and david have only common root")
	edvin := struct {
		*crypto.Key
		Chain
	}{
		Key: crypto.NewKey(),
	}
	edvin.Chain = alice.Chain.Invite(alice.Key, edvin.Key.PubKey, 1)
	assert.Equal(t, 1, CommonInviter(edvin.Chain, david.Chain),
		"alice is at level 1 and inviter of both")

	edvin2Chain := alice.Chain.Invite(alice.Key, crypto.NewKey().PubKey, 1)
	assert.Equal(t, 1, CommonInviter(edvin2Chain, david.Chain),
		"alice is at level 1 and inviter of both")

	fred1Chain := edvin.Chain.Invite(edvin.Key, crypto.NewKey().PubKey, 1)
	fred2Chain := edvin.Chain.Invite(edvin.Key, crypto.NewKey().PubKey, 1)
	assert.Equal(t, 2, CommonInviter(fred2Chain, fred1Chain),
		"edvin is at level 2")
}

func TestSameInviter(t *testing.T) {
	assert.True(t, SameInviter(alice.Chain, bob.Chain))
	assert.False(t, SameInviter(c, bob.Chain))

	cecilia := struct {
		*crypto.Key
		Chain
	}{
		Key: crypto.NewKey(),
	}
	cecilia.Chain = bob.Chain.Invite(bob.Key, cecilia.Key.PubKey, 1)
	assert.Len(t, cecilia.Chain.Blocks, 3)
	assert.True(t, cecilia.Chain.Verify())
	assert.True(t, bob.Chain.IsInvitee(cecilia.Chain))
}

func TestChallengeInvitee(t *testing.T) {
	// chain leaf is the only part who has the prive key for the leaf, so
	// it can response the challenge properly.
}
