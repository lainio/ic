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

	ceciliaKey := crypto.NewKey()
	ceciliaChain := bob.Chain.Invite(bob.Key, ceciliaKey.PubKey, 1)
	assert.Len(t, ceciliaChain.Blocks, 3)
	assert.True(t, ceciliaChain.Verify())
	assert.False(t, SameRoot(c, ceciliaChain), "we have two different roots")
	assert.True(t, SameRoot(alice.Chain, ceciliaChain))
}

// common root : my distance, her distance

// common inviter
func TestCommonInviter(t *testing.T) {
	assert.True(t, CommonInviter(alice.Chain, bob.Chain))
	assert.False(t, CommonInviter(c, bob.Chain))

	ceciliaKey := crypto.NewKey()
	ceciliaChain := bob.Chain.Invite(bob.Key, ceciliaKey.PubKey, 1)
	assert.Len(t, ceciliaChain.Blocks, 3)
	assert.True(t, ceciliaChain.Verify())
	assert.True(t, bob.Chain.IsInvitee(ceciliaChain))
}
