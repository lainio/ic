package node

import (
	"os"
	"testing"

	"github.com/findy-network/ic/crypto"
	"github.com/stretchr/testify/assert"
)

var (
	root1, alice, bob, carol,
	root2, dave, eve entity
)

type entity struct {
	crypto.Key
	Node
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
}

func setup() {
	// root, alice, bob setup
	root1.Key = crypto.NewKey()
	root2.Key = crypto.NewKey()
	alice.Key = crypto.NewKey()
	bob.Key = crypto.NewKey()
	carol.Key = crypto.NewKey()
	dave.Key = crypto.NewKey()
	eve.Key = crypto.NewKey()

	root1.Node = NewRootNode(root1.Key.PubKey)
	root2.Node = NewRootNode(root2.Key.PubKey)
}

func TestNewNode(t *testing.T) {
	aliceNode := NewRootNode(alice.Key.PubKey)
	assert.Len(t, aliceNode.Chains, 1)
	assert.Len(t, aliceNode.Chains[0].Blocks, 1)

	bobNode := NewRootNode(bob.Key.PubKey)
	assert.Len(t, bobNode.Chains, 1)
}

func TestInvite(t *testing.T) {
	alice.Node = root1.Invite(alice.Node, root1.Key, alice.Key.PubKey, 1)
	assert.Len(t, alice.Node.Chains, 1)

	for {
		c := alice.Node.Chains[0]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
		break
	}

	bob.Node = alice.Invite(bob.Node, alice.Key, bob.Key.PubKey, 1)
	assert.Len(t, bob.Node.Chains, 1)

	for {
		c := bob.Node.Chains[0]
		assert.Len(t, c.Blocks, 3)
		assert.True(t, c.Verify())
		break
	}

	common := alice.CommonChain(bob.Node)
	assert.NotNil(t, common.Blocks)

	carol.Node = root1.Invite(carol.Node, root1.Key, carol.Key.PubKey, 1)
	assert.Len(t, carol.Node.Chains, 1)

	for {
		c := carol.Node.Chains[0]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
		break
	}

	dave.Node = NewRootNode(dave.Key.PubKey)
	dave.Node = root2.Invite(dave.Node, root2.Key, dave.Key.PubKey, 1)
	assert.Len(t, dave.Node.Chains, 2)

	for {
		c := dave.Node.Chains[1]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
		break
	}

}

// func TestXXX(t *testing.T) {
// 	assert.True(t, false, "not implemented")
// }
