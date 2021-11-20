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

	root1.Node = NewRootNode(root1.PubKey)
	root2.Node = NewRootNode(root2.PubKey)
}

func TestNewNode(t *testing.T) {
	aliceNode := NewRootNode(alice.PubKey)
	assert.Len(t, aliceNode.Chains, 1)
	assert.Len(t, aliceNode.Chains[0].Blocks, 1)

	bobNode := NewRootNode(bob.PubKey)
	assert.Len(t, bobNode.Chains, 1)
}

func TestInvite(t *testing.T) {
	// root1 chains start here:
	alice.Node = root1.Invite(alice.Node, root1.Key, alice.PubKey, 1)
	assert.Len(t, alice.Node.Chains, 1)
	for {
		c := alice.Node.Chains[0]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
		break
	}

	bob.Node = alice.Invite(bob.Node, alice.Key, bob.PubKey, 1)
	assert.Len(t, bob.Node.Chains, 1)
	for {
		c := bob.Node.Chains[0]
		assert.Len(t, c.Blocks, 3)
		assert.True(t, c.Verify())
		break
	}

	common := alice.CommonChain(bob.Node)
	assert.NotNil(t, common.Blocks)

	// root2 invites carol here
	carol.Node = root2.Invite(carol.Node, root2.Key, carol.PubKey, 1)
	assert.Len(t, carol.Node.Chains, 1)
	for {
		c := carol.Node.Chains[0]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
		break
	}

	// alice is root1 and carol root2 chain, so no common ground.
	common = alice.CommonChain(carol.Node)
	assert.Nil(t, common.Blocks)

	// dave is one of the roots as well and we build it here:
	dave.Node = NewRootNode(dave.PubKey)
	eve.Node = dave.Invite(eve.Node, dave.Key, eve.PubKey, 1)
	assert.Len(t, eve.Node.Chains, 1)
	for {
		c := eve.Node.Chains[0]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
		break
	}

	dave.Node = root2.Invite(dave.Node, root2.Key, dave.PubKey, 1)
	assert.Len(t, dave.Node.Chains, 2)
	for {
		c := dave.Node.Chains[1]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
		break
	}
	// dave joins to root2 but until now, that's why eve is not member of root2
	common = root2.CommonChain(eve.Node)
	assert.Nil(t, common.Blocks)

	// carol and eve doesn't have common chains
	common = carol.CommonChain(eve.Node)
	assert.Nil(t, common.Blocks)

	// .. so carol can invite eve
	eve.Node = carol.Invite(eve.Node, carol.Key, eve.PubKey, 1)
	assert.Len(t, eve.Node.Chains, 2)

	// now eve has common chain with root1 as well
	common = eve.CommonChain(root2.Node)
	assert.NotNil(t, common.Blocks)
	
}

// func TestXXX(t *testing.T) {
// 	assert.True(t, false, "not implemented")
// }
