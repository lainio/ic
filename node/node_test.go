package node

import (
	"os"
	"testing"

	"github.com/findy-network/ic/crypto"
	"github.com/stretchr/testify/assert"
)

var (
	// root1 -> alice, alice -> bob, root2 -> carol
	root1, alice, bob, carol,

	// dave (new root) -> eve, root2 -> dave, carol -> eve (now root2 member)
	root2, dave, eve entity
	// frank, grace, heidi entity
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

func TestNewRootNode(t *testing.T) {
	aliceNode := NewRootNode(alice.PubKey)
	assert.Len(t, aliceNode.Chains, 1)
	assert.Len(t, aliceNode.Chains[0].Blocks, 1)

	bobNode := NewRootNode(bob.PubKey)
	assert.Len(t, bobNode.Chains, 1)
}

func TestInvite(t *testing.T) {
	// Root1 chains start here:
	alice.Node = root1.Invite(alice.Node, root1.Key, alice.PubKey, 1)
	assert.Len(t, alice.Node.Chains, 1)
	{
		c := alice.Node.Chains[0]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
	}

	bob.Node = alice.Invite(bob.Node, alice.Key, bob.PubKey, 1)
	assert.Len(t, bob.Node.Chains, 1)
	{
		c := bob.Node.Chains[0]
		assert.Len(t, c.Blocks, 3) // we know how long the chain is now
		assert.True(t, c.Verify())
	}

	// Bob and Alice share same chain root == Root1
	common := alice.CommonChain(bob.Node)
	assert.NotNil(t, common.Blocks)

	// Root2 invites Carol here
	carol.Node = root2.Invite(carol.Node, root2.Key, carol.PubKey, 1)
	assert.Len(t, carol.Node.Chains, 1)
	{
		c := carol.Node.Chains[0]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
	}

	// Alice is in Root1 chain and Carol in Root2 chain, so no common ground.
	common = alice.CommonChain(carol.Node)
	assert.Nil(t, common.Blocks)

	// Dave is one of the roots as well and we build it here:
	dave.Node = NewRootNode(dave.PubKey)
	eve.Node = dave.Invite(eve.Node, dave.Key, eve.PubKey, 1)
	assert.Len(t, eve.Node.Chains, 1)
	{
		c := eve.Node.Chains[0]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
	}

	// Root2 invites Dave and now Dave has 2 chains, BUT this doesn't effect
	// Eve!
	dave.Node = root2.Invite(dave.Node, root2.Key, dave.PubKey, 1)
	assert.Len(t, dave.Node.Chains, 2)
	{
		c := dave.Node.Chains[1]
		assert.Len(t, c.Blocks, 2)
		assert.True(t, c.Verify())
	}
	// Dave joins to Root2 but until now, that's why Eve is not member of Root2
	common = root2.CommonChain(eve.Node)
	assert.Nil(t, common.Blocks)

	// Carol and Eve doesn't have common chains _yet_
	common = carol.CommonChain(eve.Node)
	assert.Nil(t, common.Blocks)

	// .. so Carol can invite Eve
	eve.Node = carol.Invite(eve.Node, carol.Key, eve.PubKey, 1)
	assert.Len(t, eve.Node.Chains, 2)

	// now Eve has common chain with Root1 as well
	common = eve.CommonChain(root2.Node)
	assert.NotNil(t, common.Blocks)
}

func TestCommonChains(t *testing.T) {
	common := dave.CommonChains(eve.Node)
	assert.Len(t, common, 2)
}

func TestWebOfTrustInfo(t *testing.T) {
	common := dave.CommonChains(eve.Node)
	assert.Len(t, common, 2)

	wot:= dave.WebOfTrustInfo(eve.Node)
	assert.Equal(t, 0, wot.FromRoot)
	assert.Equal(t, 1, wot.Hops)
}
