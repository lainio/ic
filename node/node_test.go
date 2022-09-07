package node

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/crypto"
)

var (
	// root1 -> alice, alice -> bob, root2 -> carol
	root1, alice, bob, carol,

	// dave (new root) -> eve, root2 -> dave, carol -> eve (now root2 member)
	root2, dave, eve entity

	// alice -> frank, bob -> grace
	frank, grace entity
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
	assert.PushTester(t)
	defer assert.PopTester()

	aliceNode := NewRootNode(alice.PubKey)
	assert.SLen(aliceNode.Chains, 1)
	assert.SLen(aliceNode.Chains[0].Blocks, 1)

	bobNode := NewRootNode(bob.PubKey)
	assert.SLen(bobNode.Chains, 1)
}

func TestInvite(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()

	// Root1 chains start here:
	alice.Node = root1.Invite(alice.Node, root1.Key, alice.PubKey, 1)
	assert.Equal(alice.Len(), 1)
	{
		c := alice.Node.Chains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.Verify())
	}

	bob.Node = alice.Invite(bob.Node, alice.Key, bob.PubKey, 1)
	assert.Equal(bob.Len(), 1)
	{
		c := bob.Node.Chains[0]
		assert.SLen(c.Blocks, 3) // we know how long the chain is now
		assert.That(c.Verify())
	}

	// Bob and Alice share same chain root == Root1
	common := alice.CommonChain(bob.Node)
	assert.SNotNil(common.Blocks)

	// Root2 invites Carol here
	carol.Node = root2.Invite(carol.Node, root2.Key, carol.PubKey, 1)
	assert.Equal(carol.Len(), 1)
	{
		c := carol.Node.Chains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.Verify())
	}

	// Alice is in Root1 chain and Carol in Root2 chain, so no common ground.
	common = alice.CommonChain(carol.Node)
	assert.SNil(common.Blocks)

	// Dave is one of the roots as well and we build it here:
	dave.Node = NewRootNode(dave.PubKey)
	eve.Node = dave.Invite(eve.Node, dave.Key, eve.PubKey, 1)
	assert.Equal(eve.Len(), 1)
	{
		c := eve.Node.Chains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.Verify())
	}

	// Root2 invites Dave and now Dave has 2 chains, BUT this doesn't effect
	// Eve!
	dave.Node = root2.Invite(dave.Node, root2.Key, dave.PubKey, 1)
	assert.Equal(dave.Len(), 2)
	{
		c := dave.Node.Chains[1]
		assert.SLen(c.Blocks, 2)
		assert.That(c.Verify())
	}
	// Dave joins to Root2 but until now, that's why Eve is not member of Root2
	common = root2.CommonChain(eve.Node)
	assert.SNil(common.Blocks)

	// Carol and Eve doesn't have common chains _yet_
	common = carol.CommonChain(eve.Node)
	assert.SNil(common.Blocks)

	// .. so Carol can invite Eve
	eve.Node = carol.Invite(eve.Node, carol.Key, eve.PubKey, 1)
	assert.Equal(eve.Len(), 2)

	// now Eve has common chain with Root1 as well
	common = eve.CommonChain(root2.Node)
	assert.SNotNil(common.Blocks)
}

func TestCommonChains(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()

	common := dave.CommonChains(eve.Node)
	assert.SLen(common, 2)
}

func TestWebOfTrustInfo(t *testing.T) {
	assert.PushTester(t)
	defer assert.PopTester()

	common := dave.CommonChains(eve.Node)
	assert.SLen(common, 2)

	wot := dave.WebOfTrustInfo(eve.Node)
	assert.Equal(0, wot.CommonInvider)
	assert.Equal(1, wot.Hops)

	wot = NewWebOfTrust(bob.Node, carol.Node)
	assert.Equal(chain.NotConnected, wot.CommonInvider)
	assert.Equal(chain.NotConnected, wot.Hops)

	frank.Node = alice.Invite(frank.Node, alice.Key, frank.PubKey, 1)
	assert.Equal(frank.Len(), 1)
	assert.Equal(alice.Len(), 1)
	grace.Node = bob.Invite(grace.Node, bob.Key, grace.PubKey, 1)
	assert.Equal(grace.Len(), 1)
	assert.Equal(bob.Len(), 1)

	common = frank.CommonChains(grace.Node)
	assert.SLen(common, 1)
	common = root1.CommonChains(alice.Node)
	assert.SLen(common, 1)
	h, level := common[0].Hops()
	assert.Equal(1, h)
	assert.Equal(0, level)

	wot = NewWebOfTrust(frank.Node, grace.Node)
	assert.Equal(1, wot.CommonInvider)
	assert.Equal(3, wot.Hops)

	root3 := entity{Key: crypto.NewKey()}
	root3.Node = NewRootNode(root3.PubKey)
	heidi := entity{Key: crypto.NewKey()}
	heidi.Node = root3.Invite(heidi.Node, root3.Key, heidi.PubKey, 1)
	assert.SLen(heidi.Node.Chains, 1)
	assert.SLen(heidi.Node.Chains[0].Blocks, 2, "root = root3")

	// verify Eve's situation:
	assert.SLen(eve.Node.Chains, 2)
	assert.SLen(eve.Node.Chains[0].Blocks, 2, "root == dave")
	assert.Equal(3, len(eve.Node.Chains[1].Blocks), "root is root2")

	heidi.Node = eve.Invite(heidi.Node, eve.Key, heidi.PubKey, 1)
	// next dave's invitation doesn't add any new chains because there is no
	// new roots in daves chains
	heidi.Node = dave.Invite(heidi.Node, dave.Key, heidi.PubKey, 1)

	wot = NewWebOfTrust(eve.Node, heidi.Node)
	assert.Equal(0, wot.CommonInvider, "common root is dave")
	assert.Equal(1, wot.Hops, "dave intives heidi")
	assert.That(eve.IsInviterFor(heidi.Node))
	assert.That(heidi.OneHop(eve.Node))
}
