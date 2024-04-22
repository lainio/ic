package node

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/key"
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
	Node
	key.Handle
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
	root1.Handle = key.NewKey()
	root2.Handle = key.NewKey()
	alice.Handle = key.NewKey()
	bob.Handle = key.NewKey()
	carol.Handle = key.NewKey()
	dave.Handle = key.NewKey()
	eve.Handle = key.NewKey()
	// TODO: comment frank init out to test err2
	frank.Handle = key.NewKey()
	grace.Handle = key.NewKey()

	root1.Node = NewRoot(key.InfoFromHandle(root1))
	root2.Node = NewRoot(key.InfoFromHandle(root2))
}

func TestNewRootNode(t *testing.T) {
	defer assert.PushTester(t)()

	aliceNode := NewRoot(key.InfoFromHandle(alice))
	assert.SLen(aliceNode.Chains, 1)
	assert.SLen(aliceNode.Chains[0].Blocks, 1)

	bobNode := NewRoot(key.InfoFromHandle(bob))
	assert.SLen(bobNode.Chains, 1)
}

func TestInvite(t *testing.T) {
	defer assert.PushTester(t)()

	// Root1 chains start here:
	alice.Node = root1.Invite(alice.Node, root1.Handle, key.InfoFromHandle(alice), 1)
	assert.Equal(alice.Len(), 1)
	{
		c := alice.Chains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	bob.Node = alice.Invite(bob.Node, alice.Handle, key.InfoFromHandle(bob), 1)
	assert.Equal(bob.Len(), 1)
	{
		c := bob.Chains[0]
		assert.SLen(c.Blocks, 3) // we know how long the chain is now
		assert.That(c.VerifySign())
	}

	// Bob and Alice share same chain root == Root1
	common := alice.CommonChain(bob.Node)
	assert.SNotNil(common.Blocks)

	// Root2 invites Carol here
	carol.Node = root2.Invite(carol.Node, root2.Handle, key.InfoFromHandle(carol), 1)
	assert.Equal(carol.Len(), 1)
	{
		c := carol.Chains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	// Alice is in Root1 chain and Carol in Root2 chain, so no common ground.
	common = alice.CommonChain(carol.Node)
	assert.SNil(common.Blocks)

	// Dave is one of the roots as well and we build it here:
	dave.Node = NewRoot(key.InfoFromHandle(dave))
	eve.Node = dave.Invite(eve.Node, dave.Handle, key.InfoFromHandle(eve), 1)
	assert.Equal(eve.Len(), 1)
	{
		c := eve.Chains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	// Root2 invites Dave and now Dave has 2 chains, BUT this doesn't effect
	// Eve!
	dave.Node = root2.Invite(dave.Node, root2.Handle, key.InfoFromHandle(dave), 1)
	assert.Equal(dave.Len(), 2)
	{
		c := dave.Chains[1]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}
	// Dave joins to Root2 but until now, that's why Eve is not member of Root2
	common = root2.CommonChain(eve.Node)
	assert.SNil(common.Blocks)

	// Carol and Eve doesn't have common chains _yet_
	common = carol.CommonChain(eve.Node)
	assert.SNil(common.Blocks)
	// .. so Carol can invite Eve
	eve.Node = carol.Invite(eve.Node, carol.Handle, key.InfoFromHandle(eve), 1)
	assert.Equal(eve.Len(), 2)

	// now Eve has common chain with Root1 as well
	common = eve.CommonChain(root2.Node)
	assert.SNotNil(common.Blocks)
}

func TestCommonChains(t *testing.T) {
	defer assert.PushTester(t)()

	common := dave.CommonChains(eve.Node)
	assert.SLen(common, 2)
}

func TestWebOfTrustInfo(t *testing.T) {
	defer assert.PushTester(t)()

	//assert.That(false)
	//panic(1)
	//_, _ = frank.CBORPublicKey()
	common := dave.CommonChains(eve.Node)
	assert.SLen(common, 2)

	wot := dave.WebOfTrustInfo(eve.Node)
	assert.Equal(0, wot.CommonInvider)
	assert.Equal(1, wot.Hops)

	wot = NewWebOfTrust(bob.Node, carol.Node)
	assert.Equal(chain.NotConnected, wot.CommonInvider)
	assert.Equal(chain.NotConnected, wot.Hops)

	frank.Node = alice.Invite(frank.Node, alice.Handle, key.InfoFromHandle(frank), 1)
	assert.Equal(frank.Len(), 1)
	assert.Equal(alice.Len(), 1)
	grace.Node = bob.Invite(grace.Node, bob.Handle, key.InfoFromHandle(grace), 1)
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

	root3 := entity{Handle: key.NewKey()}
	root3.Node = NewRoot(key.InfoFromHandle(root3))
	heidi := entity{Handle: key.NewKey()}
	heidi.Node = root3.Invite(heidi.Node, root3.Handle, key.InfoFromHandle(heidi), 1)
	assert.SLen(heidi.Chains, 1)
	assert.SLen(heidi.Chains[0].Blocks, 2, "root = root3")

	// verify Eve's situation:
	assert.SLen(eve.Chains, 2)
	assert.SLen(eve.Chains[0].Blocks, 2, "root == dave")
	assert.Equal(3, len(eve.Chains[1].Blocks), "root is root2")

	heidi.Node = eve.Invite(heidi.Node, eve.Handle, key.InfoFromHandle(heidi), 1)
	// next dave's invitation doesn't add any new chains because there is no
	// new roots in daves chains
	heidi.Node = dave.Invite(heidi.Node, dave.Handle, key.InfoFromHandle(heidi), 1)

	wot = NewWebOfTrust(eve.Node, heidi.Node)
	assert.Equal(0, wot.CommonInvider, "common root is dave")
	assert.Equal(1, wot.Hops, "dave invites heidi")
	assert.That(eve.IsInviterFor(heidi.Node))
	assert.That(heidi.OneHop(eve.Node))
}
