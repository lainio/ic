package identity

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/key"
)

var (
	// root1 -> alice, alice -> bob, root2 -> carol
	root1, alice, bob, carol,

	// dave (new root) -> eve, root2 -> dave, carol -> eve (now root2 member)
	root2, dave, eve Identity

	// alice -> frank, bob -> grace
	frank, grace Identity
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
	// root, alice, bob setup
	root1.Handle = key.New()
	root2.Handle = key.New()
	alice.Handle = key.New()
	bob.Handle = key.New()
	carol.Handle = key.New()
	dave.Handle = key.New()
	eve.Handle = key.New()
	// TODO: comment frank init out to test err2
	frank.Handle = key.New()
	grace.Handle = key.New()

	root1 = New(root1)
	root2 = New(root2)
}

func TestNewIdentity(t *testing.T) {
	defer assert.PushTester(t)()

	aliceID := New(alice)
	assert.SLen(aliceID.Chains, 1)
	assert.SLen(aliceID.Chains[0].Blocks, 1)

	bobID := New(bob)
	assert.SLen(bobID.Chains, 1)
}

func TestIdentity_Invite(t *testing.T) {
	defer assert.PushTester(t)()

	// Root1 chains start here:
	alice = root1.Invite(alice, 1)
	assert.Equal(alice.Len(), 1)
	{
		c := alice.Chains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	bob = alice.Invite(bob, 1)
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
	carol = root2.Invite(carol, 1)
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
	dave = New(dave)
	eve = dave.Invite(eve, 1)
	assert.Equal(eve.Len(), 1)
	{
		c := eve.Chains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	// Root2 invites Dave and now Dave has 2 chains, BUT this doesn't effect
	// Eve!
	dave = root2.Invite(dave, 1)
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
	eve = carol.Invite(eve, 1)
	assert.Equal(eve.Len(), 2)

	// now Eve has common chain with Root1 as well
	common = eve.CommonChain(root2.Node)
	assert.SNotNil(common.Blocks)
}

func TestRotateKey(t *testing.T) {
	defer assert.PushTester(t)()

	// NOTE! this test has dependency to the previous.
	// TODO: merge them by using run!
	// TODO: merge ALL similar dependency tests in other packages by using run!

	length := eve.Len()
	lengths := make([]int, length)
	for i, c := range eve.Chains {
		lengths[i] = c.Len()
	}

	eve = eve.RotateKey(key.New())

	// TODO: +1 new chain is added, when doing key rotation we don't want only
	// one link length new chain. Figure out how to handle that.
	assert.SLen(eve.Chains, length)
	//t.Skip("see TODO")

	for i, c := range eve.Chains {
		assert.Equal(c.Len(), lengths[i]+1)
	}
}
