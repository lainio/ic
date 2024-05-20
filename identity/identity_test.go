package identity

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

const (
	endpointValue     = "endpoint_value"
	endpointValueDave = "endpoint_value_dave"
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
	root2 = New(root2, chain.WithEndpoint(endpointValue, true))
}

func TestNewIdentity(t *testing.T) {
	defer assert.PushTester(t)()

	aliceID := New(alice)
	assert.SLen(aliceID.InviteeChains, 1)
	assert.SLen(aliceID.InviteeChains[0].Blocks, 1)

	bobID := New(bob)
	assert.SLen(bobID.InviteeChains, 1)
}

func TestIdentity_Invite(t *testing.T) {
	defer assert.PushTester(t)()

	// Root1 chains start here:
	alice = root1.Invite(alice, 1)
	assert.Equal(alice.Len(), 1)
	{
		c := alice.InviteeChains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	bob = alice.Invite(bob, 1)
	assert.Equal(bob.Len(), 1)
	{
		c := bob.InviteeChains[0]
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
		c := carol.InviteeChains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	// Alice is in Root1 chain and Carol in Root2 chain, so no common ground.
	common = alice.CommonChain(carol.Node)
	assert.SNil(common.Blocks)

	// Dave is one of the roots as well and we build it here:
	dave = New(dave, chain.WithEndpoint(endpointValueDave, true))
	eve = dave.Invite(eve, 1)
	assert.Equal(eve.Len(), 1)
	{
		c := eve.InviteeChains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	// Root2 invites Dave and now Dave has 2 chains, BUT this doesn't effect
	// Eve!
	dave = root2.Invite(dave, 1)
	assert.Equal(dave.Len(), 2)
	{
		c := dave.InviteeChains[1]
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
	lengths := make([]hop.Distance, length)
	for i, c := range eve.InviteeChains {
		lengths[i] = c.Len()
	}

	eve = eve.RotateKey(key.New())

	// TODO: +1 new chain is added, when doing key rotation we don't want only
	// one link length new chain. Figure out how to handle that.
	assert.SLen(eve.InviteeChains, length)
	//t.Skip("see TODO")

	for i, c := range eve.InviteeChains {
		assert.Equal(c.Len(), lengths[i]+1)
	}
}

func TestTrustLevel(t *testing.T) {
	defer assert.PushTester(t)()

	lvl := dave.TrustLevel()
	assert.Equal(lvl, 0)
}

func TestEndpoint(t *testing.T) {
	defer assert.PushTester(t)()

	//                  root2
	//                  /    \
	//                \/     \/
	//              carol    dave-2-chains
	//                   \       //
	//                   \/     \/
	//                  eve(root-is-dave)
	//                  /
	//                \/
	//               eve(key-rotated)
	{
		pubkey := try.To1(root2.CBORPublicKey())
		ep := eve.Endpoint(pubkey)
		assert.NotEmpty(ep)
		assert.Equal(ep, endpointValue)
	}
	{
		pubkey := try.To1(dave.CBORPublicKey())
		ep := eve.Endpoint(pubkey)
		assert.NotEmpty(ep)
		assert.Equal(ep, endpointValueDave)
	}
}

func TestWebOfTrust(t *testing.T) {
	defer assert.PushTester(t)()

	//                  root2
	//                  /    \
	//                \/     \/
	//              carol    dave-2-chains
	//                   \       //
	//                   \/     \/
	//                  eve(root-is-dave)
	//                  /
	//                \/
	//               eve(key-rotated)
	{
		wot := root2.WebOfTrust(eve)
		assert.Equal(wot.Hops, 3)
		assert.Equal(wot.CommonInviterLevel, 0)
		assert.DeepEqual(wot.CommonInviterPubKey, try.To1(root2.CBORPublicKey()))
	}
	{
		wot := carol.WebOfTrust(eve)
		assert.Equal(wot.Hops, 2)
		assert.Equal(wot.CommonInviterLevel, 1)
		assert.DeepEqual(wot.CommonInviterPubKey, try.To1(carol.CBORPublicKey()))
	}
	{
		wot := eve.WebOfTrust(carol)
		assert.Equal(wot.Hops, 2)
		assert.Equal(wot.CommonInviterLevel, 1)
		assert.DeepEqual(wot.CommonInviterPubKey, try.To1(carol.CBORPublicKey()))
	}
	{
		wot := eve.WebOfTrust(root2)
		assert.Equal(wot.Hops, 3)
		assert.Equal(wot.CommonInviterLevel, 0)
		assert.DeepEqual(wot.CommonInviterPubKey, try.To1(root2.CBORPublicKey()))
	}
	{
		wot := eve.WebOfTrust(dave)
		assert.Equal(wot.Hops, 1+1, "rotation 1+1")
		assert.Equal(wot.CommonInviterLevel, 0)

		assert.DeepEqual(wot.CommonInviterPubKey,
			try.To1(dave.CBORPublicKey()), "dave invited originally eve!")
	}

	frank = alice.Invite(frank, 1)
	grace = bob.Invite(grace, 1)
	//                  root1
	//                  /
	//                \/
	//              alice -->   bob
	//               \            \
	//               \/            \/
	//              frank         grace
	{
		wot := frank.WebOfTrust(grace)
		assert.Equal(wot.Hops, 3)
		assert.Equal(wot.CommonInviterLevel, 1)
	}
	{
		wot := alice.WebOfTrust(bob)
		assert.Equal(wot.Hops, 1)
		assert.Equal(wot.CommonInviterLevel, 1)
	}
	//                  root1
	//                  /
	//                \/
	//              alice -->   bob
	//               \            \
	//               \/            \/
	//              frank         grace
	//              /
	//            \/
	//           frank(when-key-rotated)
	frank = frank.RotateKey(key.New())
	{
		wot := frank.WebOfTrust(grace)
		assert.Equal(wot.Hops, 4)
		assert.Equal(wot.CommonInviterLevel, 1)
	}
}

func TestChallenge(t *testing.T) {
	defer assert.PushTester(t)()

	// When let's say Bob have received Alice's Identity he can use Challenge
	// method for Alice's Identity to let Alice proof that she controls the
	// Identity
	pinCode := 1234
	// success tests:
	assert.That(alice.Challenge(pinCode,
		func(d []byte) key.Signature {
			// In real world usage here we would send the d for Alice's signing
			// over the network.
			b := chain.NewBlockFromData(d)
			// pinCode is transported out-of-band and entered *before* signing
			b.Position = pinCode
			d = b.Bytes()
			return try.To1(alice.Sign(d))
		},
	))
	assert.That(bob.Challenge(pinCode,
		func(d []byte) key.Signature {
			b := chain.NewBlockFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			return try.To1(bob.Sign(d))
		},
	))

	// failures:
	// Test that if alice tries to sign bob's challenge it won't work.
	assert.ThatNot(bob.Challenge(pinCode,
		func(d []byte) key.Signature {
			b := chain.NewBlockFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			// NOTE Alice canot sign bob's challenge
			return try.To1(alice.Sign(d))
		},
	))
	// Wrong pinCode
	assert.ThatNot(bob.Challenge(pinCode+1,
		func(d []byte) key.Signature {
			b := chain.NewBlockFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			return try.To1(bob.Sign(d))
		},
	))
}
