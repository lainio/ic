package identity

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

const (
	endpointValueRoot1 = "endpoint_value_root1"
	endpointValueRoot2 = "endpoint_value_root2"
	endpointValueRoot3 = "endpoint_value_root3"
	endpointValueDave  = "endpoint_value_dave"
)

var (
	// root1 -> alice, alice -> bob, root2 -> carol
	root1, alice, bob, carol,

	// dave (new root) -> eve, root2 -> dave, carol -> eve (now root2 member)
	root2, dave, eve Identity

	// root3 --> ivan --> mike
	//   │
	//   └───-> judy --> olivia
	root3, ivan, mike, judy, olivia Identity

	// alice -> frank, bob -> grace
	frank, grace Identity
)

func TestIdentity_All(t *testing.T) {
	defer assert.PushTester(t)()

	t.Run("create all", testSetup)
	t.Run("new identity", testNewIdentity)
	t.Run("invite", testIdentityInvite)
	t.Run("rotate key", testRotateKey)
	t.Run("rotate and invite", testRotateAndInvite)
	t.Run("trust level", testTrustLevel)
	t.Run("endpoint", testEndpoint)
	t.Run("resolver", testResolver)
	t.Run("web of trust", testWebOfTrust)
	t.Run("challenge", testChallenge)
	t.Run("great backup keys", testCreateBackupKeysAmount)
	t.Run("rotate backup key", testRotateToBackupKey)
}

func testSetup(t *testing.T) {
	defer assert.PushTester(t)()

	isResolver := true
	root1 = New(key.New(), chain.WithEndpoint(endpointValueRoot1, isResolver))
	assert.SLen(root1.InviteeChains, 1)
	assert.SLen(root1.InviteeChains[0].Blocks, 1)

	root2 = New(key.New(), chain.WithEndpoint(endpointValueRoot2, isResolver))
	root3 = New(key.New(), chain.WithEndpoint(endpointValueRoot3, isResolver))
	alice = New(key.New())
	assert.SLen(alice.InviteeChains, 1)
	assert.SLen(alice.InviteeChains[0].Blocks, 1)

	bob = New(key.New())
	carol = New(key.New())
	assert.SLen(carol.InviteeChains, 1)
	assert.SLen(carol.InviteeChains[0].Blocks, 1)

	eve = New(key.New())
	frank = New(key.New())
	grace = New(key.New())
	ivan = New(key.New())
	mike = New(key.New())
	judy = New(key.New())
	olivia = New(key.New())
}

func testNewIdentity(t *testing.T) {
	defer assert.PushTester(t)()

	aliceID := New(key.New())
	assert.SLen(aliceID.InviteeChains, 1)
	assert.SLen(aliceID.InviteeChains[0].Blocks, 1)

	bobID := New(key.New())
	assert.SLen(bobID.InviteeChains, 1)
}

func testIdentityInvite(t *testing.T) {
	defer assert.PushTester(t)()

	// Root1 chains start here:
	assert.Equal(alice.Len(), 1)
	alice = root1.Invite(alice, chain.WithPosition(1))
	assert.Equal(alice.Len(), 2)
	{
		c := alice.InviteeChains[1] // 0 is our ID chain
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	bob = alice.Invite(bob, chain.WithPosition(1))
	assert.Equal(bob.Len(), 3)
	{
		c := bob.InviteeChains[2] // 2 is the last
		assert.SLen(c.Blocks, 3)  // we know how long the chain is now
		assert.That(c.VerifySign())
	}

	// Bob and Alice share same chain root == Root1
	common := alice.CommonChain(bob.Node)
	assert.SNotNil(common.Blocks)

	// Root2 invites Carol here
	carol = root2.Invite(carol, chain.WithPosition(1))
	assert.Equal(carol.Len(), 2)
	{
		c := carol.InviteeChains[1] // 1 is the last
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	// Alice is in Root1 chain and Carol in Root2 chain, so no common ground.
	common = alice.CommonChain(carol.Node)
	assert.SNil(common.Blocks)

	// Dave is one of the roots as well and we build it here:
	dave = New(key.New(), chain.WithEndpoint(endpointValueDave, true))
	eve = dave.Invite(eve, chain.WithPosition(1))
	assert.Equal(eve.Len(), 2)
	{
		c := eve.InviteeChains[1]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	// Root2 invites Dave and now Dave has 2 chains, BUT this doesn't effect
	// Eve!
	dave = root2.Invite(dave, chain.WithPosition(1))
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
	eve = carol.Invite(eve, chain.WithPosition(1))
	assert.Equal(eve.Len(), 4)

	// now Eve has common chain with Root1 as well
	common = eve.CommonChain(root2.Node)
	assert.SNotNil(common.Blocks)
}

func testRotateKey(t *testing.T) {
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

func testRotateAndInvite(t *testing.T) {
	defer assert.PushTester(t)()

	// root3 --> ivan --> mike
	//     \
	//      --> judy --> olivia
	{
		assert.SLen(ivan.InviteeChains, 1)
		ivan = root3.InviteWithRotateKey(ivan, chain.WithPosition(1))
		assert.SLen(ivan.InviteeChains, 2)
		assert.SLen(ivan.InviteeChains[1].Blocks, 2+1,
			"2 parties + 1 rotation")
	}
	{
		assert.SLen(judy.InviteeChains, 1)
		judy = root3.InviteWithRotateKey(judy, chain.WithPosition(1))
		assert.SLen(judy.InviteeChains, 2)
		assert.SLen(judy.InviteeChains[1].Blocks, 2+1,
			"2 parties + 1 rotation")
	}
	{
		assert.SLen(mike.InviteeChains, 1)
		mike = ivan.InviteWithRotateKey(mike, chain.WithPosition(1))
		assert.SLen(judy.InviteeChains, 2)
		assert.SLen(mike.InviteeChains, 3)
		assert.SLen(mike.InviteeChains[2].Blocks, 3+1+1,
			"old length 3 + 1 new party + 1 rotation")
	}
	{
		assert.SLen(olivia.InviteeChains, 1)
		olivia = judy.InviteWithRotateKey(olivia, chain.WithPosition(1))
		assert.SLen(judy.InviteeChains, 2)
		assert.SLen(olivia.InviteeChains, 3)
		assert.SLen(olivia.InviteeChains[2].Blocks, 3+1+1,
			"old length 3 + 1 new party + 1 rotation")
	}
	// judy 'tries' to invite mike.
	// mike is already invited to root3's chain, nothing happens
	{
		assert.SLen(mike.InviteeChains, 3, "1 IC already w/ same root")
		mike = judy.InviteWithRotateKey(mike, chain.WithPosition(1))
		assert.SLen(judy.InviteeChains, 2, "nothing new")
		assert.SLen(mike.InviteeChains, 4, "nothing new")
		assert.SLen(mike.InviteeChains[2].Blocks, 3+1+1,
			"old length 3 + 1 new party + 1 rotation")
	}
}

func testTrustLevel(t *testing.T) {
	defer assert.PushTester(t)()

	lvl := dave.TrustLevel()
	assert.Equal(lvl, 0)
}

func testEndpoint(t *testing.T) {
	defer assert.PushTester(t)()

	//         ┌ root2  ┐
	//         ↓        ↓
	//       carol    dave-2-chains
	//            ↓     ↓
	//           eve(root-is-dave)
	//           ↓
	//        eve(key-rotated)
	{
		pubkey := try.To1(root2.CBORPublicKey())
		ep := eve.Endpoint(pubkey)
		assert.NotEmpty(ep)
		assert.Equal(ep, endpointValueRoot2)
	}
	{
		pubkey := try.To1(dave.CBORPublicKey())
		ep := eve.Endpoint(pubkey)
		assert.NotEmpty(ep)
		assert.Equal(ep, endpointValueDave)
	}
}

func testResolver(t *testing.T) {
	defer assert.PushTester(t)()

	{
		ep := carol.Resolver()
		assert.NotEmpty(ep)
		assert.Equal(ep, endpointValueRoot2)
	}
	//      root1
	//        ↓
	//      alice -> bob
	{
		ep := alice.Resolver()
		assert.NotEmpty(ep)
		assert.Equal(ep, endpointValueRoot1)
	}
	{
		ep := bob.Resolver()
		assert.NotEmpty(ep)
		assert.Equal(ep, endpointValueRoot1)
	}
}

func testWebOfTrust(t *testing.T) {
	defer assert.PushTester(t)()

	//         ┌ root2  ┐
	//         ↓        ↓
	//       carol    dave-2-chains
	//            ↓     ↓
	//           eve(root-is-dave)
	//           ↓
	//        eve(key-rotated)
	{
		wot := root2.WebOfTrust(eve)
		assert.Equal(wot.Hops, 3)
		assert.Equal(wot.CommonInviterLevel, 0)
		assert.DeepEqual(wot.CommonInviterPubKey, try.To1(root2.CBORPublicKey()))
	}
	{
		wot := carol.WebOfTrust(eve)
		assert.Equal(wot.Hops, 2)
		assert.Equal(wot.CommonInviterLevel, 0)
		assert.DeepEqual(wot.CommonInviterPubKey, try.To1(carol.CBORPublicKey()))
	}
	{
		wot := eve.WebOfTrust(carol)
		assert.Equal(wot.Hops, 2)
		assert.Equal(wot.CommonInviterLevel, 0)
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

	frank = alice.Invite(frank, chain.WithPosition(1))
	grace = bob.Invite(grace, chain.WithPosition(1))
	//      root1
	//        ↓
	//      alice -> bob
	//        ↓       ↓
	//      frank   grace
	{
		wot := frank.WebOfTrust(grace)
		assert.Equal(wot.Hops, 3)
		assert.Equal(wot.CommonInviterLevel, 0)
	}
	{
		wot := alice.WebOfTrust(bob)
		assert.Equal(wot.Hops, 1)
		assert.Equal(wot.CommonInviterLevel, 0)
	}
	//      root1
	//        ↓
	//      alice -> bob
	//        ↓       ↓
	//      frank   grace
	//        ↓
	//      frank(when-key-rotated)
	frank = frank.RotateKey(key.New())
	{
		wot := frank.WebOfTrust(grace)
		assert.Equal(wot.Hops, 4)
		assert.Equal(wot.CommonInviterLevel, 0)
	}
}

func testChallenge(t *testing.T) {
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

// TODO: lots of work still todo: order of these rotation functions cannot be
// free!!

func testCreateBackupKeysAmount(t *testing.T) {
	defer assert.PushTester(t)()

	dave.CreateBackupKeysAmount(3)
	assert.SLen(dave.Node.BackupKeys.Blocks, 3)

	frank.CreateBackupKeysAmount(3)
	assert.SLen(frank.Node.BackupKeys.Blocks, 3)

	grace.CreateBackupKeysAmount(2)
	assert.SLen(grace.Node.BackupKeys.Blocks, 2)

	eve.CreateBackupKeysAmount(2)
	assert.SLen(eve.Node.BackupKeys.Blocks, 2)
}

func testRotateToBackupKey(t *testing.T) {
	defer assert.PushTester(t)()

	{
		prevLen := dave.InviteeChains[0].Len()
		dave = dave.RotateToBackupKey(2)
		assert.SLen(dave.InviteeChains[0].Blocks, int(prevLen)+1)
	}
	{
		assert.SLen(frank.Node.BackupKeys.Blocks, 3)
		prevLen := frank.InviteeChains[0].Len()
		frank = frank.RotateToBackupKey(1)
		assert.SLen(frank.Node.BackupKeys.Blocks, 3)
		assert.That(frank.CheckIntegrity())
		assert.SLen(frank.InviteeChains[0].Blocks, int(prevLen)+1)
	}
	{
		assert.SLen(grace.Node.BackupKeys.Blocks, 2)
		prevLen := grace.InviteeChains[0].Len()
		grace = grace.RotateToBackupKey(1)
		assert.SLen(grace.Node.BackupKeys.Blocks, 2)
		assert.That(grace.CheckIntegrity())
		assert.SLen(grace.InviteeChains[0].Blocks, int(prevLen)+1)
	}

	// eve has most complex situation before RotateToBackupKey, and it's best
	// version to be used for table testing
	if true {
		assert.SLen(eve.Node.BackupKeys.Blocks, 2)
		prevLenghts := make([]int, eve.Len())
		prevChainsLen := len(eve.InviteeChains)
		for i := range prevChainsLen {
			prevLenghts[i] = int(eve.InviteeChains[i].Len())
		}
		eve = eve.RotateToBackupKey(1)
		assert.SLen(eve.Node.BackupKeys.Blocks, 2)
		assert.SLen(eve.InviteeChains, prevChainsLen)

		assert.That(eve.CheckIntegrity())

		for i := range prevChainsLen {
			assert.Equal(int(eve.InviteeChains[i].Len()), prevLenghts[i]+1)
		}
	}
}
