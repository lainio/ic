package node

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/digest"
	"github.com/lainio/ic/hop"
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

	root1.Node = New(key.InfoFromHandle(root1), chain.WithEndpoint("root1", true))
	root2.Node = New(key.InfoFromHandle(root2), chain.WithEndpoint("root2", true))
}

func Test_all(t *testing.T) {
	defer assert.PushTester(t)()

	t.Run("new root node", testNewRootNode)
	t.Run("invite", testInvite)
	t.Run("common chains", testCommonChains)
	t.Run("find", testFind)
	t.Run("web of trust info", testWebOfTrustInfo)
	t.Run("integrity", testCheckIntegrity)
}

func testNewRootNode(t *testing.T) {
	defer assert.PushTester(t)()

	aliceNode := New(key.InfoFromHandle(alice))
	assert.SLen(aliceNode.InviteeChains, 1)
	assert.SLen(aliceNode.InviteeChains[0].Blocks, 1)

	bobNode := New(key.InfoFromHandle(bob))
	assert.SLen(bobNode.InviteeChains, 1)
}

func testInvite(t *testing.T) {
	defer assert.PushTester(t)()

	// Root1 chains start here:
	alice.Node = root1.Invite(alice.Node, root1.Handle,
		key.InfoFromHandle(alice), chain.WithPosition(1))
	//      root1
	//        ↓
	//      alice
	assert.Equal(alice.Len(), 1)
	{
		c := alice.InviteeChains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	bob.Node = alice.Invite(bob.Node,
		alice.Handle, key.InfoFromHandle(bob), chain.WithPosition(1))
	//      root1
	//        ↓
	//      alice -> bob
	assert.Equal(bob.Len(), 1)
	{
		c := bob.InviteeChains[0]
		assert.SLen(c.Blocks, 3) // we know how long the chain is now
		assert.That(c.VerifySign())
	}

	// Bob and Alice share same chain root == Root1
	common := alice.CommonChain(bob.Node)
	assert.SNotNil(common.Blocks)

	// root2 chains start here:
	// root2 invites Carol here
	carol.Node = root2.Invite(carol.Node,
		root2.Handle, key.InfoFromHandle(carol), chain.WithPosition(1))
	//     root2
	//       ↓
	//    carol
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
	dave.Node = New(key.InfoFromHandle(dave), chain.WithEndpoint("dave", true))
	eve.Node = dave.Invite(eve.Node,
		dave.Handle, key.InfoFromHandle(eve), chain.WithPosition(1))
	//     dave
	//      ↓
	//     eve
	assert.Equal(eve.Len(), 1)
	{
		c := eve.InviteeChains[0]
		assert.SLen(c.Blocks, 2)
		assert.That(c.VerifySign())
	}

	// Root2 invites Dave and now Dave has 2 chains, BUT this doesn't effect
	// Eve! NOTE but when Dave invites new parties nowon they will get 2 chains
	dave.Node = root2.Invite(dave.Node,
		root2.Handle, key.InfoFromHandle(dave), chain.WithPosition(1))
	//         ┌ root2  ┐
	//         ↓        ↓
	//       carol    dave-2-chains
	//                  ↓
	//           eve(root-is-dave)
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
	eve.Node = carol.Invite(eve.Node,
		carol.Handle, key.InfoFromHandle(eve), chain.WithPosition(1))
	//         ┌ root2  ┐
	//         ↓        ↓
	//       carol    dave-2-chains
	//            ↓     ↓
	//           eve(root-is-dave)
	assert.Equal(eve.Len(), 2, "has two chains")

	// now Eve has common chain with Root2 as well
	common = eve.CommonChain(root2.Node)
	assert.SNotNil(common.Blocks)
}

func testCommonChains(t *testing.T) {
	defer assert.PushTester(t)()

	common := dave.CommonChains(eve.Node)
	assert.SLen(common, 2)
}

func testFind(t *testing.T) {
	defer assert.PushTester(t)()

	//         ┌ root2  ┐
	//         ↓        ↓
	//       carol    dave-2-chains
	//            ↓     ↓
	//           eve(root-is-dave)

	// found ones:
	{
		pubkey := try.To1(dave.CBORPublicKey())
		block, found := eve.Find(pubkey)
		assert.That(found)
		assert.DeepEqual(block.Public(), pubkey)
	}
	{
		pubkey := try.To1(root2.CBORPublicKey())
		block, found := eve.Find(pubkey)
		assert.That(found)
		assert.DeepEqual(block.Public(), pubkey)
	}

	// not found:
	{
		pubkey := try.To1(root1.CBORPublicKey())
		_, found := eve.Find(pubkey) // eve is invited only by root2 chains
		assert.ThatNot(found)
	}
}

func testWebOfTrustInfo(t *testing.T) {
	defer assert.PushTester(t)()

	common := dave.CommonChains(eve.Node)
	assert.SLen(common, 2)

	wot := dave.WebOfTrustInfo(eve.Node)
	assert.Equal(wot.CommonInviterLevel, 0)
	daveIDK := try.To1(dave.CBORPublicKey())
	assert.DeepEqual(wot.CommonInviterPubKey, daveIDK)
	assert.Equal(wot.Hops, 1)
	assert.That(wot.SameChain)
	digestDave := &digest.Digest{
		IDK:     daveIDK,
		RootIDK: daveIDK,
		Hops:    0,
	}
	wot2 := eve.WoT(digestDave) // Let'r try our other WoT method
	assert.NotNil(wot2)
	assert.DeepEqual(wot2.CommonInviterPubKey, daveIDK)
	assert.That(wot2.SameChain)
	assert.Equal(wot2.Hops, 1)

	wot = NewWebOfTrust(bob.Node, carol.Node)
	assert.Equal(wot.CommonInviterLevel, hop.NotConnected)
	assert.Equal(wot.Hops, hop.NotConnected)

	frank.Node = alice.Invite(frank.Node,
		alice.Handle, key.InfoFromHandle(frank), chain.WithPosition(1))
	assert.Equal(frank.Len(), 1)
	assert.Equal(alice.Len(), 1)
	grace.Node = bob.Invite(grace.Node,
		bob.Handle, key.InfoFromHandle(grace), chain.WithPosition(1))
	assert.Equal(grace.Len(), 1)
	assert.Equal(bob.Len(), 1)
	//      root1
	//        ↓
	//      alice -> bob
	//        ↓       ↓
	//      frank   grace
	aliceIDK := try.To1(alice.CBORPublicKey())
	root1IDK := try.To1(root1.CBORPublicKey())

	common = frank.CommonChains(grace.Node)
	assert.SLen(common, 1)
	common = root1.CommonChains(alice.Node)
	assert.SLen(common, 1)
	h, level := common[0].Hops()
	assert.Equal(h, 1)
	assert.Equal(level, 0)

	digestAlice := &digest.Digest{
		IDK:     aliceIDK,
		RootIDK: root1IDK,
		Hops:    1,
	}
	wot2 = frank.WoT(digestAlice)
	assert.NotNil(wot2)
	assert.DeepEqual(wot2.CommonInviterPubKey, root1IDK)
	assert.That(wot2.SameChain)
	assert.Equal(wot2.Hops, 3, "we did give root=root1")

	wot2 = grace.WoT(digestAlice)
	assert.NotNil(wot2)
	assert.DeepEqual(wot2.CommonInviterPubKey, root1IDK)
	assert.That(wot2.SameChain)
	assert.Equal(wot2.Hops, 4, "root was root1")

	digestRoot1 := &digest.Digest{
		IDK:     root1IDK,
		RootIDK: root1IDK,
		Hops:    0,
	}
	wot2 = frank.WoT(digestRoot1)
	assert.NotNil(wot2)
	assert.DeepEqual(wot2.CommonInviterPubKey, root1IDK)
	assert.That(wot2.SameChain)
	assert.Equal(wot2.Hops, 2)

	wot2 = grace.WoT(digestRoot1)
	assert.NotNil(wot2)
	assert.DeepEqual(wot2.CommonInviterPubKey, root1IDK)
	assert.That(wot2.SameChain)
	assert.Equal(wot2.Hops, 3)

	wot = NewWebOfTrust(frank.Node, grace.Node)
	assert.Equal(wot.CommonInviterLevel, 1)
	assert.DeepEqual(wot.CommonInviterPubKey, aliceIDK)
	assert.Equal(wot.Hops, 3)
	assert.ThatNot(wot.SameChain)

	root3 := entity{Handle: key.New()}
	root3.Node = New(key.InfoFromHandle(root3), chain.WithEndpoint("root3", true))
	heidi := entity{Handle: key.New()}
	heidi.Node = root3.Invite(heidi.Node,
		root3.Handle, key.InfoFromHandle(heidi), chain.WithPosition(1))
	assert.SLen(heidi.InviteeChains, 1)
	assert.SLen(heidi.InviteeChains[0].Blocks, 2, "heidi's root is 'root3'")

	// verify Eve's situation:
	assert.SLen(eve.InviteeChains, 2)
	assert.SLen(eve.InviteeChains[0].Blocks, 2, "eve's 1s root: dave")
	assert.SLen(eve.InviteeChains[1].Blocks, 3, "eve's 2nd root: root2")

	// heidi got's 2 new roots from eve:
	heidi.Node = eve.Invite(heidi.Node,
		eve.Handle, key.InfoFromHandle(heidi), chain.WithPosition(1))
	assert.SLen(heidi.InviteeChains, 3, "heidi's 2 + previous 1")

	// NOTE --- does nothing! -----
	//   next dave's invitation doesn't add any new chains because there is no
	//   new roots in daves chains
	heidiNodeLen := heidi.Len()
	heidi.Node = dave.Invite(heidi.Node,
		dave.Handle, key.InfoFromHandle(heidi), chain.WithPosition(1))
	assert.Equal(heidi.Len(), heidiNodeLen)

	//         ┌ root2  ┐                root3
	//         ↓        ↓                  │
	//       carol    dave-2-chains        │
	//            ↓     ↓                  │
	//           eve(root-is-dave)         │
	//           ↓                         ↓
	//        eve(key-rotated) ­─────────→ heidi
	wot = NewWebOfTrust(eve.Node, heidi.Node)
	assert.Equal(wot.CommonInviterLevel, 1, "common root is dave and eve is 1 from it")
	assert.DeepEqual(wot.CommonInviterPubKey, try.To1(eve.CBORPublicKey()))
	assert.Equal(wot.Hops, 1, "dave invites heidi")
	assert.That(wot.SameChain)
	assert.That(eve.IsInviterFor(heidi.Node))
	assert.That(root3.IsInviterFor(heidi.Node))
	assert.That(heidi.OneHop(eve.Node))
	assert.That(eve.OneHop(heidi.Node))
}

func testCheckIntegrity(t *testing.T) {
	defer assert.PushTester(t)()

	// - OK versions
	try.To(alice.CheckIntegrity())
	try.To(bob.CheckIntegrity())
	try.To(carol.CheckIntegrity())
	try.To(dave.CheckIntegrity())
	try.To(eve.CheckIntegrity())
	try.To(frank.CheckIntegrity())
	try.To(grace.CheckIntegrity())
	try.To(root1.CheckIntegrity())
	try.To(root2.CheckIntegrity())

	// - Not OK ruined version TODO:
	// - this very bad test but until we have better...
	grace.InviteeChains[0].Blocks[0].Public()[32] = 0 // let's ruin one byte
	err := grace.CheckIntegrity()
	assert.Error(err, "see 2 lines above ^")
	assert.ThatNot(err == ErrWrongKey)
	assert.That(err == ErrSignature)
}
