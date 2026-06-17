package intro

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

var (
	// root -> alice, root -> bob: alice and bob share same root inviter
	rootMaster, root, alice, bob entity

	// root2 -> alice2, root2 -> bob2: alice2 and bob2 share same root inviter
	root2, alice2, bob2 entity

	// for TestFind & fred who has long path
	edvin entity

	//  first path for generic path tests
	testPath            Path
	rootKey, inviteeKey key.Handle
)

type entity struct {
	key.Handle
	Path
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {}

func setup() {
	// general path for tests
	rootKey = key.New()
	testPath = New(key.InfoFromHandle(rootKey))
	inviteeKey = key.New()
	level := 1
	testPath = testPath.Invite(
		rootKey,
		key.InfoFromHandle(inviteeKey),
		WithPosition(level),
	)

	// root, alice, bob setup
	rootMaster.Handle = key.New()
	root.Handle = key.New()
	alice.Handle = key.New()
	bob.Handle = key.New()
	// start root with one rotation key
	rootMaster.Path = New(
		key.InfoFromHandle(rootMaster),
	)
	root.Path = rootMaster.Invite(
		rootMaster.Handle,
		key.InfoFromHandle(root),
		WithRotation(),
		WithPosition(1),
	)
	// root invites alice and bod but they have no invitation between
	alice.Path = root.Invite(
		root.Handle,
		key.InfoFromHandle(alice),
		WithPosition(1),
	)
	bob.Path = root.Invite(
		root.Handle,
		key.InfoFromHandle(bob),
		WithPosition(1),
	)

	// root2, alice2, bob2 setup
	root2.Handle = key.New()
	alice2.Handle = key.New()
	bob2.Handle = key.New()
	// start second root without rotation key
	root2.Path = New(key.InfoFromHandle(root2))

	// root2 invites alice2 and bod2 but they have no invitation between
	alice2.Path = root2.Invite(
		root2.Handle,
		key.InfoFromHandle(alice2),
		WithPosition(1),
	)
	bob2.Path = root2.Invite(
		root2.Handle,
		key.InfoFromHandle(bob2),
		WithPosition(1),
	)
}

func Test_all(t *testing.T) {
	defer assert.PushTester(t)()

	t.Run("new path", testNewPath)
	t.Run("read", testRead)
	t.Run(
		"verify path fail",
		testVerifyPathFail,
	)
	t.Run("verify path", testVerifyPath)
	t.Run("invitation", testInvitation)
	t.Run(
		"common inviter level",
		testCommonInviterLevel,
	)
	t.Run("same inviter", testSameInviter)
	t.Run("hops", testHops)
	t.Run("find", testFind)
	t.Run(
		"challenge invitee",
		testChallengeInvitee,
	)
}

func testNewPath(t *testing.T) {
	defer assert.PushTester(t)()

	k := key.New()
	c := New(
		key.InfoFromHandle(k),
		WithRotation(),
	)

	assert.SLen(c, 1)
	assert.Equal(c.Len(), 1)
	assert.Equal(c.KeyRotationsLen(), 1)
	//assert.Equal(c.AbsLen(), 1)

	k2 := key.New()
	c = c.Invite(
		k,
		key.InfoFromHandle(k2),
		WithRotation(),
		WithPosition(1),
	)
	assert.Equal(
		c.Len(),
		2,
		"naturally +1 from previous",
	)
	assert.Equal(c.KeyRotationsLen(), 2)
	//assert.Equal(c.AbsLen(), 1)

	k3 := key.New()
	c = c.Invite(
		k2,
		key.InfoFromHandle(k3),
		WithRotation(),
		WithPosition(1),
	)
	assert.Equal(
		c.Len(),
		3,
		"naturally +1 from previous",
	)
	assert.Equal(c.KeyRotationsLen(), 3)
	//assert.Equal(c.AbsLen(), 1)
}

func testRead(t *testing.T) {
	defer assert.PushTester(t)()

	c2 := testPath.Clone()
	assert.SLen(c2, 2)
	assert.That(c2.VerifySignatures())
}

func testVerifyPathFail(t *testing.T) {
	defer assert.PushTester(t)()

	c2 := testPath.Clone()
	assert.SLen(c2, 2)
	assert.That(c2.VerifySignatures())

	b2 := c2[1]
	b2.ParentSig[len(b2.ParentSig)-1] += 0x01

	assert.That(!c2.VerifySignatures())
}

func testVerifyPath(t *testing.T) {
	defer assert.PushTester(t)()

	assert.SLen(testPath, 2)
	assert.That(testPath.VerifySignatures())

	newInvitee := key.New()
	level := 3
	testPath = testPath.Invite(
		inviteeKey,
		key.InfoFromHandle(newInvitee),
		WithPosition(level),
	)

	assert.SLen(testPath, 3)
	assert.That(testPath.VerifySignatures())
}

func testInvitation(t *testing.T) {
	defer assert.PushTester(t)()

	assert.SLen(alice.Path, 3)
	assert.That(alice.Path.VerifySignatures())
	assert.SLen(bob.Path, 3)
	assert.That(bob.Path.VerifySignatures())

	cecilia := entity{
		Handle: key.New(),
	}
	cecilia.Path = bob.Invite(
		bob.Handle,
		key.InfoFromHandle(cecilia),
		WithPosition(1),
	)
	assert.SLen(cecilia.Path, 4)
	assert.That(cecilia.Path.VerifySignatures())
	assert.That(
		!SameRoot(testPath, cecilia.Path),
		"we have two different roots",
	)
	assert.That(
		SameRoot(alice.Path, cecilia.Path),
	)
}

// common root : my distance, her distance

// TestCommonInviterLevel tests that Path owners have one common inviter
func testCommonInviterLevel(t *testing.T) {
	defer assert.PushTester(t)()

	// alice and bod have common root:
	//       rootMaster
	//           ↓
	//       ┌  root  ┐
	//       ↓        ↓
	//     alice     bob
	cecilia := entity{
		Handle: key.New(),
	}

	// bob intives cecilia
	cecilia.Path = bob.Invite(
		bob.Handle,
		key.InfoFromHandle(cecilia),
		WithPosition(1),
	)
	//       rootMaster
	//           ↓
	//       ┌  root  ┐
	//       ↓        ↓
	//     alice     bob
	//                ↓
	//             cecilia
	assert.SLen(cecilia.Path, 4)
	assert.That(cecilia.Path.VerifySignatures())

	david := entity{
		Handle: key.New(),
	}
	// alice invites david
	david.Path = alice.Invite(
		alice.Handle,
		key.InfoFromHandle(david),
		WithPosition(1),
	)
	//       rootMaster
	//           ↓
	//       ┌  root  ┐
	//       ↓        ↓
	//     alice     bob
	//       ↓        ↓
	//     david   cecilia
	cinviter, sameIC := CommonInviterLevel(
		cecilia.Path,
		david.Path,
	)
	assert.Equal(
		cinviter,
		1,
		"common inviter is root whos lvl is 1",
	)
	assert.ThatNot(sameIC)

	edvin := entity{
		Handle: key.New(),
	}
	edvin.Path = alice.Invite(
		alice.Handle,
		key.InfoFromHandle(edvin),
		WithPosition(1),
	)
	//           rootMaster
	//               ↓
	//           ┌  root  ┐
	//           ↓        ↓
	//   ┌──── alice     bob
	//   ↓       ↓        ↓
	// edvin   david   cecilia
	cinviter, sameIC = CommonInviterLevel(
		edvin.Path,
		david.Path,
	)
	assert.Equal(
		cinviter,
		2,
		"alice is at level 2 from path's root and inviter of both",
	)
	assert.ThatNot(sameIC)

	edvin2Path := alice.Path.Invite(
		alice.Handle,
		key.InfoFromHandle(key.New()),
		WithPosition(1),
	)
	//           rootMaster
	//               ↓
	//           ┌  root  ──────────┐
	//           ↓                  ↓
	//   ┌──── alice ─────┐        bob
	//   ↓       ↓        ↓         ↓
	// edvin2  edvin    david    cecilia
	cinviter, sameIC = CommonInviterLevel(
		edvin2Path,
		david.Path,
	)
	assert.Equal(
		cinviter,
		2,
		"alice is at level 2 from path's root and inviter of both",
	)
	assert.ThatNot(sameIC)

	fred1Path := edvin.Invite(
		edvin.Handle,
		key.InfoFromHandle(key.New()),
		WithPosition(1),
	)
	fred2Path := edvin.Invite(
		edvin.Handle,
		key.InfoFromHandle(key.New()),
		WithPosition(1),
	)
	//           rootMaster                          lvl 0
	//               ↓
	//           ┌  root  ──────────┐                lvl 1
	//           ↓                  ↓
	//   ┌──── alice ─────┐        bob               lvl 2
	//   ↓       ↓        ↓         ↓
	// edvin2  edvin ┐  david    cecilia             lvl 3
	//         ↓     ↓
	//      fred1   fred2                            lvl 4
	cinviter, sameIC = CommonInviterLevel(
		fred2Path,
		fred1Path,
	)
	assert.Equal(
		cinviter,
		3,
		"edvin is at level 3 from path's root",
	)
	assert.ThatNot(sameIC)

	cinviter, sameIC = CommonInviterLevel(
		alice.Path,
		fred1Path,
	)
	assert.Equal(
		cinviter,
		2,
		"alice is at level 2 from path's root",
	)
	assert.That(
		sameIC,
		"alice is fred's path's 'root'",
	)

	cinviter, sameIC = CommonInviterLevel(
		bob.Path,
		cecilia.Path,
	)
	assert.Equal(
		cinviter,
		2,
		"bob is at level 2 from path's root",
	)
	assert.That(
		sameIC,
		"bob is cecilia's path's 'root'",
	)

	cinviter, sameIC = CommonInviterLevel(
		root.Path,
		cecilia.Path,
	)
	assert.Equal(
		cinviter,
		1,
		"root is at level 2 from path's root",
	)
	assert.That(
		sameIC,
		"root is cecilia's path's 'root'",
	)
}

// TestSameInviter test that two path holders have same inviter.
func testSameInviter(t *testing.T) {
	defer assert.PushTester(t)()

	assert.That(
		SameInviter(alice.Path, bob.Path),
	)
	assert.That(
		!SameInviter(testPath, bob.Path),
	)

	cecilia := entity{
		Handle: key.New(),
	}
	cecilia.Path = bob.Invite(
		bob.Handle,
		key.InfoFromHandle(cecilia),
		WithPosition(1),
	)
	assert.That(cecilia.Len() == 4)
	assert.That(cecilia.Path.VerifySignatures())
	assert.That(bob.IsInviterFor(cecilia.Path))
	assert.That(
		!alice.IsInviterFor(cecilia.Path),
	)
}

// TestHops test hop counts.
func testHops(t *testing.T) {
	defer assert.PushTester(t)()

	//       ┌  root2  ┐
	//       ↓         ↓
	//     alice2     bob2
	hop, cLevel := alice2.Hops(bob2.Path)
	assert.Equal(
		hop,
		2,
		"alice2 and bob2 share common root (root2)",
	)
	assert.Equal(
		cLevel,
		0,
		"alice's and bob's inviter is path root!",
	)

	//       rootMaster
	//           ↓
	//       ┌  root  ┐
	//       ↓        ↓
	//     alice     bob
	hop, cLevel = alice.Hops(bob.Path)
	assert.Equal(
		hop,
		2,
		"alice and bob share common root",
	)
	assert.Equal(
		cLevel,
		1,
		"alice's and bob's inviter is ROTATED path root",
	)

	cecilia := entity{
		Handle: key.New(),
	}
	cecilia.Path = bob.Invite(
		bob.Handle,
		key.InfoFromHandle(cecilia),
		WithPosition(1),
	)
	//       rootMaster
	//           ↓
	//       ┌  root  ┐
	//       ↓        ↓
	//     alice     bob
	//                ↓
	//             cecilia
	hop, cLevel = alice.Hops(cecilia.Path)
	assert.Equal(
		hop,
		3,
		"alice has 1 hop to root, cecilia 2 hpos == 3",
	)
	assert.Equal(
		cLevel,
		1,
		"the share inviter is path root",
	)

	david := entity{
		Handle: key.New(),
	}
	david.Path = bob.Invite(
		bob.Handle,
		key.InfoFromHandle(david),
		WithPosition(1),
	)
	//       rootMaster
	//           ↓
	//       ┌  root  ─┐
	//       ↓         ↓
	//     alice    ┌ bob ─┐
	//              ↓      ↓
	//          cecilia  david
	hop, cLevel = david.Hops(cecilia.Path)
	assert.Equal(
		hop,
		2,
		"david and cecilia share bod as inviter",
	)
	assert.Equal(
		cLevel,
		2,
		"david's and cecilia's inviter bob is 1 hop from root",
	)

	edvin = entity{
		Handle: key.New(),
	}
	edvin.Path = david.Invite(
		david.Handle,
		key.InfoFromHandle(edvin),
		WithPosition(1),
	)
	//       rootMaster
	//           ↓
	//       ┌  root  ─┐
	//       ↓         ↓
	//     alice    ┌ bob ─┐
	//              ↓      ↓
	//          cecilia  david
	//                     ↓
	//                   edvin
	hop, cLevel = edvin.Hops(cecilia.Path)
	assert.Equal(
		hop,
		3,
		"cecilia has 1 hop to common inviter bob and edvin has 2 hops == 3",
	)
	assert.Equal(
		cLevel,
		2,
		"common inviter of cecilia and edvin is bod that's 1 hop from path root",
	)

	hop, cLevel = Hops(alice.Path, edvin.Path)
	assert.Equal(
		hop,
		4,
		"alice and edvin share root as a common inviter => 1 + 3",
	)
	assert.Equal(
		cLevel,
		1,
		"alice's and edvin's common inviter root is path root",
	)
}

func testFind(t *testing.T) {
	defer assert.PushTester(t)()

	{
		foundEdge, found := edvin.Find(
			rootMaster.LastEdge().Public(),
		)
		assert.NotEqual(found, hop.NotConnected)
		assert.DeepEqual(
			foundEdge.ID(),
			key.ID(rootMaster.ID()),
		)
	}
	{
		foundEdge, found := edvin.Find(
			bob.LastEdge().Public(),
		)
		assert.NotEqual(found, hop.NotConnected)
		assert.DeepEqual(
			foundEdge.ID(),
			key.ID(bob.ID()),
		)
	}
	{
		rootEdge, found := edvin.Find(
			root.LastEdge().Public(),
		)
		assert.NotEqual(found, hop.NotConnected)
		assert.DeepEqual(
			rootEdge.ID(),
			key.ID(root.ID()),
		)
	}
}

// TestChallengeInvitee test shows how we can challenge the party who presents
// us a path. Paths are presentad as full! At least for now. They don't
// include any personal data, and we try to make sure that they won't include
// any data which could be used to correlate the use of the path. Path is only
// for the proofing the position in the Invitation Path.
func testChallengeInvitee(t *testing.T) {
	defer assert.PushTester(t)()

	// path leaf is the only part who has the private key for the leaf, so
	// it can response the challenge properly.

	// Challenge is needed that we can be sure that the party who presents the
	// path is the actual owner of the path.

	// When let's say Bob have received Alice's path he can use Challenge
	// method for Alice's Path to let Alice proof that she controls the path
	pinCode := 1234
	// success tests:
	assert.That(alice.Challenge(pinCode,
		func(d []byte) key.Signature {
			// In real world usage here we would send the d for Alice's signing
			// over the network.
			b := NewEdgeFromData(d)
			// pinCode is transported out-of-band and entered *before* signing
			b.Position = pinCode
			d = b.Bytes()
			return try.To1(alice.Sign(d))
		},
	))
	assert.That(bob.Challenge(pinCode,
		func(d []byte) key.Signature {
			b := NewEdgeFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			return try.To1(bob.Sign(d))
		},
	))

	// failures:
	// Test that if alice tries to sign bob's challenge it won't work.
	assert.ThatNot(bob.Challenge(pinCode,
		func(d []byte) key.Signature {
			b := NewEdgeFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			// NOTE Alice canot sign bob's challenge
			return try.To1(alice.Sign(d))
		},
	))
	// Wrong pinCode
	assert.ThatNot(bob.Challenge(pinCode+1,
		func(d []byte) key.Signature {
			b := NewEdgeFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			return try.To1(bob.Sign(d))
		},
	))
}
