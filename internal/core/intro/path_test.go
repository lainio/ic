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
	// root -> alice, root -> bob: alice and bob share same root parent
	rootMaster, root, alice, bob entity

	// root2 -> alice2, root2 -> bob2: alice2 and bob2 share same root parent
	root2, alice2, bob2 entity

	// for TestFind & fred who has long path
	edvin entity

	//  first path for generic path tests
	testPath          Path
	rootKey, childKey key.Handle
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
	childKey = key.New()
	level := 1
	testPath = testPath.Introduce(
		rootKey,
		key.InfoFromHandle(childKey),
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
	root.Path = rootMaster.Introduce(
		rootMaster.Handle,
		key.InfoFromHandle(root),
		WithRotation(),
		WithPosition(1),
	)
	// root invites alice and bod but they have no introduction between
	alice.Path = root.Introduce(
		root.Handle,
		key.InfoFromHandle(alice),
		WithPosition(1),
	)
	bob.Path = root.Introduce(
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

	// root2 invites alice2 and bod2 but they have no introduction between
	alice2.Path = root2.Introduce(
		root2.Handle,
		key.InfoFromHandle(alice2),
		WithPosition(1),
	)
	bob2.Path = root2.Introduce(
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
	t.Run("introduction", testIntroduction)
	t.Run(
		"common parent level",
		testCommonParentLevel,
	)
	t.Run("same parent", testSameParent)
	t.Run("hops", testHops)
	t.Run("find", testFind)
	t.Run(
		"challenge child",
		testChallengeChild,
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
	c = c.Introduce(
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
	c = c.Introduce(
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

	assert.ThatNot(c2.VerifySignatures())
}

func testVerifyPath(t *testing.T) {
	defer assert.PushTester(t)()

	assert.SLen(testPath, 2)
	assert.That(testPath.VerifySignatures())

	newChild := key.New()
	level := 3
	testPath = testPath.Introduce(
		childKey,
		key.InfoFromHandle(newChild),
		WithPosition(level),
	)

	assert.SLen(testPath, 3)
	assert.That(testPath.VerifySignatures())
}

func testIntroduction(t *testing.T) {
	defer assert.PushTester(t)()

	assert.SLen(alice.Path, 3)
	assert.That(alice.Path.VerifySignatures())
	assert.SLen(bob.Path, 3)
	assert.That(bob.Path.VerifySignatures())

	cecilia := entity{
		Handle: key.New(),
	}
	cecilia.Path = bob.Introduce(
		bob.Handle,
		key.InfoFromHandle(cecilia),
		WithPosition(1),
	)
	assert.SLen(cecilia.Path, 4)
	assert.That(cecilia.Path.VerifySignatures())
	assert.ThatNot(
		SameRoot(testPath, cecilia.Path),
		"we have two different roots",
	)
	assert.That(
		SameRoot(alice.Path, cecilia.Path),
	)
}

// common root : my distance, her distance

// TestCommonParentLevel tests that Path owners have one common parent
func testCommonParentLevel(t *testing.T) {
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
	cecilia.Path = bob.Introduce(
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
	david.Path = alice.Introduce(
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
	cparent, sameIC := CommonParentLevel(
		cecilia.Path,
		david.Path,
	)
	assert.Equal(
		cparent,
		1,
		"common parent is root whos lvl is 1",
	)
	assert.ThatNot(sameIC)

	edvin := entity{
		Handle: key.New(),
	}
	edvin.Path = alice.Introduce(
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
	cparent, sameIC = CommonParentLevel(
		edvin.Path,
		david.Path,
	)
	assert.Equal(
		cparent,
		2,
		"alice is at level 2 from path's root and parent of both",
	)
	assert.ThatNot(sameIC)

	edvin2Path := alice.Path.Introduce(
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
	cparent, sameIC = CommonParentLevel(
		edvin2Path,
		david.Path,
	)
	assert.Equal(
		cparent,
		2,
		"alice is at level 2 from path's root and parent of both",
	)
	assert.ThatNot(sameIC)

	fred1Path := edvin.Introduce(
		edvin.Handle,
		key.InfoFromHandle(key.New()),
		WithPosition(1),
	)
	fred2Path := edvin.Introduce(
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
	cparent, sameIC = CommonParentLevel(
		fred2Path,
		fred1Path,
	)
	assert.Equal(
		cparent,
		3,
		"edvin is at level 3 from path's root",
	)
	assert.ThatNot(sameIC)

	cparent, sameIC = CommonParentLevel(
		alice.Path,
		fred1Path,
	)
	assert.Equal(
		cparent,
		2,
		"alice is at level 2 from path's root",
	)
	assert.That(
		sameIC,
		"alice is fred's path's 'root'",
	)

	cparent, sameIC = CommonParentLevel(
		bob.Path,
		cecilia.Path,
	)
	assert.Equal(
		cparent,
		2,
		"bob is at level 2 from path's root",
	)
	assert.That(
		sameIC,
		"bob is cecilia's path's 'root'",
	)

	cparent, sameIC = CommonParentLevel(
		root.Path,
		cecilia.Path,
	)
	assert.Equal(
		cparent,
		1,
		"root is at level 2 from path's root",
	)
	assert.That(
		sameIC,
		"root is cecilia's path's 'root'",
	)
}

// TestSameParent test that two path holders have same parent.
func testSameParent(t *testing.T) {
	defer assert.PushTester(t)()

	assert.That(
		SameParent(alice.Path, bob.Path),
	)
	assert.ThatNot(
		SameParent(testPath, bob.Path),
	)

	cecilia := entity{
		Handle: key.New(),
	}
	cecilia.Path = bob.Introduce(
		bob.Handle,
		key.InfoFromHandle(cecilia),
		WithPosition(1),
	)
	assert.That(cecilia.Len() == 4)
	assert.That(cecilia.Path.VerifySignatures())
	assert.That(bob.IsParentFor(cecilia.Path))
	assert.ThatNot(
		alice.IsParentFor(cecilia.Path),
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
		"alice's and bob's parent is path root!",
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
		"alice's and bob's parent is ROTATED path root",
	)

	cecilia := entity{
		Handle: key.New(),
	}
	cecilia.Path = bob.Introduce(
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
		"the share parent is path root",
	)

	david := entity{
		Handle: key.New(),
	}
	david.Path = bob.Introduce(
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
		"david and cecilia share bod as parent",
	)
	assert.Equal(
		cLevel,
		2,
		"david's and cecilia's parent bob is 1 hop from root",
	)

	edvin = entity{
		Handle: key.New(),
	}
	edvin.Path = david.Introduce(
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
		"cecilia has 1 hop to common parent bob and edvin has 2 hops == 3",
	)
	assert.Equal(
		cLevel,
		2,
		"common parent of cecilia and edvin is bod that's 1 hop from path root",
	)

	hop, cLevel = Hops(alice.Path, edvin.Path)
	assert.Equal(
		hop,
		4,
		"alice and edvin share root as a common parent => 1 + 3",
	)
	assert.Equal(
		cLevel,
		1,
		"alice's and edvin's common parent root is path root",
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

// TestChallengeChild test shows how we can challenge the party who presents
// us a path. Paths are presentad as full! At least for now. They don't
// include any personal data, and we try to make sure that they won't include
// any data which could be used to correlate the use of the path. Path is only
// for the proofing the position in the Introduction Path.
func testChallengeChild(t *testing.T) {
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
			edge := NewEdgeFromData(d)
			// pinCode is transported out-of-band and entered *before* signing
			edge.Body.Options.Position = pinCode
			d = edge.Bytes()
			return try.To1(alice.Sign(d))
		},
	))
	assert.That(bob.Challenge(pinCode,
		func(d []byte) key.Signature {
			edge := NewEdgeFromData(d)
			edge.Body.Options.Position = pinCode
			d = edge.Bytes()
			return try.To1(bob.Sign(d))
		},
	))

	// failures:
	// Test that if alice tries to sign bob's challenge it won't work.
	assert.ThatNot(bob.Challenge(pinCode,
		func(d []byte) key.Signature {
			edge := NewEdgeFromData(d)
			edge.Body.Options.Position = pinCode
			d = edge.Bytes()
			// NOTE Alice canot sign bob's challenge
			return try.To1(alice.Sign(d))
		},
	))
	// Wrong pinCode
	assert.ThatNot(bob.Challenge(pinCode+1,
		func(d []byte) key.Signature {
			edge := NewEdgeFromData(d)
			edge.Body.Options.Position = pinCode
			d = edge.Bytes()
			return try.To1(bob.Sign(d))
		},
	))
}
