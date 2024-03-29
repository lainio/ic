package chain

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/crypto"
)

var (
	// root -> alice, root -> bob
	root, alice, bob entity

	//  first chain for generic chain tests
	testChain           Chain
	rootKey, inviteeKey crypto.Key
)

type entity struct {
	crypto.Key
	Chain
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
	// general chain for tests
	rootKey = crypto.NewKey()
	testChain = NewRootChain(rootKey.PubKey)
	inviteeKey = crypto.NewKey()
	level := 1
	testChain = testChain.Invite(rootKey, inviteeKey.PubKey, level)

	// root, alice, bob setup
	root.Key = crypto.NewKey()
	alice.Key = crypto.NewKey()
	bob.Key = crypto.NewKey()

	root.Chain = NewRootChain(root.PubKey)

	// root invites alice and bod but they have no invitation between
	alice.Chain = root.Invite(root.Key, alice.PubKey, 1)
	bob.Chain = root.Invite(root.Key, bob.PubKey, 1)
}

func TestNewChain(t *testing.T) {
	defer assert.PushTester(t)()

	c := NewRootChain(crypto.NewKey().PubKey)
	//new(Chain).LeafPubKey()
	assert.SLen(c.Blocks, 1)
}

func TestRead(t *testing.T) {
	defer assert.PushTester(t)()

	c2 := testChain.Clone()
	assert.SLen(c2.Blocks, 2)
	assert.That(c2.Verify())
}

func TestVerifyChainFail(t *testing.T) {
	defer assert.PushTester(t)()

	c2 := testChain.Clone()
	assert.SLen(c2.Blocks, 2)
	assert.That(c2.Verify())

	b2 := c2.Blocks[1]
	b2.InvitersSignature[len(b2.InvitersSignature)-1] += 0x01

	assert.That(!c2.Verify())
}

func TestVerifyChain(t *testing.T) {
	defer assert.PushTester(t)()

	assert.SLen(testChain.Blocks, 2)
	assert.That(testChain.Verify())

	newInvitee := crypto.NewKey()
	level := 3
	testChain = testChain.Invite(inviteeKey, newInvitee.PubKey, level)

	assert.SLen(testChain.Blocks, 3)
	assert.That(testChain.Verify())
}

func TestInvitation(t *testing.T) {
	defer assert.PushTester(t)()

	assert.SLen(alice.Blocks, 2)
	assert.That(alice.Verify())
	assert.SLen(bob.Blocks, 2)
	assert.That(bob.Verify())

	cecilia := entity{
		Key: crypto.NewKey(),
	}
	cecilia.Chain = bob.Invite(bob.Key, cecilia.PubKey, 1)
	assert.SLen(cecilia.Blocks, 3)
	assert.That(cecilia.Verify())
	assert.That(!SameRoot(testChain, cecilia.Chain), "we have two different roots")
	assert.That(SameRoot(alice.Chain, cecilia.Chain))
}

// common root : my distance, her distance

// TestCommonInviter tests that Chain owners have one common inviter
func TestCommonInviter(t *testing.T) {
	defer assert.PushTester(t)()

	// alice and bod have common root
	cecilia := entity{
		Key: crypto.NewKey(),
	}
	// bob intives cecilia
	cecilia.Chain = bob.Invite(bob.Key, cecilia.PubKey, 1)
	assert.SLen(cecilia.Blocks, 3)
	assert.That(cecilia.Verify())

	david := entity{
		Key: crypto.NewKey(),
	}
	// alice invites david
	david.Chain = alice.Invite(alice.Key, david.PubKey, 1)

	assert.Equal(0, CommonInviter(cecilia.Chain, david.Chain),
		"cecilia and david have only common root")
	edvin := entity{
		Key: crypto.NewKey(),
	}
	edvin.Chain = alice.Invite(alice.Key, edvin.PubKey, 1)
	assert.Equal(1, CommonInviter(edvin.Chain, david.Chain),
		"alice is at level 1 and inviter of both")

	edvin2Chain := alice.Chain.Invite(alice.Key, crypto.NewKey().PubKey, 1)
	assert.Equal(1, CommonInviter(edvin2Chain, david.Chain),
		"alice is at level 1 and inviter of both")

	fred1Chain := edvin.Invite(edvin.Key, crypto.NewKey().PubKey, 1)
	fred2Chain := edvin.Invite(edvin.Key, crypto.NewKey().PubKey, 1)
	assert.Equal(2, CommonInviter(fred2Chain, fred1Chain),
		"edvin is at level 2")
}

// TestSameInviter test that two chain holders have same inviter.
func TestSameInviter(t *testing.T) {
	defer assert.PushTester(t)()

	assert.That(SameInviter(alice.Chain, bob.Chain))
	assert.That(!SameInviter(testChain, bob.Chain))

	cecilia := entity{
		Key: crypto.NewKey(),
	}
	cecilia.Chain = bob.Invite(bob.Key, cecilia.PubKey, 1)
	assert.SLen(cecilia.Blocks, 3)
	assert.That(cecilia.Verify())
	assert.That(bob.IsInviterFor(cecilia.Chain))
	assert.That(!alice.IsInviterFor(cecilia.Chain))
}

func TestHops(t *testing.T) {
	defer assert.PushTester(t)()

	h, cLevel := alice.Hops(bob.Chain)
	assert.Equal(2, h)
	assert.Equal(0, cLevel)

	cecilia := entity{
		Key: crypto.NewKey(),
	}
	cecilia.Chain = bob.Invite(bob.Key, cecilia.PubKey, 1)
	h, cLevel = alice.Hops(cecilia.Chain)
	assert.Equal(3, h)
	assert.Equal(0, cLevel)

	david := entity{
		Key: crypto.NewKey(),
	}
	david.Chain = bob.Invite(bob.Key, david.PubKey, 1)
	h, cLevel = david.Hops(cecilia.Chain)
	assert.Equal(2, h)
	assert.Equal(1, cLevel)

	edvin := entity{
		Key: crypto.NewKey(),
	}
	edvin.Chain = david.Invite(david.Key, edvin.PubKey, 1)
	h, cLevel = edvin.Hops(cecilia.Chain)
	assert.Equal(3, h)
	assert.Equal(1, cLevel)

	h, cLevel = Hops(alice.Chain, edvin.Chain)
	assert.Equal(4, h)
	assert.Equal(0, cLevel)
}

// TestChallengeInvitee test shows how we can challenge the party who presents
// us a chain. Chains are presentad as full! At least for now. They don't
// include any personal data, and we try to make sure that they won't include
// any data which could be used to correlate the use of the chain. Chain is only
// for the proofing the position in the Invitation Chain.
func TestChallengeInvitee(t *testing.T) {
	defer assert.PushTester(t)()

	// chain leaf is the only part who has the private key for the leaf, so
	// it can response the challenge properly.

	// Challenge is needed that we can be sure that the party who presents the
	// chain is the actual owner of the chain.

	// When let's say Bob have received Alice's chain he can use Challenge
	// method for Alice's Chain to let Alice proof that she controls the chain
	pinCode := 1234
	assert.That(alice.Challenge(pinCode,
		func(d []byte) crypto.Signature {
			// In real world usage here we would send the d for Alice's signing
			// over the network.
			b := NewBlockFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			return alice.Sign(d)
		},
	))
	assert.That(bob.Challenge(pinCode,
		func(d []byte) crypto.Signature {
			b := NewBlockFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			return bob.Sign(d)
		},
	))
	// Test that if alice tries to sign bob's challenge it won't work.
	assert.ThatNot(bob.Challenge(pinCode,
		func(d []byte) crypto.Signature {
			b := NewBlockFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			// NOTE Alice canot sign bob's challenge
			return alice.Sign(d)
		},
	))
	// Wrong pinCode
	assert.ThatNot(bob.Challenge(pinCode+1,
		func(d []byte) crypto.Signature {
			b := NewBlockFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			return bob.Sign(d)
		},
	))
}

// Issuer adds her own chain to every credential it's issuing, I haven't solved
// the correlation yet. Is it an issue because chain doesn't include any
// identifiers. PubKey is identifier, if we don't use PubKey as an identifier,
// it the only option to use some other identifier and behind it similar to
// DIDDoc concept. How about if chain holder creates new sub chains just to hide
// it's actual identity?
// For what purpose we could use them?
// My current opinion is that this is not a big problem. At least we know that
// we can get rid of it if we want.

// Other poptential problem is key rotation. It isn't so big problem when we
// have a network in the came. Invitation Chain IDs aren
