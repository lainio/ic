package chain

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

var (
	// root -> alice, root -> bob: alice and bob share same root inviter
	root, alice, bob entity

	//  first chain for generic chain tests
	testChain           Chain
	rootKey, inviteeKey key.Handle
)

type entity struct {
	key.Handle
	Chain
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {}

func setup() {
	// general chain for tests
	rootKey = key.New()
	testChain = NewRoot(key.InfoFromHandle(rootKey))
	inviteeKey = key.New()
	level := 1
	testChain = testChain.Invite(rootKey, key.InfoFromHandle(inviteeKey), level)

	// root, alice, bob setup
	root.Handle = key.New()
	alice.Handle = key.New()
	bob.Handle = key.New()

	root.Chain = NewRoot(key.InfoFromHandle(root))

	// root invites alice and bod but they have no invitation between
	alice.Chain = root.Invite(root.Handle, key.InfoFromHandle(alice), 1)
	bob.Chain = root.Invite(root.Handle, key.InfoFromHandle(bob), 1)
}

func TestNewChain(t *testing.T) {
	defer assert.PushTester(t)()

	k := key.New()
	c := NewRoot(key.InfoFromHandle(k))
	//new(Chain).LeafPubKey()
	assert.SLen(c.Blocks, 1)
	assert.Equal(c.Len(), 1)
	assert.Equal(c.KeyRotationsLen(), 0)

	k2 := key.New()
	c = c.rotationInvite(k, key.InfoFromHandle(k2), 1)
	assert.Equal(c.Len(), 2, "naturally +1 from previous")
	assert.Equal(c.KeyRotationsLen(), 1)

	k3 := key.New()
	c = c.rotationInvite(k2, key.InfoFromHandle(k3), 1)
	assert.Equal(c.Len(), 3, "naturally +1 from previous")
	assert.Equal(c.KeyRotationsLen(), 2)
}

func TestRead(t *testing.T) {
	defer assert.PushTester(t)()

	c2 := testChain.Clone()
	assert.SLen(c2.Blocks, 2)
	assert.That(c2.VerifySign())
}

func TestVerifyChainFail(t *testing.T) {
	defer assert.PushTester(t)()

	c2 := testChain.Clone()
	assert.SLen(c2.Blocks, 2)
	assert.That(c2.VerifySign())

	b2 := c2.Blocks[1]
	b2.InvitersSignature[len(b2.InvitersSignature)-1] += 0x01

	assert.That(!c2.VerifySign())
}

func TestVerifyChain(t *testing.T) {
	defer assert.PushTester(t)()

	assert.SLen(testChain.Blocks, 2)
	assert.That(testChain.VerifySign())

	newInvitee := key.New()
	level := 3
	testChain = testChain.Invite(inviteeKey, key.InfoFromHandle(newInvitee), level)

	assert.SLen(testChain.Blocks, 3)
	assert.That(testChain.VerifySign())
}

func TestInvitation(t *testing.T) {
	defer assert.PushTester(t)()

	assert.SLen(alice.Blocks, 2)
	assert.That(alice.Chain.VerifySign())
	assert.SLen(bob.Blocks, 2)
	assert.That(bob.Chain.VerifySign())

	cecilia := entity{
		Handle: key.New(),
	}
	cecilia.Chain = bob.Invite(bob.Handle, key.InfoFromHandle(cecilia), 1)
	assert.SLen(cecilia.Blocks, 3)
	assert.That(cecilia.Chain.VerifySign())
	assert.That(!SameRoot(testChain, cecilia.Chain), "we have two different roots")
	assert.That(SameRoot(alice.Chain, cecilia.Chain))
}

// common root : my distance, her distance

// TestCommonInviterLevel tests that Chain owners have one common inviter
func TestCommonInviterLevel(t *testing.T) {
	defer assert.PushTester(t)()

	// alice and bod have common root:
	//                   root
	//                  /    \
	//                \/     \/
	//              alice   bob
	cecilia := entity{
		Handle: key.New(),
	}

	// bob intives cecilia
	cecilia.Chain = bob.Invite(bob.Handle, key.InfoFromHandle(cecilia), 1)
	//                   root
	//                  /    \
	//                \/     \/
	//              alice   bob
	//                       \
	//                       \/
	//                      cecilia
	assert.SLen(cecilia.Blocks, 3)
	assert.That(cecilia.Chain.VerifySign())

	david := entity{
		Handle: key.New(),
	}
	// alice invites david
	david.Chain = alice.Invite(alice.Handle, key.InfoFromHandle(david), 1)
	//                   root
	//                  /    \
	//                \/     \/
	//              alice   bob
	//               |        \
	//              \/        \/
	//            david      cecilia
	assert.Equal(0, CommonInviterLevel(cecilia.Chain, david.Chain),
		"cecilia's and david's common inviter is chain root")

	edvin := entity{
		Handle: key.New(),
	}
	edvin.Chain = alice.Invite(alice.Handle, key.InfoFromHandle(edvin), 1)
	//                   root
	//                  /    \
	//                \/     \/
	//            alice     bob
	//       ____/   |        \
	//     \/       \/        \/
	//  edvin     david      cecilia
	assert.Equal(1, CommonInviterLevel(edvin.Chain, david.Chain),
		"alice is at level 1 from chain's root and inviter of both")

	edvin2Chain := alice.Chain.Invite(alice.Handle, key.InfoFromHandle(key.New()), 1)
	//                   root
	//                  /    \
	//                \/     \/
	//            alice     bob
	//       ____/   | \      \___
	//     \/       \/  \/        \/
	//  edvin  edvin2   david    cecilia
	assert.Equal(1, CommonInviterLevel(edvin2Chain, david.Chain),
		"alice is at level 1 from chain's root and inviter of both")

	fred1Chain := edvin.Invite(edvin.Handle, key.InfoFromHandle(key.New()), 1)
	fred2Chain := edvin.Invite(edvin.Handle, key.InfoFromHandle(key.New()), 1)
	//                   root                        lvl 0
	//                  /    \
	//                \/     \/
	//            alice     bob                      lvl 1
	//       ____/   | \      \___
	//     \/       \/  \/        \/
	//  edvin  edvin2   david    cecilia             lvl 2
	//  |   \__
	// \/      \/
	// fred1   fred2
	assert.Equal(2, CommonInviterLevel(fred2Chain, fred1Chain),
		"edvin is at level 2 from chain's root")
}

// TestSameInviter test that two chain holders have same inviter.
func TestSameInviter(t *testing.T) {
	defer assert.PushTester(t)()

	assert.That(SameInviter(alice.Chain, bob.Chain))
	assert.That(!SameInviter(testChain, bob.Chain))

	cecilia := entity{
		Handle: key.New(),
	}
	cecilia.Chain = bob.Invite(bob.Handle, key.InfoFromHandle(cecilia), 1)
	assert.SLen(cecilia.Blocks, 3)
	assert.That(cecilia.Chain.VerifySign())
	assert.That(bob.IsInviterFor(cecilia.Chain))
	assert.That(!alice.IsInviterFor(cecilia.Chain))
}

func TestHops(t *testing.T) {
	defer assert.PushTester(t)()

	//                   root
	//                  /    \
	//                \/     \/
	//              alice   bob
	h, cLevel := alice.Hops(bob.Chain)
	assert.Equal(2, h, "alice and bob share common root")
	assert.Equal(0, cLevel, "alice's and bob's inviter is chain root")

	cecilia := entity{
		Handle: key.New(),
	}
	cecilia.Chain = bob.Invite(bob.Handle, key.InfoFromHandle(cecilia), 1)
	//                   root
	//                  /    \
	//                \/     \/
	//              alice   bob
	//                       \
	//                       \/
	//                      cecilia
	h, cLevel = alice.Hops(cecilia.Chain)
	assert.Equal(3, h, "alice has 1 hop to root, cecilia 2 hpos == 3")
	assert.Equal(0, cLevel, "the share inviter is chain root")

	david := entity{
		Handle: key.New(),
	}
	david.Chain = bob.Invite(bob.Handle, key.InfoFromHandle(david), 1)
	//                   root
	//                  /    \
	//                \/     \/
	//              alice   bob
	//                     |   \
	//                    \/   \/
	//                cecilia   david
	h, cLevel = david.Hops(cecilia.Chain)
	assert.Equal(2, h, "david and cecilia share bod as inviter")
	assert.Equal(1, cLevel, "david's and cecilia's inviter bob is 1 hop from root")

	edvin := entity{
		Handle: key.New(),
	}
	edvin.Chain = david.Invite(david.Handle, key.InfoFromHandle(edvin), 1)
	//                   root
	//                  /    \
	//                \/     \/
	//              alice   bob
	//                     |   \
	//                    \/   \/
	//                cecilia   david
	//                           |
	//                          \/
	//                         edvin
	h, cLevel = edvin.Hops(cecilia.Chain)
	assert.Equal(3, h, "cecilia has 1 hop to common inviter bob and edvin has 2 hops == 3")
	assert.Equal(1, cLevel, "common inviter of cecilia and edvin is bod that's 1 hop from chain root")

	h, cLevel = Hops(alice.Chain, edvin.Chain)
	assert.Equal(4, h, "alice and edvin share root as a common inviter => 1 + 3")
	assert.Equal(0, cLevel, "alice's and edvin's common inviter root is chain root")
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
	// success tests:
	assert.That(alice.Challenge(pinCode,
		func(d []byte) key.Signature {
			// In real world usage here we would send the d for Alice's signing
			// over the network.
			b := NewBlockFromData(d)
			// pinCode is transported out-of-band and entered before signing
			b.Position = pinCode
			d = b.Bytes()
			return try.To1(alice.Sign(d))
		},
	))
	assert.That(bob.Challenge(pinCode,
		func(d []byte) key.Signature {
			b := NewBlockFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			return try.To1(bob.Sign(d))
		},
	))

	// failures:
	// Test that if alice tries to sign bob's challenge it won't work.
	assert.ThatNot(bob.Challenge(pinCode,
		func(d []byte) key.Signature {
			b := NewBlockFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			// NOTE Alice canot sign bob's challenge
			return try.To1(alice.Sign(d))
		},
	))
	// Wrong pinCode
	assert.ThatNot(bob.Challenge(pinCode+1,
		func(d []byte) key.Signature {
			b := NewBlockFromData(d)
			b.Position = pinCode
			d = b.Bytes()
			return try.To1(bob.Sign(d))
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
