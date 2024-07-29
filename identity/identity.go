// package identity is the API level pkg. TODO: move rest to internal?
package identity

import (
	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/node"
)

// Identity is high level entity to encapsulate all the needed information to
// present either our own identity or their identity. With the their identity
// the [key.Hand] is in read-only mode, i.e., we don't have full [key.Handle]
// but [key.Info] only. Hand -> Handle -> Key, or Hand -> Info -> Key.Public
type Identity struct {
	// Node is the persistent and public part of our Identity. Only our keys
	// are private.
	// chains inside these share the same key.ID&Public.
	node.Node

	// Our key(s) are here. This private in away.
	// However, if ours, we have full [key.Handle] if not only [key.Info]
	key.Hand
}

// New creates a new joining identity with the given [key.Handle]. The 'joining'
// means that we'll wait other party to invite us, and then we'll get our IC.
// See [NewRoot] for the cases where we want to start our own chain.
// NOTE that this is the preferred way to create Identity and join the network.
func New(h key.Handle) Identity {
	info := key.InfoFromHandle(h)
	return Identity{
		Node: node.Node{}, // Just empty Node! Important, no root IC.
		Hand: key.Hand{
			Handle: h,
			Info:   &info,
		},
	}
}

// NewRoot creates a Root Identity object, which allows us to start a whole new
// IC. Please prefer [New] function over this to maximize connectivity in the
// network.
// NOTE that this far too simple for production use when we need to setup many
// keys (probably) for the backup keys, etc.
// NOTE that we can create new backup keys as long as we own the previous one.
func NewRoot(h key.Handle, flags ...chain.Opts) Identity {
	info := key.InfoFromHandle(h)
	return Identity{
		Node: node.New(info, flags...),
		Hand: key.Hand{
			Handle: h,
			Info:   &info,
		},
	}
}

func NewFromData(d []byte) (i Identity) {
	i.Node = node.NewFromData(d)
	idk := i.Node.GetIDK() // TODO: If not Invited yet we need IDK!
	i.Hand = key.Hand{
		Handle: nil,
		Info:   &idk,
	}

	return i
}

func (i Identity) Bytes() []byte {
	// TODO: CBOR type
	// It's enough to get Node data for read-only Identities
	return i.Node.Bytes()
}

// InviteWithRotateKey we first create new key for this specefic invitation.
// this is like double blinding. minimize correlation. TODO: does this still
// work is the real world,
func (i Identity) InviteWithRotateKey( // TODO: rename ..WithRotatedKey() <- donne already
	rhs Identity,
	opts ...chain.Opts,
) Identity {
	rotatingKeyHandle := key.New()
	rhs.Node = i.Node.InviteWithRotateKey(
		i.Handle, rotatingKeyHandle,
		rhs.Node,
		key.InfoFromHandle(rhs.Handle), opts...,
	)
	return rhs
}

// Invite invites other identity holder to all (decided later) our ICs.
func (i Identity) Invite(rhs Identity, opts ...chain.Opts) Identity {
	assert.That(i.ValidHandle())
	assert.That(rhs.ValidInfo())

	rhs.Node = i.Node.Invite(i.Handle, rhs.Node, *rhs.Info, opts...)
	return rhs
}

func (i Identity) RotateKey(newKH key.Handle) Identity {
	assert.SLonger(i.InviteeChains, 0)
	newInfo := New(newKH)

	newID := i.Invite(newInfo, chain.WithRotation(), chain.WithPosition(0))
	return newID
}

// RotateToBackupKey plah, ... TODO: should we put the keyIndex somewhere that
// wen know that rotation to that key is already doone? And we don't try that
// key again, etc.? Of course, we can manually find that information, but still
// is it something that we should do?
func (i Identity) RotateToBackupKey(keyIndex int) Identity {
	newNode, newKH := i.Node.RotateToBackupKey(keyIndex)
	newIdentity := Identity{Node: newNode, Hand: key.NewHand(newKH)}
	return newIdentity
}

func (i *Identity) CreateBackupKeysAmount(count int) {
	assert.That(i.ValidHandle())
	i.Node.CreateBackupKeysAmount(count, i.Handle)
}

// Resolver finds and returns a Resolver Endpoint for the Identity if available.
func (i Identity) Resolver() string {
	return i.Node.Resolver()
}

// Endpoint finds endpoint for the pubkey if available. Endpoint is one of the
// opts that can be stored to chain blocks. Endpoint is used to communicate thru
// that pubkey. What kind of communication is possible depends on the identity
// node behind then pubkey.
func (i Identity) Endpoint(pubkey key.Public) string {
	bl, found := i.Find(pubkey)
	if found {
		return bl.Endpoint
	}
	return ""
}

// WebOfTrustInfo returns web-of-trust information of two identitys if they
// share a trust chain (common root). If not returns nil.
func (i Identity) WebOfTrust(rhs Identity) *node.WebOfTrust {
	return i.WebOfTrustInfo(rhs.Node)
}

// Challenge offers a method and placeholder for challenging other chain holder.
// Most common cases is that caller of the function implements the closure where
// it calls other party over the network to sign the challenge which is readily
// build and randomized.
func (i Identity) Challenge(pinCode int, f func(d []byte) key.Signature) bool {
	assert.SLonger(i.InviteeChains, 0)
	// All InviteeChains are equally useful for Challenge.
	// TODO: should we still randomize the used index? it's now 0 but it could
	// be any of the available?
	return i.InviteeChains[0].Challenge(pinCode, f)
}

// TrustLevel calculates current trust-level of the Identity domain.
// Calcultation is simple summary of Invitee chains and the levels there
// TODO: Where this is used?
func (i Identity) TrustLevel() int {
	return 0
}

// Friends tells if these two are friends by IC.
// TODO: Where this is used?
func (i Identity) Friends(rhs Identity) bool {
	return false
}
