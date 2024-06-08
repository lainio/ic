// package identity is the API level pkg. TODO: move rest to internal?
package identity

import (
	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/node"
)

// Identity is high level entity to encapsulate all the needed information to
// present either our own identity or their identity. When we handle their
// identity our [key.Hand] is in read-only mode, i.e., we don't have full
// [key.Handle] but [key.Info] only.
type Identity struct {
	node.Node // chains inside these share the same key.ID&Public

	key.Hand // if ours, we have full [key.Handle] if not only [key.Info]
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

func (i Identity) InviteWithRotateKey( // TODO: rename ..WithRotatedKey()
	rhs Identity,
	opts ...chain.Opts,
) Identity {
	rotatingKeyHandle := key.New()
	rhs.Node = i.Node.InviteWithRotateKey(rhs.Node,
		i.Handle, rotatingKeyHandle,
		key.InfoFromHandle(rhs.Handle), opts...,
	)
	return rhs
}

// Invite invites other identity holder to all (decided later) our ICs.
func (i Identity) Invite(rhs Identity, opts ...chain.Opts) Identity {
	assert.INotNil(i.Handle)
	assert.NotNil(rhs.Info)

	rhs.Node = i.Node.Invite(rhs.Node, i.Handle, *rhs.Info, opts...)
	return rhs
}

func (i Identity) RotateKey(newKH key.Handle) Identity {
	assert.SLonger(i.InviteeChains, 0)
	newInfo := New(newKH)

	newID := i.Invite(newInfo, chain.WithRotation(), chain.WithPosition(0))
	return newID
}

func (i Identity) RotateToBackupKey(keyIndex int) Identity {
	newNode, newKH := i.Node.RotateToBackupKey(keyIndex)
	newIdentity := Identity{Node: newNode, Hand: key.NewHand(newKH)}
	return newIdentity
}

func (i *Identity) CreateBackupKeysAmount(count int) {
	i.Node.CreateBackupKeysAmount(count)
}

func (i Identity) Resolver() string {
	return i.Node.Resolver()
}

func (i Identity) Endpoint(pubkey key.Public) string {
	bl, found := i.Find(pubkey)
	if found {
		return bl.Endpoint
	}
	return ""
}

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
