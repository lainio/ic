// package identity is the API level pkg. TODO: move rest to internal?
package identity

import (
	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/node"
)

type Identity struct {
	node.Node // chains inside these share the same key.ID&Public

	key.Handle
}

// New creates a Identity object. NOTE that this far too simple for production
// use when we need to setup many keys (propably) for the backup keys, etc. NOTE
// we can create new backup keys as long as we own the previous one.
func New(h key.Handle, flags ...chain.Opts) Identity {
	info := key.InfoFromHandle(h)
	return Identity{Node: node.New(info, flags...), Handle: h}
}

func (i Identity) InviteWithRotateKey(
	rhs Identity,
	opts ...chain.Opts,
) Identity {
	newKH := key.New()
	rhs.Node = i.Node.InviteWithRotateKey(
		rhs.Node, i, newKH, key.InfoFromHandle(rhs.Handle), opts...)
	return rhs
}

// Invite invites other identity holder to all (decided later) our ICs.
func (i Identity) Invite(rhs Identity, opts ...chain.Opts) Identity {
	rhs.Node = i.Node.Invite(rhs.Node, i, key.InfoFromHandle(rhs.Handle), opts...)
	return rhs
}

func (i Identity) RotateKey(newKH key.Handle) Identity {
	newInfo := New(newKH, chain.WithRotation())

	newID := i.Invite(newInfo, chain.WithPosition(0))
	return newID
}

func (i Identity) RotateToBackupKey(keyIndex int) Identity {
	newNode, newKH := i.Node.RotateToBackupKey(keyIndex)
	newIdentity := Identity{Node: newNode, Handle: newKH}
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
