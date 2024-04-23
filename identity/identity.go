// package identity is the API level pkg. TODO: move rest to internal?
package identity

import (
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/node"
)

// TODO: How to we add new backup keys to the system? This is the most
// interesting question of them all. We must have one key pair for everything
// that we get one ID key, aka Public key. But if we could have multiple SEs
// where to store our private key? But maybe more interesting would be that we
// could have multiple private keys? How we could do that? If we mark other
// parents of the IC to control block. This would allow parent keypair to
// control subkeys, so they could work as an backup keys. But we don't know yet
// how it would affect to our control algorithms? Now everything suspects that we
// have one identity key.Handle that controls everything we are doing. but how
// about if we could have multiple key.handles and the control would go thru
// parent/child thru IC?
// NOTE: we tried to add new root but of course it failed! It's impossible. It
// seems that it is very difficult to have multiple key handles registered for
// the same invitation chain. Second option could be that we have always append
// our chains by ourselves after whe have been Invited. That woulb give us
// multiple chain blocks that are fully under our control!

// TODO: Should we mark these 'helper' blocks somehow in the chain. they aren't
// less important, but maybe it would give opportunities to optimize certain
// things later?

type Identity struct {
	node.Node // these share the same key.ID&Public
	key.Handle
}

func New(h key.Handle, flags ...bool) Identity {
	info := key.InfoFromHandle(h)
	return Identity{Node: node.NewRoot(info, flags...), Handle: h}
}

// Invite ivites other identity holder to all (decided later) our ICs.
func (i Identity) Invite(rhs Identity, position int) Identity {
	rhs.Node = i.Node.Invite(rhs.Node, i, key.InfoFromHandle(rhs.Handle), position)
	return rhs
}

func (i Identity) RotateKey(newKH key.Handle) Identity {
	rotation := true
	newInfo := New(newKH, rotation)

	newID := i.Invite(newInfo, 0)
	return newID
}
