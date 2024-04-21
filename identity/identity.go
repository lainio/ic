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
// how it would affect to our control algorithms? Now everthing suspects that we
// have one identity key.Handle that controls everything we are doing. but how
// about if we could have multiple key.handles and the control would go thru
// parent/child thru IC?

type Identity struct {
	node.Node // these share the same key.ID&Public
	key.Handle
}

func NewIdentity(h key.Handle) Identity {
	info := key.InfoFromHandle(h)
	return Identity{Node: node.NewRootNode(info), Handle: h}
}
