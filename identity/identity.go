package identity

import (
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/node"
)

// TODO: how to we add new backup keys to the system?

type Identity struct {
	node.Node // these share the same key.ID&Public
	key.Handle
}

func NewIdentity(h key.Handle) Identity {
	info := key.InfoFromHandle(h)
	return Identity{Node: node.NewRootNode(info), Handle: h}
}
