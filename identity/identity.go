package identity

import (
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/node"
)

type Identity struct {
	node.Node
	key.Handle
}

func NewIdentity(h key.Handle) Identity {
	info := key.InfoFromHandle(h)
	return Identity{Node: node.NewRootNode(info), Handle: h}
}
