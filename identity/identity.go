package identity

import (
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/node"
)

type Identity struct {
	node.Node
	key.Handle
}

func NewIdentity(h key.Handle) Identity {
	pubK := try.To1(h.CBORPublicKey())
	return Identity{Node: node.NewRootNode(pubK), Handle: h}
}
