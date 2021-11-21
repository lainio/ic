package node

import (
	"github.com/findy-network/ic/chain"
	"github.com/findy-network/ic/crypto"
)

type Node struct {
	Chains []chain.Chain
}

func NewRootNode(pubKey crypto.PubKey) Node {
	n := Node{Chains: make([]chain.Chain, 1, 12)}
	n.Chains[0] = chain.NewRootChain(pubKey)
	return n
}

func (n Node) AddChain(c chain.Chain) (rn Node) {
	rn.Chains = append(n.Chains, c)
	return rn
}

func (n Node) Invite(
	inviteesNode Node,
	invitersKey crypto.Key,
	inviteesPubKey crypto.PubKey,
	position int,
) (
	rn Node,
) {
	rn.Chains = make([]chain.Chain, 0, len(n.Chains)+len(inviteesNode.Chains))

	// keep all the existing web-of-trust chains
	rn.Chains = append(rn.Chains, inviteesNode.Chains...)

	// add only those which invitee isn't member already
	for _, c := range n.Chains {
		// if inviteesNode already is inivited to same web-of-trust
		if inviteesNode.sharedRoot(c) {
			// only keep it
			continue
		}

		// inviter (n) has something that invitee dosen't belong yet
		newChain := c.Invite(invitersKey, inviteesPubKey, position)
		rn.Chains = append(rn.Chains, newChain)
	}
	return rn
}

func (n Node) CommonChains(their Node) []chain.Chain {
	common := make([]chain.Chain, 0, len(n.Chains))
	for _, my := range n.Chains {
		if their.sharedRoot(my) {
			common = append(common, my)
		}
	}
	return common
}

func (n Node) CommonChain(their Node) chain.Chain {
	for _, my := range n.Chains {
		if their.sharedRoot(my) {
			return my
		}
	}
	return chain.Nil
}

func (n Node) sharedRoot(their chain.Chain) bool {
	for _, my := range n.Chains {
		if chain.SameRoot(their, my) {
			return true
		}
	}
	return false
}
