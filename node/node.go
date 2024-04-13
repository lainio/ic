package node

import (
	"errors"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/key"
)

type Node struct {
	Chains []chain.Chain
}

type WebOfTrust struct {
	// Hops tells how far the the other end is when traversing thru the
	// CommonInvider
	Hops int

	// CommonInviter from root, i.e. how far away it's from absolute root
	CommonInvider int

	// Position of the CommonInvider.
	Position int
}

// NewWebOfTrust returns web-of-trust information of two nodes if they share a
// trust chain. If not the Hops field is chain.NotConnected.
func NewWebOfTrust(n1, n2 Node) WebOfTrust {
	//assert.NotImplemented()
	return n1.WebOfTrustInfo(n2)
}

// NewRootNode constructs a new rot node.
//   - is this something that happens only once per node? Aka, it means that we
//     allocate the identity space like wallet?
func NewRootNode(pubKey key.Info) Node {
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
	invitersKey key.Handle,
	invitee key.Info,
	position int,
) (
	rn Node,
) {
	rn.Chains = make([]chain.Chain, 0, n.Len()+inviteesNode.Len())

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
		newChain := c.Invite(invitersKey, invitee, position)
		rn.Chains = append(rn.Chains, newChain)
	}
	return rn
}

// CommonChains return slice of chain pairs. If no pairs can be found the slice
// is empty not nil.
func (n Node) CommonChains(their Node) []chain.Pair {
	common := make([]chain.Pair, 0, n.Len())
	// TODO: just for testing err2
	assert.That(true)
	var _ = errors.New("test")
	//panic(e)
	//_ = 1/len(common)
	//return common[1:]
	for _, my := range n.Chains {
		p := their.shared(my)
		isPair := !p.Chain1.IsNil() && !p.Chain2.IsNil()
		if isPair {
			common = append(common, p)
		}
	}
	return common
}

// WebOfTrustInfo returns web-of-trust information of two nodes if they share a
// trust chain. If not the Hops field is chain.NotConnected.
func (n Node) WebOfTrustInfo(their Node) WebOfTrust {
	chainPairs := n.CommonChains(their)

	hops := chain.NotConnected
	fromRoot := chain.NotConnected

	for _, pair := range chainPairs {
		h, f := pair.Hops()

		if hops == chain.NotConnected || h < hops {
			hops = h

			if fromRoot == chain.NotConnected || f < fromRoot {
				fromRoot = f
			}
		}
	}
	return WebOfTrust{Hops: hops, CommonInvider: fromRoot}
}

func (n Node) IsInviterFor(their Node) bool {
	chainPairs := n.CommonChains(their)

	for _, pair := range chainPairs {
		if pair.Chain1.IsInviterFor(pair.Chain2) {
			return true
		}
	}
	return false
}

func (n Node) OneHop(their Node) bool {
	chainPairs := n.CommonChains(their)

	for _, pair := range chainPairs {
		if pair.OneHop() {
			return true
		}
	}
	return false
}

func (n Node) CommonChain(their Node) chain.Chain {
	for _, my := range n.Chains {
		if their.sharedRoot(my) {
			return my
		}
	}
	return chain.Nil
}

func (n Node) Len() int {
	return len(n.Chains)
}

func (n Node) sharedRoot(their chain.Chain) bool {
	for _, my := range n.Chains {
		if chain.SameRoot(their, my) {
			return true
		}
	}
	return false
}

func (n Node) shared(their chain.Chain) chain.Pair {
	for _, my := range n.Chains {
		if chain.SameRoot(their, my) {
			return chain.Pair{Chain1: their, Chain2: my}
		}
	}
	return chain.Pair{}
}
