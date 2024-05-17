package node

import (
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

type Node struct {
	// TODO: should we have myltiple IDChains? or just one or all in the same?

	InviteeChains []chain.Chain

	ChainsInviter []chain.Chain // TODO: if the node is service, this will be
	// too large. We need extremely good reason to have this kind of storage.
	// Also we will have service type inviters who will have we large count of
	// invitees. And if that's something we don't need, we don't store it.
	// However, if it's small and doesn't matter, let's think about it then.
}

type WebOfTrust struct {
	// Hops tells how far the the other end is when traversing thru the
	// CommonInviter
	Hops hop.Distance // TODO: rename HopsThruInviter
	// TODO: should we have Hops that's the actual distance when we are in same
	// chain? Or flag that we are in the same chain? Latter is better.

	// CommonInviter from root, i.e. how far away it's from absolute root
	CommonInviterLevel hop.Distance // TODO: CommonInviter type??

	// ID_Key aka pubkey for the common invider
	CommonInviterPubKey key.Public

	// Position of the CommonInviter.
	Position int
}

// NewWebOfTrust returns web-of-trust information of two nodes if they share a
// trust chain. If not the Hops field is hop.NotConnected.
func NewWebOfTrust(n1, n2 Node) WebOfTrust {
	return n1.WebOfTrustInfo(n2)
}

// New constructs a new node.
//   - is this something that happens only once per node? Aka, it means that we
//     allocate the identity space like wallet?
func New(pubKey key.Info, flags ...chain.Opts) Node {
	n := Node{InviteeChains: make([]chain.Chain, 1, 12)}
	n.InviteeChains[0] = chain.New(pubKey, flags...)
	return n
}

func (n Node) AddChain(c chain.Chain) (rn Node) {
	rn.InviteeChains = append(n.InviteeChains, c)
	return rn
}

// Invite is method to add invitee's node's invitation chains (IC) to all of
// those ICs of us (n Node) that invitee doesn't yet belong.
// NOTE! Use identity.Invite at the API lvl.
// This has worked since we started, but at the identity level we need symmetric
// invitation system.
func (n Node) Invite(
	// TODO: order of the arguments?
	inviteesNode Node,
	inviter key.Handle,
	invitee key.Info,
	position int,
) (
	rn Node,
) {
	rn.InviteeChains = make([]chain.Chain, 0, n.Len()+inviteesNode.Len())

	// keep all the existing web-of-trust chains if not rotation case
	if !inviteesNode.rotationChain() {
		rn.InviteeChains = append(rn.InviteeChains, inviteesNode.InviteeChains...)
	}

	// add only those which invitee isn't member already
	for _, c := range n.InviteeChains {
		// if inviteesNode already is inivited to same web-of-trust
		if inviteesNode.sharedRoot(c) {
			// only keep it
			continue
		}

		// inviter (n) has something that invitee dosen't belong yet
		newChain := c.Invite(inviter, invitee,
			chain.WithPosition(position))
		rn.InviteeChains = append(rn.InviteeChains, newChain)
	}
	return rn
}

func (n Node) rotationChain() (yes bool) {
	if n.Len() == 1 && n.InviteeChains[0].Len() == 1 {
		yes = n.InviteeChains[0].Blocks[0].Rotation
	}
	return yes
}

// CommonChains return slice of chain pairs. If no pairs can be found the slice
// is empty not nil.
func (n Node) CommonChains(their Node) []chain.Pair {
	common := make([]chain.Pair, 0, n.Len())
	for _, my := range n.InviteeChains {
		p := their.sharedRootPair(my)
		if p.Valid() {
			common = append(common, p)
		}
	}
	return common
}

// WebOfTrustInfo returns web-of-trust information of two nodes if they share a
// trust chain. If not the Hops field is hop.NotConnected.
func (n Node) WebOfTrustInfo(their Node) WebOfTrust {
	chainPairs := n.CommonChains(their)

	hops := hop.NewNotConnected()
	fromRoot := hop.NewNotConnected()
	var commonIDKey key.Public

	for _, pair := range chainPairs {
		hps, lvl := pair.Hops()

		if hops.PickShorter(hps) {
			commonIDKey = pair.CommonInviterIDKey(lvl)
			fromRoot.PickShorter(lvl)
		}
	}
	return WebOfTrust{
		Hops:                hops,
		CommonInviterLevel:  fromRoot,
		CommonInviterPubKey: commonIDKey,
	}
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
	for _, my := range n.InviteeChains {
		if their.sharedRoot(my) {
			return my
		}
	}
	return chain.Nil
}

func (n Node) Find(pubkey key.Public) (b chain.Block, found bool) {
	for _, c := range n.InviteeChains {
		bl, found := c.Find(pubkey)
		if found {
			return bl, true
		}
	}
	return
}

func (n Node) Len() int {
	return len(n.InviteeChains)
}

func (n Node) sharedRoot(their chain.Chain) bool {
	for _, my := range n.InviteeChains {
		if chain.SameRoot(their, my) {
			return true
		}
	}
	return false
}

func (n Node) sharedRootPair(their chain.Chain) chain.Pair {
	for _, my := range n.InviteeChains {
		if chain.SameRoot(their, my) {
			return chain.Pair{Chain1: their, Chain2: my}
		}
	}
	return chain.Pair{}
}
