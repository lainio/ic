package node

import (
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

type Node struct {
	BackupKeys chain.Chain // The Name of chain is enough

	InviteeChains []chain.Chain

	ChainsInviter []chain.Chain // TODO: if the node is service, this will be
	// too large. We need extremely good reason to have this kind of storage.
	// Also we will have service type inviters who will have we large count of
	// invitees. And if that's something we don't need, we don't store it.
	// However, if it's small and doesn't matter, let's think about it then.
}

// WebOfTrust includes most important information about WoT.
type WebOfTrust struct {
	// Hops tells how far the the other end is when traversing thru the
	// CommonInviter. NOTE that if parties don't have WoT this is
	// hop.NotConnected.
	Hops hop.Distance

	// SameChain tells if two parties are in the same Invitation Chain (IC).
	// You should take this to count when make decisions about Hops.
	SameChain bool

	// CommonInviterLevel is hops from root, i.e. how far away it's from
	// absolute root that's always level: 0.
	CommonInviterLevel hop.Distance // TODO: CommonInviter type??

	// CommonInviterPubKey, ID_Key aka pubkey for the common inviter. This
	// helps you to locate common inviter from the ICs.
	CommonInviterPubKey key.Public

	// Position of the CommonInviter. // TODO: currently not used
	Position int
}

// NewWebOfTrust returns web-of-trust information of two nodes if they share a
// trust chain. If not the Hops field is hop.NotConnected.
func NewWebOfTrust(n1, n2 Node) *WebOfTrust {
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

// CreateBackupKeysAmount creates backup keys for this Node.
// Note that:
//   - It can be done only once.
//   - Minimum amount is two (2).
//   - Maximum amount is two (12).
func (n *Node) CreateBackupKeysAmount(count int) {
	// TODO: first block is the root block! take care of that.
	// first key in this chain is the genesis key for the whole Identity so
	// it's a key that cannot be used for rotation! We should think about the
	// API again. Maybe index is correct term later but we should explain what
	// the count here means.
	assert.NotZero(count)
	assert.NotEqual(count, 1, "two backup keys is minimum")
	assert.SLen(n.BackupKeys.Blocks, 0)

	inviterKH := key.New()
	n.BackupKeys = chain.New(key.InfoFromHandle(inviterKH))
	count = count - 1
	for range count {
		kh := key.New()
		n.BackupKeys = n.BackupKeys.Invite(inviterKH, key.InfoFromHandle(kh))
		inviterKH = kh
	}
}

func (n Node) RotateToBackupKey(keyIndex int) (Node, key.Handle) {
	bkHandle := n.getBackupKey(keyIndex)

	rotationNode := New(key.InfoFromHandle(bkHandle),
		chain.WithBackupKeyIndex(keyIndex), chain.WithRotation())

	rotationNode = n.Invite(rotationNode, bkHandle, n.getIDK(),
		chain.WithBackupKeyIndex(keyIndex), chain.WithRotation())

	n.CopyBackupKeysTo(&rotationNode)
	return rotationNode, bkHandle
}

func (n Node) CopyBackupKeysTo(tgt *Node) *Node {
	tgt.BackupKeys = n.BackupKeys.Clone()
	return tgt
}

// InviteWithRotateKey is method to add invitee's node's invitation chains (IC)
// to all of those ICs of us (n Node) that invitee doesn't yet belong.
func (n Node) InviteWithRotateKey(
	// TODO: order of the arguments?
	inviteesNode Node,
	inviterOrg, inviterNew key.Handle,
	invitee key.Info,
	opts ...chain.Opts,
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
		newChain := c.Invite(inviterOrg, key.InfoFromHandle(inviterNew), opts...)
		newChain = newChain.Invite(inviterNew, invitee, opts...)
		rn.InviteeChains = append(rn.InviteeChains, newChain)
	}
	return rn
}

// TODO: merge these 2 functions to one, refactoring.

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
	opts ...chain.Opts,
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
		newChain := c.Invite(inviter, invitee, opts...)
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

func (n Node) WoT(digest *chain.Digest) *WebOfTrust {
	var (
		found bool
		hops  = hop.NewNotConnected()
		lvl   = hop.NewNotConnected()
	)
	for _, c := range n.InviteeChains {
		_, idkFound := c.Find(digest.RootIDK)
		if idkFound {
			currentLvl := c.FindLevel(digest.RootIDK)
			if lvl.PickShorter(currentLvl) {
				// locations are in the same IC: - 1 if for our own block
				hops = c.Len() - 1 - lvl
				found = idkFound
			}
		}
	}

	if found {
		return &WebOfTrust{
			SameChain:           true,
			Hops:                hops + digest.Hops,
			CommonInviterLevel:  lvl, // their lvl in IC
			CommonInviterPubKey: digest.RootIDK,
		}
	}
	return nil
}

// WebOfTrustInfo returns web-of-trust information of two nodes if they share a
// trust chain. If not the Hops field is hop.NotConnected.
func (n Node) WebOfTrustInfo(their Node) *WebOfTrust {
	chainPairs := n.CommonChains(their)

	hops := hop.NewNotConnected()
	fromRoot := hop.NewNotConnected()
	var (
		commonIDKey key.Public
		sameChain   bool
	)
	for _, pair := range chainPairs {
		hps, lvl := pair.Hops()

		if hops.PickShorter(hps) {
			commonIDKey = pair.CommonInviterIDKey(lvl)
			_, sameChain = chain.CommonInviterLevel(pair.Chain1, pair.Chain2)
			fromRoot.PickShorter(lvl)
		}
	}
	return &WebOfTrust{
		Hops:                hops,
		CommonInviterLevel:  fromRoot,
		CommonInviterPubKey: commonIDKey,
		SameChain:           sameChain,
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

func (n Node) Resolver() (endpoint string) {
	for _, c := range n.InviteeChains {
		endpoint = c.Resolver()
		if endpoint != "" {
			return endpoint
		}
	}
	return
}

// Find finds the first (TODO: rename?) chain block that has the IDK.
func (n Node) Find(IDK key.Public) (block chain.Block, found bool) {
	for _, c := range n.InviteeChains {
		block, found = c.Find(IDK)
		if found {
			return
		}
	}
	return
}

// CheckIntegrity checks your Node's integrity, which means that all of the
// InviteeChains must be signed properly and their LastBlock shares same IDK.
// The last part is the logical binging under the Node structure.
//
// NOTE that you cannot trust the Node who's integrity is violated!
//
// TODO: consider returning an error or even panicing an error, but maybe caller
// can do that?
func (n Node) CheckIntegrity() bool {
	if len(n.InviteeChains) == 0 ||
		!n.InviteeChains[0].VerifySignExtended(n.getBKPublic) {
		return false
	}

	IDK := n.InviteeChains[0].LastBlock().Public()

	for _, c := range n.InviteeChains[1:] {
		notOK := !(key.EqualBytes(c.LastBlock().Public(), IDK) &&
			c.VerifySignExtended(n.getBKPublic))
		if notOK {
			return false
		}
	}
	return true
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

func (n Node) getBKPublic(keyIndex int) key.Public {
	return try.To1(n.getBackupKey(keyIndex).CBORPublicKey())
}

func (n Node) getBackupKey(keyIndex int) key.Handle {
	assert.SLonger(n.BackupKeys.Blocks, keyIndex)

	return key.NewFromInfo(n.BackupKeys.Blocks[keyIndex].Invitee)
}

func (n Node) getIDK() key.Info {
	assert.SLonger(n.InviteeChains, 0)
	assert.SLonger(n.InviteeChains[0].Blocks, 0)

	return n.InviteeChains[0].LastBlock().Invitee
}
