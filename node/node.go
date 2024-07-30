package node

import (
	"bytes"
	"encoding/gob"
	"errors"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/digest"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

type Node struct {
	// TODO: found a BUG:
	//  - this chain must be created when the root Node is created. See New
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

// NewRoot constructs a new Root Node.
//   - it's root node because it has a self started IC!
//   - is this something that happens only once per node? Aka, it means that we
//     allocate the identity space like wallet?
func NewRoot(pubKey key.Info, flags ...chain.Opts) Node { // TODO: why key.Info
	n := Node{InviteeChains: make([]chain.Chain, 1, 12)}
	n.InviteeChains[0] = chain.New(pubKey, flags...) // TODO: convert here?
	// TODO: how about BackupKeys? They much match our identity keys.
	//  - we cannot creat BackupKeys if we lose control of our IDK (its privK)
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
func (n *Node) CreateBackupKeysAmount(count int, inviterKH key.Handle) {
	// first key in this chain is the genesis key for the whole Identity so
	// it's a key that cannot be used for rotation! We should think about the
	// API again. Maybe index is correct term later but we should explain what
	// the count here means.
	//  - what this means? this isn't totally clear after break
	// questions, TODO:
	//  - is genesis block key stored here or not? should it be?
	// possible answers, TODO:
	//  = backup keys is one independent chain which type only binds it to the
	//  node? That's why we don't need to bind genesis key with the other
	//  genesis key or what ever it is?
	//  = *remember* that we have two types of Nodes them who can invite and
	//  them (most should be) who are waiting to be invited
	// TODO: => backupkeys must be created before first invitation to us is
	// made OR we cannot bind safe BackupKeys to this node and the rest of the
	// chains.
	assert.SLen(n.BackupKeys.Blocks, 0, "you can create backup keys only once")
	assert.NotZero(count)
	assert.NotEqual(count, 1, "two backup keys is minimum")

	// we can create BackupKeys only if we still control our IDK or..
	// we haven't been invited *yet*.
	if len(n.InviteeChains) > 0 {
		assert.INotNil(inviterKH)
	} else {
		// TODO: this is the one that must be used in invitation too
		//  - it is when [Identity] is used to handle invitation
		inviterKH = key.New()
	}

	n.BackupKeys = chain.New(key.InfoFromHandle(inviterKH))
	count = count - 1
	for range count {
		kh := key.New()
		n.BackupKeys = n.BackupKeys.Invite(inviterKH, key.InfoFromHandle(kh))
		inviterKH = kh
	}
}

func (n Node) RotateToBackupKey(keyIndex int) (Node, key.Handle) {
	bkHandle := n.getBackupKeyHandle(keyIndex)

	rotationNode := NewRoot(
		key.InfoFromHandle(bkHandle),
		chain.WithBackupKeyIndex(keyIndex),
		chain.WithRotation(),
	)

	rotationNode = n.Invite(
		bkHandle,
		rotationNode,
		n.GetIDK(),
		chain.WithBackupKeyIndex(keyIndex),
		chain.WithRotation(),
	)

	n.CopyBackupKeysTo(&rotationNode)
	return rotationNode, bkHandle
}

func (n Node) CopyBackupKeysTo(tgt *Node) *Node {
	tgt.BackupKeys = n.BackupKeys.Clone()
	return tgt
}

// InviteWithRotateKey is method to add to all of those ICs of us (inviter, n
// Node) that invitee doesn't yet belong.
//   - if inviter == inviterNew then this's a normal Invite
func (n Node) InviteWithRotateKey(
	inviter, inviterNew key.Handle,
	inviteesNode Node,
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
		var newChain chain.Chain
		if key.EqualBytes(inviter.ID(), inviterNew.ID()) {
			newChain = c.Invite(inviter, invitee, opts...)
		} else {
			newChain = c.Invite(inviter, key.InfoFromHandle(inviterNew), opts...)
			newChain = newChain.Invite(inviterNew, invitee, opts...)
		}
		rn.InviteeChains = append(rn.InviteeChains, newChain)
	}
	return rn
}

// Invite is method to add to those ICs of us (inviter, n Node) that invitee
// doesn't yet belong.
// NOTE! Use identity.Invite at the API lvl.
// This has worked since we started, but at the identity level we need symmetric
// invitation system. TODO: <- check what this comment means!
// TODO: move chain, crypto, and node to internal
func (n Node) Invite(
	inviter key.Handle,
	inviteesNode Node,
	invitee key.Info,
	opts ...chain.Opts,
) (
	rn Node,
) {
	return n.InviteWithRotateKey(inviter, inviter, inviteesNode, invitee, opts...)
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

// WoT returns web of trust information for the given [digest.Digest]. The
// digest includes the minimal amount of information without the actual IC to
// allow us to calculate WoT if our Node includes enough information to do it,
// i.e., ICs including a correct RootIDK. If not returns nil.
//
// See [WebOfTrustInfo] for cases where you have both [Node]s.
func (n Node) WoT(digest *digest.Digest) *WebOfTrust {
	var (
		found bool
		hops  = hop.NewNotConnected()
		lvl   = hop.NewNotConnected()
	)

	// find the shortest if possible
	for _, c := range n.InviteeChains {
		_, idkFound := c.Find(digest.RootIDK)
		if idkFound {
			currentLvl := c.FindLevel(digest.RootIDK)
			if lvl.PickShorter(currentLvl) {
				// locations are in the same IC: - 1 if for our own block
				hops = c.Len() - 1 - lvl
				found = true
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
// trust chain (common root). If not returns nil.
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

// IsInviterFor tells if we are an inviter for a given node.
func (n Node) IsInviterFor(their Node) bool {
	chainPairs := n.CommonChains(their)

	for _, pair := range chainPairs {
		if pair.Chain1.IsInviterFor(pair.Chain2) {
			return true
		}
	}
	return false
}

func (n Node) IsRoot() bool {
	return (n.Len() == 1 && n.InviteeChains[0].Len() == 1) ||
		(n.Len() > 1 &&
			key.EqualBytes(
				n.InviteeChains[0].FirstBlock().Invitee.Public,
				n.InviteeChains[1].LastBlock().Invitee.Public,
			))
}

// OneHop returns true if two nodes are from one hop away.
func (n Node) OneHop(their Node) bool {
	chainPairs := n.CommonChains(their)

	for _, pair := range chainPairs {
		if pair.OneHop() {
			return true
		}
	}
	return false
}

// CommonChain returns the [chain.Chain] that's common for nodes.
func (n Node) CommonChain(their Node) chain.Chain {
	for _, my := range n.InviteeChains {
		if their.sharedRoot(my) {
			return my
		}
	}
	return chain.Nil
}

// Resolver returns an endpoint to the resolver if it's accessible.
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

var (
	ErrWrongKey  = errors.New("wrong public key")
	ErrSignature = errors.New("wrong signature")
)

// CheckIntegrity checks your Node's integrity, which means that all of the
// InviteeChains must be signed properly and their LastBlock shares same IDK.
// The last part is the logical binging under the Node structure.
// NOTE that you cannot trust the Node who's integrity is violated!
func (n Node) CheckIntegrity() error {
	if n.Len() == 0 { // empty non Root Node is fine.
		return nil
	}

	// use 1st ICs PubKey for our IDK, all the rest must use the same
	IDK := n.InviteeChains[0].LastBlock().Public()

	for _, c := range n.InviteeChains {
		if !key.EqualBytes(c.LastBlock().Public(), IDK) {
			return ErrWrongKey
		}

		if !c.VerifySignaturesWithGetBKID(n.getBKPublic) {
			return ErrSignature
		}
	}
	return nil
}

func (n Node) Len() int { // TODO: rename -> ICLen
	return len(n.InviteeChains)
}

// TODO: start to use CBOR? for everything, all add as format?

// NewFromData TODO:
func NewFromData(d []byte) (n Node) {
	r := bytes.NewReader(d)
	dec := gob.NewDecoder(r)
	try.To(dec.Decode(&n))
	return n
}

func (n Node) Bytes() []byte {
	// TODO: CBOR type
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	try.To(enc.Encode(n))
	return buf.Bytes()
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
	return n.BackupKeys.Blocks[keyIndex].Invitee.Public
}

func (n Node) getBackupKeyHandle(keyIndex int) key.Handle {
	assert.SLonger(n.BackupKeys.Blocks, keyIndex)

	return key.NewFromInfo(n.BackupKeys.Blocks[keyIndex].Invitee)
}

// GetIDK return Node's current IDK as [key.Info].
func (n Node) GetIDK() key.Info {
	assert.SLonger(n.InviteeChains, 0)
	assert.SLonger(n.InviteeChains[0].Blocks, 0)

	return n.InviteeChains[0].LastBlock().Invitee
}
