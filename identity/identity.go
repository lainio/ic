// package identity is the API level pkg. TODO: move rest to internal?
package identity

import (
	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/node"
)

// WIP: we need to have ID chain that allows us to RotateKey even when we don't
// have the original private key in our control. How we can do that? We'll have
// our backup keys in the onen chain in our Node. TODO: Stupid! who ever could
// add this IDK chain after or could they.. No they couldn't with out having the
// original IDK in their control. We don't have hided Master Key, OR
// actually we could have if we start everything with one rotation, but the
// question is what good does it give to us? The question is that what direction
// we should use the backup key chain?

// When normally we'll rotate key
// just by adding a new block to all of the Node's chains (Type is Rotation).
// Now we don't have a key to do that but when have a related key. Maybe we must
// fork the chain? Is this so important... Maybe it is because disastorous
// things happen but the question is where we should handle thouse things? In
// the cain, or in the some where else?

// TODO: however, key rotation chain blocks should not be calculated when web of
// trust calculations are executed. NOTE: this is not so simple as it seems at
// the first sight. Also we *don't need to do it too complex*. Key rotation
// should be limited to happen only chain roots, not later!! we could even think
// that it's allowed only when no invitations are done for us, i.e., that key
// rotation should be done during the setup, not later. Why we did it later, if
// we still control the key pair, we would loose all of our ICs? If we use key
// rotation to build subkeys, it's different situation and these hops should be
// calculated. If hop count is very important, we don't know it yet, we should
// do something. Now we have the position property to categorize our blocks, but
// how important it really is.

// TODO: key rotation need the concept of the Root Chain, i.e., the cain that's
// block are all under our control AND every block type is Rotation! Another
// name could be Identity Chain (like Identity Matrix)

// If we mark other
// parents of the IC to control block. This would allow parent keypair to
// control subkeys, so they could work as an backup keys. But we don't know yet
// how it would affect to our control algorithms? Now everything suspects that we
// have one identity key.Handle that controls everything we are doing. but how
// about if we could have multiple key.handles and the control would go thru
// parent/child thru IC?

type Identity struct {
	node.Node // chains inside these share the same key.ID&Public

	// TODO: should we have multiple key.Handle if we have pre rotated?
	// we will have dynamic rotation (RotateKey), and we'll have ID chain later
	// that's used for catastrophes, i.e., we have lost the control of our
	// private key. Then we need a backup key. Backup keys are stored in ID
	// Chain. Because we can sign nothing, we need a backup route where will
	// tell that use this key form this id chain. All of the ID Chains have the
	// same original root. Even when we don't have root key (genesis key) any
	// more chain's validity can be proofed.
	key.Handle
}

// New creates a Identity object. NOTE that this far too simple for production
// use when we need to setup many keys (propably) for the backup keys, etc. NOTE
// we can create new backup keys as long as we own the previous one.
func New(h key.Handle, flags ...chain.Opts) Identity {
	info := key.InfoFromHandle(h)
	return Identity{Node: node.New(info, flags...), Handle: h}
}

func (i Identity) InviteWithRotateKey(
	rhs Identity,
	opts ...chain.Opts,
) Identity {
	newKH := key.New()
	rhs.Node = i.Node.InviteWithRotateKey(
		rhs.Node, i, newKH, key.InfoFromHandle(rhs.Handle), opts...)
	return rhs
}

// Invite invites other identity holder to all (decided later) our ICs.
// TODO: position is given just as but we have chain.Options, maybe use them?
func (i Identity) Invite(rhs Identity, opts ...chain.Opts) Identity {
	rhs.Node = i.Node.Invite(rhs.Node, i, key.InfoFromHandle(rhs.Handle), opts...)
	return rhs
}

func (i Identity) RotateKey(newKH key.Handle) Identity {
	newInfo := New(newKH, chain.WithRotation())

	newID := i.Invite(newInfo, chain.WithPosition(0))
	return newID
}

func (i Identity) Resolver() string {
	return i.Node.Resolver()
}

func (i Identity) Endpoint(pubkey key.Public) string {
	bl, found := i.Find(pubkey)
	if found {
		return bl.Endpoint
	}
	return ""
}

func (i Identity) WebOfTrust(rhs Identity) *node.WebOfTrust {
	return i.WebOfTrustInfo(rhs.Node)
}

// Challenge offers a method and placeholder for challenging other chain holder.
// Most common cases is that caller of the function implements the closure where
// it calls other party over the network to sign the challenge which is readily
// build and randomized.
func (i Identity) Challenge(pinCode int, f func(d []byte) key.Signature) bool {
	assert.SLonger(i.InviteeChains, 0)
	// All InviteeChains are equally useful for Challenge.
	return i.InviteeChains[0].Challenge(pinCode, f)
}

// TrustLevel calculates current trust-level of the Identity domain.
// Calcultation is simple summary of Invitee chains and the levels there
// TODO: Where this is used?
func (i Identity) TrustLevel() int {
	return 0
}

// Friends tells if these two are friends by IC.
// TODO: Where this is used?
func (i Identity) Friends(rhs Identity) bool {
	return false
}
