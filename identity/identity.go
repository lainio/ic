// package identity is the API level pkg. TODO: move rest to internal?
package identity

import (
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/node"
)

// TODO: How to we add new backup keys to the system? This is the most
// interesting question of them all. We must have one key pair for everything
// that we get one ID key, aka Public key. But if we could have multiple
// enclaves where to store our private key, the same key? But maybe more
// interesting would be that we could have multiple private keys? How we could
// do that? - Now we have RotateKey which works when we have previouos key
// available, only then. If we use RotateKey multiple times we end up having
// several key pairs which keys we control. this means that even when we lose
// some of the keys we can still control our identity.

// TODO: however, key rotation chain blocks should not be calculated when web of
// trust calculations are executed. NOTE: this is not so simple as it seems at
// the first sight. Also we don't need to do it too complex. Key rotation
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

// TODO: we should start to make tests at the Identity level.

// TODO: network decicion is that we start with the simple http or grpc calls.
// If grpc can be tunneled easily thru Onion Routing we will use it! It's faster
// and finally easier. If Tor can be just one extra layer that will be added to
// system later, we can build and test stuff much earlier!

// If we mark other
// parents of the IC to control block. This would allow parent keypair to
// control subkeys, so they could work as an backup keys. But we don't know yet
// how it would affect to our control algorithms? Now everything suspects that we
// have one identity key.Handle that controls everything we are doing. but how
// about if we could have multiple key.handles and the control would go thru
// parent/child thru IC?
// NOTE: we tried to add new root but of course it failed! It's impossible. It
// seems that it is very difficult to have multiple key handles registered for
// the same invitation chain. Second option could be that we have always append
// our chains by ourselves after whe have been Invited. That woulb give us
// multiple chain blocks that are fully under our control!

// TODO: Should we mark these 'helper' blocks somehow in the chain. they aren't
// less important, but maybe it would give opportunities to optimize certain
// things later?

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

func New(h key.Handle, flags ...chain.Opts) Identity {
	info := key.InfoFromHandle(h)
	return Identity{Node: node.New(info, flags...), Handle: h}
}

// Invite invites other identity holder to all (decided later) our ICs.
// TODO: position is given just as but we have chain.Options, maybe use them?
func (i Identity) Invite(rhs Identity, position int) Identity {
	// TODO: if they have common chain already?
	rhs.Node = i.Node.Invite(rhs.Node, i, key.InfoFromHandle(rhs.Handle), position)
	return rhs
}

func (i Identity) RotateKey(newKH key.Handle) Identity {
	newInfo := New(newKH, chain.WithRotation(true))

	newID := i.Invite(newInfo, 0)
	return newID
}

// TODO: implement tests!! for node, and chain pkgs.
func (i Identity) Endpoint(pubkey key.Public) string {
	bl, found := i.Find(pubkey)
	if found {
		return bl.Endpoint
	}
	return ""
}

func (i Identity) WebOfTrust(rhs Identity) node.WebOfTrust {
	return i.WebOfTrustInfo(rhs.Node)
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
