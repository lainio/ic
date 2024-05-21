package chain

import (
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

// Pair is helper type to keep two related chains together. Related chains means
// that two chains have common inviter even the actual chains are different. It
// also means that chains have some ancestor that they share.
//
// Pair type offers helper methods to calculate hops between two chains. Pair
// and Chain are symmetric.
type Pair struct {
	Chain1, Chain2 Chain
}

func (p Pair) Valid() bool {
	return !p.Chain1.IsNil() && !p.Chain2.IsNil()
}

// Hops returns hops and common inviter's level if that exists. If not both
// return values are NotConnected.
func (p Pair) Hops() (hop.Distance, hop.Distance) {
	return Hops(p.Chain1, p.Chain2)
}

func (p Pair) OneHop() bool {
	return p.Chain1.IsInviterFor(p.Chain2) ||
		p.Chain2.IsInviterFor(p.Chain1)
}

// CommonInviterIDKey returns IDKey aka pubkey of common inviter by root level.
func (p Pair) CommonInviterIDKey(lvl hop.Distance) key.Public {
	block := p.Chain1.Blocks[lvl]
	return block.Invitee.Public
}

// SameRoot not needed yet.
func (p Pair) _() bool {
	return SameRoot(p.Chain1, p.Chain2)
}
