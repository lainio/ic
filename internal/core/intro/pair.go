package intro

// Pair is helper type to keep two related chains together. Related chains means
// that two chains have common inviter even the actual chains are different. It
// also means that chains have some ancestor that they share.
//
// Pair type offers helper methods to calculate hops between two chains. Pair
// and Path are symmetric.
type Pair struct {
	Chain1, Chain2 Path
}

func (p Pair) Valid() bool {
	return p.Chain1 != nil && p.Chain2 != nil
}
