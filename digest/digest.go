package digest

import (
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

// TODO: when we need key.ID?
//  - it's needed when we start to challenge i.e. ask key owner to sign
//  something. That means that if we can be sure there is Block available we can
//  use just key.Public other places. It's shorter. It also means that if we
//  have some sort storage/map (key.Public -> key.ID) so called reverse map in
//  our case, we can be semi stateless. However, if we could use both
//  key.ID+key.Public, we could be fully stateless. That's the case in our
//  authentication. key.Public is important for verification, and key.ID is for
//  signing.
// TODO: maybe we should use key.Info everywhere we just can?

type Digest struct {
	IDK key.Public // TODO: when we need key.ID? Should we use key.Info?

	// TODO: should this be array?
	RootIDK key.Public // TODO: when we need key.ID? Should we use key.Info?

	Hops hop.Distance
}
