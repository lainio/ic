package pw

import "github.com/lainio/ic/key"

// Connection is compact data structure to save pw information. It's more
// compact that [chain.Block], which is one of the reasons we are using it
// instead of the Block. It's probably true that Identities and Nodes have vast
// amount of Connections to others. So, it's important that we keep them small.
type Connection struct {
	// when we are using this, we have stateless, and now we are *different*
	// than Block structure. We are almost symmetric. How about Endpoint? By
	// using PW specific endpoints we could have more dynamic, and the solution
	// would symmetric and for that beautiful.
	We   key.Info 
	They key.Info
	// or... only their IDK?
	IDK      key.Public
	Endpoint string // TODO: we start with simple, but probably later we...
}

func New(idk key.Public, ep string) Connection {
	return Connection{
		IDK:      idk,
		Endpoint: ep,
	}
}

// TODO: currently our DB solution is based on User structure which
// encapsulates the Identity struct. The idea, if we have own bucket for pws we
// can use BoltDB's (or any key/value dbs) search functionality which is
// extremely fast and keep our code simple, or simpler.
//  - we should not forget that pws are important as a persistent structures
//  - we should remember that inside each pws the ongoing communication will be
//  saved in case it's msg based.
