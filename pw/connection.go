package pw

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"slices"

	"github.com/findy-network/findy-common-go/x"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

// Connection is compact data structure to save pw information. It's more
// compact than [chain.Block], which is one of the reasons we are using it
// instead of the Block. It's probably true that Identities and Nodes have vast
// amount of Connections to others. So, it's important that we keep them small.
type Connection struct {
	DBID uint32 // ref id to User in DB

	// when we are using this, we have stateless, and now we are *different*
	// than Block structure. We are almost symmetric. How about Endpoint? By
	// using PW specific endpoints we could have more dynamic, and the solution
	// would symmetric and for that beautiful.
	IsAddresser bool

	Addresser ConnEndpoint
	Addressee ConnEndpoint
}

type ConnEndpoint struct {
	// these are the field we know now
	//

	key.Info

	Endpoint string // TODO: we start with simple, but probably later we...
}

// Key is interface method for key/value DB. Our db indexing use cases are 99%
// that we need to find out if the other end is already in our db, and that's
// why we use [IsAddressers] field to select the correct IDK.
//
// TODO: HUGE Bug we can have only very very limited amount of pairwises with
// this key.
// TODO: How to solve this? Maybe this can be a sub-key of something? Or we need
// a DB ID like with the Nodes.
// TODO: work in progress
func (c *Connection) Key() []byte {
	return slices.Concat(uint32ToBytes(c.DBID), c.TheirIDK())
}

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func (c *Connection) TheirIDK() key.Public {
	if c.IsAddresser {
		return c.Addressee.Public
	}
	return c.Addresser.Public
}

func (c *Connection) OurIDK() key.Public {
	if !c.IsAddresser {
		return c.Addressee.Public
	}
	return c.Addresser.Public
}

func (c *Connection) String() string {
	start := fmt.Sprintf("Addresser: %v", x.Whom(c.IsAddresser, "Yes", "No "))
	idk := c.Addresser.PKString()
	if c.IsAddresser {
		idk = c.Addressee.PKString()
	}
	return fmt.Sprintf("%s, Ref IDK: %v, A-er: %v, A-ee: %v, DBID: %d",
		start, idk, c.Addresser.PKString(), c.Addressee.PKString(), c.DBID)
}

func (c *Connection) Data() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	try.To(enc.Encode(c))
	return buf.Bytes()
}

func New(DBID uint32, isAddresser bool, addresser, addressee ConnEndpoint) *Connection {
	return &Connection{
		DBID: DBID,

		IsAddresser: isAddresser,
		Addresser:   addresser,
		Addressee:   addressee,
	}
}

func NewFromData(b []byte) (c *Connection) {
	if len(b) == 0 {
		return nil
	}
	buf := bytes.NewReader(b)
	dec := gob.NewDecoder(buf)
	try.To(dec.Decode(&c))

	return
}

// TODO: currently our DB solution is based on User structure which
// encapsulates the Identity struct. The idea, if we have own bucket for pws we
// can use BoltDB's (or any key/value dbs) search functionality which is
// extremely fast and keep our code simple, or simpler.
//  - we should not forget that pws are important as a persistent structures
//  - we should remember that inside each pws the ongoing communication will be
//  saved in case it's msg based.

// TODO: the spec:
//
// We should have 2 buckets:
//   1. pw initiated by us
//   2. pw initiated by them
// -> this would make it easier to search and stored stuff. Let's see how it
// affects to the PW.
//   - we could use correct names from the protocol: addresser, addressee,
//   inviter, invitee, and now by depending in what bucket these connections are
//   the indexing must be done according to that => we should include the bucket
//   flag to the actual data structure. (done)
