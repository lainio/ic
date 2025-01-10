package digest

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/fxamacker/cbor/v2"
	"github.com/lainio/err2/try"
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
//   - nope, we should keep this as compact we can.

type Digest struct {
	IDK key.Public // TODO: when we need key.ID? Should we use key.Info?

	// TODO: should this be array? Yes, good question, let's test size?
	RootIDK key.Public // TODO: when we need key.ID? Should we use key.Info?

	Hops hop.Distance
}

func NewFromString(s string) (di Digest) {
	data := base58.Decode(s)
	return NewFromData(data)
}

func NewFromData(data []byte) (di Digest) {
	r := bytes.NewReader(data)
	dec := cbor.NewDecoder(r)
	try.To(dec.Decode(&di))
	return di
}

func (d Digest) String() string {
	return fmt.Sprintf(
		"IDK: %v, RootIDK: %v, Hops: %v",
		d.IDK.PKString(), d.RootIDK.PKString(), d.Hops,
	)
}

func (d Digest) Bytes() []byte {
	var buf bytes.Buffer
	enc := cbor.NewEncoder(&buf)
	try.To(enc.Encode(d))
	return buf.Bytes()
}

func (d Digest) Base58() string {
	data := d.Bytes()
	s := base58.Encode(data)
	return s
}
