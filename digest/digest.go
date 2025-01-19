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

type RootInfo struct {
	IDK  key.Public
	Hops hop.Distance
}

type Digest struct {
	IDK   key.Public
	Roots []RootInfo
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
		"IDK: %v, 1st RootIDK: %v, 1st Hops: %v",
		d.IDK.PKString(), d.Roots[0].IDK.PKString(), d.Roots[0].Hops,
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

func (d Digest) Equal(rhs Digest) bool {
	data := d.Bytes()
	dataRhs := rhs.Bytes()
	return bytes.Equal(data, dataRhs)
}
