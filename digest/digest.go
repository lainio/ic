package digest

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	"github.com/findy-network/findy-common-go/x"
	"github.com/fxamacker/cbor/v2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

const (
	KeySplit = ":"
	HopSplit = "."
)

type RootInfo struct {
	IDK  key.Public
	Hops hop.Distance
}

type DigestV2 string

func (d DigestV2) String() string {
	return string(d)
}

func (ri RootInfo) Digest() DigestV2 {
	return DigestV2(fmt.Sprintf("%v.%d", ri.IDK.PKString(), ri.Hops))
}

func (d DigestV2) PKStringIDK() string {
	s := d.String()
	ids := strings.Split(s, KeySplit)
	assert.SNotEmpty(ids)
	return ids[0]
}

func (d DigestV2) PKDigest(index int) (pk string, h hop.Distance) {
	s := d.String()
	ids := strings.Split(s, KeySplit)
	assert.SNotEmpty(ids)
	assert.SLonger(ids, index+1)

	subs := strings.Split(ids[index+1], HopSplit)
	assert.SLen(subs, 2)

	pk = subs[0]
	hInt := try.To1(strconv.Atoi(subs[1]))
	h = hop.Distance(hInt)
	return
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

func (d Digest) Digest() DigestV2 {
	s := d.IDK.PKString() + KeySplit
	for i, v := range d.Roots {
		s += x.Whom(i > 0, KeySplit, "")
		s += v.Digest().String()
	}
	return DigestV2(s)
}

func (d Digest) Equal(rhs Digest) bool {
	data := d.Bytes()
	dataRhs := rhs.Bytes()
	return bytes.Equal(data, dataRhs)
}
