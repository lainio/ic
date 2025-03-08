package digest

import (
	"strconv"
	"strings"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/hop"
)

func (d DigestV2) String() string {
	return string(d)
}

func (d DigestV2) PKStringIDK() string {
	s := d.String()
	ids := strings.Split(s, KeySplit)
	assert.SNotEmpty(ids)
	return ids[0]
}

func (d DigestV2) Build() (r RefDigestV2) {
	s := d.String()
	ids := strings.Split(s, KeySplit)
	assert.SNotEmpty(ids)
	r.PKStringIDK = ids[0]

	r.Roots = make([]RefRootInfo, len(ids)-1)
	for i, v := range ids[1:] {
		subs := strings.Split(v, HopSplit)
		assert.SLen(subs, 2)

		r.Roots[i].PKStringIDK = subs[0]
		hInt := try.To1(strconv.Atoi(subs[1]))
		r.Roots[i].Hop = hop.Distance(hInt)
	}
	return
}

type DigestV2 string

type RefRootInfo struct {
	PKStringIDK string
	Hop         hop.Distance
}

type RefDigestV2 struct {
	PKStringIDK string
	Roots       []RefRootInfo
}

func (rd RefDigestV2) PKDigest(index int) RefRootInfo {
	assert.That(index < len(rd.Roots))
	return rd.Roots[index]
}

func (rd RefDigestV2) WoT(rhs RefDigestV2) (yes bool) {
	if rd.PKStringIDK == rhs.PKStringIDK { // we are the same one
		return true
	}

	for _, v := range rd.Roots {
		for _, vrhs := range rhs.Roots {
			if v.PKStringIDK == vrhs.PKStringIDK {
				return true
			}
		}
	}

	return
}
