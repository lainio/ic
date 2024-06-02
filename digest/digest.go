package digest

import (
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/key"
)

type Digest struct {
	IDK     key.Public
	RootIDK key.Public
	Hops    hop.Distance
}
