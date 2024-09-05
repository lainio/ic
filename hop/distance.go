package hop

import "fmt"

// NotConnected tells that chains aren't connected at all, i.e. we don't have
// any route to other.
const NotConnected = -1

type Distance int

func NewNotConnected() Distance {
	return Distance(NotConnected)
}

func (d Distance) String() string {
	if d == NotConnected {
		return "NotConnected"
	} else {
		return fmt.Sprintf("Distance:%d", d)
	}
}

// PickShorter selects shorter of two Distance and tells if swap was needed.
// Because Distance is simple int it's fine to just swap existing lhs object to
// rhs object. Naturally the caller must know this! The old value can be
// discarded.
func (d *Distance) PickShorter(rhs Distance) (swap bool) {
	swap = *d == NotConnected || rhs < *d
	if swap {
		*d = rhs
	}
	return swap
}
