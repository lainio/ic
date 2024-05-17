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

func (d *Distance) PickShorter(rhs Distance) (swap bool) {
	if *d == NotConnected || rhs < *d {
		*d = rhs
		return true
	}
	return false
}
