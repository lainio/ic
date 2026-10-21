package intro

import (
	"bytes"
	"errors"
	"slices"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

// ErrDifferentAcceptance reports a proposal different from the selected one.
var ErrDifferentAcceptance = errors.New("another introduction is selected")

// AcceptanceChoice remembers an exact signed proposal before asking the child
// to sign, even if signing fails. It has no change-of-mind, persistence, or
// recovery policy. Another instance or direct key use bypasses it; it changes
// no modeled state and receiving its acceptance must not automatically create
// Known. It does not establish membership or human consent.
//
// Create with NewAcceptanceChoice, use through a pointer, and do not copy after
// use. The owner must serialize access, including reentrant access through
// callbacks. AcceptanceChoice provides no concurrency guarantee.
type AcceptanceChoice struct {
	child        key.Handle
	expectedRoot key.Public
	selected     Path
	acceptance   key.Signature
}

// NewAcceptanceChoice borrows child and owns a copy of expectedRoot. It performs
// no I/O or input checks; Accept checks inputs before selecting a proposal.
// The caller independently establishes the expected root and owns the handle's
// lifecycle.
func NewAcceptanceChoice(
	child key.Handle, expectedRoot key.Public,
) *AcceptanceChoice {
	return &AcceptanceChoice{
		child: child, expectedRoot: slices.Clone(expectedRoot),
	}
}

// Accept checks the path, expected parent, and matching child before remembering
// the exact Path.Bytes() proposal and signing it. A different proposal after
// selection returns ErrDifferentAcceptance, even if its parent is the same.
// Exact retries recheck the path and parent, then return a copy of any saved
// signature without signing again. Signing errors retain the selection and
// cache no partial result; an explicit retry may sign the selected proposal
// again. Every returned error accompanies a nil signature and keeps its chain.
func (c *AcceptanceChoice) Accept(
	offered Path, expectedParent key.Public,
) (acceptance key.Signature, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err)

	candidate := offered.Clone()
	if c.selected != nil &&
		!bytes.Equal(candidate.Bytes(), c.selected.Bytes()) {
		return nil, ErrDifferentAcceptance
	}

	assert.SLonger(candidate, 1, ErrBadAcceptance)
	try.To(candidate.ProveFromRoot(c.expectedRoot))
	assert.SNotEmpty(expectedParent, ErrWrongParent)
	assert.That(
		candidate.SecondLastEdge().Public().Equal(expectedParent),
		ErrWrongParent,
	)

	if c.selected == nil {
		assert.INotNil(c.child, ErrBadAcceptance)
		public := candidate.LastEdge().Public()
		assert.SNotEmpty(public, ErrBadAcceptance)
		signerPublic := try.To1(c.child.CBORPublicKey())
		assert.That(public.Equal(signerPublic), ErrBadAcceptance)

		c.selected = candidate
	}
	if c.acceptance != nil {
		return slices.Clone(c.acceptance), nil
	}

	// Keep the selection on error: the signer may already have performed work.
	signed := try.To1(c.selected.SignAcceptanceFor(
		c.child, c.expectedRoot, expectedParent,
	))
	c.acceptance = slices.Clone(signed)

	return slices.Clone(c.acceptance), nil
}
