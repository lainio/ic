package onboarding

import (
	"encoding/json"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

// EncodeIntroduction encodes a completed choice already validated by
// ReadStoredChoice. This pure helper preserves the owner export policy: refuse
// private handle IDs on every edge and never strip signed material. Peer
// disclosure additionally applies CheckIntroduction's admission policy.
func EncodeIntroduction(stored StoredChoice) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.SLonger(stored.Proposal, 1, ErrInvalidIntroduction)
	assert.SNotEmpty(stored.Acceptance, ErrInvalidIntroduction)
	assert.That(PublicIntroduction(stored.Proposal), ErrInvalidIntroduction)
	// ReadStoredChoice parses canonical bytes, so Bytes reproduces the exact
	// saved proposal. The detached acceptance is returned exactly as saved.
	document := try.To1(json.Marshal(struct {
		Version    int    `json:"version"`
		Proposal   []byte `json:"proposal"`
		Acceptance []byte `json:"acceptance"`
	}{1, stored.Proposal.Bytes(), stored.Acceptance}))
	assert.That(len(document) <= MaxIntroductionBytes, ErrInvalidIntroduction)
	return document, nil
}
