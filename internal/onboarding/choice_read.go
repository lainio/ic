package onboarding

import (
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// StoredChoice contains caller-owned saved evidence. A nil Acceptance means
// the proposal is pending; a nonnil Acceptance has verified for this proposal.
type StoredChoice struct {
	Proposal   intro.Path
	Acceptance key.Signature
}

// ReadStoredChoice inspects existing records using one read-only transaction.
// The caller independently establishes nonempty public identities for this
// dedicated child/root Vault; neither may be inferred from the saved records.
// The open Vault is borrowed and remains open. No signing handle is needed;
// opening the encrypted Vault still requires its storage provider.
//
// Absence returns a zero choice, false, nil. A usable proposal returns true,
// with nil acceptance if pending, or its verified saved acceptance if completed.
// Every error returns a zero choice and false, preserving the underlying cause.
// Invalid material is never repaired, rewritten, or treated as absence.
// Reading neither signs nor reserves encryption usage or creates a namespace.
//
// Found means a usable saved proposal, not membership or enrollment. Reading
// changes no modeled state or Known and proves no peer delivery, freshness,
// global uniqueness, device authority, human consent, or identity binding.
func ReadStoredChoice(
	vault *storage.Vault,
	expectedRoot, expectedChild key.Public,
) (choice StoredChoice, found bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.SNotEmpty(expectedRoot, intro.ErrWrongRoot)
	assert.SNotEmpty(expectedChild, intro.ErrBadAcceptance)

	var selected []byte
	var acceptance key.Signature
	var selectedPresent, acceptancePresent bool
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		name := []byte("introduction-choice-demo")
		if !try.To1(tx.HasChild(name)) {
			return nil
		}
		records := try.To1(tx.Child(name))
		selected, selectedPresent = try.To2(
			records.Get([]byte("selected-proposal")),
		)
		acceptance, acceptancePresent = try.To2(
			records.Get([]byte("acceptance")),
		)
		return nil
	}))
	if !selectedPresent {
		assert.ThatNot(acceptancePresent, intro.ErrBadAcceptance)
		return StoredChoice{}, false, nil
	}

	proposal := try.To1(intro.ParsePath(selected))
	assert.SLonger(proposal, 1, intro.ErrBadAcceptance)
	try.To(proposal.ProveFromRoot(expectedRoot))
	assert.That(
		proposal.LastEdge().Public().Equal(expectedChild),
		intro.ErrBadAcceptance,
	)
	if acceptancePresent {
		try.To(proposal.VerifyAcceptance(acceptance))
	}

	return StoredChoice{Proposal: proposal, Acceptance: acceptance}, true, nil
}
