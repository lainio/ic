// Package onboarding composes introduction checks, storage, and keys into
// application workflows.
package onboarding

import (
	"bytes"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// SignAfterStoredChoice validates a cloned offer and commits or matches its
// complete canonical proposal in the first Vault.Update. A saved acceptance is
// verified and returned without Sign, Put, or another encryption. Otherwise,
// the checked signer runs outside all transactions; its result is verified and
// saved in a second Update before success. Both paths require a matching child
// handle and independently chosen root/parent; public-key access still occurs.
// A different stored proposal returns intro.ErrDifferentAcceptance. Invalid or
// orphaned acceptances return intro.ErrBadAcceptance without signing or repair;
// empty records are not absent. Storage/verification errors retain their causes.
// Every error accompanies a nil signature. Signing or save failure retains the
// committed choice; explicit retries may sign again if no result was saved.
//
// The caller supplies an open, dedicated Vault for one child/root binding and
// independently establishes expectedRoot and expectedParent. It must serialize
// use, including reentrant access, and maintain an intact, non-rolled-back Vault.
// This function borrows the Vault and child handle, closes neither, and stores
// no handle or provider secret.
//
// Each call consults storage. Selection-only records are legitimate pending
// choices. Signing and saving are not atomic: this is saved-result reuse, not
// exactly-once signing or delivery. The private development layout is not a
// published wallet format. No membership, human/ancestor consent, Known
// promotion, or global parent uniqueness follows. Deletion, copies, restores,
// other Vaults/devices, or direct key use can bypass this local restriction.
// No concurrency, reentrancy, physical crash safety, cross-process key recovery,
// or rollback-resistance guarantee is provided.
func SignAfterStoredChoice(
	vault *storage.Vault,
	child key.Handle,
	expectedRoot, expectedParent key.Public,
	offered intro.Path,
) (acceptance key.Signature, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	candidate := offered.Clone()
	assert.SLonger(candidate, 1, intro.ErrBadAcceptance)
	try.To(candidate.ProveFromRoot(expectedRoot))

	assert.SNotEmpty(expectedParent, intro.ErrWrongParent)
	assert.That(
		candidate.SecondLastEdge().Public().Equal(expectedParent),
		intro.ErrWrongParent,
	)

	assert.INotNil(child, intro.ErrBadAcceptance)
	public := candidate.LastEdge().Public()
	assert.SNotEmpty(public, intro.ErrBadAcceptance)
	signerPublic := try.To1(child.CBORPublicKey())
	assert.That(public.Equal(signerPublic), intro.ErrBadAcceptance)
	proposal := candidate.Bytes()

	var saved key.Signature
	var completed bool
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		defer assert.PushAsserter(assert.Plain)()

		records := try.To1(tx.EnsureChild([]byte("introduction-choice-demo")))
		stored, found := try.To2(records.Get([]byte("selected-proposal")))
		saved, completed = try.To2(records.Get([]byte("acceptance")))
		if found {
			assert.That(
				bytes.Equal(stored, proposal),
				intro.ErrDifferentAcceptance,
			)
			return nil
		}
		assert.ThatNot(completed, intro.ErrBadAcceptance)
		try.To(records.Put([]byte("selected-proposal"), proposal))
		return nil
	}))

	// Update has returned successfully: the selection transaction has ended.
	if completed {
		try.To(candidate.VerifyAcceptance(saved))
		return saved, nil
	}

	// Signing errors keep the choice and discard any partial signature.
	signed := try.To1(candidate.SignAcceptanceFor(
		child, expectedRoot, expectedParent,
	))
	try.To(candidate.VerifyAcceptance(signed))

	// Save only the verified result, without recreating or replacing state.
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		defer assert.PushAsserter(assert.Plain)()

		name := []byte("introduction-choice-demo")
		assert.That(try.To1(tx.HasChild(name)), intro.ErrBadAcceptance)
		records := try.To1(tx.ChildForUpdate(name))
		stored, found := try.To2(records.Get([]byte("selected-proposal")))
		assert.That(found, intro.ErrBadAcceptance)
		assert.That(
			bytes.Equal(stored, proposal),
			intro.ErrDifferentAcceptance,
		)
		_, found = try.To2(records.Get([]byte("acceptance")))
		assert.ThatNot(found, intro.ErrBadAcceptance)
		try.To(records.Put([]byte("acceptance"), signed))
		return nil
	}))
	return signed, nil
}
