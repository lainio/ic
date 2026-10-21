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
// complete canonical proposal in one Vault.Update before calling the existing
// checked signer outside the transaction. A different stored proposal returns
// intro.ErrDifferentAcceptance; empty/corrupt records are not treated as absent.
// Every returned error preserves its cause and accompanies a nil signature.
// Signing errors retain the committed choice, even after real signing work.
//
// The caller supplies an open, dedicated Vault for one child/root binding and
// independently establishes expectedRoot and expectedParent. It must serialize
// use, including reentrant access, and maintain an intact, non-rolled-back Vault.
// This function borrows the Vault and child handle, closes neither, and stores
// no handle or provider secret.
//
// Each call consults storage; identical retries may sign again. Only the choice
// is stored: unlike intro.AcceptanceChoice, no acceptance is cached or stored.
// The private development layout is not a published wallet format. No modeled
// authority or global parent uniqueness follows. Deletion, copies, restores,
// other Vaults/devices, or direct key use can bypass this local restriction.
// No concurrency, reentrancy, or rollback-resistance guarantee is provided.
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

	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		defer assert.PushAsserter(assert.Plain)()

		records := try.To1(tx.EnsureChild([]byte("introduction-choice-demo")))
		stored, found := try.To2(records.Get([]byte("selected-proposal")))
		if found {
			assert.That(
				bytes.Equal(stored, proposal),
				intro.ErrDifferentAcceptance,
			)
			return nil
		}
		try.To(records.Put([]byte("selected-proposal"), proposal))
		return nil
	}))

	// Update has returned successfully: the selection transaction has ended.
	// Signing errors keep that choice and discard any partial signature.
	signed := try.To1(candidate.SignAcceptanceFor(
		child, expectedRoot, expectedParent,
	))
	return signed, nil
}
