package onboarding

import (
	"bytes"
	"errors"
	"slices"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const knownNamespace = "known-introductions-v1"

var (
	errInvalidKnown       = errors.New("invalid known introduction binding")
	errConflictingParents = errors.New("conflicting local introduction parents")
	errKnownUnchanged     = errors.New("known introductions unchanged")
)

// VerifyReceived explicitly promotes saved introduction subjects under the
// independently configured Root. One Update revalidates all received records,
// existing Known bindings, and local parent consistency before any writes.
// The count is newly promoted subjects, not modeled edges; errors return zero.
// Matching retries roll back without writes or encryption usage.
//
// A root-pinned signed path and child acceptance are local operational evidence,
// not proof of global Edges membership, parent uniqueness, or presenter key
// control. This borrows the Vault and changes only Known introduction markers,
// never Received, local choice, trust, ads, devices, or PW state. It is intended
// for a future explicitly documented composite connection workflow.
func VerifyReceived(vault *storage.Vault, expectedRoot key.Public) (_ int, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	expectedRoot = bytes.Clone(expectedRoot)
	newlyKnown := 0
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)

		missing := try.To1(receivedBindings(tx, expectedRoot))
		if try.To1(tx.HasChild([]byte(knownNamespace))) {
			known := try.To1(tx.Child([]byte(knownNamespace)))
			try.To(known.Each(func(subject, marker []byte) (err error) {
				defer err2.Handle(&err, nil)

				binding, found := missing[string(subject)]
				assert.That(found && bytes.Equal(marker, binding), errInvalidKnown)
				delete(missing, string(subject))
				return nil
			}))
		}
		if len(missing) == 0 {
			// Avoid committing backend bookkeeping on a true no-op.
			return errKnownUnchanged
		}
		// All validation has finished. Only missing markers incur a seal.
		known := try.To1(tx.EnsureChild([]byte(knownNamespace)))
		for subject, marker := range missing {
			try.To(known.Put([]byte(subject), marker))
		}
		newlyKnown = len(missing)
		return nil
	})
	if updateErr != errKnownUnchanged {
		try.To(updateErr)
	}
	return newlyKnown, nil
}

// ListKnownIntroductions returns independent, byte-sorted subject keys from one
// View. Every marker must bind its exact saved received record, whose proof,
// Root, acceptance, and subject are rechecked along with local parent consistency
// among Known paths. Unpromoted received subjects are not listed or promoted.
// Absence is empty; corruption returns no result. Reads need no encryption
// allowance and grant no contact, trust, device, ad, or PW authority.
func ListKnownIntroductions(vault *storage.Vault, expectedRoot key.Public) (
	_ []key.Public, err error,
) {
	defer err2.Handle(&err, nil)

	expectedRoot = bytes.Clone(expectedRoot)
	var subjects []key.Public
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		subjects = try.To1(listKnownIntroductions(tx, expectedRoot))
		return nil
	}))
	return subjects, nil
}

// IsKnownIntroductionInTx uses the same full evidence/binding validation as
// ListKnownIntroductions in the caller's transaction. It performs only local
// reads and pure verification, never a reentrant Vault operation or signer
// callback. All Known entries are validated even if subject is found early.
// There is no implicit Root/self convention or promotion in this projection.
func IsKnownIntroductionInTx(tx storage.ReadTx, expectedRoot, subject key.Public) (bool, error) {
	subjects, err := listKnownIntroductions(tx, expectedRoot)
	if err != nil {
		return false, err
	}
	_, found := slices.BinarySearchFunc(subjects, subject, func(a, b key.Public) int { return bytes.Compare(a, b) })
	return found, nil
}

func listKnownIntroductions(tx storage.ReadTx, expectedRoot key.Public) (_ []key.Public, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	subjects := make([]key.Public, 0)
	if !try.To1(tx.HasChild([]byte(knownNamespace))) {
		return subjects, nil
	}
	known := try.To1(tx.Child([]byte(knownNamespace)))
	var received storage.ReadNS
	if try.To1(tx.HasChild([]byte(receivedNamespace))) {
		received = try.To1(tx.Child([]byte(receivedNamespace)))
	}
	parents := make(map[string]key.Public)
	try.To(known.Each(func(subject, marker []byte) (err error) {
		defer err2.Handle(&err, nil)

		assert.That(len(subjects) < maxReceivedSubjects && received != nil, errInvalidKnown)
		record, found := try.To2(received.Get(subject))
		assert.That(found, errInvalidKnown)
		binding := try.To1(receivedBinding(record, subject, expectedRoot, parents))
		assert.That(bytes.Equal(marker, binding), errInvalidKnown)
		subjects = append(subjects, bytes.Clone(subject))
		return nil
	}))
	slices.SortFunc(subjects, func(a, b key.Public) int { return bytes.Compare(a, b) })
	return subjects, nil
}

func receivedBindings(tx storage.ReadTx, root key.Public) (_ map[string][]byte, err error) {
	defer err2.Handle(&err, nil)

	bindings := make(map[string][]byte)
	if !try.To1(tx.HasChild([]byte(receivedNamespace))) {
		return bindings, nil
	}
	received := try.To1(tx.Child([]byte(receivedNamespace)))
	parents := make(map[string]key.Public)
	try.To(received.Each(func(subject, record []byte) (err error) {
		defer err2.Handle(&err, nil)

		assert.That(len(bindings) < maxReceivedSubjects, errInvalidReceived)
		bindings[string(subject)] = try.To1(receivedBinding(record, subject, root, parents))
		return nil
	}))
	return bindings, nil
}

func receivedBinding(record, subject []byte, root key.Public, parents map[string]key.Public) (
	_ []byte, err error,
) {
	defer err2.Handle(&err, nil)

	proposal, _ := try.To2(readReceived(record, subject, root))
	// Shared admission policy has already verified this path. Decode only to
	// compare parent claims across records, using complete public-key bytes.
	path := try.To1(intro.ParsePath(proposal))
	for i, edge := range path[1:] {
		child, parent := string(edge.Public()), path[i].Public()
		previous, found := parents[child]
		assert.That(!found || bytes.Equal(previous, parent), errConflictingParents)
		parents[child] = parent
	}
	// Private version + tagged digest of the exact received representation,
	// including its detached acceptance. No proposal/signature is duplicated.
	digest := key.HashTagged(knownNamespace, record)
	return append([]byte{1}, digest[:]...), nil
}
