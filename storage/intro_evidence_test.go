package storage_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// ExampleVault_introductionEvidence stores completed evidence in a test-local
// layout, not a public wallet schema. Signing precedes storage: this does not
// commit selection before signing or persist/restore AcceptanceChoice.
// A durable choice needs its own selection-before-signing contract.
// These auxiliary bytes implement no modeled action and change no Edges,
// Received, Known, trust, device, recovery, or PW state. Reading grants no
// membership; global parent uniqueness remains unresolved.
func ExampleVault_introductionEvidence() {
	defer err2.Catch(err2.Stdout)

	root, alice := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	expectedParent := expectedRoot // Alice chooses R as her immediate parent.
	offered := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)

	choice := intro.NewAcceptanceChoice(alice, expectedRoot)
	acceptance := try.To1(choice.Accept(offered, expectedParent))
	proposalBytes := offered.Bytes()

	dir := try.To1(os.MkdirTemp("", "intro-evidence-example-"))
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "vault.db")

	// The existing consumerProvider serves one vault/key version with a finite,
	// workload-independent test budget. It supplies no production key custody
	// or lifetime accounting. Keep its secret and shared counter across reopen.
	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret) // After all handle cleanup, including on failure.
	try.To1(rand.Read(p.secret))

	ctx := context.Background()
	db := try.To1(storage.OpenBolt(path))
	defer func() { _ = db.Close() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { _ = vault.Close() }()

	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, "storing introduction evidence")

		records := try.To1(tx.EnsureChild([]byte("introduction-demo")))
		try.To(records.Put([]byte("proposal"), proposalBytes))
		try.To(records.Put([]byte("acceptance"), acceptance))
		return nil
	}))
	try.To(vault.Close())
	try.To(db.Close())

	// Same-process reopening with the external provider still alive. This is
	// neither process-restart/key recovery nor rollback-resistant storage.
	reopened := try.To1(storage.OpenBolt(path))
	defer func() { _ = reopened.Close() }()
	reopenedVault := try.To1(reopened.OpenVault(ctx, p.vault, p.id, p))
	defer func() { _ = reopenedVault.Close() }()

	var recoveredProposal []byte
	var recoveredAcceptance key.Signature
	try.To(reopenedVault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, "reading introduction evidence")

		records := try.To1(tx.Child([]byte("introduction-demo")))
		var found bool
		recoveredProposal, found = try.To2(records.Get([]byte("proposal")))
		assert.That(found, "proposal missing after reopen")
		recoveredAcceptance, found = try.To2(
			records.Get([]byte("acceptance")),
		)
		assert.That(found, "acceptance missing after reopen")
		return nil
	}))

	// Get returned caller-owned bytes. Storage authentication is separate from
	// decoding, proving under the independently chosen root, and acceptance.
	recovered := try.To1(intro.ParsePath(recoveredProposal))
	proposalPreserved := bytes.Equal(recoveredProposal, proposalBytes)
	acceptancePreserved := bytes.Equal(recoveredAcceptance, acceptance)
	assert.That(proposalPreserved)
	assert.That(acceptancePreserved)
	proofErr := recovered.ProveFromRoot(expectedRoot)
	try.To(proofErr)
	acceptanceErr := recovered.VerifyAcceptance(recoveredAcceptance)
	try.To(acceptanceErr)

	try.To(reopenedVault.Close())
	try.To(reopened.Close())
	clear(p.secret)
	try.To(os.RemoveAll(dir))

	try.To1(fmt.Println("proposal bytes preserved:", proposalPreserved))
	try.To1(fmt.Println("acceptance bytes preserved:", acceptancePreserved))
	try.To1(fmt.Println("reopened path proof passes:", proofErr == nil))
	try.To1(fmt.Println("reopened acceptance verifies:", acceptanceErr == nil))
	// Output:
	// proposal bytes preserved: true
	// acceptance bytes preserved: true
	// reopened path proof passes: true
	// reopened acceptance verifies: true
}

func TestVaultIntroductionEvidenceRollback(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	original := rootPath.Introduce(root, key.InfoFromHandle(alice))
	choice := intro.NewAcceptanceChoice(alice, expectedRoot)
	acceptance := try.To1(choice.Accept(original, expectedRoot))
	originalBytes := original.Bytes()
	assert.NoError(original.ProveFromRoot(expectedRoot))
	assert.NoError(original.VerifyAcceptance(acceptance))

	replacement := rootPath.Introduce(root, key.InfoFromHandle(bob))
	replacementBytes := replacement.Bytes()
	assert.NoError(replacement.ProveFromRoot(expectedRoot))
	assert.ThatNot(bytes.Equal(replacementBytes, originalBytes))

	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret)
	try.To1(rand.Read(p.secret))
	path := filepath.Join(t.TempDir(), "vault.db")
	ctx := context.Background()
	db := try.To1(storage.OpenBolt(path))
	defer func() { _ = db.Close() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { _ = vault.Close() }()

	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, "storing original introduction evidence")

		records := try.To1(tx.EnsureChild([]byte("introduction-demo")))
		try.To(records.Put([]byte("proposal"), originalBytes))
		try.To(records.Put([]byte("acceptance"), acceptance))
		return nil
	}))

	// Ordinary callback failure after the first Put, before a matching
	// acceptance can be written. This does not test physical power loss.
	interrupted := errors.New("replacement interrupted")
	err := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, "replacing introduction evidence")

		records := try.To1(tx.ChildForUpdate([]byte("introduction-demo")))
		try.To(records.Put([]byte("proposal"), replacementBytes))
		return interrupted
	})
	assert.ErrorIs(err, interrupted)
	try.To(vault.Close())
	try.To(db.Close())

	reopened := try.To1(storage.OpenBolt(path))
	defer func() { _ = reopened.Close() }()
	reopenedVault := try.To1(reopened.OpenVault(ctx, p.vault, p.id, p))
	defer func() { _ = reopenedVault.Close() }()
	proposal, signature := try.To2(readIntroductionEvidence(reopenedVault))
	assert.DeepEqual(proposal, originalBytes)
	assert.DeepEqual(signature, acceptance)

	recovered := try.To1(intro.ParsePath(proposal))
	assert.NoError(recovered.ProveFromRoot(expectedRoot))
	assert.NoError(recovered.VerifyAcceptance(signature))
	try.To(reopenedVault.Close())
	try.To(reopened.Close())
}

func TestVaultIntroductionEvidenceStorageIsNotVerification(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	aliceInfo := key.InfoFromHandle(alice)
	rootPath := intro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, aliceInfo)
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, aliceInfo)
	assert.NoError(direct.ProveFromRoot(expectedRoot))
	assert.NoError(indirect.ProveFromRoot(expectedRoot))

	choice := intro.NewAcceptanceChoice(alice, expectedRoot)
	acceptance := try.To1(choice.Accept(direct, expectedRoot))
	assert.NoError(direct.VerifyAcceptance(acceptance))
	proposalBytes := indirect.Bytes()

	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret)
	try.To1(rand.Read(p.secret))
	path := filepath.Join(t.TempDir(), "vault.db")
	ctx := context.Background()
	db := try.To1(storage.OpenBolt(path))
	defer func() { _ = db.Close() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { _ = vault.Close() }()

	// Deliberately mismatched test data through an ordinary authorized write:
	// B = R -> Bob -> Alice with acceptance of A = R -> Alice only.
	// This is not disk tampering or a failure of Vault authentication.
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, "storing mismatched introduction evidence")

		records := try.To1(tx.EnsureChild([]byte("introduction-demo")))
		try.To(records.Put([]byte("proposal"), proposalBytes))
		try.To(records.Put([]byte("acceptance"), acceptance))
		return nil
	}))
	try.To(vault.Close())
	try.To(db.Close())

	reopened := try.To1(storage.OpenBolt(path))
	defer func() { _ = reopened.Close() }()
	reopenedVault := try.To1(reopened.OpenVault(ctx, p.vault, p.id, p))
	defer func() { _ = reopenedVault.Close() }()
	proposal, signature := try.To2(readIntroductionEvidence(reopenedVault))
	assert.DeepEqual(proposal, proposalBytes)
	assert.DeepEqual(signature, acceptance)

	recovered := try.To1(intro.ParsePath(proposal))
	assert.NoError(recovered.ProveFromRoot(expectedRoot))
	assert.ErrorIs(
		recovered.VerifyAcceptance(signature),
		intro.ErrBadAcceptance,
	)
	try.To(reopenedVault.Close())
	try.To(reopened.Close())
}

func readIntroductionEvidence(vault *storage.Vault) (
	proposal []byte, acceptance key.Signature, err error,
) {
	defer err2.Handle(&err, "reading stored introduction evidence")

	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, "reading introduction evidence records")

		records := try.To1(tx.Child([]byte("introduction-demo")))
		var found bool
		proposal, found = try.To2(records.Get([]byte("proposal")))
		assert.That(found, "proposal missing after reopen")
		acceptance, found = try.To2(records.Get([]byte("acceptance")))
		assert.That(found, "acceptance missing after reopen")
		return nil
	}))
	return proposal, acceptance, nil
}
