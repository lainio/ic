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
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// ExampleVault_acceptanceRetry reuses a completed result from an intact Vault
// in the same process, keeping the provider secret, counter, and keys alive.
// The saved acceptance is auxiliary signing state, not membership or Known.
func ExampleVault_acceptanceRetry() {
	defer err2.Catch(err2.Stdout)

	root, alice := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	alicePublic := key.Public(try.To1(alice.CBORPublicKey()))
	expectedParent := expectedRoot // Alice independently chooses R.
	offered := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	// Test scaffolding counts actual Sign calls while using Alice's real key.
	signer := &choiceSigningHandle{Handle: alice}

	dir := try.To1(os.MkdirTemp("", "intro-acceptance-retry-example-"))
	defer func() { try.Out(os.RemoveAll(dir)).Logf() }()
	path := filepath.Join(dir, "vault.db")
	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret)
	try.To1(rand.Read(p.secret))

	ctx := context.Background()
	db := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(db.Close()).Logf() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(vault.Close()).Logf() }()

	observed := try.To1(onboarding.SignAfterStoredChoice(
		vault, signer, expectedRoot, expectedParent, offered,
	))
	try.To(vault.Close())
	try.To(db.Close())

	reopened := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(reopened.Close()).Logf() }()
	reopenedVault := try.To1(reopened.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(reopenedVault.Close()).Logf() }()

	// Inspect with public identities only, before any signing-workflow retry.
	saved, found := try.To2(onboarding.ReadStoredChoice(
		reopenedVault, expectedRoot, alicePublic,
	))
	assert.That(found)
	assert.DeepEqual(saved.Proposal.Bytes(), offered.Bytes())
	assert.DeepEqual(saved.Acceptance, observed)
	assert.NoError(saved.Proposal.VerifyAcceptance(saved.Acceptance))
	assert.Equal(signer.signCalls, 1)

	// Retry the same offer; the earlier signature is only a test observation.
	retry := try.To1(onboarding.SignAfterStoredChoice(
		reopenedVault, signer, expectedRoot, expectedParent, offered,
	))
	verifyErr := offered.VerifyAcceptance(retry)
	try.To(verifyErr)
	same := bytes.Equal(retry, observed)
	assert.That(same)
	assert.Equal(signer.signCalls, 1)

	try.To(reopenedVault.Close())
	try.To(reopened.Close())
	clear(p.secret)
	try.To(os.RemoveAll(dir))

	try.To1(fmt.Println("saved choice found:", found))
	try.To1(fmt.Println("acceptance verifies after reopen:", verifyErr == nil))
	try.To1(fmt.Println("same acceptance returned:", same))
	try.To1(fmt.Println("signing calls:", signer.signCalls))
	// Output:
	// saved choice found: true
	// acceptance verifies after reopen: true
	// same acceptance returned: true
	// signing calls: 1
}

func TestVaultAcceptanceRetryCompleted(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	a := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	b := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	assert.NoError(b.ProveFromRoot(expectedRoot))
	assert.ThatNot(bytes.Equal(a.Bytes(), b.Bytes()))

	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret)
	try.To1(rand.Read(p.secret))
	path := filepath.Join(t.TempDir(), "vault.db")
	ctx := context.Background()
	db := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(db.Close()).Logf() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(vault.Close()).Logf() }()
	signer := &choiceSigningHandle{Handle: alice}

	initial := try.To1(onboarding.SignAfterStoredChoice(
		vault, signer, expectedRoot, expectedRoot, a,
	))
	assert.NoError(a.VerifyAcceptance(initial))
	assert.Equal(signer.signCalls, 1)
	observed := bytes.Clone(initial)
	initial[0] ^= 1 // The first returned slice must not alias stored state.
	try.To(vault.Close())
	try.To(db.Close())

	reopened := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(reopened.Close()).Logf() }()
	reopenedVault := try.To1(reopened.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(reopenedVault.Close()).Logf() }()
	signer.signErr = errors.New("completed retry must not sign")
	p.mu.Lock()
	p.remainingEncryptions = 0
	p.mu.Unlock()

	retry, err := onboarding.SignAfterStoredChoice(
		reopenedVault, signer, expectedRoot, expectedRoot, a,
	)
	assert.Equal(signer.signCalls, 1)
	assert.NoError(err)
	assert.NoError(a.VerifyAcceptance(retry))
	assert.DeepEqual([]byte(retry), observed)
	retry[0] ^= 1 // A cached Get result also belongs to its caller.
	again := try.To1(onboarding.SignAfterStoredChoice(
		reopenedVault, signer, expectedRoot, expectedRoot, a,
	))
	assert.DeepEqual([]byte(again), observed)
	assert.NoError(a.VerifyAcceptance(again))

	for _, tc := range []struct {
		name   string
		child  key.Handle
		parent key.Public
		offer  intro.Path
		want   error
	}{
		{"wrong parent", signer, bobPublic, a, intro.ErrWrongParent},
		{"different offer", signer, bobPublic, b, intro.ErrDifferentAcceptance},
		{"nil child", nil, expectedRoot, a, intro.ErrBadAcceptance},
		{"wrong child", bob, expectedRoot, a, intro.ErrBadAcceptance},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			rejected, err := onboarding.SignAfterStoredChoice(
				reopenedVault, tc.child, expectedRoot, tc.parent, tc.offer,
			)
			assert.ErrorIs(err, tc.want)
			assert.SNil(rejected)
			assert.Equal(signer.signCalls, 1)
		})
	}
	assert.Equal(signer.signCalls, 1)
	try.To(reopenedVault.Close())
	try.To(reopened.Close())
}

func TestVaultAcceptanceRetrySaveFailure(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	a := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	b := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	assert.NoError(b.ProveFromRoot(expectedRoot))
	assert.ThatNot(bytes.Equal(a.Bytes(), b.Bytes()))

	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret)
	try.To1(rand.Read(p.secret))
	path := filepath.Join(t.TempDir(), "vault.db")
	ctx := context.Background()
	db := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(db.Close()).Logf() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(vault.Close()).Logf() }()
	signer := &choiceSigningHandle{Handle: alice}

	// Operation-error injection, not power loss: selection consumes the last
	// encryption, real signing succeeds, and saving the acceptance must fail.
	p.mu.Lock()
	remaining := p.remainingEncryptions
	p.remainingEncryptions = 1
	p.mu.Unlock()
	failed, err := onboarding.SignAfterStoredChoice(
		vault, signer, expectedRoot, expectedRoot, a,
	)
	assert.ErrorIs(err, storage.ErrKeyUsageExhausted)
	assert.ErrorIsNot(err, intro.ErrBadAcceptance)
	assert.SNil(failed)
	assert.Equal(signer.signCalls, 1)
	try.To(vault.Close())
	try.To(db.Close())

	reopened := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(reopened.Close()).Logf() }()
	reopenedVault := try.To1(reopened.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(reopenedVault.Close()).Logf() }()
	stored, found := try.To2(readSelectedProposal(reopenedVault))
	assert.That(found)
	assert.DeepEqual(stored, a.Bytes())
	saved, found := try.To2(readStoredAcceptance(reopenedVault))
	assert.ThatNot(found)
	assert.SNil(saved)

	rejected, err := onboarding.SignAfterStoredChoice(
		reopenedVault, signer, expectedRoot, bobPublic, b,
	)
	assert.ErrorIs(err, intro.ErrDifferentAcceptance)
	assert.ErrorIsNot(err, intro.ErrWrongParent)
	assert.SNil(rejected)
	assert.Equal(signer.signCalls, 1)

	p.mu.Lock()
	p.remainingEncryptions = remaining
	p.mu.Unlock()
	retry := try.To1(onboarding.SignAfterStoredChoice(
		reopenedVault, signer, expectedRoot, expectedRoot, a,
	))
	assert.NoError(a.VerifyAcceptance(retry))
	assert.Equal(signer.signCalls, 2)
	saved, found = try.To2(readStoredAcceptance(reopenedVault))
	assert.That(found)
	assert.DeepEqual(saved, retry)

	signer.signErr = errors.New("saved retry must not sign")
	again := try.To1(onboarding.SignAfterStoredChoice(
		reopenedVault, signer, expectedRoot, expectedRoot, a,
	))
	assert.NoError(a.VerifyAcceptance(again))
	assert.DeepEqual(again, retry)
	assert.Equal(signer.signCalls, 2)
	stored, found = try.To2(readSelectedProposal(reopenedVault))
	assert.That(found)
	assert.DeepEqual(stored, a.Bytes())
	try.To(reopenedVault.Close())
	try.To(reopened.Close())
}

func TestVaultAcceptanceRetryInvalidStoredResult(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	a := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	b := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	assert.NoError(a.ProveFromRoot(expectedRoot))
	assert.NoError(b.ProveFromRoot(expectedRoot))
	assert.ThatNot(bytes.Equal(a.Bytes(), b.Bytes()))
	aSignature := try.To1(
		a.SignAcceptanceFor(alice, expectedRoot, expectedRoot),
	)
	bSignature := try.To1(b.SignAcceptanceFor(alice, expectedRoot, bobPublic))
	assert.NoError(a.VerifyAcceptance(aSignature))
	assert.NoError(b.VerifyAcceptance(bSignature))
	assert.ErrorIs(a.VerifyAcceptance(bSignature), intro.ErrBadAcceptance)

	for _, tc := range []struct {
		name       string
		selected   bool
		acceptance key.Signature
	}{
		{"empty acceptance", true, key.Signature{}},
		{"other proposal acceptance", true, bSignature},
		{"orphaned acceptance", false, aSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			p := newConsumerProvider(
				storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
			)
			defer clear(p.secret)
			try.To1(rand.Read(p.secret))
			path := filepath.Join(t.TempDir(), "vault.db")
			ctx := context.Background()
			db := try.To1(storage.OpenBolt(path))
			defer func() { try.Out(db.Close()).Logf() }()
			try.To(db.CreateVault(ctx, p.vault, p.id, p))
			vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
			defer func() { try.Out(vault.Close()).Logf() }()
			signer := &choiceSigningHandle{Handle: alice}

			// Authorized writes test application consistency, not a bypass
			// of storage authentication or rollback protection.
			try.To(vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)

				name := []byte("introduction-choice-demo")
				records := try.To1(tx.EnsureChild(name))
				if tc.selected {
					selectedKey := []byte("selected-proposal")
					try.To(records.Put(selectedKey, a.Bytes()))
				}
				try.To(records.Put([]byte("acceptance"), tc.acceptance))
				return nil
			}))
			beforeProposal, selected := try.To2(readSelectedProposal(vault))
			assert.Equal(selected, tc.selected)
			beforeSignature, found := try.To2(readStoredAcceptance(vault))
			assert.That(found) // Includes the present, empty acceptance.
			assert.That(bytes.Equal(beforeSignature, tc.acceptance))

			rejected, err := onboarding.SignAfterStoredChoice(
				vault, signer, expectedRoot, expectedRoot, a,
			)
			assert.ErrorIs(err, intro.ErrBadAcceptance)
			assert.SNil(rejected)
			assert.Equal(signer.signCalls, 0)
			proposal, selected := try.To2(readSelectedProposal(vault))
			assert.Equal(selected, tc.selected)
			assert.DeepEqual(proposal, beforeProposal)
			signature, found := try.To2(readStoredAcceptance(vault))
			assert.That(found)
			assert.DeepEqual(signature, beforeSignature)
			try.To(vault.Close())
			try.To(db.Close())
		})
	}
}

// Test observation of the private development layout, not an application API.
func readStoredAcceptance(vault *storage.Vault) (
	acceptance key.Signature, found bool, err error,
) {
	defer err2.Handle(&err, nil)

	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		name := []byte("introduction-choice-demo")
		if !try.To1(tx.HasChild(name)) {
			return nil
		}
		records := try.To1(tx.Child(name))
		acceptance, found = try.To2(records.Get([]byte("acceptance")))
		return nil
	}))
	return acceptance, found, nil
}
