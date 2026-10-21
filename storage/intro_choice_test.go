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

// ExampleVault_choiceBeforeSigning uses onboarding.SignAfterStoredChoice with
// one dedicated Vault for Alice and R.
// The owner selects an offer; receiving a claim never enrolls it automatically.
// The helper persists auxiliary local signing choice in a private development
// layout, not a public wallet schema. It changes no Edges, Received, Known,
// trust, PW, device, or recovery state and supplies no GlobalHasParent predicate
// or uniqueness proof for another participant.
//
// Assume one cooperating caller and an intact, non-rolled-back Vault. Reopening
// here keeps the same process, keys, and provider alive; it tests no process
// restart, signer/key recovery, crash durability, or cross-device exclusion.
// Deleting, copying, or rolling back the file, using another Vault, or signing
// directly can bypass this guard.
func ExampleVault_choiceBeforeSigning() {
	defer err2.Catch(err2.Stdout)

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	a := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	b := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	aBytes := a.Bytes()

	dir := try.To1(os.MkdirTemp("", "intro-choice-example-"))
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "vault.db")
	p := newConsumerProvider(
		storage.VaultID{1}, storage.KeyID{7}, make([]byte, 32),
	)
	defer clear(p.secret) // After handle cleanup, including on failure.
	try.To1(rand.Read(p.secret))

	ctx := context.Background()
	db := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(db.Close()).Logf() }()
	try.To(db.CreateVault(ctx, p.vault, p.id, p))
	vault := try.To1(db.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(vault.Close()).Logf() }()

	// Alice explicitly chooses A with R as her immediate parent.
	acceptance := try.To1(onboarding.SignAfterStoredChoice(
		vault, alice, expectedRoot, expectedRoot, a,
	))
	try.To(a.VerifyAcceptance(acceptance))
	try.To(vault.Close())
	try.To(db.Close())

	reopened := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(reopened.Close()).Logf() }()
	reopenedVault := try.To1(reopened.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(reopenedVault.Close()).Logf() }()
	stored, found := try.To2(readSelectedProposal(reopenedVault))
	assert.That(found, "selected proposal missing after reopen")
	preserved := bytes.Equal(stored, aBytes)
	assert.That(preserved)

	rejected, err := onboarding.SignAfterStoredChoice(
		reopenedVault, alice, expectedRoot, bobPublic, b,
	)
	assert.ErrorIs(err, intro.ErrDifferentAcceptance)
	assert.ErrorIsNot(err, intro.ErrWrongParent)
	assert.SNil(rejected)
	refused := errors.Is(err, intro.ErrDifferentAcceptance) && rejected == nil

	// Retry the original proposal without rebuilding its signed parent edge.
	retry := try.To1(onboarding.SignAfterStoredChoice(
		reopenedVault, alice, expectedRoot, expectedRoot, a,
	))
	verifyErr := a.VerifyAcceptance(retry)
	try.To(verifyErr)
	try.To(reopenedVault.Close())
	try.To(reopened.Close())
	clear(p.secret)
	try.To(os.RemoveAll(dir))

	try.To1(fmt.Println("selected proposal survives reopen:", preserved))
	try.To1(fmt.Println("different proposal refused after reopen:", refused))
	try.To1(fmt.Println(
		"selected proposal signs after reopen:", verifyErr == nil,
	))
	// Output:
	// selected proposal survives reopen: true
	// different proposal refused after reopen: true
	// selected proposal signs after reopen: true
}

func TestVaultChoiceBeforeSigningFailure(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	a := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	b := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	aBytes := a.Bytes()
	assert.NoError(b.ProveFromRoot(expectedRoot))
	assert.ThatNot(bytes.Equal(aBytes, b.Bytes()))

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

	cause := errors.New("injected error after signing")
	signer := &choiceSigningHandle{
		Handle: alice, signErr: cause,
		beforeSign: func() (err error) {
			defer err2.Handle(&err, nil)

			// A separate View inside Sign observes committed A, not pending
			// callback state. This is an ordering test, not a callback API.
			stored, found := try.To2(readSelectedProposal(vault))
			assert.That(found)
			assert.DeepEqual(stored, aBytes)
			return nil
		},
	}
	failed, err := onboarding.SignAfterStoredChoice(
		vault, signer, expectedRoot, expectedRoot, a,
	)
	assert.ErrorIs(err, cause)
	assert.SNil(failed)
	assert.Equal(signer.signCalls, 1)
	try.To(vault.Close())
	try.To(db.Close())

	reopened := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(reopened.Close()).Logf() }()
	reopenedVault := try.To1(reopened.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(reopenedVault.Close()).Logf() }()
	fresh := &choiceSigningHandle{Handle: alice}
	rejected, err := onboarding.SignAfterStoredChoice(
		reopenedVault, fresh, expectedRoot, bobPublic, b,
	)
	assert.ErrorIs(err, intro.ErrDifferentAcceptance)
	assert.ErrorIsNot(err, intro.ErrWrongParent)
	assert.SNil(rejected)
	assert.Equal(fresh.signCalls, 0)

	acceptance := try.To1(onboarding.SignAfterStoredChoice(
		reopenedVault, fresh, expectedRoot, expectedRoot, a,
	))
	assert.Equal(fresh.signCalls, 1)
	assert.NoError(a.VerifyAcceptance(acceptance))
	stored, found := try.To2(readSelectedProposal(reopenedVault))
	assert.That(found)
	assert.DeepEqual(stored, aBytes)
	try.To(reopenedVault.Close())
	try.To(reopened.Close())
}

func TestVaultChoiceBeforeSigningRejectedSelection(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	a := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	b := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	assert.ThatNot(bytes.Equal(a.Bytes(), b.Bytes()))

	for _, tc := range []struct {
		name    string
		parent  key.Public
		exhaust bool
		want    error
	}{
		{"wrong expected parent", bobPublic, false, intro.ErrWrongParent},
		{"proposal write fails", expectedRoot, true, storage.ErrKeyUsageExhausted},
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

			// Exhaust only this fixture after creating/opening its Vault.
			// This tests operation-error rollback, not physical power loss.
			var remaining uint32
			if tc.exhaust {
				p.mu.Lock()
				remaining = p.remainingEncryptions
				p.remainingEncryptions = 0
				p.mu.Unlock()
			}
			failed, err := onboarding.SignAfterStoredChoice(
				vault, signer, expectedRoot, tc.parent, a,
			)
			if tc.exhaust {
				p.mu.Lock()
				p.remainingEncryptions = remaining
				p.mu.Unlock()
			}
			assert.ErrorIs(err, tc.want)
			assert.SNil(failed)
			assert.Equal(signer.signCalls, 0)
			stored, found := try.To2(readSelectedProposal(vault))
			assert.ThatNot(found)
			assert.SNil(stored)

			acceptance := try.To1(onboarding.SignAfterStoredChoice(
				vault, signer, expectedRoot, bobPublic, b,
			))
			assert.Equal(signer.signCalls, 1)
			assert.NoError(b.VerifyAcceptance(acceptance))
			stored, found = try.To2(readSelectedProposal(vault))
			assert.That(found)
			assert.DeepEqual(stored, b.Bytes())
			try.To(vault.Close())
			try.To(db.Close())
		})
	}
}

type choiceSigningHandle struct {
	key.Handle
	beforeSign func() (err error)
	signErr    error
	signCalls  int
}

func (h *choiceSigningHandle) Sign(data []byte) (signature []byte, err error) {
	defer err2.Handle(&err, nil)

	h.signCalls++
	if h.beforeSign != nil {
		try.To(h.beforeSign())
	}
	signed := try.To1(h.Handle.Sign(data))
	// Deliberately return real work with an error to model ambiguous failure;
	// this fault injection is not evidence of a real signer defect.
	return signed, h.signErr
}

func readSelectedProposal(vault *storage.Vault) (
	proposal []byte, found bool, err error,
) {
	defer err2.Handle(&err, nil)

	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		name := []byte("introduction-choice-demo")
		if !try.To1(tx.HasChild(name)) {
			return nil
		}
		records := try.To1(tx.Child(name))
		proposal, found = try.To2(records.Get([]byte("selected-proposal")))
		return nil
	}))
	return proposal, found, nil
}
