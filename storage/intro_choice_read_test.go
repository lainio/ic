package storage_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestReadStoredChoiceAbsent(t *testing.T) {
	defer assert.PushTester(t)()

	expectedRoot := key.Public(try.To1(key.New().CBORPublicKey()))
	expectedChild := key.Public(try.To1(key.New().CBORPublicKey()))
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

	for _, namespaceExists := range []bool{false, true} {
		if namespaceExists {
			try.To(vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)

				try.To1(tx.EnsureChild([]byte("introduction-choice-demo")))
				return nil
			}))
		}
		before := try.To1(os.ReadFile(path))
		p.mu.Lock()
		remaining := p.remainingEncryptions
		p.mu.Unlock()

		choice, found := try.To2(onboarding.ReadStoredChoice(
			vault, expectedRoot, expectedChild,
		))
		assert.ThatNot(found)
		assert.SNil(choice.Proposal)
		assert.SNil(choice.Acceptance)
		assert.DeepEqual(try.To1(os.ReadFile(path)), before)
		p.mu.Lock()
		after := p.remainingEncryptions
		p.mu.Unlock()
		assert.Equal(after, remaining)
	}
	try.To(vault.Close())

	choice, found, err := onboarding.ReadStoredChoice(
		vault, expectedRoot, expectedChild,
	)
	assert.ErrorIs(err, storage.ErrVaultClosed)
	assert.ThatNot(found)
	assert.SNil(choice.Proposal)
	assert.SNil(choice.Acceptance)
	try.To(db.Close())
}

func TestReadStoredChoicePendingCompleted(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice := key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	alicePublic := key.Public(try.To1(alice.CBORPublicKey()))
	offered := intro.New(key.InfoFromHandle(root)).Introduce(
		root, key.InfoFromHandle(alice),
	)
	proposalBytes := offered.Bytes()
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

	cause := errors.New("injected signing error leaves pending choice")
	signer := &choiceSigningHandle{Handle: alice, signErr: cause}
	failed, err := onboarding.SignAfterStoredChoice(
		vault, signer, expectedRoot, expectedRoot, offered,
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
	beforePending := try.To1(os.ReadFile(path))
	p.mu.Lock()
	remaining := p.remainingEncryptions
	p.mu.Unlock()

	pending, found := try.To2(onboarding.ReadStoredChoice(
		reopenedVault, expectedRoot, alicePublic,
	))
	assert.That(found)
	assert.DeepEqual(pending.Proposal.Bytes(), proposalBytes)
	assert.NoError(pending.Proposal.ProveFromRoot(expectedRoot))
	assert.SNil(pending.Acceptance)
	assert.Equal(signer.signCalls, 1)
	assert.DeepEqual(try.To1(os.ReadFile(path)), beforePending)
	p.mu.Lock()
	afterPending := p.remainingEncryptions
	p.mu.Unlock()
	assert.Equal(afterPending, remaining)

	// Only an explicit successful retry completes the saved choice.
	signer.signErr = nil
	observed := try.To1(onboarding.SignAfterStoredChoice(
		reopenedVault, signer, expectedRoot, expectedRoot, offered,
	))
	assert.NoError(offered.VerifyAcceptance(observed))
	assert.Equal(signer.signCalls, 2)
	try.To(reopenedVault.Close())
	try.To(reopened.Close())

	completedDB := try.To1(storage.OpenBolt(path))
	defer func() { try.Out(completedDB.Close()).Logf() }()
	completedVault := try.To1(completedDB.OpenVault(ctx, p.vault, p.id, p))
	defer func() { try.Out(completedVault.Close()).Logf() }()
	// Fixture fault injection after setup: reading must need no encryptions.
	p.mu.Lock()
	p.remainingEncryptions = 0
	p.mu.Unlock()
	signer.signErr = errors.New("inspection must not sign")
	beforeCompleted := try.To1(os.ReadFile(path))

	saved, found := try.To2(onboarding.ReadStoredChoice(
		completedVault, expectedRoot, alicePublic,
	))
	assert.That(found)
	assert.DeepEqual(saved.Proposal.Bytes(), proposalBytes)
	assert.DeepEqual(saved.Acceptance, observed)
	assert.NoError(saved.Proposal.VerifyAcceptance(saved.Acceptance))
	assert.Equal(signer.signCalls, 2)

	// Mutate nested proposal bytes and the signature owned by this caller.
	saved.Proposal.LastEdge().Public()[0] ^= 1
	saved.Proposal.LastEdge().ParentSig[0] ^= 1
	saved.Acceptance[0] ^= 1
	again, found := try.To2(onboarding.ReadStoredChoice(
		completedVault, expectedRoot, alicePublic,
	))
	assert.That(found)
	assert.DeepEqual(again.Proposal.Bytes(), proposalBytes)
	assert.DeepEqual(again.Acceptance, observed)
	assert.NoError(again.Proposal.ProveFromRoot(expectedRoot))
	assert.NoError(again.Proposal.VerifyAcceptance(again.Acceptance))

	for _, tc := range []struct {
		name        string
		root, child key.Public
		want        error
	}{
		{"wrong root", alicePublic, alicePublic, intro.ErrWrongRoot},
		{"wrong child", expectedRoot, expectedRoot, intro.ErrBadAcceptance},
		{"empty root", nil, alicePublic, intro.ErrWrongRoot},
		{"empty child", expectedRoot, nil, intro.ErrBadAcceptance},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			rejected, found, err := onboarding.ReadStoredChoice(
				completedVault, tc.root, tc.child,
			)
			assert.ErrorIs(err, tc.want)
			assert.ThatNot(found)
			assert.SNil(rejected.Proposal)
			assert.SNil(rejected.Acceptance)
		})
	}
	assert.Equal(signer.signCalls, 2)
	assert.DeepEqual(try.To1(os.ReadFile(path)), beforeCompleted)
	p.mu.Lock()
	afterCompleted := p.remainingEncryptions
	p.mu.Unlock()
	assert.Equal(afterCompleted, uint32(0))
	try.To(completedVault.Close())
	try.To(completedDB.Close())
}

func TestReadStoredChoiceInvalidRecords(t *testing.T) {
	defer assert.PushTester(t)()

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.To1(root.CBORPublicKey()))
	alicePublic := key.Public(try.To1(alice.CBORPublicKey()))
	bobPublic := key.Public(try.To1(bob.CBORPublicKey()))
	rootPath := intro.New(key.InfoFromHandle(root))
	offered := rootPath.Introduce(root, key.InfoFromHandle(alice))
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	other := bobPath.Introduce(bob, key.InfoFromHandle(alice))
	acceptance := try.To1(
		offered.SignAcceptanceFor(alice, expectedRoot, expectedRoot),
	)
	transferred := try.To1(
		other.SignAcceptanceFor(alice, expectedRoot, bobPublic),
	)
	assert.NoError(offered.VerifyAcceptance(acceptance))
	assert.NoError(other.VerifyAcceptance(transferred))
	assert.ErrorIs(
		offered.VerifyAcceptance(transferred),
		intro.ErrBadAcceptance,
	)

	encoded := offered.Bytes()
	assert.Equal(encoded[0], byte(0x82))
	noncanonical := append([]byte{0x98, 0x02}, encoded[1:]...)
	badProof := offered.Clone()
	badProof[1].Body.Options.Position++
	assert.ErrorIs(badProof.ProveFromRoot(expectedRoot), intro.ErrBadSignature)

	for _, tc := range []struct {
		name       string
		proposal   []byte
		acceptance key.Signature
		want       error
	}{
		{"orphaned acceptance", nil, acceptance, intro.ErrBadAcceptance},
		{"empty acceptance", encoded, key.Signature{}, intro.ErrBadAcceptance},
		{"transferred acceptance", encoded, transferred, intro.ErrBadAcceptance},
		{"malformed proposal", noncanonical, nil, wire.ErrNonCanonicalCBOR},
		{"empty proposal", []byte{}, nil, nil},
		{"no introduction", rootPath.Bytes(), nil, intro.ErrBadAcceptance},
		{"bad proof", badProof.Bytes(), nil, intro.ErrBadSignature},
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

			// Authorized writes create inconsistent application records;
			// storage authentication is not bypassed or attacked here.
			try.To(vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)

				name := []byte("introduction-choice-demo")
				records := try.To1(tx.EnsureChild(name))
				if tc.proposal != nil {
					try.To(
						records.Put(
							[]byte("selected-proposal"),
							tc.proposal,
						),
					)
				}
				if tc.acceptance != nil {
					try.To(
						records.Put([]byte("acceptance"), tc.acceptance),
					)
				}
				return nil
			}))
			_, selected := try.To2(readSelectedProposal(vault))
			assert.Equal(selected, tc.proposal != nil)
			_, accepted := try.To2(readStoredAcceptance(vault))
			assert.Equal(accepted, tc.acceptance != nil)
			before := try.To1(os.ReadFile(path))
			p.mu.Lock()
			remaining := p.remainingEncryptions
			p.mu.Unlock()

			rejected, found, err := onboarding.ReadStoredChoice(
				vault, expectedRoot, alicePublic,
			)
			assert.Error(err)
			if tc.want != nil {
				assert.ErrorIs(err, tc.want)
			} else {
				assert.ErrorIsNot(err, intro.ErrBadAcceptance)
			}
			assert.ThatNot(found)
			assert.SNil(rejected.Proposal)
			assert.SNil(rejected.Acceptance)
			assert.DeepEqual(try.To1(os.ReadFile(path)), before)
			p.mu.Lock()
			after := p.remainingEncryptions
			p.mu.Unlock()
			assert.Equal(after, remaining)
			try.To(vault.Close())
			try.To(db.Close())
		})
	}
}
