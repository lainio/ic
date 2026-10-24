package nodevault

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
	bolt "go.etcd.io/bbolt"
)

// ExampleStore uses a real saved Alice, independent caller configuration and
// an independently supplied storage secret. Fixture provisioning is test-only.
func ExampleStore() {
	defer err2.Catch(err2.Stdout)

	dir := try.To1(os.MkdirTemp("", "nodevault-example-"))
	defer func() { try.Out(os.RemoveAll(dir)).Logf() }()
	f := try.To1(prepareFixture(dir))
	defer clear(f.secret)
	ctx := context.Background()
	store := try.To1(Create(ctx, f.state(), f.secret, f.binding))
	defer func() { try.Out(store.Close()).Logf() }()
	try.To1(onboarding.SignAfterStoredChoice(
		store.Vault(), f.alice, f.binding.Root, f.binding.Root, f.proposal,
	))
	try.To(store.Close())

	reopened := try.To1(Open(ctx, f.state(), f.secret, f.binding))
	defer func() { try.Out(reopened.Close()).Logf() }()
	saved, found := try.To2(onboarding.ReadStoredChoice(
		reopened.Vault(), f.binding.Root, f.binding.Child,
	))
	verifyErr := saved.Proposal.VerifyAcceptance(saved.Acceptance)
	try.To(verifyErr)
	try.To(reopened.Close())
	try.To(os.RemoveAll(dir))

	try.To1(fmt.Println("saved choice found after reopen:", found))
	try.To1(fmt.Println("saved acceptance verifies:", verifyErr == nil))
	// Output:
	// saved choice found after reopen: true
	// saved acceptance verifies: true
}

func TestStorePersistence(t *testing.T) {
	defer assert.PushTester(t)()

	dir := t.TempDir()
	root := try.To1(
		nodeidentity.Create(filepath.Join(dir, "root.json"), randomSecret()),
	)
	alicePath := filepath.Join(dir, "alice.json")
	unlock := randomSecret()
	defer clear(unlock)
	alice := try.To1(nodeidentity.Create(alicePath, unlock))
	binding := Binding{VaultID: storage.VaultID{1}, KeyID: storage.KeyID{7},
		Root: try.To1(
			root.CBORPublicKey(),
		), Child: try.To1(alice.CBORPublicKey())}
	proposal := intro.New(key.Info{Public: binding.Root}).Introduce(
		root, key.Info{Public: binding.Child},
	)
	secret := randomSecret()
	defer clear(secret)
	path := filepath.Join(dir, "state")
	store := try.To1(Create(t.Context(), path, secret, binding))
	defer func() { try.Out(store.Close()).Logf() }()
	signed := try.To1(onboarding.SignAfterStoredChoice(
		store.Vault(), alice, binding.Root, binding.Root, proposal,
	))
	try.To(store.Close())

	alice = try.To1(nodeidentity.Open(alicePath, unlock))
	assert.DeepEqual(try.To1(alice.CBORPublicKey()), []byte(binding.Child))
	reopened := try.To1(Open(t.Context(), path, secret, binding))
	defer func() { try.Out(reopened.Close()).Logf() }()
	saved, found := try.To2(onboarding.ReadStoredChoice(
		reopened.Vault(), binding.Root, binding.Child,
	))
	assert.That(found)
	assert.DeepEqual(saved.Proposal.Bytes(), proposal.Bytes())
	assert.DeepEqual(saved.Acceptance, signed)
	assert.NoError(saved.Proposal.VerifyAcceptance(saved.Acceptance))
	try.To(reopened.Close())
}

func randomSecret() []byte {
	secret := make([]byte, 32)
	try.To1(rand.Read(secret))
	return secret
}

type fixture struct {
	dir         string
	secret      []byte
	binding     Binding
	alice       key.Handle
	proposal    intro.Path
	different   intro.Path
	otherParent key.Public
}

func (f fixture) state() string { return filepath.Join(f.dir, "state") }

// All handles are prepared before subprocesses or worker goroutines start.
// Only Alice is needed later; each signer uses its own private wrapping key.
func prepareFixture(dir string) (f fixture, err error) {
	defer err2.Handle(&err)

	f.dir = dir
	f.secret = randomSecret()
	try.To(os.WriteFile(filepath.Join(dir, "storage-secret"), f.secret, 0600))
	unlock, rootUnlock, bobUnlock := randomSecret(), randomSecret(), randomSecret()
	defer clear(unlock)
	defer clear(rootUnlock)
	defer clear(bobUnlock)
	try.To(os.WriteFile(filepath.Join(dir, "unlock"), unlock, 0600))
	aliceDir := filepath.Join(dir, "alice")
	try.To(os.Mkdir(aliceDir, 0700))
	try.To1(
		nodeidentity.Create(filepath.Join(aliceDir, "identity.json"), unlock),
	)
	f.alice = try.To1(
		nodeidentity.OpenDirectory(aliceDir, filepath.Join(dir, "unlock")),
	)
	root := try.To1(
		nodeidentity.Create(filepath.Join(dir, "root.json"), rootUnlock),
	)
	bob := try.To1(
		nodeidentity.Create(filepath.Join(dir, "bob.json"), bobUnlock),
	)
	f.binding = Binding{VaultID: storage.VaultID{1}, KeyID: storage.KeyID{7},
		Root: try.To1(
			root.CBORPublicKey(),
		), Child: try.To1(f.alice.CBORPublicKey())}
	f.otherParent = try.To1(bob.CBORPublicKey())
	rootPath := intro.New(key.Info{Public: f.binding.Root})
	f.proposal = rootPath.Introduce(root, key.Info{Public: f.binding.Child})
	bobPath := rootPath.Introduce(root, key.Info{Public: f.otherParent})
	f.different = bobPath.Introduce(bob, key.Info{Public: f.binding.Child})
	return f, nil
}

type countingSigner struct {
	key.Handle
	calls int
	fail  error
}

func (s *countingSigner) Sign(data []byte) ([]byte, error) {
	s.calls++
	if s.fail != nil {
		return nil, s.fail
	}
	return s.Handle.Sign(data)
}

func TestPendingChoiceSurvives(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	defer clear(f.secret)
	s := try.To1(Create(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(s.Close()).Logf() }()
	cause := errors.New("signing unavailable")
	signer := &countingSigner{Handle: f.alice, fail: cause}
	signature, err := onboarding.SignAfterStoredChoice(
		s.Vault(), signer, f.binding.Root, f.binding.Root, f.proposal,
	)
	assert.ErrorIs(err, cause)
	assert.SNil(signature)
	assert.Equal(signer.calls, 1)
	try.To(s.Close())

	reopened := try.To1(Open(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(reopened.Close()).Logf() }()
	saved, found := try.To2(onboarding.ReadStoredChoice(
		reopened.Vault(), f.binding.Root, f.binding.Child,
	))
	assert.That(found)
	assert.DeepEqual(saved.Proposal.Bytes(), f.proposal.Bytes())
	assert.SNil(saved.Acceptance)
	signer = &countingSigner{Handle: f.alice}
	signature, err = onboarding.SignAfterStoredChoice(
		reopened.Vault(), signer, f.binding.Root, f.otherParent, f.different,
	)
	assert.ErrorIs(err, intro.ErrDifferentAcceptance)
	assert.SNil(signature)
	assert.Equal(signer.calls, 0)
	signature = try.To1(onboarding.SignAfterStoredChoice(
		reopened.Vault(), signer, f.binding.Root, f.binding.Root, f.proposal,
	))
	assert.NoError(f.proposal.VerifyAcceptance(signature))
	assert.Equal(signer.calls, 1)
	try.To(reopened.Close())
}

func TestReservationSurvivesRollbackAndClose(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	defer clear(f.secret)
	s := try.To1(Create(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(s.Close()).Logf() }()
	assert.Equal(try.To1(readUsage(s.usage, f.binding)), reservationSize)
	assert.Equal(s.provider.remaining, reservationSize-1) // Manifest seal.
	cause := errors.New("rollback after sealing")
	err := s.Vault().Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)

		try.To(tx.Put([]byte("rolled-back"), []byte("value")))
		return cause
	})
	assert.ErrorIs(err, cause)
	assert.Equal(s.provider.remaining, reservationSize-2)
	assert.Equal(try.To1(readUsage(s.usage, f.binding)), reservationSize)
	try.To(s.Vault().View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		_, found := try.To2(tx.Get([]byte("rolled-back")))
		assert.ThatNot(found)
		return nil
	}))
	ownedSecret := s.provider.secret
	vault := s.Vault()
	try.To(s.Close())
	try.To(s.Close())
	assert.DeepEqual(ownedSecret, make([]byte, 32))
	assert.Equal(s.provider.remaining, uint64(0))
	assert.ErrorIs(vault.View(func(storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		return nil
	}), storage.ErrClosed)

	reopened := try.To1(Open(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(reopened.Close()).Logf() }()
	assert.Equal(
		try.To1(readUsage(reopened.usage, f.binding)),
		2*reservationSize,
	)
	assert.Equal(reopened.provider.remaining, reservationSize)
	try.To(reopened.Close())
	assert.Equal(try.To1(diskCharge(f)), 2*reservationSize)
}

func TestLastReservationAndExhaustedRead(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	defer clear(f.secret)
	s := try.To1(Create(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(s.Close()).Logf() }()
	saved := try.To1(onboarding.SignAfterStoredChoice(
		s.Vault(), f.alice, f.binding.Root, f.binding.Root, f.proposal,
	))
	try.To(s.Close())
	// Private near-exhaustion fixture; no public quota or millions of seals.
	try.To(
		editUsage(
			f,
			"charged",
			binary.BigEndian.AppendUint64(nil, encryptionLimit-2),
		),
	)
	last := try.To1(Open(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(last.Close()).Logf() }()
	assert.Equal(last.provider.remaining, uint64(2))
	assert.Equal(try.To1(readUsage(last.usage, f.binding)), encryptionLimit)
	err := last.Vault().Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)

		for _, name := range []string{"first", "second", "denied"} {
			try.To(tx.Put([]byte(name), []byte("value")))
		}
		return nil
	})
	assert.ErrorIs(err, storage.ErrKeyUsageExhausted)
	assert.Equal(last.provider.remaining, uint64(0))
	assert.Equal(try.To1(readUsage(last.usage, f.binding)), encryptionLimit)
	try.To(last.Vault().View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		_, found := try.To2(tx.Get([]byte("first")))
		assert.ThatNot(found) // The failing seal rolled back earlier writes.
		return nil
	}))
	try.To(last.Close())

	readOnly := try.To1(Open(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(readOnly.Close()).Logf() }()
	assert.Equal(readOnly.provider.remaining, uint64(0))
	choice, found := try.To2(onboarding.ReadStoredChoice(
		readOnly.Vault(), f.binding.Root, f.binding.Child,
	))
	assert.That(found)
	assert.DeepEqual(choice.Acceptance, saved)
	signer := &countingSigner{
		Handle: f.alice,
		fail:   errors.New("must not sign"),
	}
	retry := try.To1(onboarding.SignAfterStoredChoice(
		readOnly.Vault(), signer, f.binding.Root, f.binding.Root, f.proposal,
	))
	assert.DeepEqual(retry, saved)
	assert.Equal(signer.calls, 0)
	assert.ErrorIs(
		readOnly.Vault().Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			return tx.Put([]byte("still denied"), nil)
		}),
		storage.ErrKeyUsageExhausted,
	)
	try.To(readOnly.Close())
	assert.Equal(try.To1(diskCharge(f)), encryptionLimit)
}

func TestReservationCommitFailureGrantsNothing(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	defer clear(f.secret)
	s := try.To1(Create(t.Context(), f.state(), f.secret, f.binding))
	try.To(s.Close())
	path := filepath.Join(f.state(), "usage.db")
	before := try.To1(os.ReadFile(path))
	// The real bbolt commit reaches WriteAt on a read-only descriptor. This
	// injects an OS commit error without any production fault-injection hook.
	db := try.To1(bolt.Open(path, 0600, &bolt.Options{
		Timeout: lockTimeout,
		OpenFile: func(name string, _ int, mode os.FileMode) (_ *os.File, err error) {
			defer err2.Handle(&err, nil)
			return os.OpenFile(name, os.O_RDONLY, mode)
		},
	}))
	defer func() { try.Out(db.Close()).Logf() }()
	p := try.To1(newProvider(f.secret, f.binding))
	defer clear(p.secret)
	err := p.reserve(t.Context(), db)
	assert.ErrorIs(err, syscall.EBADF)
	assert.Equal(p.remaining, uint64(0))
	l := try.To1(p.Acquire(t.Context(), f.binding.VaultID, f.binding.KeyID))
	assert.ErrorIs(l.ConsumeEncryption(), storage.ErrKeyUsageExhausted)
	try.To(l.Release())
	try.To(db.Close())
	assert.DeepEqual(try.To1(os.ReadFile(path)), before)
	assert.Equal(try.To1(diskCharge(f)), reservationSize)
	reopened := try.To1(Open(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(reopened.Close()).Logf() }()
	assert.Equal(
		try.To1(readUsage(reopened.usage, f.binding)),
		2*reservationSize,
	)
	try.To(reopened.Close())
}

func TestSharedLeases(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	defer clear(f.secret)
	s := try.To1(Create(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(s.Close()).Logf() }()
	type result struct {
		spent uint64
		err   error
	}
	results := make(chan result, 8)
	var workers sync.WaitGroup
	for range 8 {
		l := try.To1(
			s.provider.Acquire(t.Context(), f.binding.VaultID, f.binding.KeyID),
		)
		workers.Add(1)
		go func() {
			defer workers.Done()
			var spent uint64
			for {
				err := l.ConsumeEncryption()
				if err != nil {
					results <- result{spent, errors.Join(err, l.Release())}
					return
				}
				spent++
			}
		}()
	}
	workers.Wait()
	close(results)
	var spent uint64
	for result := range results {
		assert.ErrorIs(result.err, storage.ErrKeyUsageExhausted)
		spent += result.spent
	}
	assert.Equal(spent, reservationSize-1)
	assert.Equal(s.provider.remaining, uint64(0))
	assert.Equal(try.To1(readUsage(s.usage, f.binding)), reservationSize)
	try.To(s.Close())
}

func TestLockBoundAndOwnedInputs(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	defer clear(f.secret)
	secret := bytes.Clone(f.secret)
	defer clear(secret)
	binding := f.binding
	binding.Root, binding.Child = bytes.Clone(
		binding.Root,
	), bytes.Clone(
		binding.Child,
	)
	s := try.To1(Create(t.Context(), f.state(), secret, binding))
	defer func() { try.Out(s.Close()).Logf() }()
	clear(secret)
	clear(binding.Root)
	clear(binding.Child)
	assert.DeepEqual(s.provider.secret, f.secret)
	assert.DeepEqual(s.provider.binding, f.binding)
	assert.Equal(try.To1(readUsage(s.usage, f.binding)), reservationSize)
	try.To1(onboarding.SignAfterStoredChoice(
		s.Vault(), f.alice, f.binding.Root, f.binding.Root, f.proposal,
	))

	start := time.Now()
	second, err := Open(t.Context(), f.state(), f.secret, f.binding)
	assert.ErrorIs(err, bolt.ErrTimeout)
	assert.Nil(second)
	assert.That(time.Since(start) < lockTimeout+3*time.Second)
	assert.Equal(try.To1(readUsage(s.usage, f.binding)), reservationSize)
	try.To(s.Close())
	assert.Equal(try.To1(os.Stat(f.state())).Mode().Perm(), os.FileMode(0700))
	for _, name := range []string{"vault.db", "usage.db"} {
		info := try.To1(os.Stat(filepath.Join(f.state(), name)))
		assert.Equal(info.Mode().Perm(), os.FileMode(0600))
		assert.That(info.Size() > 0)
	}
	reopened := try.To1(Open(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(reopened.Close()).Logf() }()
	_, found := try.To2(
		onboarding.ReadStoredChoice(
			reopened.Vault(),
			f.binding.Root,
			f.binding.Child,
		),
	)
	assert.That(found)
	try.To(reopened.Close())
}

func TestRejectedInputsLeaveRecordsUnchanged(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	defer clear(f.secret)
	s := try.To1(Create(t.Context(), f.state(), f.secret, f.binding))
	try.To1(onboarding.SignAfterStoredChoice(
		s.Vault(), f.alice, f.binding.Root, f.binding.Root, f.proposal,
	))
	try.To(s.Close())
	identityPath := filepath.Join(f.dir, "alice", "identity.json")
	identity := try.To1(os.ReadFile(identityPath))
	usagePath := filepath.Join(f.state(), "usage.db")
	usage := try.To1(os.ReadFile(usagePath))
	vaultPath := filepath.Join(f.state(), "vault.db")
	records := try.To1(databaseRecords(vaultPath))

	for _, name := range []string{
		"wrong secret", "short secret", "long secret", "vault", "key",
		"root", "child", "empty root", "empty child", "canceled",
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()

			secret := bytes.Clone(f.secret)
			defer clear(secret)
			b := f.binding
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch name {
			case "wrong secret":
				secret[0] ^= 1
			case "short secret":
				secret = secret[:31]
			case "long secret":
				secret = append(secret, 0)
			case "vault":
				b.VaultID[0] ^= 1
			case "key":
				b.KeyID[0] ^= 1
			case "root":
				b.Root = f.otherParent
			case "child":
				b.Child = f.otherParent
			case "empty root":
				b.Root = nil
			case "empty child":
				b.Child = nil
			case "canceled":
				cancel()
			}
			rejected, err := Open(ctx, f.state(), secret, b)
			assert.Error(err)
			assert.Nil(rejected)
			assert.DeepEqual(try.To1(os.ReadFile(usagePath)), usage)
			// OpenBolt commits bookkeeping even when its bucket exists. Compare
			// actual record bytes, including encrypted manifest and choice.
			assert.DeepEqual(try.To1(databaseRecords(vaultPath)), records)
			assert.DeepEqual(try.To1(os.ReadFile(identityPath)), identity)
		})
	}
	assert.Equal(try.To1(diskCharge(f)), reservationSize)
	reopened := try.To1(Open(t.Context(), f.state(), f.secret, f.binding))
	try.To(reopened.Close()) // Failed opens released both handles and the lock.
}

func TestInvalidStateIsNeverRepaired(t *testing.T) {
	for _, name := range []string{
		"missing usage", "missing vault", "empty usage", "empty vault",
		"truncated usage", "truncated vault", "blank bolt vault",
		"empty engine", "missing metadata", "unknown version", "missing version",
		"missing root", "missing child", "short vault ID", "short key ID",
		"missing counter", "short counter", "zero counter", "over limit", "overflow",
	} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()

			f := try.To1(prepareFixture(t.TempDir()))
			defer clear(f.secret)
			s := try.To1(Create(t.Context(), f.state(), f.secret, f.binding))
			try.To(s.Close())
			try.To(damageState(f, name))
			before := try.To1(stateFiles(f))
			identityPath := filepath.Join(f.dir, "alice", "identity.json")
			identity := try.To1(os.ReadFile(identityPath))

			for range 2 {
				rejected, err := Open(
					t.Context(),
					f.state(),
					f.secret,
					f.binding,
				)
				assert.Error(err)
				assert.Nil(rejected)
				rejected, err = Create(
					t.Context(),
					f.state(),
					f.secret,
					f.binding,
				)
				assert.ErrorIs(err, os.ErrExist)
				assert.Nil(rejected)
				assert.DeepEqual(try.To1(stateFiles(f)), before)
				assert.DeepEqual(try.To1(os.ReadFile(identityPath)), identity)
			}
		})
	}
}

func TestPrivateFilesAndExclusiveCreation(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	defer clear(f.secret)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	rejected, err := Create(ctx, f.state(), f.secret, f.binding)
	assert.ErrorIs(err, context.Canceled)
	assert.Nil(rejected)
	rejected, err = Create(t.Context(), f.state(), f.secret[:31], f.binding)
	assert.Error(err)
	assert.Nil(rejected)
	rejected, err = Open(t.Context(), f.state(), f.secret, f.binding)
	assert.ErrorIs(err, os.ErrNotExist)
	assert.Nil(rejected)
	_, err = os.Lstat(f.state())
	assert.ErrorIs(err, os.ErrNotExist)
	s := try.To1(Create(t.Context(), f.state(), f.secret, f.binding))
	try.To(s.Close())
	before := try.To1(stateFiles(f))

	link := filepath.Join(f.dir, "state-link")
	try.To(os.Symlink(f.state(), link))
	rejected, err = Open(t.Context(), link, f.secret, f.binding)
	assert.Error(err)
	assert.Nil(rejected)
	for _, name := range []string{"vault.db", "usage.db"} {
		path := filepath.Join(f.state(), name)
		try.To(os.Chmod(path, 0640))
		rejected, err = Open(t.Context(), f.state(), f.secret, f.binding)
		assert.Error(err)
		assert.Nil(rejected)
		assert.Equal(try.To1(os.Stat(path)).Mode().Perm(), os.FileMode(0640))
		try.To(os.Chmod(path, 0600))
		moved := filepath.Join(f.dir, name)
		try.To(os.Rename(path, moved))
		try.To(os.Symlink(moved, path))
		rejected, err = Open(t.Context(), f.state(), f.secret, f.binding)
		assert.Error(err)
		assert.Nil(rejected)
		try.To(os.Remove(path))
		try.To(os.Rename(moved, path))
	}
	try.To(os.Chmod(f.state(), 0750))
	rejected, err = Open(t.Context(), f.state(), f.secret, f.binding)
	assert.Error(err)
	assert.Nil(rejected)
	try.To(os.Chmod(f.state(), 0700))
	rejected, err = Create(t.Context(), f.state(), f.secret, f.binding)
	assert.ErrorIs(err, os.ErrExist)
	assert.Nil(rejected)
	assert.DeepEqual(try.To1(stateFiles(f)), before)
}

// Damage only disposable test fixtures, never files owned by the caller.
func damageState(f fixture, name string) (err error) {
	defer err2.Handle(&err, nil)

	for _, file := range []string{"usage", "vault"} {
		path := filepath.Join(f.state(), file+".db")
		switch name {
		case "missing " + file:
			return os.Remove(path)
		case "empty " + file:
			return os.Truncate(path, 0)
		case "truncated " + file:
			return os.Truncate(path, 1)
		}
	}
	if name == "blank bolt vault" || name == "empty engine" {
		path := filepath.Join(f.state(), "vault.db")
		try.To(os.Remove(path))
		db := try.To1(
			bolt.Open(path, 0600, &bolt.Options{Timeout: lockTimeout}),
		)
		defer func() { err = errors.Join(err, db.Close()) }()
		if name == "empty engine" {
			return db.Update(func(tx *bolt.Tx) (err error) {
				defer err2.Handle(&err, nil)
				try.To1(tx.CreateBucket([]byte("engine")))
				return nil
			})
		}
		return nil
	}
	if name == "missing metadata" {
		db := try.To1(bolt.Open(filepath.Join(f.state(), "usage.db"), 0600,
			&bolt.Options{Timeout: lockTimeout}))
		defer func() { err = errors.Join(err, db.Close()) }()
		return db.Update(func(tx *bolt.Tx) (err error) {
			defer err2.Handle(&err, nil)
			return tx.DeleteBucket([]byte(usageBucket))
		})
	}
	changes := map[string]struct {
		field string
		value []byte
	}{
		"unknown version": {"version", []byte{2}},
		"missing version": {"version", nil},
		"missing root":    {"root", nil}, "missing child": {"child", nil},
		"short vault ID": {
			"vault",
			[]byte{1},
		}, "short key ID": {"key", []byte{7}},
		"missing counter": {
			"charged",
			nil,
		}, "short counter": {"charged", []byte{1}},
		"zero counter": {"charged", make([]byte, 8)},
		"over limit": {
			"charged",
			binary.BigEndian.AppendUint64(nil, encryptionLimit+1),
		},
		"overflow": {"charged", bytes.Repeat([]byte{255}, 8)},
	}
	change := changes[name]
	return editUsage(f, change.field, change.value)
}

func stateFiles(f fixture) (files map[string][]byte, err error) {
	defer err2.Handle(&err, nil)

	files = make(map[string][]byte)
	for _, name := range []string{"vault.db", "usage.db"} {
		data, readErr := os.ReadFile(filepath.Join(f.state(), name))
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		try.To(readErr)
		files[name] = data
	}
	return files, nil
}

// Observe logical bytes without duplicating the encrypted storage codec.
func databaseRecords(path string) (records map[string][]byte, err error) {
	defer err2.Handle(&err, nil)

	db := try.To1(bolt.Open(path, 0600,
		&bolt.Options{Timeout: lockTimeout, ReadOnly: true}))
	defer func() { err = errors.Join(err, db.Close()) }()
	records = make(map[string][]byte)
	try.To(db.View(func(tx *bolt.Tx) (err error) {
		defer err2.Handle(&err, nil)
		return tx.ForEach(func(name []byte, b *bolt.Bucket) (err error) {
			defer err2.Handle(&err, nil)
			return collectRecords(b, fmt.Sprintf("%x", name), records)
		})
	}))
	return records, nil
}

func collectRecords(
	b *bolt.Bucket,
	prefix string,
	records map[string][]byte,
) (err error) {
	defer err2.Handle(&err, nil)

	return b.ForEach(func(name, value []byte) (err error) {
		defer err2.Handle(&err, nil)

		path := fmt.Sprintf("%s/%x", prefix, name)
		if child := b.Bucket(name); child != nil {
			records[path] = nil
			return collectRecords(child, path, records)
		}
		records[path] = bytes.Clone(value)
		return nil
	})
}

func diskCharge(f fixture) (charged uint64, err error) {
	defer err2.Handle(&err, nil)

	db := try.To1(bolt.Open(filepath.Join(f.state(), "usage.db"), 0600,
		&bolt.Options{Timeout: lockTimeout, ReadOnly: true}))
	defer func() { err = errors.Join(err, db.Close()) }()
	return readUsage(db, f.binding)
}

func editUsage(f fixture, name string, value []byte) (err error) {
	defer err2.Handle(&err, nil)

	db := try.To1(bolt.Open(filepath.Join(f.state(), "usage.db"), 0600,
		&bolt.Options{Timeout: lockTimeout}))
	defer func() { err = errors.Join(err, db.Close()) }()
	return db.Update(func(tx *bolt.Tx) (err error) {
		defer err2.Handle(&err, nil)

		b := tx.Bucket([]byte(usageBucket))
		if value == nil {
			return b.Delete([]byte(name))
		}
		return b.Put([]byte(name), value)
	})
}
