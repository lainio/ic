package storage

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/engine"
	"github.com/lainio/ic/storage/internal/record"
)

// This finite provider exists only in tests; it supplies no durable accounting.
// It conservatively counts several bindings against one test pool. Shared-key
// tests retain the same provider, secret, VaultID and KeyID for every handle.
type lifecycleProvider struct {
	mu     sync.Mutex
	secret []byte
	// Permitted encryptions left in the pool shared by every lease from this
	// provider. New handles and file reopening never reset it.
	remainingEncryptions uint32
	spent                uint32 // Successful debits, including discarded seals.
	consumeCalls         int    // Attempts, including injected/exhausted failures.
	calls                []struct {
		vault VaultID
		id    KeyID
	}
	leases                                       []*lifecycleLease
	acquireErr, checkErr, consumeErr, releaseErr error
	failCheckAt                                  int
	nilLease                                     bool
	acquireEntered, acquireWait                  chan struct{}
}

type lifecycleLease struct {
	p                    *lifecycleProvider
	checks               int
	releases             int
	checkErr, releaseErr error
	failCheckAt          int
}

func newLifecycleProvider(t *testing.T, budget uint32) *lifecycleProvider {
	t.Helper()
	return &lifecycleProvider{secret: manifestSecret(t), remainingEncryptions: budget}
}

func (p *lifecycleProvider) Acquire(ctx context.Context, vault VaultID, id KeyID) (Lease, error) {
	p.mu.Lock()
	p.calls = append(p.calls, struct {
		vault VaultID
		id    KeyID
	}{vault, id})
	entered, wait := p.acquireEntered, p.acquireWait
	p.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
		<-wait
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.acquireErr != nil {
		return nil, p.acquireErr
	}
	if p.nilLease {
		return nil, nil
	}
	l := &lifecycleLease{p: p, checkErr: p.checkErr, releaseErr: p.releaseErr, failCheckAt: p.failCheckAt}
	p.leases = append(p.leases, l)
	return l, nil
}

func (l *lifecycleLease) Secret() []byte { return l.p.secret }

func (l *lifecycleLease) Check() error {
	l.p.mu.Lock()
	defer l.p.mu.Unlock()
	l.checks++
	if l.releases != 0 {
		return errors.New("test: check after release")
	}
	if l.failCheckAt == 0 || l.checks >= l.failCheckAt {
		return l.checkErr
	}
	return nil
}

func (l *lifecycleLease) ConsumeEncryption() error {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consumeCalls++
	if p.consumeErr != nil {
		return p.consumeErr
	}
	if p.remainingEncryptions == 0 {
		return ErrKeyUsageExhausted
	}
	p.remainingEncryptions--
	p.spent++
	return nil
}

func (l *lifecycleLease) Release() error {
	l.p.mu.Lock()
	defer l.p.mu.Unlock()
	l.releases++
	return l.releaseErr
}

func TestVaultLifecycle(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) *Database
	}{
		{"memory", func(_ *testing.T) *Database { return NewMemory() }},
		{"bbolt", func(t *testing.T) *Database {
			return try.To1(OpenBolt(filepath.Join(t.TempDir(), "lifecycle.db")))
		}},
	} {
		t.Run(backend.name, func(t *testing.T) {
			t.Run("flow", func(t *testing.T) { lifecycleFlow(t, backend.open) })
			t.Run("failures", func(t *testing.T) { lifecycleFailures(t, backend.open) })
			t.Run("drain", func(t *testing.T) { lifecycleDrain(t, backend.open) })
			t.Run("callback_unwinding", func(t *testing.T) { lifecycleUnwinding(t, backend.open) })
			t.Run("pending", func(t *testing.T) { lifecyclePending(t, backend.open) })
			t.Run("publication", func(t *testing.T) { lifecyclePublication(t, backend.open) })
		})
	}
}

func lifecycleFlow(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	db := open(t)
	t.Cleanup(func() { _ = db.Close() }) // Fallback if an assertion aborts; checked below.
	ctx := context.Background()
	vault, id := VaultID{1, 7}, KeyID{2, 9}
	p := newLifecycleProvider(t, 2)
	borrowed := bytes.Clone(p.secret)
	t.Cleanup(func() { clear(borrowed) })
	assert.Equal(ErrVaultExists, errVaultExists)
	assert.Equal(ErrVaultNotFound, errVaultNotFound)
	assert.Equal(ErrVaultManifest, errVaultManifest)
	try.To(db.CreateVault(ctx, vault, id, p))
	assert.Equal(p.spent, uint32(1))
	assert.Equal(p.consumeCalls, 1)
	assert.Equal(p.leases[0].releases, 1)
	assert.ErrorIs(db.CreateVault(ctx, vault, id, p), ErrVaultExists)
	assert.Equal(p.spent, uint32(1), "duplicate does not consume")
	assert.Equal(p.consumeCalls, 1)
	assert.Equal(p.leases[1].releases, 1)

	v := try.To1(db.OpenVault(ctx, vault, id, p))
	assert.Equal(p.spent, uint32(1), "open/verification do not spend")
	var token [32]byte
	var envelope, owned []byte
	try.To(v.withScope(func(s *record.Scope) (err error) {
		defer err2.Handle(&err, nil)
		token = try.To1(s.Token(nil, []byte("key")))
		envelope = try.To1(s.Seal(nil, []byte("key"), []byte("value")))
		_, owned = try.To2(s.Open(nil, token, []byte("key"), envelope))
		return nil
	}))
	try.To(v.Close()) // Closing consumes nothing.
	try.To(v.Close())
	assert.Equal(p.leases[2].releases, 1)
	assert.ErrorIs(v.withScope(func(*record.Scope) error {
		t.Fatal("closed handle callback ran")
		return nil
	}), ErrVaultClosed)
	assert.Equal(string(owned), "value")

	ro := try.To1(db.OpenVault(ctx, vault, id, p))
	assert.NotEqual(ro, v)
	try.To(ro.withScope(func(s *record.Scope) (err error) {
		defer err2.Handle(&err, nil)
		assert.Equal(try.To1(s.Token(nil, []byte("key"))), token)
		_, value := try.To2(s.Open(nil, token, []byte("key"), envelope))
		assert.Equal(string(value), "value")
		sealed, err := s.Seal(nil, []byte("key"), nil)
		assert.SNil(sealed)
		assert.ErrorIs(err, ErrKeyUsageExhausted)
		return nil
	}))
	assert.Equal(p.spent, uint32(2))
	assert.Equal(p.remainingEncryptions, uint32(0))
	try.To(ro.Close())
	for _, call := range p.calls {
		assert.Equal(call.vault, vault)
		assert.Equal(call.id, id)
	}
	assert.Equal(bytes.Equal(p.secret, borrowed), true, "storage never clears borrowed bytes")

	wrong := newLifecycleProvider(t, 1)
	missing, err := db.OpenVault(ctx, VaultID{99}, id, wrong)
	assert.Nil(missing)
	assert.ErrorIs(err, ErrVaultNotFound)
	bad, err := db.OpenVault(ctx, vault, id, wrong)
	assert.Nil(bad)
	assert.ErrorIs(err, ErrVaultManifest)
	for _, lease := range wrong.leases {
		assert.Equal(lease.releases, 1)
	}
	try.To(db.Close())
	try.To(db.Close())
}

func TestVaultLifecycleReopen(t *testing.T) {
	defer assert.PushTester(t)()
	path := filepath.Join(t.TempDir(), "reopen.db")
	db := try.To1(OpenBolt(path))
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	vault, id := VaultID{4}, KeyID{5}
	p := newLifecycleProvider(t, 2)
	releaseErr := errors.New("post-commit release failure")
	p.releaseErr = releaseErr
	assert.ErrorIs(db.CreateVault(ctx, vault, id, p), releaseErr)
	p.releaseErr = nil
	// Creation committed despite its cleanup error, and remains after reopen.
	v := try.To1(db.OpenVault(ctx, vault, id, p))
	try.To(v.Close()) // Keep the unused shared encryption.
	try.To(db.Close())

	reopened := try.To1(OpenBolt(path))
	t.Cleanup(func() { _ = reopened.Close() })
	noKey, err := reopened.OpenVault(ctx, vault, id, nil)
	assert.Nil(noKey)
	assert.ErrorIs(err, ErrProvider)
	ro := try.To1(reopened.OpenVault(ctx, vault, id, p))
	try.To(ro.withScope(func(s *record.Scope) error {
		_, err := s.Token(nil, []byte("read"))
		return err
	}))
	assert.Equal(p.remainingEncryptions, uint32(1))
	assert.Equal(p.consumeCalls, 1, "open/close and reopen never consume")
	try.To(ro.Update(func(tx WriteTx) error {
		return tx.Put([]byte("last"), []byte("value"))
	}))
	assert.ErrorIs(ro.Update(func(tx WriteTx) error {
		return tx.Put([]byte("denied"), nil)
	}), ErrKeyUsageExhausted)
	assert.Equal(p.remainingEncryptions, uint32(0))
	assert.Equal(p.spent, uint32(2))
	assert.Equal(p.consumeCalls, 3)
	try.To(reopened.Close())
	for _, l := range p.leases {
		assert.Equal(l.releases, 1)
	}
	for _, call := range p.calls {
		assert.Equal(call.vault, vault)
		assert.Equal(call.id, id)
	}
}

func lifecycleFailures(t *testing.T, open func(*testing.T) *Database) {
	for _, operation := range []string{"create", "open"} {
		t.Run(operation, func(t *testing.T) {
			for _, name := range []string{"acquire", "nil_lease", "check", "consume", "secret", "admission", "engine", "publication"} {
				if operation == "create" && name == "publication" ||
					operation == "open" && name == "consume" {
					continue
				}
				t.Run(name, func(t *testing.T) {
					defer assert.PushTester(t)()
					db := open(t)
					t.Cleanup(func() { _ = db.Close() })
					ctx := context.Background()
					vault, id := VaultID{1}, KeyID{2}
					p := newLifecycleProvider(t, 3)
					if operation == "open" && name != "engine" {
						try.To(db.CreateVault(ctx, vault, id, p))
					}
					beforeLeases, beforeCalls := len(p.leases), p.consumeCalls
					beforeSpent, beforeRemaining := p.spent, p.remainingEncryptions
					cause := errors.New("injected provider failure")
					releaseErr := errors.New("injected release failure")
					p.releaseErr = releaseErr
					want := cause
					wantLease := true
					switch name {
					case "acquire":
						p.acquireErr = cause
						wantLease = false
					case "nil_lease":
						p.nilLease, want = true, ErrProvider
						wantLease = false
					case "check":
						p.checkErr = cause
					case "consume":
						p.consumeErr = cause
					case "secret":
						p.secret = p.secret[:31]
						_, want = record.Derive(p.secret, vault, id, func() error { return ErrKeyUsageExhausted })
						assert.Error(want)
					case "admission":
						p.checkErr, p.failCheckAt = cause, 2
					case "publication":
						p.checkErr, p.failCheckAt = cause, 3
					case "engine":
						try.To(db.engine.Update(func(root engine.WriteTx) error {
							return root.Put([]byte(vaultCollection), []byte("conflict"))
						}))
						want = engine.ErrConflict
					}
					borrowed := bytes.Clone(p.secret)
					t.Cleanup(func() { clear(borrowed) })
					var err error
					if operation == "create" {
						err = db.CreateVault(ctx, vault, id, p)
					} else {
						var v *Vault
						v, err = db.OpenVault(ctx, vault, id, p)
						assert.Nil(v, "no handle may escape a failed open")
					}
					assert.ErrorIs(err, want)
					if wantLease {
						assert.Equal(len(p.leases), beforeLeases+1)
						assert.Equal(p.leases[beforeLeases].releases, 1)
						assert.ErrorIs(err, releaseErr)
					} else {
						assert.Equal(len(p.leases), beforeLeases)
						assert.ThatNot(errors.Is(err, releaseErr))
					}
					wantCalls := beforeCalls
					if name == "consume" {
						wantCalls++
						assert.ThatNot(errors.Is(err, ErrKeyUsageExhausted))
					}
					assert.Equal(p.consumeCalls, wantCalls)
					assert.Equal(p.remainingEncryptions, beforeRemaining)
					assert.Equal(p.spent, beforeSpent)
					assert.Equal(bytes.Equal(p.secret, borrowed), true)
					assert.Equal(len(db.vaults), 0)
					if operation == "create" && name != "engine" {
						p.acquireErr, p.checkErr, p.consumeErr, p.releaseErr = nil, nil, nil, nil
						p.nilLease = false
						p.secret = p.secret[:32]
						v, err := db.OpenVault(ctx, vault, id, p)
						assert.Nil(v)
						assert.ErrorIs(err, ErrVaultNotFound, "failed creation did not leave state")
					}
					try.To(db.Close())
				})
			}
		})
	}
	t.Run("canceled_context_and_nil_provider", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		t.Cleanup(func() { _ = db.Close() })
		p := newLifecycleProvider(t, 1)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assert.ErrorIs(db.CreateVault(ctx, VaultID{1}, KeyID{2}, p), context.Canceled)
		v, err := db.OpenVault(ctx, VaultID{1}, KeyID{2}, p)
		assert.Nil(v)
		assert.ErrorIs(err, context.Canceled)
		assert.SLen(p.calls, 0)
		ctx = context.Background()
		assert.ErrorIs(db.CreateVault(ctx, VaultID{1}, KeyID{2}, nil), ErrProvider)
		v, err = db.OpenVault(ctx, VaultID{1}, KeyID{2}, nil)
		assert.Nil(v)
		assert.ErrorIs(err, ErrProvider)
		v, err = db.OpenVault(ctx, VaultID{1}, KeyID{2}, p)
		assert.Nil(v)
		assert.ErrorIs(err, ErrVaultNotFound)
		assert.Equal(p.consumeCalls, 0)
		assert.Equal(p.remainingEncryptions, uint32(1))
		assert.Equal(p.leases[0].releases, 1)
		try.To(db.Close())
	})
}

func lifecycleVerificationFailure(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	db := open(t)
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	vault, id := VaultID{1}, KeyID{2}
	p := newLifecycleProvider(t, 2)
	try.To(db.CreateVault(ctx, vault, id, p))
	scope := manifestScope(t, p.secret, vault, id, &manifestGate{})
	envelope := readManifest(t, db.engine, scope, vault)
	envelope[len(envelope)-1] ^= 1
	token := try.To1(scope.Token([][]byte{{3}}, []byte("manifest")))
	_, _, cause := scope.Open([][]byte{{3}}, token, []byte("manifest"), envelope)
	assert.Error(cause)
	try.To(db.engine.Update(func(root engine.WriteTx) error {
		return putManifestFixture(root, vault, token, envelope)
	}))
	releaseErr := errors.New("failed verification release")
	p.releaseErr = releaseErr
	for range 2 {
		v, err := db.OpenVault(ctx, vault, id, p)
		assert.Nil(v)
		assert.ErrorIs(err, ErrVaultManifest)
		assert.ErrorIs(err, cause, "record cause survives manifest and lifecycle composition")
		assert.ErrorIs(err, releaseErr)
	}
	assert.Equal(p.spent, uint32(1))
	assert.Equal(p.remainingEncryptions, uint32(1), "failed verification consumes nothing")
	assert.Equal(p.consumeCalls, 1)
	for _, lease := range p.leases {
		assert.Equal(lease.releases, 1)
	}
	try.To(db.Close())
}

func lifecycleSignal(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle signal timed out")
	}
}

func lifecycleResult(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle result timed out")
		return nil
	}
}

// Observe the real admission decision under its mutex, without sleep ordering
// or a test-only hook in production. A nil Vault waits for Database.Close.
func lifecycleStopped(t *testing.T, db *Database, v *Vault) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		if db.mu.TryLock() {
			stopped := db.closed || v != nil && v.closing
			db.mu.Unlock()
			if stopped {
				return
			}
		}
		select {
		case <-timer.C:
			t.Fatal("admission did not stop")
		default:
			runtime.Gosched()
		}
	}
}

func lifecycleDrain(t *testing.T, open func(*testing.T) *Database) {
	for _, mode := range []string{"vault_close", "database_close", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			t.Cleanup(func() { _ = db.Close() })
			ctx := context.Background()
			vault, id := VaultID{1}, KeyID{2}
			p := newLifecycleProvider(t, 3)
			try.To(db.CreateVault(ctx, vault, id, p))
			v := try.To1(db.OpenVault(ctx, vault, id, p))
			sibling := try.To1(db.OpenVault(ctx, vault, id, p))
			lease := v.lease.(*lifecycleLease)
			siblingLease := sibling.lease.(*lifecycleLease)
			scope := v.scope // Retained only to inspect Clear after draining.
			entered, resume, workDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(resume) })
			workResult := make(chan error, 1)
			var owned []byte
			go func() {
				defer close(workDone)
				workResult <- v.withScope(func(s *record.Scope) (err error) {
					defer err2.Handle(&err, nil)
					defer assert.PushAsserter(assert.Plain)()
					token := try.To1(s.Token(nil, []byte("held")))
					close(entered)
					<-resume
					// Admitted work can still consume while either Close waits,
					// or after expiry.
					envelope := try.To1(s.Seal(nil, []byte("held"), []byte("owned")))
					_, owned = try.To2(s.Open(nil, token, []byte("held"), envelope))
					assert.Equal(string(owned), "owned")
					return nil
				})
			}()
			t.Cleanup(func() { unblock(); lifecycleSignal(t, workDone) })
			lifecycleSignal(t, entered)

			denied := errors.New("test lease expired")
			releaseErr, otherRelease := errors.New("first release failed"), errors.New("other release failed")
			p.mu.Lock()
			switch mode {
			case "expiry":
				lease.checkErr, lease.releaseErr = denied, releaseErr
			case "database_close":
				lease.releaseErr, siblingLease.releaseErr = releaseErr, otherRelease
			}
			p.mu.Unlock()
			stopResult, stopDone := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(stopDone)
				switch mode {
				case "vault_close":
					stopResult <- v.Close()
				case "database_close":
					stopResult <- db.Close()
				case "expiry":
					stopResult <- v.withScope(func(*record.Scope) error {
						return errors.New("denied callback executed")
					})
				}
			}()
			t.Cleanup(func() { unblock(); lifecycleSignal(t, stopDone) })
			lifecycleStopped(t, db, v)
			select {
			case <-stopDone:
				t.Fatal("cleanup completed while work was pinned")
			default:
			}
			p.mu.Lock()
			checks, releases := lease.checks, lease.releases
			p.mu.Unlock()
			assert.Equal(releases, 0)
			called := false
			err := v.withScope(func(*record.Scope) error { called = true; return nil })
			assert.ThatNot(called)
			want := ErrVaultClosed
			if mode == "database_close" {
				want = ErrClosed
			}
			assert.ErrorIs(err, want)
			if mode == "expiry" {
				assert.ErrorIs(err, denied)
			}
			p.mu.Lock()
			checksAfter := lease.checks
			p.mu.Unlock()
			assert.Equal(checksAfter, checks, "rejected work never checks released/closing resources")
			if mode != "database_close" {
				try.To(sibling.withScope(func(s *record.Scope) error {
					_, err := s.Token(nil, []byte("independent"))
					return err
				}))
			}

			concurrent := make(chan error, 4)
			if mode == "database_close" {
				for range 2 {
					go func() { concurrent <- v.Close() }()
					go func() { concurrent <- db.Close() }()
				}
			}
			unblock()
			try.To(lifecycleResult(t, workResult))
			stopErr := lifecycleResult(t, stopResult)
			if mode == "vault_close" {
				assert.NoError(stopErr)
			} else {
				assert.ErrorIs(stopErr, releaseErr)
				if mode == "expiry" {
					assert.ErrorIs(stopErr, denied)
				} else {
					assert.ErrorIs(stopErr, otherRelease, "Database.Close attempted every cleanup")
					for range 4 {
						assert.ErrorIs(lifecycleResult(t, concurrent), releaseErr)
					}
				}
			}
			_, err = scope.Token(nil, []byte("held"))
			assert.Equal(err, record.ErrCleared)
			assert.Equal(string(owned), "owned", "returned owned bytes survive cleanup")
			assert.Equal(lease.releases, 1)
			assert.Equal(lease.checks, checks, "no authorization recheck during admitted work")
			assert.Equal(p.spent, uint32(2))
			if mode != "database_close" {
				assert.Equal(siblingLease.releases, 0)
			}
			handleCloseErr := v.Close()
			assert.Equal(v.Close(), handleCloseErr)
			closeErr := db.Close()
			if mode == "vault_close" {
				assert.NoError(closeErr)
			} else {
				assert.ErrorIs(closeErr, releaseErr)
			}
			assert.Equal(db.Close(), closeErr)
			assert.Equal(siblingLease.releases, 1)
			assert.Equal(len(db.vaults), 0)
			called = false
			assert.Equal(db.engine.View(func(engine.ReadTx) error { called = true; return nil }), engine.ErrClosed)
			assert.ThatNot(called, "engine closes even after failing lease releases")
			calls := len(p.calls)
			assert.ErrorIs(db.CreateVault(ctx, vault, id, p), ErrClosed)
			late, err := db.OpenVault(ctx, vault, id, p)
			assert.Nil(late)
			assert.ErrorIs(err, ErrClosed)
			assert.Equal(len(p.calls), calls)
		})
	}
}

func lifecycleUnwinding(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	db := open(t)
	t.Cleanup(func() { _ = db.Close() })
	p := newLifecycleProvider(t, 1)
	ctx := context.Background()
	try.To(db.CreateVault(ctx, VaultID{1}, KeyID{2}, p))
	v := try.To1(db.OpenVault(ctx, VaultID{1}, KeyID{2}, p))
	callbackErr := errors.New("callback failure")
	assert.Equal(v.withScope(func(*record.Scope) error { return callbackErr }), callbackErr)
	// Deliberately leave this err2 panic for the admission boundary to recover.
	assert.Equal(v.withScope(func(*record.Scope) error { try.To(callbackErr); return nil }), callbackErr)
	scope := v.scope
	entered, resume, workerDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(resume) })
	panicResult := make(chan any, 1)
	marker := &struct{ message string }{"unexpected callback panic"}
	go func() {
		defer close(workerDone)
		defer func() { panicResult <- recover() }()
		_ = v.withScope(func(_ *record.Scope) error {
			defer assert.PushAsserter(assert.Plain)()
			close(entered)
			<-resume
			panic(marker)
		})
	}()
	t.Cleanup(func() { unblock(); lifecycleSignal(t, workerDone) })
	lifecycleSignal(t, entered)
	closed, closeDone := make(chan error, 1), make(chan struct{})
	go func() { defer close(closeDone); closed <- v.Close() }()
	t.Cleanup(func() { unblock(); lifecycleSignal(t, closeDone) })
	lifecycleStopped(t, db, v)
	unblock()
	lifecycleSignal(t, workerDone)
	assert.Equal(<-panicResult, any(marker), "unexpected panic propagates unchanged")
	try.To(lifecycleResult(t, closed))
	_, err := scope.Token(nil, []byte("cleared"))
	assert.Equal(err, record.ErrCleared)
	assert.Equal(p.leases[1].releases, 1, "both errors and panic released their pins")
	try.To(db.Close())
}

func lifecyclePending(t *testing.T, open func(*testing.T) *Database) {
	for _, operation := range []string{"create", "open"} {
		t.Run(operation+"_acquire", func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			t.Cleanup(func() { _ = db.Close() })
			p := newLifecycleProvider(t, 2)
			ctx := context.Background()
			vault, id := VaultID{1}, KeyID{2}
			if operation == "open" {
				try.To(db.CreateVault(ctx, vault, id, p))
			}
			entered, resume := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(resume) })
			p.acquireEntered, p.acquireWait = entered, resume
			var handle *Vault
			result, workDone := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(workDone)
				if operation == "create" {
					result <- db.CreateVault(ctx, vault, id, p)
				} else {
					var err error
					handle, err = db.OpenVault(ctx, vault, id, p)
					result <- err
				}
			}()
			t.Cleanup(func() { unblock(); lifecycleSignal(t, workDone) })
			lifecycleSignal(t, entered)
			closed, closeDone := make(chan error, 1), make(chan struct{})
			go func() { defer close(closeDone); closed <- db.Close() }()
			t.Cleanup(func() { unblock(); lifecycleSignal(t, closeDone) })
			lifecycleStopped(t, db, nil)
			select {
			case <-closeDone:
				t.Fatal("Close failed to drain pending provider work")
			default:
			}
			// Admission remains responsive while provider I/O is blocked.
			assert.ErrorIs(db.CreateVault(ctx, VaultID{9}, id, p), ErrClosed)
			unblock()
			assert.ErrorIs(lifecycleResult(t, result), ErrClosed)
			assert.Nil(handle, "no publication after Close starts")
			try.To(lifecycleResult(t, closed))
			for _, lease := range p.leases {
				assert.Equal(lease.releases, 1)
			}
			assert.Equal(len(db.vaults), 0)
			assert.Equal(db.engine.View(func(engine.ReadTx) error { return nil }), engine.ErrClosed)
		})
	}
	t.Run("cancel_during_acquire", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		t.Cleanup(func() { _ = db.Close() })
		p := newLifecycleProvider(t, 2)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		try.To(db.CreateVault(ctx, VaultID{1}, KeyID{2}, p))
		p.acquireEntered, p.acquireWait = make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(p.acquireWait) })
		result, done := make(chan error, 1), make(chan struct{})
		var handle *Vault
		go func() {
			defer close(done)
			var err error
			handle, err = db.OpenVault(ctx, VaultID{1}, KeyID{2}, p)
			result <- err
		}()
		t.Cleanup(func() { unblock(); lifecycleSignal(t, done) })
		lifecycleSignal(t, p.acquireEntered)
		cancel()
		unblock()
		assert.ErrorIs(lifecycleResult(t, result), context.Canceled)
		assert.Nil(handle)
		assert.Equal(p.remainingEncryptions, uint32(1))
		assert.Equal(p.spent, uint32(1))
		assert.Equal(p.consumeCalls, 1)
		assert.Equal(len(p.leases), 1, "canceled Acquire returns no lease")
		assert.Equal(p.leases[0].releases, 1)
		try.To(db.Close())
	})
}

// Pause only after the real backend's verification transaction has completed.
// This tests the publication boundary without holding any engine lock or adding
// a test hook to production code.
type lifecycleVerifiedEngine struct {
	engine.Engine
	verified, resume chan struct{}
}

func (e *lifecycleVerifiedEngine) View(fn func(engine.ReadTx) error) error {
	err := e.Engine.View(fn)
	if err == nil {
		close(e.verified)
		<-e.resume
	}
	return err
}

func lifecyclePublication(t *testing.T, open func(*testing.T) *Database) {
	for _, mode := range []string{"close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			t.Cleanup(func() { _ = db.Close() })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			p := newLifecycleProvider(t, 2)
			try.To(db.CreateVault(ctx, VaultID{1}, KeyID{2}, p))
			paused := &lifecycleVerifiedEngine{
				Engine: db.engine, verified: make(chan struct{}), resume: make(chan struct{}),
			}
			db.engine = paused
			unblock := sync.OnceFunc(func() { close(paused.resume) })
			result, workDone := make(chan error, 1), make(chan struct{})
			var handle *Vault
			go func() {
				defer close(workDone)
				var err error
				handle, err = db.OpenVault(ctx, VaultID{1}, KeyID{2}, p)
				result <- err
			}()
			t.Cleanup(func() { unblock(); lifecycleSignal(t, workDone) })
			lifecycleSignal(t, paused.verified)
			closed, closeDone := make(chan error, 1), make(chan struct{})
			want := context.Canceled
			if mode == "close" {
				want = ErrClosed
				go func() { defer close(closeDone); closed <- db.Close() }()
				t.Cleanup(func() { unblock(); lifecycleSignal(t, closeDone) })
				lifecycleStopped(t, db, nil)
			} else {
				cancel()
			}
			unblock()
			assert.ErrorIs(lifecycleResult(t, result), want)
			assert.Nil(handle, "verified state alone must never publish authority")
			if mode == "close" {
				try.To(lifecycleResult(t, closed))
			}
			assert.Equal(p.leases[1].releases, 1)
			assert.Equal(p.remainingEncryptions, uint32(1))
			assert.Equal(p.spent, uint32(1))
			assert.Equal(p.consumeCalls, 1)
			assert.Equal(len(db.vaults), 0)
			try.To(db.Close())
		})
	}
}
