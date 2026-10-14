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

var errLifecycleBudget = errors.New("test lifetime budget exhausted")

// This finite provider exists only in tests. Its budget survives re-unlock and
// file reopen within the test; it supplies no durable/global accounting proof.
type lifecycleProvider struct {
	mu        sync.Mutex
	secret    []byte
	remaining uint32
	reserved  uint32
	spent     uint32
	calls     []struct {
		vault VaultID
		id    KeyID
	}
	leases                                       []*lifecycleLease
	acquireErr, checkErr, reserveErr, releaseErr error
	failCheckAt                                  int
	nilLease, nilGate                            bool
	reserves                                     int
	acquireEntered, acquireWait                  chan struct{}
	reserveEntered, reserveWait                  chan struct{}
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
	return &lifecycleProvider{secret: manifestSecret(t), remaining: budget}
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

func (l *lifecycleLease) Reserve(n uint32) (func() error, error) {
	p := l.p
	if p.reserveEntered != nil {
		p.reserveEntered <- struct{}{}
		<-p.reserveWait
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.reserves++
	if p.reserveErr != nil {
		return nil, p.reserveErr
	}
	if n > p.remaining {
		return nil, errLifecycleBudget
	}
	p.remaining -= n
	p.reserved += n
	if p.nilGate {
		return nil, nil
	}
	// The gate uses only local synchronized state, with no Check or provider I/O.
	remaining := n
	return func() error {
		p.mu.Lock()
		defer p.mu.Unlock()
		if remaining == 0 {
			return errLifecycleBudget
		}
		remaining--
		p.spent++
		return nil
	}, nil
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
		{"memory", func(t *testing.T) *Database { return NewMemory() }},
		{"bbolt", func(t *testing.T) *Database {
			return try.To1(OpenBolt(filepath.Join(t.TempDir(), "lifecycle.db")))
		}},
	} {
		t.Run(backend.name, func(t *testing.T) {
			t.Run("flow", func(t *testing.T) { lifecycleFlow(t, backend.open) })
			t.Run("failures", func(t *testing.T) { lifecycleFailures(t, backend.open) })
			t.Run("verification", func(t *testing.T) { lifecycleVerificationFailure(t, backend.open) })
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
	p := newLifecycleProvider(t, 4)
	borrowed := bytes.Clone(p.secret)
	t.Cleanup(func() { clear(borrowed) })
	assert.Equal(ErrVaultExists, errVaultExists)
	assert.Equal(ErrVaultNotFound, errVaultNotFound)
	assert.Equal(ErrVaultManifest, errVaultManifest)
	try.To(db.CreateVault(ctx, vault, id, p))
	assert.Equal(p.spent, uint32(1))
	assert.Equal(p.reserved, uint32(1))
	assert.Equal(p.leases[0].releases, 1)
	assert.ErrorIs(db.CreateVault(ctx, vault, id, p), ErrVaultExists)
	assert.Equal(p.spent, uint32(1), "duplicate reserves but does not seal")
	assert.Equal(p.reserved, uint32(2))
	assert.Equal(p.leases[1].releases, 1)

	v := try.To1(db.UnlockVault(ctx, vault, id, p, 2))
	assert.Equal(p.spent, uint32(1), "unlock/verification do not spend")
	var token [32]byte
	var envelope, owned []byte
	try.To(v.withScope(func(s *record.Scope) (err error) {
		defer err2.Handle(&err, nil)
		token = try.To1(s.Token(nil, []byte("key")))
		envelope = try.To1(s.Seal(nil, []byte("key"), []byte("value")))
		_, owned = try.To2(s.Open(nil, token, []byte("key"), envelope))
		return nil
	}))
	try.To(v.Lock()) // One unused seal is forfeited.
	try.To(v.Lock())
	assert.Equal(p.leases[2].releases, 1)
	assert.ErrorIs(v.withScope(func(*record.Scope) error {
		t.Fatal("locked callback ran")
		return nil
	}), ErrLocked)
	assert.Equal(string(owned), "value")

	ro := try.To1(db.UnlockVault(ctx, vault, id, p, 0))
	assert.NotEqual(ro, v)
	try.To(ro.withScope(func(s *record.Scope) (err error) {
		defer err2.Handle(&err, nil)
		assert.Equal(try.To1(s.Token(nil, []byte("key"))), token)
		_, value := try.To2(s.Open(nil, token, []byte("key"), envelope))
		assert.Equal(string(value), "value")
		sealed, err := s.Seal(nil, []byte("key"), nil)
		assert.SNil(sealed)
		assert.ErrorIs(err, errLifecycleBudget)
		return nil
	}))
	assert.Equal(p.spent, uint32(2))
	assert.Equal(p.remaining, uint32(0))
	try.To(ro.Lock())
	for _, call := range p.calls {
		assert.Equal(call.vault, vault)
		assert.Equal(call.id, id)
	}
	assert.Equal(bytes.Equal(p.secret, borrowed), true, "storage never clears borrowed bytes")

	wrong := newLifecycleProvider(t, 1)
	missing, err := db.UnlockVault(ctx, VaultID{99}, id, wrong, 0)
	assert.Nil(missing)
	assert.ErrorIs(err, ErrVaultNotFound)
	bad, err := db.UnlockVault(ctx, vault, id, wrong, 0)
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
	v := try.To1(db.UnlockVault(ctx, vault, id, p, 1))
	try.To(v.Lock()) // Forfeit an unused reservation.
	try.To(db.Close())

	reopened := try.To1(OpenBolt(path))
	t.Cleanup(func() { _ = reopened.Close() })
	noKey, err := reopened.UnlockVault(ctx, vault, id, nil, 0)
	assert.Nil(noKey)
	assert.ErrorIs(err, ErrProvider)
	noBudget, err := reopened.UnlockVault(ctx, vault, id, p, 1)
	assert.Nil(noBudget)
	assert.ErrorIs(err, errLifecycleBudget)
	ro := try.To1(reopened.UnlockVault(ctx, vault, id, p, 0))
	try.To(ro.withScope(func(s *record.Scope) error {
		_, err := s.Token(nil, []byte("read"))
		return err
	}))
	assert.Equal(p.remaining, uint32(0))
	assert.Equal(p.spent, uint32(1))
	assert.Equal(p.reserved, uint32(2))
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
	for _, operation := range []string{"create", "unlock"} {
		t.Run(operation, func(t *testing.T) {
			for _, name := range []string{"acquire", "nil_lease", "check", "reserve", "nil_gate", "secret", "admission", "engine", "publication"} {
				if operation == "create" && name == "publication" {
					continue
				}
				t.Run(name, func(t *testing.T) {
					defer assert.PushTester(t)()
					db := open(t)
					t.Cleanup(func() { _ = db.Close() })
					ctx := context.Background()
					vault, id := VaultID{1}, KeyID{2}
					p := newLifecycleProvider(t, 3)
					if operation == "unlock" && name != "engine" {
						try.To(db.CreateVault(ctx, vault, id, p))
					}
					beforeLeases, beforeReserves := len(p.leases), p.reserves
					beforeSpent, beforeReserved := p.spent, p.reserved
					cause := errors.New("injected provider failure")
					releaseErr := errors.New("injected release failure")
					p.releaseErr = releaseErr
					want := cause
					wantLease, wantReserve := true, true
					switch name {
					case "acquire":
						p.acquireErr = cause
						wantLease, wantReserve = false, false
					case "nil_lease":
						p.nilLease, want = true, ErrProvider
						wantLease, wantReserve = false, false
					case "check":
						p.checkErr, wantReserve = cause, false
					case "reserve":
						p.reserveErr = cause
					case "nil_gate":
						p.nilGate, want = true, ErrAllowance
					case "secret":
						p.secret = p.secret[:31]
						_, want = record.Derive(p.secret, vault, id, func() error { return errLifecycleBudget })
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
						v, err = db.UnlockVault(ctx, vault, id, p, 1)
						assert.Nil(v, "no handle may escape a failed unlock")
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
					if wantReserve {
						assert.Equal(p.reserves, beforeReserves+1)
						if name != "reserve" {
							assert.Equal(p.reserved, beforeReserved+1, "failed work never refunds")
						}
					} else {
						assert.Equal(p.reserves, beforeReserves)
					}
					assert.Equal(p.spent, beforeSpent)
					assert.Equal(bytes.Equal(p.secret, borrowed), true)
					assert.Equal(len(db.vaults), 0)
					if operation == "create" && name != "engine" {
						p.acquireErr, p.checkErr, p.reserveErr, p.releaseErr = nil, nil, nil, nil
						p.nilGate, p.nilLease = false, false
						p.secret = p.secret[:32]
						v, err := db.UnlockVault(ctx, vault, id, p, 0)
						assert.Nil(v)
						assert.ErrorIs(err, ErrVaultNotFound, "failed creation did not leave state")
					}
					try.To(db.Close())
				})
			}
		})
	}
	t.Run("bounds_and_cancelled_context", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		t.Cleanup(func() { _ = db.Close() })
		p := newLifecycleProvider(t, maxAllowance)
		v, err := db.UnlockVault(context.Background(), VaultID{1}, KeyID{2}, p, maxAllowance+1)
		assert.Nil(v)
		assert.ErrorIs(err, ErrAllowance)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assert.ErrorIs(db.CreateVault(ctx, VaultID{1}, KeyID{2}, p), context.Canceled)
		v, err = db.UnlockVault(ctx, VaultID{1}, KeyID{2}, p, 0)
		assert.Nil(v)
		assert.ErrorIs(err, context.Canceled)
		assert.SLen(p.calls, 0)
		v, err = db.UnlockVault(context.Background(), VaultID{1}, KeyID{2}, p, maxAllowance)
		assert.Nil(v)
		assert.ErrorIs(err, ErrVaultNotFound, "the cap itself is an allowed reservation")
		assert.Equal(p.reserved, maxAllowance)
		assert.Equal(p.remaining, uint32(0))
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
	for _, allowance := range []uint32{1, 0} {
		v, err := db.UnlockVault(ctx, vault, id, p, allowance)
		assert.Nil(v)
		assert.ErrorIs(err, ErrVaultManifest)
		assert.ErrorIs(err, cause, "record cause survives manifest and lifecycle composition")
		assert.ErrorIs(err, releaseErr)
	}
	assert.Equal(p.spent, uint32(1))
	assert.Equal(p.remaining, uint32(0), "failed verification forfeits reservation")
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
	for _, mode := range []string{"lock", "close", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			t.Cleanup(func() { _ = db.Close() })
			ctx := context.Background()
			vault, id := VaultID{1}, KeyID{2}
			p := newLifecycleProvider(t, 3)
			try.To(db.CreateVault(ctx, vault, id, p))
			v := try.To1(db.UnlockVault(ctx, vault, id, p, 1))
			sibling := try.To1(db.UnlockVault(ctx, vault, id, p, 1))
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
					// Precharged work can still seal after Lock, Close or expiry.
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
			if mode == "expiry" {
				lease.checkErr, lease.releaseErr = denied, releaseErr
			} else if mode == "close" {
				lease.releaseErr, siblingLease.releaseErr = releaseErr, otherRelease
			}
			p.mu.Unlock()
			stopResult, stopDone := make(chan error, 1), make(chan struct{})
			go func() {
				defer close(stopDone)
				switch mode {
				case "lock":
					stopResult <- v.Lock()
				case "close":
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
			want := ErrLocked
			if mode == "close" {
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
			if mode != "close" {
				try.To(sibling.withScope(func(s *record.Scope) error {
					_, err := s.Token(nil, []byte("independent"))
					return err
				}))
			}

			concurrent := make(chan error, 4)
			if mode == "close" {
				for range 2 {
					go func() { concurrent <- v.Lock() }()
					go func() { concurrent <- db.Close() }()
				}
			}
			unblock()
			try.To(lifecycleResult(t, workResult))
			stopErr := lifecycleResult(t, stopResult)
			if mode == "lock" {
				assert.NoError(stopErr)
			} else {
				assert.ErrorIs(stopErr, releaseErr)
				if mode == "expiry" {
					assert.ErrorIs(stopErr, denied)
				} else {
					assert.ErrorIs(stopErr, otherRelease, "Close attempted every cleanup")
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
			if mode != "close" {
				assert.Equal(siblingLease.releases, 0)
			}
			lockErr := v.Lock()
			assert.Equal(v.Lock(), lockErr)
			closeErr := db.Close()
			if mode == "lock" {
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
			late, err := db.UnlockVault(ctx, vault, id, p, 0)
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
	v := try.To1(db.UnlockVault(ctx, VaultID{1}, KeyID{2}, p, 0))
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
		_ = v.withScope(func(s *record.Scope) error {
			defer assert.PushAsserter(assert.Plain)()
			close(entered)
			<-resume
			panic(marker)
		})
	}()
	t.Cleanup(func() { unblock(); lifecycleSignal(t, workerDone) })
	lifecycleSignal(t, entered)
	locked, lockDone := make(chan error, 1), make(chan struct{})
	go func() { defer close(lockDone); locked <- v.Lock() }()
	t.Cleanup(func() { unblock(); lifecycleSignal(t, lockDone) })
	lifecycleStopped(t, db, v)
	unblock()
	lifecycleSignal(t, workerDone)
	assert.Equal(<-panicResult, any(marker), "unexpected panic propagates unchanged")
	try.To(lifecycleResult(t, locked))
	_, err := scope.Token(nil, []byte("cleared"))
	assert.Equal(err, record.ErrCleared)
	assert.Equal(p.leases[1].releases, 1, "both errors and panic released their pins")
	try.To(db.Close())
}

func lifecyclePending(t *testing.T, open func(*testing.T) *Database) {
	for _, operation := range []string{"create", "unlock"} {
		for _, stage := range []string{"acquire", "reserve"} {
			t.Run(operation+"_"+stage, func(t *testing.T) {
				defer assert.PushTester(t)()
				db := open(t)
				t.Cleanup(func() { _ = db.Close() })
				p := newLifecycleProvider(t, 2)
				ctx := context.Background()
				vault, id := VaultID{1}, KeyID{2}
				if operation == "unlock" {
					try.To(db.CreateVault(ctx, vault, id, p))
				}
				entered, resume := make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(resume) })
				if stage == "acquire" {
					p.acquireEntered, p.acquireWait = entered, resume
				} else {
					p.reserveEntered, p.reserveWait = entered, resume
				}
				var handle *Vault
				result, workDone := make(chan error, 1), make(chan struct{})
				go func() {
					defer close(workDone)
					if operation == "create" {
						result <- db.CreateVault(ctx, vault, id, p)
					} else {
						var err error
						handle, err = db.UnlockVault(ctx, vault, id, p, 1)
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
	}
	t.Run("cancel_after_reservation", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		t.Cleanup(func() { _ = db.Close() })
		p := newLifecycleProvider(t, 2)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		try.To(db.CreateVault(ctx, VaultID{1}, KeyID{2}, p))
		p.reserveEntered, p.reserveWait = make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(p.reserveWait) })
		result, done := make(chan error, 1), make(chan struct{})
		var handle *Vault
		go func() {
			defer close(done)
			var err error
			handle, err = db.UnlockVault(ctx, VaultID{1}, KeyID{2}, p, 1)
			result <- err
		}()
		t.Cleanup(func() { unblock(); lifecycleSignal(t, done) })
		lifecycleSignal(t, p.reserveEntered)
		cancel()
		unblock()
		assert.ErrorIs(lifecycleResult(t, result), context.Canceled)
		assert.Nil(handle)
		assert.Equal(p.remaining, uint32(0))
		assert.Equal(p.spent, uint32(1))
		assert.Equal(p.leases[1].releases, 1)
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
				handle, err = db.UnlockVault(ctx, VaultID{1}, KeyID{2}, p, 1)
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
			assert.Equal(p.remaining, uint32(0))
			assert.Equal(p.spent, uint32(1))
			assert.Equal(len(db.vaults), 0)
			try.To(db.Close())
		})
	}
}
