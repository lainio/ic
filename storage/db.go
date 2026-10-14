// Package storage provides partial provider-backed Vault lifecycle integration.
// It is not yet usable record storage or production lifetime accounting.
// Database and Vault must be used through constructed pointers: copying, zero
// values, and reentrant provider or operation callbacks are unsupported.
package storage

import (
	"context"
	"errors"
	"sync"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/engine"
	"github.com/lainio/ic/storage/internal/record"
)

const maxAllowance uint32 = 1 << 24

// Database owns its engine, pending operations, and published Vault handles.
// Use OpenBolt or NewMemory; Close is terminal.
type Database struct {
	mu         sync.Mutex // Admission, publication, and handle registration.
	engine     engine.Engine
	pending    sync.WaitGroup
	closed     bool
	done       chan struct{}
	vaults     map[*Vault]struct{}
	cleanupErr error // Completed handle cleanup errors, including concurrent Lock.
	closeErr   error // Published by closing done.
}

// OpenBolt opens a durable database, creating its engine if absent. Parent
// directories must exist. No keys or allowances are recovered from the file.
func OpenBolt(path string) (db *Database, err error) {
	defer err2.Handle(&err, nil)
	e := try.To1(engine.OpenBolt(path))
	return newDatabase(e), nil
}

// NewMemory creates an independent ephemeral database.
func NewMemory() *Database { return newDatabase(engine.NewMemory()) }

func newDatabase(e engine.Engine) *Database {
	return &Database{engine: e, done: make(chan struct{}), vaults: make(map[*Vault]struct{})}
}

func (db *Database) begin(ctx context.Context) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if db.closed {
		return ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Close stops additions under mu before waiting, including at zero count.
	db.pending.Add(1)
	return nil
}

// checkAdmission requires mu and no engine transaction. A pending operation
// already pins the engine until its own cleanup finishes.
func (db *Database) checkAdmission(ctx context.Context, lease Lease) (err error) {
	defer err2.Handle(&err, nil)
	if db.closed {
		return ErrClosed
	}
	try.To(ctx.Err())
	try.To(lease.Check())
	return ctx.Err()
}

func (db *Database) admit(ctx context.Context, lease Lease) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.checkAdmission(ctx, lease)
}

// CreateVault creates only absent state and returns no unlocked handle. A
// duplicate attempt may reserve usage without spending a seal. No usage is
// refunded. Once admitted, cancellation/Close need not undo a committed create.
// A Release error can be returned AFTER commit: an error does not imply absence.
// Operation and cleanup errors are both preserved; creation is never retried.
func (db *Database) CreateVault(ctx context.Context, vault VaultID, id KeyID,
	provider KeyProvider) (err error) {
	if err := db.begin(ctx); err != nil {
		return err
	}
	defer db.pending.Done()
	var scope *record.Scope
	var lease Lease
	defer func() { err = errors.Join(err, releaseScope(scope, lease)) }()
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.INotNil(provider, ErrProvider)
	lease = try.To1(provider.Acquire(ctx, vault, id))
	assert.INotNil(lease, ErrProvider)
	try.To(lease.Check())
	spend := try.To1(lease.Reserve(1))
	assert.That(spend != nil, ErrAllowance)
	scope = try.To1(record.Derive(lease.Secret(), vault, id, spend))
	try.To(db.admit(ctx, lease))
	return db.engine.Update(func(root engine.WriteTx) error {
		return createVaultState(root, scope, vault, id)
	})
}

// UnlockVault authenticates existing state using externally expected identities.
// It never creates or repairs state. Allowance is reserved once, including zero
// for read-only work, and verification spends no seals. Publication transfers
// sole cleanup ownership to the registered handle under the admission gate.
func (db *Database) UnlockVault(ctx context.Context, vault VaultID, id KeyID,
	provider KeyProvider, allowance uint32) (v *Vault, err error) {
	if err := db.begin(ctx); err != nil {
		return nil, err
	}
	defer db.pending.Done()
	var scope *record.Scope
	var lease Lease
	defer func() {
		if v == nil {
			err = errors.Join(err, releaseScope(scope, lease))
		}
	}()
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.That(allowance <= maxAllowance, ErrAllowance)
	assert.INotNil(provider, ErrProvider)
	lease = try.To1(provider.Acquire(ctx, vault, id))
	assert.INotNil(lease, ErrProvider)
	try.To(lease.Check())
	spend := try.To1(lease.Reserve(allowance))
	assert.That(spend != nil, ErrAllowance)
	scope = try.To1(record.Derive(lease.Secret(), vault, id, spend))
	try.To(db.admit(ctx, lease))
	try.To(db.engine.View(func(root engine.ReadTx) error {
		return verifyVaultState(root, scope, vault, id)
	}))

	db.mu.Lock()
	defer db.mu.Unlock()
	try.To(db.checkAdmission(ctx, lease))
	v = &Vault{db: db, scope: scope, lease: lease}
	db.vaults[v] = struct{}{}
	return v, nil
}

func releaseScope(scope *record.Scope, lease Lease) error {
	if scope != nil {
		scope.Clear()
	}
	if lease != nil {
		return lease.Release()
	}
	return nil
}

// Close stops all admission, drains pending operations and owned handles, then
// closes the engine. All handle cleanups are attempted even after errors.
// Repeated/concurrent calls wait for completion and return the same result.
func (db *Database) Close() (err error) {
	db.mu.Lock()
	if db.closed {
		db.mu.Unlock()
		<-db.done
		return db.closeErr
	}
	db.closed = true
	db.mu.Unlock()

	db.pending.Wait()
	db.mu.Lock()
	vaults := make([]*Vault, 0, len(db.vaults))
	for v := range db.vaults {
		vaults = append(vaults, v)
	}
	db.mu.Unlock()
	for _, v := range vaults {
		_ = v.Lock() // Each completed Lock records its result in cleanupErr.
	}
	engineErr := db.engine.Close()
	db.mu.Lock()
	db.closeErr = errors.Join(db.cleanupErr, engineErr)
	close(db.done)
	db.mu.Unlock()
	return db.closeErr
}
