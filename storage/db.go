// Package storage provides encrypted namespace transactions through open
// Vault handles.
// Keys and finite sealing allowances come from an external provider; production
// lifetime accounting is not implemented here.
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
	cleanupErr error // Handle cleanup errors, including concurrent Vault.Close.
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

// CreateVault creates only absent state and returns no open handle. A
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

// OpenVault returns a handle for reading and updating an existing vault.
// The application supplies the vault ID, key ID, and provider. The provider
// decides whether access is allowed and supplies the secret. Storage checks the
// vault's encrypted identity record (manifest) before returning the handle.
// Missing or invalid state is never created or repaired; use CreateVault to
// create a vault separately.
//
// Allowance is reserved once for new encryptions; verification spends none.
// Zero reserves no new encryptions and still permits reading, authorized deletion,
// and namespace creation. The caller must close the returned handle when done.
func (db *Database) OpenVault(ctx context.Context, vault VaultID, id KeyID,
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

	// Publication transfers sole cleanup ownership to the registered handle
	// under the admission gate.
	db.mu.Lock()
	defer db.mu.Unlock()
	try.To(db.checkAdmission(ctx, lease))
	v = &Vault{db: db, vault: vault, scope: scope, lease: lease}
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

// Close shuts down this database, its remaining Vault handles, and its engine.
// To end access through just one handle, use Vault.Close instead.
// Close rejects new work, waits for pending operations and handle cleanup, then
// closes the engine. All handle cleanups are attempted even after errors.
// Repeated/concurrent calls wait for completion and return the same result.
// Close must not be called from a provider or operation callback.
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
		_ = v.Close() // Each completed Vault.Close records its result in cleanupErr.
	}
	engineErr := db.engine.Close()
	db.mu.Lock()
	db.closeErr = errors.Join(db.cleanupErr, engineErr)
	close(db.done)
	db.mu.Unlock()
	return db.closeErr
}
