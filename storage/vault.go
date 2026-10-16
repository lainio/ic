package storage

import (
	"errors"
	"sync"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/record"
)

// Vault is an open handle for reading and updating one vault's encrypted records.
// It is bound to the vault ID and key version supplied to Database.OpenVault.
// Use only the returned pointer; View and Update access its logical root and
// nested namespaces.
//
// Close ends this handle's access permanently. Database.OpenVault can return a
// new handle for the same IDs after authorization and a new reservation.
// Closing cannot revoke data already returned to and owned by the caller.
type Vault struct {
	db       *Database
	vault    VaultID // Immutable routing identity from authenticated publication.
	scope    *record.Scope
	lease    Lease
	active   sync.WaitGroup
	closing  bool  // Protected by db.mu, as is cause.
	cause    error // First admission denial, retained through cleanup.
	once     sync.Once
	closeErr error // Published by once, read only after Do completes.
}

// withScope is the private composition boundary for future transactions. The
// callback must terminate, must not retain Scope, and must not reenter storage.
// Check and pinning are serialized with Vault.Close and Database.Close;
// no engine lock is held.
func (v *Vault) withScope(fn func(*record.Scope) error) (err error) {
	defer err2.Handle(&err, nil)
	denied := false
	err = func() (err error) {
		v.db.mu.Lock()
		defer v.db.mu.Unlock()
		if v.db.closed {
			return ErrClosed
		}
		if v.closing {
			return errors.Join(ErrVaultClosed, v.cause)
		}
		if cause := v.lease.Check(); cause != nil {
			v.closing, v.cause, denied = true, cause, true
			return cause
		}
		v.active.Add(1)
		return nil
	}()
	if denied {
		return v.Close() // Drain and release outside the admission gate.
	}
	try.To(err)
	defer v.active.Done() // Runs on errors and unexpected panics, before recovery.
	return fn(v.scope)
}

// Close ends access through this handle. Independently opened handles and stored
// records remain unchanged; Database.Close shuts down the whole database.
// Close rejects new operations, waits for already accepted work through engine
// completion, clears owned key buffers best-effort, and releases the lease once.
// It neither checks authorization again nor revokes precharged gates while work
// drains.
//
// Repeated/concurrent calls wait for cleanup and return its result, including any
// admission denial and Release error. A cleanup error does not make the closed
// handle reusable. Close must not be called from a provider or operation callback.
func (v *Vault) Close() (err error) {
	v.db.mu.Lock()
	v.closing = true
	v.db.mu.Unlock()
	v.once.Do(func() {
		v.active.Wait()
		v.closeErr = errors.Join(v.cause, releaseScope(v.scope, v.lease))
		v.scope, v.lease = nil, nil
		v.db.mu.Lock()
		delete(v.db.vaults, v)
		v.db.cleanupErr = errors.Join(v.db.cleanupErr, v.closeErr)
		v.db.mu.Unlock()
	})
	return v.closeErr
}
