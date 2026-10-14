package storage

import (
	"errors"
	"sync"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/record"
)

// Vault owns one authenticated Scope and lease. Lock affects only this handle;
// another unlock requires authorization and a new reservation for the same IDs.
// Use only the pointer returned by UnlockVault. No public record operations are
// available yet. Already returned owned bytes cannot be revoked by Lock.
type Vault struct {
	db      *Database
	scope   *record.Scope
	lease   Lease
	active  sync.WaitGroup
	closing bool  // Protected by db.mu, as is cause.
	cause   error // First admission denial, retained through cleanup.
	once    sync.Once
	lockErr error // Published by once, read only after Do completes.
}

// withScope is the private composition boundary for future transactions. The
// callback must terminate, must not retain Scope, and must not reenter storage.
// Check and pinning are serialized with Lock/Close; no engine lock is held.
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
			return errors.Join(ErrLocked, v.cause)
		}
		if cause := v.lease.Check(); cause != nil {
			v.closing, v.cause, denied = true, cause, true
			return cause
		}
		v.active.Add(1)
		return nil
	}()
	if denied {
		return v.Lock() // Drain and release outside the admission gate.
	}
	try.To(err)
	defer v.active.Done() // Runs on errors and unexpected panics, before recovery.
	return fn(v.scope)
}

// Lock terminally stops admission, drains pinned callbacks, clears owned keys,
// and releases the lease once. It neither checks authorization again nor revokes
// precharged gates while work drains. Repeated/concurrent calls wait for cleanup
// and return its result, including any admission denial and Release error.
func (v *Vault) Lock() (err error) {
	v.db.mu.Lock()
	v.closing = true
	v.db.mu.Unlock()
	v.once.Do(func() {
		v.active.Wait()
		v.lockErr = errors.Join(v.cause, releaseScope(v.scope, v.lease))
		v.scope, v.lease = nil, nil
		v.db.mu.Lock()
		delete(v.db.vaults, v)
		v.db.cleanupErr = errors.Join(v.db.cleanupErr, v.lockErr)
		v.db.mu.Unlock()
	})
	return v.lockErr
}
