package storage

import (
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/engine"
	"github.com/lainio/ic/storage/internal/record"
)

// ReadTx reads encrypted records in one Vault's logical root. Keys are opaque,
// nonempty bytes. Handles expire at callback exit; later calls return ErrTxClosed.
// The first operation error stops further work and fails the transaction even
// when ignored. Handles must not be used concurrently.
type ReadTx interface {
	// Get returns verified, caller-owned bytes. Missing records return nil, false,
	// nil; empty values are present. Any error returns nil, false, err.
	Get(key []byte) (value []byte, found bool, err error)
}

// WriteTx adds atomic mutations and reads its own pending writes. Inputs are
// neither modified nor retained. An existing record must verify before mutation.
type WriteTx interface {
	ReadTx
	// Put seals a value, including a nil/empty value. A completed seal spends
	// allowance even if the transaction later aborts or the backend write fails.
	Put(key, value []byte) (err error)
	// Delete succeeds on absence and spends no sealing allowance.
	Delete(key []byte) (err error)
}

const vaultRecords = "\x01"

// View runs fn once on the calling goroutine with only read capabilities.
// Admission pins the unlocked scope through engine completion. Recursive
// transactions and lifecycle calls inside the callback are unsupported.
func (v *Vault) View(fn func(tx ReadTx) (err error)) (err error) {
	return v.withScope(func(scope *record.Scope) error {
		return v.db.engine.View(func(root engine.ReadTx) (err error) {
			tx := &readTx{scope: scope}
			defer tx.finish(&err)
			defer err2.Handle(&err, nil)
			state := try.To1(readVaultRoot(root, v.vault))
			if try.To1(state.HasChild([]byte(vaultRecords))) {
				tx.records = try.To1(state.Child([]byte(vaultRecords)))
			}
			return fn(tx)
		})
	})
}

// Update runs fn once on the calling goroutine and commits only on success.
// Callback and operation errors abort all pending changes, preserving both
// causes. err2 propagation is recovered before the commit decision; unexpected
// and runtime panics abort and propagate. Admission and callback rules match View.
func (v *Vault) Update(fn func(tx WriteTx) (err error)) (err error) {
	return v.withScope(func(scope *record.Scope) error {
		return v.db.engine.Update(func(root engine.WriteTx) (err error) {
			tx := &writeTx{readTx: &readTx{scope: scope}}
			defer func() {
				tx.state = nil
				tx.finish(&err)
			}()
			defer err2.Handle(&err, nil)
			// Probe through the shared read contract before opening writable state.
			// Missing collection/Vault is not an invitation to create either one.
			try.To1(readVaultRoot(root, v.vault))
			collection := try.To1(root.ChildForUpdate([]byte(vaultCollection)))
			tx.state = try.To1(collection.ChildForUpdate(v.vault[:]))
			if try.To1(tx.state.HasChild([]byte(vaultRecords))) {
				tx.records = try.To1(tx.state.Child([]byte(vaultRecords)))
			}
			return fn(tx)
		})
	})
}

func readVaultRoot(root engine.ReadNS, vault VaultID) (state engine.ReadNS, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()
	assert.That(try.To1(root.HasChild([]byte(vaultCollection))), ErrVaultNotFound)
	collection := try.To1(root.Child([]byte(vaultCollection)))
	assert.That(try.To1(collection.HasChild(vault[:])), ErrVaultNotFound)
	return collection.Child(vault[:])
}

// Separate concrete capabilities keep a View from asserting to WriteTx. No
// engine interface is embedded, so raw navigation cannot escape through methods.
type readTx struct {
	scope   *record.Scope
	records engine.ReadNS // Nil is a valid empty logical root.
	err     error
	closed  bool
}

type writeTx struct {
	*readTx
	state engine.WriteNS
}

func (tx *readTx) finish(err *error) {
	tx.closed = true
	if *err == nil {
		*err = tx.err
	} else if tx.err != nil && !errors.Is(*err, tx.err) {
		*err = errors.Join(*err, tx.err)
	}
	tx.scope, tx.records, tx.err = nil, nil, nil
}

func (tx *readTx) fail(err error) error {
	if tx.err == nil {
		tx.err = err
	}
	return tx.err
}

func (tx *readTx) check() error {
	if tx.closed {
		return ErrTxClosed
	}
	return tx.err
}

func (tx *readTx) Get(key []byte) (value []byte, found bool, err error) {
	if err := tx.check(); err != nil {
		return nil, false, err
	}
	defer err2.Handle(&err, tx.fail)
	token := try.To1(tx.scope.Token([][]byte{{1}}, key))
	return tx.open(token, key)
}

// Token validation precedes this helper, so key is nonnil and nonempty. Full
// Open checks the requested key as well as the expected token and root context.
func (tx *readTx) open(token [32]byte, key []byte) (value []byte, found bool, err error) {
	defer err2.Handle(&err, nil)
	if tx.records == nil {
		return nil, false, nil
	}
	envelope, exists := try.To2(tx.records.Get(token[:]))
	if !exists {
		return nil, false, nil
	}
	_, verified := try.To2(tx.scope.Open([][]byte{{1}}, token, key, envelope))
	return verified, true, nil
}

func (tx *writeTx) Put(key, value []byte) (err error) {
	if err := tx.check(); err != nil {
		return err
	}
	defer err2.Handle(&err, tx.fail)
	token := try.To1(tx.scope.Token([][]byte{{1}}, key))
	try.To2(tx.open(token, key))
	envelope := try.To1(tx.scope.Seal([][]byte{{1}}, key, value))
	records := try.To1(tx.state.EnsureChild([]byte(vaultRecords)))
	tx.records = records
	return records.Put(token[:], envelope)
}

func (tx *writeTx) Delete(key []byte) (err error) {
	if err := tx.check(); err != nil {
		return err
	}
	defer err2.Handle(&err, tx.fail)
	token := try.To1(tx.scope.Token([][]byte{{1}}, key))
	_, found := try.To2(tx.open(token, key))
	if !found {
		return nil
	}
	records := try.To1(tx.state.ChildForUpdate([]byte(vaultRecords)))
	return records.Delete(token[:])
}
