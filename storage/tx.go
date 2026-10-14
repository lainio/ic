package storage

import (
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/engine"
	"github.com/lainio/ic/storage/internal/record"
)

// ReadTx is the logical root of one Vault transaction.
type ReadTx interface{ ReadNS }

// WriteTx is the writable logical root. All namespaces commit or roll back
// together and read the same pending state.
type WriteTx interface{ WriteNS }

const vaultRecords = "\x01"

// View runs fn once on the calling goroutine with only read capabilities.
// Admission pins the unlocked scope through engine completion. Recursive
// transactions and lifecycle calls inside the callback are unsupported.
func (v *Vault) View(fn func(tx ReadTx) (err error)) (err error) {
	return v.withScope(func(scope *record.Scope) error {
		return v.db.engine.View(func(root engine.ReadTx) (err error) {
			tx := &readTx{txState: &txState{scope: scope}, path: [][]byte{{1}}}
			defer tx.finish(&err)
			defer err2.Handle(&err, nil)
			tx.node = try.To1(readVaultRoot(root, v.vault))
			try.To1(tx.container(vaultRecords))
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
			tx := &writeTx{readTx: &readTx{txState: &txState{scope: scope}, path: [][]byte{{1}}}}
			defer tx.finish(&err)
			defer err2.Handle(&err, nil)
			// Probe through the shared read contract before opening writable state.
			// Missing collection/Vault is not an invitation to create either one.
			try.To1(readVaultRoot(root, v.vault))
			collection := try.To1(root.ChildForUpdate([]byte(vaultCollection)))
			tx.state = try.To1(collection.ChildForUpdate(v.vault[:]))
			tx.node = tx.state
			try.To1(tx.container(vaultRecords))
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
	*txState
	node engine.ReadNS
	path [][]byte // Owned, immutable [01] followed by logical segments.
}

type writeTx struct {
	*readTx
	state engine.WriteNS
}

// One state owns the scope reference, first failure and lifetime for all handles.
type txState struct {
	scope  *record.Scope
	err    error
	closed bool
}

func (tx *txState) finish(err *error) {
	tx.closed = true
	if *err == nil {
		*err = tx.err
	} else if tx.err != nil && !errors.Is(*err, tx.err) {
		*err = errors.Join(*err, tx.err)
	}
	tx.scope, tx.err = nil, nil
}

func (tx *txState) fail(err error) error {
	if tx.err == nil {
		tx.err = err
	}
	return tx.err
}

func (tx *txState) check() error {
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
	token := try.To1(tx.scope.Token(tx.path, key))
	try.To(tx.recordName(key))
	return tx.open(token, key)
}

// Token validation precedes this helper, so key is nonnil and nonempty. Full
// Open checks the requested key as well as the expected token and scoped context.
func (tx *readTx) open(token [32]byte, key []byte) (value []byte, found bool, err error) {
	defer err2.Handle(&err, nil)
	records := try.To1(tx.container(vaultRecords))
	if records == nil {
		return nil, false, nil
	}
	envelope, exists := try.To2(records.Get(token[:]))
	if !exists {
		return nil, false, nil
	}
	_, verified := try.To2(tx.scope.Open(tx.path, token, key, envelope))
	return verified, true, nil
}

func (tx *writeTx) Put(key, value []byte) (err error) {
	if err := tx.check(); err != nil {
		return err
	}
	defer err2.Handle(&err, tx.fail)
	token := try.To1(tx.scope.Token(tx.path, key))
	try.To(tx.recordName(key))
	try.To2(tx.open(token, key))
	envelope := try.To1(tx.scope.Seal(tx.path, key, value))
	records := try.To1(tx.state.EnsureChild([]byte(vaultRecords)))
	return records.Put(token[:], envelope)
}

func (tx *writeTx) Delete(key []byte) (err error) {
	if err := tx.check(); err != nil {
		return err
	}
	defer err2.Handle(&err, tx.fail)
	token := try.To1(tx.scope.Token(tx.path, key))
	try.To(tx.recordName(key))
	_, found := try.To2(tx.open(token, key))
	if !found {
		return nil
	}
	records := try.To1(tx.state.ChildForUpdate([]byte(vaultRecords)))
	return records.Delete(token[:])
}
