// Package engine provides private, unencrypted transactional infrastructure for
// storage's future mandatory-encryption Vault layer. It is not an application
// storage API. Its disk layout is provisional.
package engine

import "errors"

var (
	ErrClosed            = errors.New("storage engine is closed")
	ErrTxClosed          = errors.New("storage transaction callback has ended")
	ErrEmptyKey          = errors.New("storage key is empty")
	ErrEmptyName         = errors.New("storage namespace name is empty")
	ErrNamespaceNotFound = errors.New("storage namespace does not exist")
	ErrConflict          = errors.New("storage record and namespace conflict")
)

// Engine owns a namespace tree. Its methods may be called concurrently, subject to
// the backend's transaction guarantees: bbolt allows readers and one writer.
// Callbacks run once and must not recursively start transactions or perform
// lifecycle operations (including Close or reopening the same file). Such calls
// may deadlock. Transaction and namespace handles must not be shared across
// goroutines.
type Engine interface {
	// View observes a consistent snapshot and exposes only read capabilities.
	View(func(ReadTx) error) error

	// Update commits atomically on success. Callback errors and the first
	// operation error (even if ignored by the callback) abort all changes.
	// err2 error panics become errors; unexpected panics roll back and propagate.
	// Callback and operation errors are preserved, joined if both are present.
	Update(func(WriteTx) error) error

	// Close stops admission, waits for admitted transactions, and releases the
	// backend. It is terminal and idempotent; only an explicit open creates a
	// new instance. It must not be called from a transaction callback.
	Close() error
}

// ReadTx is the transaction's root namespace.
type ReadTx interface{ ReadNS }

// WriteTx is the writable transaction's root namespace.
type WriteTx interface{ WriteNS }

// ReadNS is valid only during its transaction callback. All handles share the
// first operation error; even an ignored error fails the enclosing transaction.
// After callback exit, ErrTxClosed takes precedence over all other errors.
// Records and children share names: wrong-kind access returns ErrConflict.
type ReadNS interface {
	// Get returns caller-owned bytes that survive callback exit and Close.
	// found distinguishes a missing key from a present empty value. Empty keys
	// return ErrEmptyKey.
	Get(key []byte) (value []byte, found bool, err error)
	// Child opens an existing child or returns ErrNamespaceNotFound. Names are
	// single nonempty byte segments (ErrEmptyName otherwise); slashes are literal.
	// The returned handle has only read capabilities, even through a WriteNS.
	Child(name []byte) (ns ReadNS, err error)
	// Each visits direct records only, including empty values, in unspecified
	// order. Keys and values are caller-owned copies. A callback error or an
	// operation error within it stops iteration and fails the transaction even
	// if ignored. Mutating this namespace while iterating it is unsupported.
	Each(fn func(key, value []byte) error) (err error)
}

// WriteNS adds mutations and reads its own pending writes. Changes throughout
// the tree, including child creation, commit or roll back as one transaction.
type WriteNS interface {
	ReadNS
	// ChildForUpdate opens an existing child without creating it. Name and
	// missing-child errors are the same as Child.
	ChildForUpdate(name []byte) (ns WriteNS, err error)
	// EnsureChild creates or opens an immediate child, owning the name bytes.
	// Use it directly for create-or-open: a failed Child aborts the transaction.
	EnsureChild(name []byte) (ns WriteNS, err error)
	// Put copies its inputs before returning; nil values are present empties.
	Put(key, value []byte) (err error)
	// Delete succeeds for an absent record, but never deletes a child subtree.
	Delete(key []byte) (err error)
}

// txState is shared by the root and every child, independent of capabilities.
type txState struct {
	closed bool
	err    error
}

func (tx *txState) finish(err *error) {
	tx.closed = true
	if *err == nil {
		*err = tx.err
	} else if tx.err != nil && !errors.Is(*err, tx.err) {
		*err = errors.Join(*err, tx.err)
	}
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

func (tx *txState) checkName(name []byte, empty error) error {
	if err := tx.check(); err != nil {
		return err
	}
	if len(name) == 0 {
		return tx.fail(empty)
	}
	return nil
}
