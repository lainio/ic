// Package engine provides private, unencrypted transactional infrastructure for
// storage's future mandatory-encryption Vault layer. It is not an application
// storage API. Its single namespace and disk layout are provisional.
package engine

import "errors"

var (
	ErrClosed   = errors.New("storage engine is closed")
	ErrTxClosed = errors.New("storage transaction callback has ended")
	ErrEmptyKey = errors.New("storage key is empty")
)

// Engine owns one namespace. Its methods may be called concurrently, subject to
// the backend's transaction guarantees: bbolt allows readers and one writer.
// Callbacks run once and must not recursively start transactions or perform
// lifecycle operations (including Close or reopening the same file). Such calls
// may deadlock. Transaction handles must not be shared across goroutines.
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

// ReadTx is valid only during its callback. Later operations return ErrTxClosed.
// All operations reject empty keys with ErrEmptyKey. An operation error causes
// the enclosing View or Update to fail even if the callback ignores that error.
type ReadTx interface {
	// Get returns caller-owned bytes that survive callback exit and Close.
	// found distinguishes a missing key from a present empty value.
	Get(key []byte) (value []byte, found bool, err error)
}

// WriteTx adds mutations and reads its own pending writes. After the first
// operation error, subsequent operations return that error until callback exit.
type WriteTx interface {
	ReadTx
	// Put copies its inputs before returning; nil values are present empties.
	Put(key, value []byte) error
	// Delete succeeds for an absent key.
	Delete(key []byte) error
}
