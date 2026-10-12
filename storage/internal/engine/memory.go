package engine

import (
	"bytes"
	"errors"
	"maps"
	"sync"

	"github.com/lainio/err2"
)

type memoryEngine struct {
	mu        sync.Mutex // Protects admission and the committed map reference.
	writer    sync.Mutex // Serializes snapshot selection through publication.
	active    sync.WaitGroup
	closed    bool
	committed map[string][]byte
}

// NewMemory creates an empty, independent, ephemeral engine.
func NewMemory() Engine {
	return &memoryEngine{committed: make(map[string][]byte)}
}

func (e *memoryEngine) begin() (map[string][]byte, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, ErrClosed
	}
	// Close sets closed under this lock before waiting, so no Add can race a
	// Wait on a zero count. The returned map and its values stay immutable.
	e.active.Add(1)
	return e.committed, nil
}

func (e *memoryEngine) View(fn func(ReadTx) error) (err error) {
	snapshot, err := e.begin()
	if err != nil {
		return err
	}
	defer e.active.Done()
	read := &memoryReadTx{records: snapshot}
	defer read.finish(&err)
	defer err2.Handle(&err, nil)
	return fn(read)
}

func (e *memoryEngine) Update(fn func(WriteTx) error) error {
	e.writer.Lock()
	defer e.writer.Unlock()
	snapshot, err := e.begin()
	if err != nil {
		return err
	}
	defer e.active.Done()

	// Only the map is cloned: Put replaces values with owned copies, and Get
	// never exposes these shared, immutable byte arrays.
	pending := maps.Clone(snapshot)
	err = func() (err error) {
		read := &memoryReadTx{records: pending}
		defer read.finish(&err)
		defer err2.Handle(&err, nil)
		return fn(&memoryWriteTx{memoryReadTx: read})
	}()
	if err != nil {
		return err
	}
	// Publish only after recovery and finish return successfully. Unexpected
	// panics unwind past this point, even when the named callback error is nil.
	e.mu.Lock()
	e.committed = pending
	e.mu.Unlock()
	return nil
}

func (e *memoryEngine) Close() error {
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
	e.active.Wait()
	e.mu.Lock()
	e.committed = nil
	e.mu.Unlock()
	return nil
}

// Separate concrete types prevent a View handle from asserting to WriteTx.
type memoryReadTx struct {
	records map[string][]byte
	err     error
}

type memoryWriteTx struct {
	*memoryReadTx
}

func (tx *memoryReadTx) finish(err *error) {
	tx.records = nil
	if *err == nil {
		*err = tx.err
	} else if tx.err != nil && !errors.Is(*err, tx.err) {
		*err = errors.Join(*err, tx.err)
	}
}

func (tx *memoryReadTx) check(key []byte) error {
	if tx.records == nil {
		return ErrTxClosed
	}
	if tx.err != nil {
		return tx.err
	}
	if len(key) == 0 {
		tx.err = ErrEmptyKey
		return tx.err
	}
	return nil
}

func (tx *memoryReadTx) Get(key []byte) ([]byte, bool, error) {
	if err := tx.check(key); err != nil {
		return nil, false, err
	}
	value, found := tx.records[string(key)]
	return bytes.Clone(value), found, nil
}

func (tx *memoryWriteTx) Put(key, value []byte) error {
	if err := tx.check(key); err != nil {
		return err
	}
	owned := make([]byte, len(value))
	copy(owned, value)
	tx.records[string(key)] = owned
	return nil
}

func (tx *memoryWriteTx) Delete(key []byte) error {
	if err := tx.check(key); err != nil {
		return err
	}
	delete(tx.records, string(key))
	return nil
}
