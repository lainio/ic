package engine

import (
	"bytes"
	"maps"
	"sync"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

type memoryEngine struct {
	mu        sync.Mutex // Protects admission and the committed tree reference.
	writer    sync.Mutex // Serializes snapshot selection through publication.
	active    sync.WaitGroup
	closed    bool
	committed *memoryNamespace
}

type memoryNamespace struct {
	records  map[string][]byte
	children map[string]*memoryNamespace
}

func newMemoryNamespace() *memoryNamespace {
	return &memoryNamespace{
		records:  make(map[string][]byte),
		children: make(map[string]*memoryNamespace),
	}
}

func (ns *memoryNamespace) clone() *memoryNamespace {
	pending := &memoryNamespace{
		records:  maps.Clone(ns.records),
		children: make(map[string]*memoryNamespace, len(ns.children)),
	}
	for name, child := range ns.children {
		pending.children[name] = child.clone()
	}
	return pending
}

// NewMemory creates an empty, independent, ephemeral engine.
func NewMemory() Engine {
	return &memoryEngine{committed: newMemoryNamespace()}
}

func (e *memoryEngine) begin() (*memoryNamespace, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, ErrClosed
	}
	// Close sets closed under this lock before waiting, so no Add can race a
	// Wait on a zero count. The returned tree and its values stay immutable.
	e.active.Add(1)
	return e.committed, nil
}

func (e *memoryEngine) View(fn func(ReadTx) error) (err error) {
	snapshot, err := e.begin()
	if err != nil {
		return err
	}
	defer e.active.Done()
	read := &memoryReadTx{txState: &txState{}, ns: snapshot}
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

	// Clone every map in the tree. Byte arrays remain shared and immutable:
	// Put replaces values with owned copies; reads never expose stored bytes.
	pending := snapshot.clone()
	err = func() (err error) {
		read := &memoryReadTx{txState: &txState{}, ns: pending}
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
	*txState
	ns *memoryNamespace
}

type memoryWriteTx struct {
	*memoryReadTx
}

func (tx *memoryReadTx) checkKey(key []byte) error {
	if err := tx.checkName(key, ErrEmptyKey); err != nil {
		return err
	}
	if tx.ns.children[string(key)] != nil {
		return tx.fail(ErrConflict)
	}
	return nil
}

func (tx *memoryReadTx) Get(key []byte) ([]byte, bool, error) {
	if err := tx.checkKey(key); err != nil {
		return nil, false, err
	}
	value, found := tx.ns.records[string(key)]
	return bytes.Clone(value), found, nil
}

func (tx *memoryReadTx) child(name []byte) (*memoryReadTx, error) {
	if err := tx.checkName(name, ErrEmptyName); err != nil {
		return nil, err
	}
	if _, found := tx.ns.records[string(name)]; found {
		return nil, tx.fail(ErrConflict)
	}
	child := tx.ns.children[string(name)]
	if child == nil {
		return nil, tx.fail(ErrNamespaceNotFound)
	}
	return &memoryReadTx{txState: tx.txState, ns: child}, nil
}

func (tx *memoryReadTx) Child(name []byte) (ns ReadNS, err error) {
	defer err2.Handle(&err, nil)
	return try.To1(tx.child(name)), nil
}

func (tx *memoryReadTx) HasChild(name []byte) (bool, error) {
	if err := tx.checkName(name, ErrEmptyName); err != nil {
		return false, err
	}
	if _, found := tx.ns.records[string(name)]; found {
		return false, tx.fail(ErrConflict)
	}
	return tx.ns.children[string(name)] != nil, nil
}

func (tx *memoryReadTx) Each(fn func(key, value []byte) error) error {
	if err := tx.check(); err != nil {
		return err
	}
	for key, value := range tx.ns.records {
		if err := tx.fail(fn([]byte(key), bytes.Clone(value))); err != nil {
			return err
		}
	}
	return nil
}

func (tx *memoryWriteTx) ChildForUpdate(name []byte) (ns WriteNS, err error) {
	defer err2.Handle(&err, nil)
	child := try.To1(tx.child(name))
	return &memoryWriteTx{memoryReadTx: child}, nil
}

func (tx *memoryWriteTx) EnsureChild(name []byte) (WriteNS, error) {
	if err := tx.checkName(name, ErrEmptyName); err != nil {
		return nil, err
	}
	if _, found := tx.ns.records[string(name)]; found {
		return nil, tx.fail(ErrConflict)
	}
	child := tx.ns.children[string(name)]
	if child == nil {
		child = newMemoryNamespace()
		tx.ns.children[string(name)] = child
	}
	return &memoryWriteTx{memoryReadTx: &memoryReadTx{txState: tx.txState, ns: child}}, nil
}

func (tx *memoryWriteTx) Put(key, value []byte) error {
	if err := tx.checkKey(key); err != nil {
		return err
	}
	owned := make([]byte, len(value))
	copy(owned, value)
	tx.ns.records[string(key)] = owned
	return nil
}

func (tx *memoryWriteTx) Delete(key []byte) error {
	if err := tx.checkKey(key); err != nil {
		return err
	}
	delete(tx.ns.records, string(key))
	return nil
}
