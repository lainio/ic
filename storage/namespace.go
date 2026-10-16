package storage

import (
	"bytes"
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/engine"
)

// ReadNS reads one logical namespace through an open Vault. Handles are valid
// only inside the transaction callback and must not be used concurrently. All
// handles share the first failure, even if ignored; after exit ErrTxClosed wins.
// Names are opaque nonempty byte segments: slashes and metadata names are literal.
// Names/tree structure remain visible, unauthenticated metadata. Presence grants
// no application authority and provides no deletion or replay protection.
type ReadNS interface {
	// Get returns verified, caller-owned bytes. Absence is nil, false, nil;
	// empty values are present. Errors return nil, false, err. Keys are nonempty.
	Get(key []byte) (value []byte, found bool, err error)
	// HasChild probes without creating state. Absence is false, nil.
	HasChild(name []byte) (found bool, err error)
	// Child opens an existing child with read-only capabilities, including in
	// Update. Absence returns ErrNamespaceNotFound and fails the transaction.
	Child(name []byte) (ns ReadNS, err error)
	// Each streams verified direct records, including empty values, in
	// unspecified order. Keys/values are caller-owned. Children are skipped.
	// Callback errors stop delivery and fail the transaction. Earlier deliveries
	// and external callback effects cannot be undone by a later failure.
	// Mutating this namespace during iteration is unsupported; reading it and
	// updating a separate sibling in the same Update are supported.
	Each(fn func(key, value []byte) (err error)) (err error)
}

// WriteNS adds atomic mutations in the same transaction. Records and children
// share logical names; wrong-kind access returns ErrConflict. Empty names return
// ErrEmptyName. Retained name/path bytes are copied; record inputs are not retained.
type WriteNS interface {
	ReadNS
	// ChildForUpdate opens only an existing immediate child.
	ChildForUpdate(name []byte) (ns WriteNS, err error)
	// EnsureChild creates or opens an immediate child, without spending a seal.
	EnsureChild(name []byte) (ns WriteNS, err error)
	// Put verifies any existing record, then seals even an empty value. A seal
	// spends allowance even if the transaction aborts or the backend write fails.
	Put(key, value []byte) (err error)
	// Delete verifies and deletes records only. Absence succeeds without creating
	// containers. It spends no seals, including with a zero sealing allowance.
	Delete(key []byte) (err error)
}

const vaultChildren = "\x02"

var errLookupTokenLength = errors.New("storage: invalid lookup token length")

// Probe every time: another handle may have created this container since the
// last read. A missing container is empty; wrong-kind state is never repaired.
func (tx *readTx) container(name string) (ns engine.ReadNS, err error) {
	defer err2.Handle(&err, nil)
	if !try.To1(tx.node.HasChild([]byte(name))) {
		return nil, nil
	}
	return tx.node.Child([]byte(name))
}

func (tx *readTx) hasChild(name []byte) (found bool, err error) {
	defer err2.Handle(&err, nil)
	children := try.To1(tx.container(vaultChildren))
	if children == nil {
		return false, nil
	}
	return children.HasChild(name)
}

func (tx *readTx) recordName(key []byte) (err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()
	assert.ThatNot(try.To1(tx.hasChild(key)), ErrConflict)
	return nil
}

// Validate the full candidate context before even probing absence. Authenticate
// a record occupying this name before classifying it as a logical conflict.
func (tx *readTx) childPath(name []byte) (path [][]byte, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()
	assert.That(len(name) != 0, ErrEmptyName)
	path = make([][]byte, len(tx.path)+1)
	copy(path, tx.path)
	path[len(tx.path)] = bytes.Clone(name)
	try.To(tx.scope.ValidatePath(path))
	token := try.To1(tx.scope.Token(tx.path, name))
	_, found := try.To2(tx.open(token, name))
	assert.ThatNot(found, ErrConflict)
	return path, nil
}

func (tx *readTx) HasChild(name []byte) (found bool, err error) {
	if err := tx.check(); err != nil {
		return false, err
	}
	defer err2.Handle(&err, tx.fail)
	try.To1(tx.childPath(name))
	return tx.hasChild(name)
}

func (tx *readTx) Child(name []byte) (ns ReadNS, err error) {
	if err := tx.check(); err != nil {
		return nil, err
	}
	defer err2.Handle(&err, tx.fail)
	defer assert.PushAsserter(assert.Plain)()
	path := try.To1(tx.childPath(name))
	assert.That(try.To1(tx.hasChild(name)), ErrNamespaceNotFound)
	children := try.To1(tx.container(vaultChildren))
	node := try.To1(children.Child(name))
	return &readTx{txState: tx.txState, node: node, path: path}, nil
}

func (tx *writeTx) ChildForUpdate(name []byte) (ns WriteNS, err error) {
	return tx.writeChild(name, false)
}

func (tx *writeTx) EnsureChild(name []byte) (ns WriteNS, err error) {
	return tx.writeChild(name, true)
}

func (tx *writeTx) writeChild(name []byte, create bool) (ns WriteNS, err error) {
	if err := tx.check(); err != nil {
		return nil, err
	}
	defer err2.Handle(&err, tx.fail)
	defer assert.PushAsserter(assert.Plain)()
	path := try.To1(tx.childPath(name))
	found := try.To1(tx.hasChild(name))
	assert.That(found || create, ErrNamespaceNotFound)
	var node engine.WriteNS
	if found {
		children := try.To1(tx.state.ChildForUpdate([]byte(vaultChildren)))
		node = try.To1(children.ChildForUpdate(name))
	} else {
		children := try.To1(tx.state.EnsureChild([]byte(vaultChildren)))
		node = try.To1(children.EnsureChild(name))
	}
	return &writeTx{readTx: &readTx{txState: tx.txState, node: node, path: path}, state: node}, nil
}

func (tx *readTx) Each(fn func(key, value []byte) (err error)) (err error) {
	if err := tx.check(); err != nil {
		return err
	}
	defer err2.Handle(&err, tx.fail)
	records := try.To1(tx.container(vaultRecords))
	if records == nil {
		return nil
	}
	return records.Each(func(token, envelope []byte) (err error) {
		defer err2.Handle(&err, tx.fail)
		defer assert.PushAsserter(assert.Plain)()
		assert.SLen(token, 32, errLookupTokenLength)
		key, value := try.To2(tx.scope.Open(tx.path, [32]byte(token), nil, envelope))
		try.To(tx.recordName(key))
		try.To(fn(key, value))
		return tx.check() // The callback may have ignored a sibling's failure.
	})
}
