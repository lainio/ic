package storage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/engine"
)

func TestVaultNamespaces(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) *Database
	}{
		{"memory", func(_ *testing.T) *Database { return NewMemory() }},
		{"bbolt", func(t *testing.T) *Database {
			return try.To1(OpenBolt(filepath.Join(t.TempDir(), "namespaces.db")))
		}},
	} {
		t.Run(backend.name, func(t *testing.T) {
			t.Run("data", func(t *testing.T) { vaultNamespacesData(t, backend.open) })
			t.Run("atomic", func(t *testing.T) { vaultNamespacesAtomic(t, backend.open) })
			t.Run("conflicts", func(t *testing.T) { vaultNamespacesConflicts(t, backend.open) })
			t.Run("raw_kind", func(t *testing.T) { vaultNamespacesRawKind(t, backend.open) })
			t.Run("path_bounds", func(t *testing.T) { vaultNamespacesPathBounds(t, backend.open) })
			t.Run("iteration", func(t *testing.T) { vaultNamespacesIteration(t, backend.open) })
			t.Run("context", func(t *testing.T) { vaultNamespacesContext(t, backend.open) })
			if backend.name == "memory" {
				t.Run("snapshot", vaultNamespacesSnapshot)
			} else {
				t.Run("persistence", vaultNamespacesPersistence)
			}
		})
	}
}

// Explicit physical traversal, independent of the facade's constants/path code.
func rawNamespace(root engine.ReadNS, vault VaultID, path ...[]byte) (ns engine.ReadNS, err error) {
	defer err2.Handle(&err, nil)
	collection := try.To1(root.Child([]byte("vaults")))
	ns = try.To1(collection.Child(vault[:]))
	for _, name := range path {
		children := try.To1(ns.Child([]byte{2}))
		ns = try.To1(children.Child(name))
	}
	return ns, nil
}

func vaultNamespacesData(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	db := open(t)
	t.Cleanup(func() { _ = db.Close() })
	v, p := newRecordVault(t, db, VaultID{1}, 20)
	empty := func(ns ReadNS) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, ns, []byte("missing"), nil, false)
		assert.ThatNot(try.To1(ns.HasChild([]byte("missing"))))
		return ns.Each(func([]byte, []byte) error {
			t.Fatal("empty namespace delivered a record")
			return nil
		})
	}
	try.To(v.View(func(tx ReadTx) error { return empty(tx) }))
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(empty(tx))
		return tx.Delete([]byte("missing"))
	}))
	try.To(db.engine.View(func(root engine.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(rawNamespace(root, v.vault))
		assert.ThatNot(try.To1(ns.HasChild([]byte{1})))
		assert.ThatNot(try.To1(ns.HasChild([]byte{2})))
		return nil
	}))
	key := []byte("key")
	literalNames := [][]byte{[]byte("/"), []byte("."), []byte(".."), []byte("vaults"), []byte("manifest"), {1}, {2}, {3}, {0, 255}}
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(tx.Put(key, []byte("root")))
		name := []byte("left")
		left := try.To1(tx.EnsureChild(name))
		name[0] = 'X'
		assert.ThatNot(try.To1(tx.HasChild(name)))
		name = []byte("left")
		read := try.To1(tx.Child(name))
		name[0] = 'Y'
		_, writable := read.(WriteNS)
		assert.ThatNot(writable)
		_, raw := any(read).(engine.ReadNS)
		assert.ThatNot(raw)
		try.To(empty(read))
		try.To(left.Put(key, []byte("left")))
		checkRecord(t, read, key, []byte("left"), true)
		assert.ThatNot(try.To1(read.HasChild([]byte("deep"))))
		deep := try.To1(left.EnsureChild([]byte("deep")))
		assert.That(try.To1(read.HasChild([]byte("deep"))))
		deepRead := try.To1(read.Child([]byte("deep")))
		try.To(deep.Put(key, nil))
		checkRecord(t, deepRead, key, nil, true)
		name = []byte("left")
		again := try.To1(tx.ChildForUpdate(name))
		name[0] = 'Z'
		try.To(again.Put(key, []byte("updated")))
		checkRecord(t, left, key, []byte("updated"), true)
		right := try.To1(tx.EnsureChild([]byte("right")))
		try.To(right.Put(key, []byte("right")))
		try.To1(tx.EnsureChild([]byte("empty")))
		for _, name := range literalNames {
			ns := try.To1(tx.EnsureChild(name))
			try.To(ns.Put(key, name))
		}
		return nil
	}))
	try.To(v.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, key, []byte("root"), true)
		left := try.To1(tx.Child([]byte("left")))
		checkRecord(t, left, key, []byte("updated"), true)
		checkRecord(t, try.To1(left.Child([]byte("deep"))), key, nil, true)
		checkRecord(t, try.To1(tx.Child([]byte("right"))), key, []byte("right"), true)
		for _, name := range literalNames {
			checkRecord(t, try.To1(tx.Child(name)), key, name, true)
		}
		return empty(try.To1(tx.Child([]byte("empty"))))
	}))
	try.To(db.engine.View(func(root engine.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		empty := try.To1(rawNamespace(root, v.vault, []byte("empty")))
		assert.ThatNot(try.To1(empty.HasChild([]byte{1})))
		assert.ThatNot(try.To1(empty.HasChild([]byte{2})))
		deep := try.To1(rawNamespace(root, v.vault, []byte("left"), []byte("deep")))
		assert.ThatNot(try.To1(deep.HasChild([]byte{3})))
		records := try.To1(deep.Child([]byte{1}))
		path := [][]byte{{1}, []byte("left"), []byte("deep")}
		token := try.To1(v.scope.Token(path, key))
		envelope, found := try.To2(records.Get(token[:]))
		assert.That(found)
		openedKey, value := try.To2(v.scope.Open(path, token, key, envelope))
		assert.Equal(bytes.Equal(openedKey, key), true)
		assert.SLen(value, 0)
		return nil
	}))
	spent := p.spent
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		left := try.To1(tx.ChildForUpdate([]byte("left")))
		deep := try.To1(left.ChildForUpdate([]byte("deep")))
		for _, ns := range []WriteNS{tx, left, deep} {
			try.To(ns.Delete(key))
			checkRecord(t, ns, key, nil, false)
			try.To(ns.Delete(key))
		}
		checkRecord(t, try.To1(tx.Child([]byte("right"))), key, []byte("right"), true)
		return nil
	}))
	assert.Equal(p.spent, spent)
	assert.Equal(p.consumeCalls, int(p.spent))
	try.To(db.Close())
}

func checkNamespaceFailure(t *testing.T, ns ReadNS, want error) {
	t.Helper()
	assert.INotNil(ns)
	value, found, err := ns.Get(nil)
	assert.SNil(value)
	assert.ThatNot(found)
	assert.Equal(err, want)
	found, err = ns.HasChild(nil)
	assert.ThatNot(found)
	assert.Equal(err, want)
	child, err := ns.Child(nil)
	assert.INil(child)
	assert.Equal(err, want)
	assert.Equal(ns.Each(func([]byte, []byte) error {
		t.Fatal("failed or expired namespace invoked Each callback")
		return nil
	}), want)
	if write, ok := ns.(WriteNS); ok {
		assert.Equal(write.Put(nil, nil), want)
		assert.Equal(write.Delete(nil), want)
		child, err := write.ChildForUpdate(nil)
		assert.INil(child)
		assert.Equal(err, want)
		child, err = write.EnsureChild(nil)
		assert.INil(child)
		assert.Equal(err, want)
	}
}

func vaultNamespacesAtomic(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	db := open(t)
	t.Cleanup(func() { _ = db.Close() })
	v, p := newRecordVault(t, db, VaultID{1}, 6)
	key := []byte("key")
	var saved []ReadNS
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		left := try.To1(tx.EnsureChild([]byte("left")))
		right := try.To1(tx.EnsureChild([]byte("right")))
		for _, ns := range []WriteNS{tx, left, right} {
			try.To(ns.Put(key, []byte("original")))
			saved = append(saved, ns)
		}
		saved = append(saved, try.To1(tx.Child([]byte("left"))))
		return nil
	}))
	for _, ns := range saved {
		checkNamespaceFailure(t, ns, ErrTxClosed)
	}
	saved = nil
	outer := errors.New("independent outer failure")
	var first error
	result := v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		left := try.To1(tx.ChildForUpdate([]byte("left")))
		right := try.To1(tx.ChildForUpdate([]byte("right")))
		created := try.To1(left.EnsureChild([]byte("created")))
		read := try.To1(left.Child([]byte("created")))
		saved = []ReadNS{tx, left, right, created, read}
		for _, ns := range []WriteNS{tx, left, created} {
			try.To(ns.Put(key, []byte("pending")))
		}
		try.To(right.Delete(key))
		first = created.Put([]byte("exhausted"), nil)
		assert.ErrorIs(first, ErrKeyUsageExhausted)
		for _, ns := range saved {
			checkNamespaceFailure(t, ns, first)
		}
		return outer
	})
	assert.ErrorIs(result, first)
	assert.ErrorIs(result, outer)
	for _, ns := range saved {
		checkNamespaceFailure(t, ns, ErrTxClosed)
	}
	assert.Equal(p.spent, uint32(7), "rolled-back seals stay spent")
	assert.Equal(p.consumeCalls, int(p.spent)+1)
	assert.Equal(len(p.calls), 2)
	try.To(v.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		left := try.To1(tx.Child([]byte("left")))
		right := try.To1(tx.Child([]byte("right")))
		saved = []ReadNS{tx, left, right}
		for _, ns := range saved {
			checkRecord(t, ns, key, []byte("original"), true)
		}
		assert.ThatNot(try.To1(left.HasChild([]byte("created"))))
		return nil
	}))
	for _, ns := range saved {
		checkNamespaceFailure(t, ns, ErrTxClosed)
	}
	// An exhausted shared budget permits metadata creation and verified deletion.
	zero := try.To1(db.OpenVault(context.Background(), v.vault, KeyID{7}, p))
	try.To(zero.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		left := try.To1(tx.ChildForUpdate([]byte("left")))
		try.To1(left.EnsureChild([]byte("allowed")))
		return left.Delete(key)
	}))
	try.To(zero.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		left := try.To1(tx.Child([]byte("left")))
		assert.That(try.To1(left.HasChild([]byte("allowed"))))
		checkRecord(t, left, key, nil, false)
		return nil
	}))
	assert.Equal(p.spent, uint32(7))
	try.To(db.Close())
}

func vaultNamespacesConflicts(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	db := open(t)
	t.Cleanup(func() { _ = db.Close() })
	v, p := newRecordVault(t, db, VaultID{1}, 2)
	assert.Equal(ErrEmptyName, engine.ErrEmptyName)
	assert.Equal(ErrNamespaceNotFound, engine.ErrNamespaceNotFound)
	assert.Equal(ErrConflict, engine.ErrConflict)
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.EnsureChild([]byte("parent")))
		try.To(ns.Put([]byte("full"), []byte("value")))
		try.To(ns.Put([]byte("empty"), nil))
		try.To1(ns.EnsureChild([]byte("child")))
		return nil
	}))
	for _, op := range []struct {
		name string
		call func(WriteNS, []byte) error
	}{
		{"probe", func(ns WriteNS, key []byte) error { _, err := ns.HasChild(key); return err }},
		{"child", func(ns WriteNS, key []byte) error { _, err := ns.Child(key); return err }},
		{"write_child", func(ns WriteNS, key []byte) error { _, err := ns.ChildForUpdate(key); return err }},
		{"ensure", func(ns WriteNS, key []byte) error { _, err := ns.EnsureChild(key); return err }},
	} {
		t.Run(op.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			for _, tc := range []struct {
				name []byte
				want error
			}{{nil, ErrEmptyName}, {[]byte("full"), ErrConflict}, {[]byte("empty"), ErrConflict}} {
				assert.Equal(v.Update(func(tx WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					ns := try.To1(tx.ChildForUpdate([]byte("parent")))
					assert.Equal(op.call(ns, tc.name), tc.want)
					checkNamespaceFailure(t, tx, tc.want)
					return nil
				}), tc.want)
			}
		})
	}
	for _, op := range []func(WriteNS) error{
		func(ns WriteNS) error { _, _, err := ns.Get([]byte("child")); return err },
		func(ns WriteNS) error { return ns.Put([]byte("child"), nil) },
		func(ns WriteNS) error { return ns.Delete([]byte("child")) },
	} {
		assert.Equal(v.Update(func(tx WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			return op(try.To1(tx.ChildForUpdate([]byte("parent"))))
		}), ErrConflict)
	}
	for _, writable := range []bool{false, true} {
		assert.Equal(v.Update(func(tx WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			ns := try.To1(tx.ChildForUpdate([]byte("parent")))
			if writable {
				_, err = ns.ChildForUpdate([]byte("absent"))
			} else {
				_, err = ns.Child([]byte("absent"))
			}
			assert.Equal(err, ErrNamespaceNotFound)
			checkNamespaceFailure(t, tx, err)
			return nil
		}), ErrNamespaceNotFound)
	}
	try.To(v.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.Child([]byte("parent")))
		checkRecord(t, ns, []byte("full"), []byte("value"), true)
		checkRecord(t, ns, []byte("empty"), nil, true)
		assert.That(try.To1(ns.HasChild([]byte("child"))))
		assert.ThatNot(try.To1(ns.HasChild([]byte("absent"))))
		return nil
	}))
	assert.Equal(p.spent, uint32(3))
	try.To(db.Close())
}

func vaultNamespacesPathBounds(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	db := open(t)
	t.Cleanup(func() { _ = db.Close() })
	v, p := newRecordVault(t, db, VaultID{1}, 0)
	// Representative codec bounds, including the prefix's segment and bytes.
	for _, tc := range []struct {
		name string
		path [][]byte
		bad  []byte
	}{
		{"segment", nil, make([]byte, 1025)},
		{"depth", bytesToSegments(63, []byte("d")), []byte("overflow")},
		{"encoded_size", bytesToSegments(15, make([]byte, 1024)), make([]byte, 932)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			try.To(v.Update(func(tx WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				var ns WriteNS = tx
				for _, name := range tc.path {
					ns = try.To1(ns.EnsureChild(name))
				}
				return nil
			}))
			path := append([][]byte{{1}}, tc.path...)
			path = append(path, tc.bad)
			want := v.scope.ValidatePath(path)
			assert.Error(want)
			for _, op := range []func(WriteNS) error{
				func(ns WriteNS) error { _, err := ns.HasChild(tc.bad); return err },
				func(ns WriteNS) error { _, err := ns.Child(tc.bad); return err },
				func(ns WriteNS) error { _, err := ns.ChildForUpdate(tc.bad); return err },
				func(ns WriteNS) error { _, err := ns.EnsureChild(tc.bad); return err },
			} {
				assert.Equal(v.Update(func(tx WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					var ns WriteNS = tx
					for _, name := range tc.path {
						ns = try.To1(ns.ChildForUpdate(name))
					}
					return op(ns)
				}), want)
			}
			try.To(db.engine.View(func(root engine.ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(rawNamespace(root, v.vault, tc.path...))
				assert.ThatNot(try.To1(ns.HasChild([]byte{1})))
				// The root may already have valid children from another case.
				if try.To1(ns.HasChild([]byte{2})) {
					children := try.To1(ns.Child([]byte{2}))
					assert.ThatNot(try.To1(children.HasChild(tc.bad)))
				}
				return nil
			}))
		})
	}
	assert.Equal(p.spent, uint32(1))
	try.To(db.Close())
}

func vaultNamespacesRawKind(t *testing.T, open func(*testing.T) *Database) {
	for _, prefix := range []byte{1, 2} {
		t.Run(string('0'+prefix), func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			t.Cleanup(func() { _ = db.Close() })
			v, p := newRecordVault(t, db, VaultID{1}, 0)
			try.To(v.Update(func(tx WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				try.To1(tx.EnsureChild([]byte("broken")))
				return nil
			}))
			try.To(db.engine.Update(func(root engine.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(rawNamespaceForUpdate(root, v.vault, []byte("broken")))
				return ns.Put([]byte{prefix}, nil)
			}))
			assert.Equal(v.Update(func(tx WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(tx.ChildForUpdate([]byte("broken")))
				_, cause := ns.EnsureChild([]byte("new"))
				assert.Equal(cause, ErrConflict)
				checkNamespaceFailure(t, tx, cause)
				return nil
			}), ErrConflict)
			try.To(db.engine.View(func(root engine.ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(rawNamespace(root, v.vault, []byte("broken")))
				value, found := try.To2(ns.Get([]byte{prefix}))
				assert.That(found)
				assert.SLen(value, 0)
				return nil
			}))
			assert.Equal(p.spent, uint32(1))
			try.To(db.Close())
		})
	}
}

func bytesToSegments(count int, segment []byte) [][]byte {
	path := make([][]byte, count)
	for i := range path {
		path[i] = segment
	}
	return path
}

func namespaceManifest(t *testing.T, v *Vault) []byte {
	t.Helper()
	var envelope []byte
	try.To(v.db.engine.View(func(root engine.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(rawNamespace(root, v.vault))
		metadata := try.To1(ns.Child([]byte{3}))
		token := try.To1(v.scope.Token([][]byte{{3}}, []byte("manifest")))
		var found bool
		envelope, found = try.To2(metadata.Get(token[:]))
		assert.That(found)
		return nil
	}))
	return envelope
}

func vaultNamespacesIteration(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	db := open(t)
	t.Cleanup(func() { _ = db.Close() })
	v, p := newRecordVault(t, db, VaultID{1}, 9)
	manifest := namespaceManifest(t, v)
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(tx.Put([]byte("root"), []byte("original")))
		left := try.To1(tx.EnsureChild([]byte("left")))
		try.To(left.Put([]byte("key"), []byte("value")))
		try.To(left.Put([]byte("empty"), nil))
		deep := try.To1(left.EnsureChild([]byte("deep")))
		try.To(deep.Put([]byte("hidden"), []byte("descendant")))
		try.To1(tx.EnsureChild([]byte("right")))
		return nil
	}))
	var retained [][2][]byte
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		rootCount := 0
		try.To(tx.Each(func(key, value []byte) error {
			rootCount++
			assert.Equal(string(key), "root")
			assert.Equal(string(value), "original")
			return nil
		}))
		assert.Equal(rootCount, 1)
		left := try.To1(tx.Child([]byte("left")))
		right := try.To1(tx.ChildForUpdate([]byte("right")))
		seen := make(map[string]string)
		try.To(left.Each(func(key, value []byte) (err error) {
			defer err2.Handle(&err, nil)
			_, duplicate := seen[string(key)]
			assert.ThatNot(duplicate)
			seen[string(key)] = string(value)
			checkRecord(t, left, key, value, true)
			retained = append(retained, [2][]byte{key, value})
			return right.Put(key, value)
		}))
		assert.Equal(len(seen), 2)
		assert.Equal(seen["key"], "value")
		empty, present := seen["empty"]
		assert.That(present)
		assert.Equal(empty, "")
		try.To(left.Each(func(key, value []byte) error {
			key[0] = 'X'
			if len(value) != 0 {
				value[0] = 'X'
			}
			return nil
		}))
		checkRecord(t, left, []byte("key"), []byte("value"), true)
		checkRecord(t, right, []byte("key"), []byte("value"), true)
		checkRecord(t, left, []byte("empty"), nil, true)
		return nil
	}))
	for _, mode := range []string{"callback", "ignored_sibling", "panic"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			want := errors.New("stop iteration")
			var saved ReadNS
			marker := &struct{ message string }{"intentional Each panic"}
			var caught any
			var result error
			calls := 0
			func() {
				defer func() { caught = recover() }()
				result = v.Update(func(tx WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					try.To(tx.Put([]byte("root"), []byte("pending")))
					left := try.To1(tx.ChildForUpdate([]byte("left")))
					right := try.To1(tx.ChildForUpdate([]byte("right")))
					try.To1(right.EnsureChild([]byte("pending")))
					saved = left
					got := left.Each(func([]byte, []byte) error {
						calls++
						switch mode {
						case "ignored_sibling":
							want = right.Put(nil, nil)
							assert.Error(want)
							return nil
						case "panic":
							panic(marker) // Intentionally propagates through Each.
						default:
							return want
						}
					})
					assert.Equal(got, want)
					checkNamespaceFailure(t, tx, want)
					return nil // Even an ignored Each error aborts pending writes.
				})
			}()
			assert.Equal(calls, 1)
			if mode == "panic" {
				assert.Equal(caught, any(marker))
			} else {
				assert.INil(caught)
				assert.Equal(result, want)
			}
			checkNamespaceFailure(t, saved, ErrTxClosed)
			try.To(v.View(func(tx ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				checkRecord(t, tx, []byte("root"), []byte("original"), true)
				right := try.To1(tx.Child([]byte("right")))
				assert.ThatNot(try.To1(right.HasChild([]byte("pending"))))
				checkRecord(t, right, []byte("key"), []byte("value"), true)
				return nil
			}))
		})
	}
	assert.Equal(p.spent, uint32(10))
	assert.Equal(bytes.Equal(namespaceManifest(t, v), manifest), true)
	try.To(db.Close())
	assert.Equal(len(retained), 2)
	for _, pair := range retained {
		if string(pair[0]) == "empty" {
			assert.SLen(pair[1], 0)
		} else {
			assert.Equal(string(pair[0]), "key")
			assert.Equal(string(pair[1]), "value")
		}
	}
}

func rawNamespaceForUpdate(root engine.WriteNS, vault VaultID, path ...[]byte) (ns engine.WriteNS, err error) {
	defer err2.Handle(&err, nil)
	collection := try.To1(root.ChildForUpdate([]byte("vaults")))
	ns = try.To1(collection.ChildForUpdate(vault[:]))
	for _, name := range path {
		children := try.To1(ns.ChildForUpdate([]byte{2}))
		ns = try.To1(children.ChildForUpdate(name))
	}
	return ns, nil
}

func vaultNamespacesContext(t *testing.T, open func(*testing.T) *Database) {
	for _, mode := range []string{"relocated", "tampered", "malformed_token", "token_payload", "child_conflict"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			t.Cleanup(func() { _ = db.Close() })
			// One manifest, one valid record, one fixture encryption if needed.
			p := newLifecycleProvider(t, 3)
			vault, id := VaultID{1}, KeyID{7}
			try.To(db.CreateVault(context.Background(), vault, id, p))
			v := try.To1(db.OpenVault(context.Background(), vault, id, p))
			manifest := namespaceManifest(t, v)
			key := []byte("key")
			try.To(v.Update(func(tx WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				source := try.To1(tx.EnsureChild([]byte("source")))
				try.To1(tx.EnsureChild([]byte("target")))
				return source.Put(key, []byte("value"))
			}))
			path := [][]byte{{1}, []byte("source")}
			token := try.To1(v.scope.Token(path, key))
			var envelope []byte
			try.To(db.engine.View(func(root engine.ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(rawNamespace(root, vault, path[1]))
				records := try.To1(ns.Child([]byte{1}))
				var found bool
				envelope, found = try.To2(records.Get(token[:]))
				assert.That(found)
				return nil
			}))
			switch mode {
			case "relocated", "malformed_token":
				path[1] = []byte("target")
				token = try.To1(v.scope.Token(path, key))
			case "tampered":
				envelope[len(envelope)-1] ^= 1
			case "token_payload":
				// Craft exactly one authenticated inconsistency using the accepted
				// wire format. No production/test-exported codec bypass is added.
				var info []byte
				for _, field := range [][]byte{[]byte("ms/v1/enc"), vault[:], id[:]} {
					info = binary.BigEndian.AppendUint32(info, uint32(len(field)))
					info = append(info, field...)
				}
				ke := try.To1(hkdf.Key(sha256.New, p.secret, []byte("ms/v1/hkdf"), string(info), 32))
				defer clear(ke)
				block := try.To1(aes.NewCipher(ke))
				aead := try.To1(cipher.NewGCMWithRandomNonce(block))
				encoded := binary.BigEndian.AppendUint32(nil, 16)
				encoded = append(encoded, vault[:]...)
				encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(path)))
				for _, segment := range path {
					encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(segment)))
					encoded = append(encoded, segment...)
				}
				var aad []byte
				for _, field := range [][]byte{[]byte("ms/v1/record"), envelope[:22], encoded, token[:]} {
					aad = binary.BigEndian.AppendUint32(aad, uint32(len(field)))
					aad = append(aad, field...)
				}
				payload := try.To1(aead.Open(nil, nil, envelope[22:], aad))
				assert.Equal(string(payload[4:7]), "key")
				payload[4] = 'X' // Same valid lengths, a different logical key.
				try.To(v.lease.ConsumeEncryption())
				envelope = append(bytes.Clone(envelope[:22]), aead.Seal(nil, nil, payload, aad)...)
				authenticated := try.To1(aead.Open(nil, nil, envelope[22:], aad))
				assert.Equal(bytes.Equal(authenticated, payload), true)
			}
			rawToken := token[:]
			_, _, want := v.scope.Open(path, token, nil, envelope)
			switch mode {
			case "malformed_token":
				rawToken = rawToken[:31]
				want = errLookupTokenLength
			case "child_conflict":
				assert.NoError(want)
				want = ErrConflict
			default:
				assert.Error(want)
			}
			try.To(db.engine.Update(func(root engine.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(rawNamespaceForUpdate(root, vault, path[1]))
				records := try.To1(ns.EnsureChild([]byte{1}))
				try.To(records.Put(rawToken, envelope))
				if mode == "child_conflict" {
					children := try.To1(ns.EnsureChild([]byte{2}))
					try.To1(children.EnsureChild(key))
				}
				return nil
			}))
			spent := p.spent
			assert.Equal(v.View(func(tx ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(tx.Child(path[1]))
				assert.Equal(ns.Each(func([]byte, []byte) error {
					t.Fatal("rejected record reached application callback")
					return nil
				}), want)
				checkNamespaceFailure(t, tx, want)
				return nil
			}), want)
			if mode == "tampered" {
				// Child operations authenticate an occupied record before conflict.
				for _, op := range []func(WriteNS) error{
					func(ns WriteNS) error { _, err := ns.HasChild(key); return err },
					func(ns WriteNS) error { _, err := ns.Child(key); return err },
					func(ns WriteNS) error { _, err := ns.ChildForUpdate(key); return err },
					func(ns WriteNS) error { _, err := ns.EnsureChild(key); return err },
				} {
					assert.Equal(v.Update(func(tx WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						return op(try.To1(tx.ChildForUpdate(path[1])))
					}), want)
				}
			}
			try.To(db.engine.View(func(root engine.ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(rawNamespace(root, vault, path[1]))
				records := try.To1(ns.Child([]byte{1}))
				stored, found := try.To2(records.Get(rawToken))
				assert.That(found)
				assert.Equal(bytes.Equal(stored, envelope), true)
				return nil
			}))
			assert.Equal(p.spent, spent)
			assert.Equal(bytes.Equal(namespaceManifest(t, v), manifest), true)
			try.To(db.Close())
		})
	}
}

func vaultNamespacesPersistence(t *testing.T) {
	defer assert.PushTester(t)()
	path := filepath.Join(t.TempDir(), "reopen.db")
	db := try.To1(OpenBolt(path))
	t.Cleanup(func() { _ = db.Close() })
	v, p := newRecordVault(t, db, VaultID{1}, 3)
	manifest := namespaceManifest(t, v)
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(tx.Put([]byte("root"), []byte("saved")))
		parent := try.To1(tx.EnsureChild([]byte("parent")))
		deep := try.To1(parent.EnsureChild([]byte("deep")))
		return deep.Put([]byte("key"), []byte("nested"))
	}))
	stop := errors.New("rollback before reopen")
	assert.Equal(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		parent := try.To1(tx.ChildForUpdate([]byte("parent")))
		child := try.To1(parent.EnsureChild([]byte("aborted")))
		try.To(child.Put([]byte("key"), nil))
		return stop
	}), stop)
	try.To(db.Close())
	reopened := try.To1(OpenBolt(path))
	t.Cleanup(func() { _ = reopened.Close() })
	// Same provider/generation, with no counter reset or seal refund.
	v = try.To1(reopened.OpenVault(context.Background(), VaultID{1}, KeyID{7}, p))
	try.To(v.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, []byte("root"), []byte("saved"), true)
		parent := try.To1(tx.Child([]byte("parent")))
		checkRecord(t, try.To1(parent.Child([]byte("deep"))), []byte("key"), []byte("nested"), true)
		assert.ThatNot(try.To1(parent.HasChild([]byte("aborted"))))
		return nil
	}))
	assert.Equal(bytes.Equal(namespaceManifest(t, v), manifest), true)
	assert.Equal(p.remainingEncryptions, uint32(0))
	assert.Equal(p.consumeCalls, 4)
	assert.Equal(p.spent, uint32(4))
	try.To(reopened.Close())
}

func vaultNamespacesSnapshot(t *testing.T) {
	defer assert.PushTester(t)()
	db := NewMemory()
	t.Cleanup(func() { _ = db.Close() })
	v, _ := newRecordVault(t, db, VaultID{1}, 2)
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		parent := try.To1(tx.EnsureChild([]byte("parent")))
		deep := try.To1(parent.EnsureChild([]byte("deep")))
		return deep.Put([]byte("key"), []byte("old"))
	}))
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	unblock := sync.OnceFunc(func() { close(resume) })
	go func() {
		defer close(done)
		result <- v.View(func(tx ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			defer assert.PushAsserter(assert.Plain)()
			parent := try.To1(tx.Child([]byte("parent")))
			deep := try.To1(parent.Child([]byte("deep")))
			value, found := try.To2(deep.Get([]byte("key")))
			assert.That(found)
			assert.Equal(string(value), "old")
			close(entered)
			<-resume
			// Retained and newly traversed handles stay on this engine snapshot.
			for _, ns := range []ReadNS{deep, try.To1(parent.Child([]byte("deep")))} {
				value, found := try.To2(ns.Get([]byte("key")))
				assert.That(found)
				assert.Equal(string(value), "old")
			}
			assert.ThatNot(try.To1(parent.HasChild([]byte("new"))))
			return nil
		})
	}()
	t.Cleanup(func() { unblock(); lifecycleSignal(t, done) })
	lifecycleSignal(t, entered)
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		parent := try.To1(tx.ChildForUpdate([]byte("parent")))
		deep := try.To1(parent.ChildForUpdate([]byte("deep")))
		try.To(deep.Put([]byte("key"), []byte("new")))
		try.To1(parent.EnsureChild([]byte("new")))
		return nil
	}))
	unblock()
	try.To(lifecycleResult(t, result))
	lifecycleSignal(t, done)
	try.To(v.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		parent := try.To1(tx.Child([]byte("parent")))
		checkRecord(t, try.To1(parent.Child([]byte("deep"))), []byte("key"), []byte("new"), true)
		assert.That(try.To1(parent.HasChild([]byte("new"))))
		return nil
	}))
	try.To(db.Close())
}
