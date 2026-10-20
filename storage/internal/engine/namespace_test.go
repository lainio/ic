package engine

import (
	"errors"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestBoltNamespaces(t *testing.T) {
	runNamespaceContract(t, func(t *testing.T) Engine {
		return openTestBolt(t, filepath.Join(t.TempDir(), "engine.db"))
	})
}

func TestMemoryNamespaces(t *testing.T) {
	runNamespaceContract(t, openTestMemory)
}

func runNamespaceContract(t *testing.T, open func(*testing.T) Engine) {
	t.Helper()
	t.Run("presence", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		try.To(db.Update(func(tx WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			assert.ThatNot(try.To1(tx.HasChild([]byte("a/b"))))
			parent := try.To1(tx.EnsureChild([]byte("a/b")))
			assert.That(try.To1(tx.HasChild([]byte("a/b"))))
			assert.ThatNot(try.To1(tx.HasChild([]byte("a"))))
			assert.ThatNot(try.To1(parent.HasChild([]byte{0, 3})))
			child := try.To1(parent.EnsureChild([]byte{0, 3}))
			assert.That(try.To1(parent.HasChild([]byte{0, 3})))
			try.To(child.Put([]byte("key"), []byte("nested")))
			return tx.Put([]byte("root"), []byte("original"))
		}))
		try.To(db.View(func(tx ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			name := []byte("a/b")
			assert.That(try.To1(tx.HasChild(name)))
			name[0] = 'x'
			assert.ThatNot(try.To1(tx.HasChild(name)))
			assert.ThatNot(try.To1(tx.HasChild([]byte("a"))))
			parent := try.To1(tx.Child([]byte("a/b")))
			assert.That(try.To1(parent.HasChild([]byte{0, 3})))
			assert.ThatNot(try.To1(parent.HasChild([]byte("absent"))))
			child := try.To1(parent.Child([]byte{0, 3}))
			checkRecord(t, child, "key", "nested", true)
			checkRecord(t, tx, "root", "original", true)
			return nil
		}))
	})
	t.Run("presence_errors", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		seedNamespaces(t, db)
		for _, tc := range []struct {
			name []byte
			want error
		}{
			{nil, ErrEmptyName}, {[]byte{}, ErrEmptyName},
			{[]byte("key"), ErrConflict}, {[]byte("empty"), ErrConflict},
		} {
			probe := func(tx ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				left := try.To1(tx.Child([]byte("left")))
				found, err := left.HasChild(tc.name)
				assert.ThatNot(found)
				assert.Equal(err, tc.want)
				found, err = tx.HasChild([]byte("left"))
				assert.ThatNot(found)
				assert.Equal(err, tc.want)
				return nil // Real probe errors must still fail the transaction.
			}
			assert.Equal(db.View(probe), tc.want)
			assert.Equal(db.Update(func(tx WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				try.To(tx.Put([]byte("root"), []byte("pending")))
				return probe(tx)
			}), tc.want)
		}
		checkNamespaceSeed(t, db)
	})
	t.Run("traversal_and_ownership", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		try.To(db.Update(func(tx WriteTx) error {
			try.To(tx.Put([]byte("root"), []byte("original")))
			name := []byte("a")
			a := try.To1(tx.EnsureChild(name))
			name[0] = 'x'
			b := try.To1(a.EnsureChild([]byte("b")))
			try.To(b.Put([]byte("key"), []byte("nested")))
			checkRecord(t, b, "key", "nested", true)
			again := try.To1(tx.EnsureChild([]byte("a")))
			child := try.To1(again.ChildForUpdate([]byte("b")))
			checkRecord(t, child, "key", "nested", true)
			try.To(child.Put([]byte("second"), []byte("shared")))
			checkRecord(t, b, "second", "shared", true)
			read := try.To1(a.Child([]byte("b")))
			checkRecord(t, read, "key", "nested", true)
			literal := try.To1(tx.EnsureChild([]byte("a/b")))
			try.To(literal.Put([]byte("key"), []byte("literal")))
			sibling := try.To1(tx.EnsureChild([]byte("sibling")))
			try.To(sibling.Put([]byte("key"), []byte("sibling")))
			checkRecord(t, a, "key", "", false)
			checkRecord(t, tx, "key", "", false)
			return nil
		}))
		try.To(db.View(func(tx ReadTx) error {
			name := []byte("a")
			a := try.To1(tx.Child(name))
			name[0] = 'x'
			b := try.To1(a.Child([]byte("b")))
			checkRecord(t, b, "key", "nested", true)
			checkRecord(t, b, "second", "shared", true)
			literal := try.To1(tx.Child([]byte("a/b")))
			checkRecord(t, literal, "key", "literal", true)
			sibling := try.To1(tx.Child([]byte("sibling")))
			checkRecord(t, sibling, "key", "sibling", true)
			checkRecord(t, tx, "root", "original", true)
			return nil
		}))
		try.To(db.Update(func(tx WriteTx) error {
			name := []byte("a")
			a := try.To1(tx.ChildForUpdate(name))
			name[0] = 'x'
			b := try.To1(a.ChildForUpdate([]byte("b")))
			return b.Put([]byte("key"), []byte("updated"))
		}))
		try.To(db.View(func(tx ReadTx) error {
			a := try.To1(tx.Child([]byte("a")))
			b := try.To1(a.Child([]byte("b")))
			checkRecord(t, b, "key", "updated", true)
			return nil
		}))
	})
	for _, tc := range rollbackCases() {
		t.Run("atomicity/"+tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			seedNamespaces(t, db)
			var handles []WriteNS
			var err error
			panicked := capturePanic(func() {
				err = db.Update(func(tx WriteTx) error {
					left := try.To1(tx.ChildForUpdate([]byte("left")))
					right := try.To1(tx.ChildForUpdate([]byte("right")))
					created := try.To1(left.EnsureChild([]byte("new")))
					deep := try.To1(created.EnsureChild([]byte("deep")))
					handles = []WriteNS{tx, left, right, created, deep}
					try.To(tx.Put([]byte("root"), []byte("pending")))
					try.To(left.Put([]byte("key"), []byte("pending")))
					try.To(right.Delete([]byte("key")))
					try.To(deep.Put([]byte("key"), []byte("pending")))
					return tc.finish(deep)
				})
			})
			if tc.runtime {
				_, ok := panicked.(runtime.Error)
				assert.That(ok, "runtime panic must propagate")
			} else {
				assert.Equal(panicked, tc.wantPanic)
			}
			assert.Equal(err, tc.wantErr)
			for _, ns := range handles {
				checkNamespaceExpired(t, ns)
			}
			checkNamespaceSeed(t, db)
			assert.Equal(db.View(func(tx ReadTx) error {
				left := try.To1(tx.Child([]byte("left")))
				_, err := left.Child([]byte("new"))
				return err
			}), ErrNamespaceNotFound)
		})
	}
	t.Run("names_and_conflicts", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		seedNamespaces(t, db)
		for _, name := range [][]byte{nil, {}, []byte("absent"), []byte("key"), []byte("empty")} {
			want := ErrConflict
			if len(name) == 0 {
				want = ErrEmptyName
			} else if string(name) == "absent" {
				want = ErrNamespaceNotFound
			}
			assert.Equal(db.View(func(tx ReadTx) error {
				left := try.To1(tx.Child([]byte("left")))
				child, err := left.Child(name)
				assert.INil(child)
				assert.Equal(err, want)
				return nil
			}), want)
			for _, op := range []func(WriteNS) (WriteNS, error){
				func(ns WriteNS) (WriteNS, error) { return ns.ChildForUpdate(name) },
				func(ns WriteNS) (WriteNS, error) { return ns.EnsureChild(name) },
			} {
				if string(name) == "absent" {
					break // EnsureChild creates absent children; checked in traversal.
				}
				assert.Equal(db.Update(func(tx WriteTx) error {
					left := try.To1(tx.ChildForUpdate([]byte("left")))
					child, err := op(left)
					assert.INil(child)
					assert.Equal(err, want)
					return nil
				}), want)
			}
		}
		assert.Equal(db.Update(func(tx WriteTx) error {
			child, err := tx.ChildForUpdate([]byte("absent"))
			assert.INil(child)
			assert.Equal(err, ErrNamespaceNotFound)
			child, err = tx.EnsureChild([]byte("absent"))
			assert.INil(child)
			assert.Equal(err, ErrNamespaceNotFound, "a failed open is abort-only")
			return nil
		}), ErrNamespaceNotFound)
		assert.Equal(db.View(func(tx ReadTx) error {
			_, _, err := tx.Get([]byte("left"))
			assert.Equal(err, ErrConflict)
			return nil
		}), ErrConflict)
		for _, op := range []func(WriteNS) error{
			func(ns WriteNS) error { _, _, err := ns.Get([]byte("left")); return err },
			func(ns WriteNS) error { return ns.Put([]byte("left"), nil) },
			func(ns WriteNS) error { return ns.Delete([]byte("left")) },
		} {
			assert.Equal(db.Update(func(tx WriteTx) error {
				assert.Equal(op(tx), ErrConflict)
				return nil
			}), ErrConflict)
		}
		try.To(db.Update(func(tx WriteTx) error {
			left := try.To1(tx.ChildForUpdate([]byte("left")))
			return left.Delete([]byte("absent"))
		}))
		checkNamespaceSeed(t, db) // Wrong-kind Delete must preserve the subtree.
	})
	t.Run("shared_first_error", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		seedNamespaces(t, db)
		callbackErr := errors.New("callback failure")
		err := db.Update(func(tx WriteTx) error {
			left := try.To1(tx.ChildForUpdate([]byte("left")))
			right := try.To1(tx.ChildForUpdate([]byte("right")))
			read := try.To1(tx.Child([]byte("left")))
			try.To(right.Put([]byte("key"), []byte("pending")))
			_, first := read.Child([]byte("missing"))
			assert.Equal(first, ErrNamespaceNotFound)
			for _, ns := range []WriteNS{tx, left, right} {
				found, err := ns.HasChild(nil)
				assert.ThatNot(found)
				assert.Equal(err, first)
				_, _, err = ns.Get(nil)
				assert.Equal(err, first)
				assert.Equal(ns.Put(nil, nil), first)
				assert.Equal(ns.Delete(nil), first)
				_, err = ns.Child(nil)
				assert.Equal(err, first)
				_, err = ns.ChildForUpdate(nil)
				assert.Equal(err, first)
				_, err = ns.EnsureChild(nil)
				assert.Equal(err, first)
			}
			return callbackErr
		})
		assert.ErrorIs(err, callbackErr)
		assert.ErrorIs(err, ErrNamespaceNotFound)
		checkNamespaceSeed(t, db)
		assert.Equal(db.View(func(tx ReadTx) error {
			left := try.To1(tx.Child([]byte("left")))
			right := try.To1(tx.Child([]byte("right")))
			_, _, first := left.Get(nil)
			assert.Equal(first, ErrEmptyKey)
			found, err := right.HasChild(nil)
			assert.ThatNot(found)
			assert.Equal(err, first)
			_, _, err = right.Get([]byte("key"))
			assert.Equal(err, first)
			_, err = tx.Child([]byte("left"))
			assert.Equal(err, first)
			return nil
		}), ErrEmptyKey)
	})
	for _, mode := range []string{"view", "update"} {
		for _, tc := range append([]rollbackCase{{name: "success"}}, rollbackCases()...) {
			t.Run("expiry_and_capabilities/"+mode+"/"+tc.name, func(t *testing.T) {
				defer assert.PushTester(t)()
				db := open(t)
				seedNamespaces(t, db)
				var handles []ReadNS
				var err error
				panicked := capturePanic(func() {
					inspect := func(tx ReadTx) error {
						left := try.To1(tx.Child([]byte("left")))
						deep := try.To1(left.Child([]byte("deep")))
						handles = append(handles, tx, left, deep)
						for _, ns := range []ReadNS{left, deep} {
							_, writable := ns.(WriteNS)
							assert.ThatNot(writable)
							_, writeTx := ns.(WriteTx)
							assert.ThatNot(writeTx)
						}
						if tc.finish == nil {
							return nil
						}
						if mode == "view" {
							// Read failures exercise the same ignored/returned error exits.
							if tc.wantErr == ErrEmptyKey {
								_, _, err := deep.Get(nil)
								assert.Equal(err, ErrEmptyKey)
								return nil
							}
							return tc.finish(nil)
						}
						write := try.To1(tx.(WriteTx).ChildForUpdate([]byte("left")))
						handles = append(handles, write)
						return tc.finish(write)
					}
					if mode == "view" {
						err = db.View(inspect)
					} else {
						err = db.Update(func(tx WriteTx) error {
							write := try.To1(tx.ChildForUpdate([]byte("left")))
							handles = append(handles, write)
							return inspect(tx)
						})
					}
				})
				if tc.runtime {
					_, ok := panicked.(runtime.Error)
					assert.That(ok)
				} else {
					assert.Equal(panicked, tc.wantPanic)
				}
				assert.Equal(err, tc.wantErr)
				for _, ns := range handles {
					checkNamespaceExpired(t, ns)
				}
			})
		}
	}
	t.Run("iteration_records_and_ownership", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		seedNamespaces(t, db)
		var retained [][2][]byte
		inspect := func(tx ReadTx) error { //nolint:unparam
			rootCount := 0
			try.To(tx.Each(func(key, value []byte) error {
				rootCount++
				assert.Equal(string(key), "root")
				assert.Equal(string(value), "original")
				return nil
			}))
			assert.Equal(rootCount, 1)
			left := try.To1(tx.Child([]byte("left")))
			seen := make(map[string]string)
			try.To(left.Each(func(key, value []byte) error {
				_, duplicate := seen[string(key)]
				assert.ThatNot(duplicate)
				seen[string(key)] = string(value)
				retained = append(retained, [2][]byte{key, value})
				return nil
			}))
			assert.Equal(len(seen), 2)
			assert.Equal(seen["key"], "left")
			empty, found := seen["empty"]
			assert.That(found)
			assert.Equal(empty, "")
			checkRecord(t, left, "empty", "", true)
			checkRecord(t, left, "absent", "", false)
			try.To(left.Each(func(key, value []byte) error {
				key[0] = 'X'
				if len(value) > 0 {
					value[0] = 'X'
				}
				return nil
			}))
			checkRecord(t, left, "key", "left", true)
			checkRecord(t, left, "empty", "", true)
			checkRecord(t, left, "Xey", "", false)
			return nil
		}
		try.To(db.View(inspect))
		try.To(db.Update(func(tx WriteTx) error {
			left := try.To1(tx.ChildForUpdate([]byte("left")))
			try.To(left.Put([]byte("key"), []byte("left")))
			try.To(left.Put([]byte("empty"), []byte{}))
			empty := try.To1(tx.EnsureChild([]byte("empty-ns")))
			try.To(empty.Each(func([]byte, []byte) error {
				t.Fatal("empty namespace invoked Each callback")
				return nil
			}))
			return inspect(tx)
		}))
		checkNamespaceSeed(t, db)
		try.To(db.Close())
		assert.Equal(len(retained), 4)
		for _, pair := range retained {
			if string(pair[0]) == "empty" {
				assert.Equal(len(pair[1]), 0)
			} else {
				assert.Equal(string(pair[0]), "key")
				assert.Equal(string(pair[1]), "left")
				pair[1][0] = 'Y'
			}
			pair[0][0] = 'Y'
		}
	})
	for _, mode := range []string{"view", "update"} {
		for _, nestedFailure := range []bool{false, true} {
			name := "callback_error"
			if nestedFailure {
				name = "ignored_operation_error"
			}
			t.Run("iteration_errors/"+mode+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				db := open(t)
				seedNamespaces(t, db)
				want := errors.New("stop iteration")
				if nestedFailure {
					want = ErrEmptyKey
				}
				inspect := func(tx ReadTx) error { //nolint:unparam
					left := try.To1(tx.Child([]byte("left")))
					right := try.To1(tx.Child([]byte("right")))
					calls := 0
					err := left.Each(func([]byte, []byte) error {
						calls++
						if nestedFailure {
							_, _, err := right.Get(nil)
							assert.Equal(err, want)
							return nil // Each must notice the ignored sibling failure.
						}
						return want
					})
					assert.Equal(err, want)
					assert.Equal(calls, 1)
					assert.Equal(tx.Each(func([]byte, []byte) error {
						t.Fatal("poisoned transaction invoked Each callback")
						return nil
					}), want)
					_, _, err = right.Get([]byte("key"))
					assert.Equal(err, want)
					return nil // An ignored Each error must still fail the transaction.
				}
				if mode == "view" {
					assert.Equal(db.View(inspect), want)
				} else {
					assert.Equal(db.Update(func(tx WriteTx) error {
						left := try.To1(tx.ChildForUpdate([]byte("left")))
						try.To(left.Put([]byte("key"), []byte("pending")))
						try.To(tx.Put([]byte("root"), []byte("pending")))
						try.To1(left.EnsureChild([]byte("new")))
						return inspect(tx)
					}), want)
					checkNamespaceSeed(t, db)
					assert.Equal(db.View(func(tx ReadTx) error {
						left := try.To1(tx.Child([]byte("left")))
						_, err := left.Child([]byte("new"))
						return err
					}), ErrNamespaceNotFound)
				}
			})
		}
	}
	t.Run("iteration_panic", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		seedNamespaces(t, db)
		marker := &struct{ message string }{"iteration panic"}
		var leaked WriteNS
		panicked := capturePanic(func() {
			_ = db.Update(func(tx WriteTx) error {
				leaked = try.To1(tx.ChildForUpdate([]byte("left")))
				try.To(leaked.Put([]byte("key"), []byte("pending")))
				return leaked.Each(func([]byte, []byte) error { panic(marker) })
			})
		})
		assert.Equal(panicked, any(marker))
		checkNamespaceExpired(t, leaked)
		checkNamespaceSeed(t, db)
	})
	t.Run("concurrent_nested_increments", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		try.To(db.Update(func(tx WriteTx) error {
			parent := try.To1(tx.EnsureChild([]byte("counters")))
			child := try.To1(parent.EnsureChild([]byte("nested")))
			return child.Put([]byte("count"), []byte("0"))
		}))
		const workers, increments = 4, 20
		start := make(chan struct{})
		stop := make(chan struct{})
		defer close(stop)
		results := make([]<-chan error, workers)
		for i := range results {
			results[i] = memoryWorker(func() (err error) {
				defer err2.Handle(&err, nil)
				select {
				case <-start:
				case <-stop:
					return nil
				}
				for range increments {
					select {
					case <-stop:
						return nil
					default:
					}
					try.To(db.Update(func(tx WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						defer assert.PushAsserter(assert.Plain)()
						parent := try.To1(tx.ChildForUpdate([]byte("counters")))
						child := try.To1(parent.ChildForUpdate([]byte("nested")))
						value, found := try.To2(child.Get([]byte("count")))
						assert.That(found, "missing nested counter")
						count := try.To1(strconv.Atoi(string(value)))
						runtime.Gosched()
						return child.Put([]byte("count"), []byte(strconv.Itoa(count+1)))
					}))
				}
				return nil
			})
		}
		close(start)
		for _, result := range results {
			assert.NoError(awaitMemory(t, result))
		}
		try.To(db.View(func(tx ReadTx) error {
			parent := try.To1(tx.Child([]byte("counters")))
			child := try.To1(parent.Child([]byte("nested")))
			checkRecord(t, child, "count", strconv.Itoa(workers*increments), true)
			return nil
		}))
	})
}

func seedNamespaces(t *testing.T, db Engine) {
	t.Helper()
	try.To(db.Update(func(tx WriteTx) error {
		try.To(tx.Put([]byte("root"), []byte("original")))
		for _, name := range []string{"left", "right"} {
			ns := try.To1(tx.EnsureChild([]byte(name)))
			try.To(ns.Put([]byte("key"), []byte(name)))
			try.To(ns.Put([]byte("empty"), nil))
			deep := try.To1(ns.EnsureChild([]byte("deep")))
			try.To(deep.Put([]byte("key"), []byte("descendant")))
		}
		return nil
	}))
}

func checkNamespaceSeed(t *testing.T, db Engine) {
	t.Helper()
	try.To(db.View(func(tx ReadTx) error {
		checkRecord(t, tx, "root", "original", true)
		for _, name := range []string{"left", "right"} {
			ns := try.To1(tx.Child([]byte(name)))
			checkRecord(t, ns, "key", name, true)
			checkRecord(t, ns, "empty", "", true)
			deep := try.To1(ns.Child([]byte("deep")))
			checkRecord(t, deep, "key", "descendant", true)
		}
		return nil
	}))
}

func checkNamespaceExpired(t *testing.T, ns ReadNS) {
	t.Helper()
	assert.INotNil(ns)
	found, err := ns.HasChild(nil)
	assert.ThatNot(found)
	assert.Equal(err, ErrTxClosed)
	_, _, err = ns.Get(nil)
	assert.Equal(err, ErrTxClosed)
	child, err := ns.Child(nil)
	assert.INil(child)
	assert.Equal(err, ErrTxClosed)
	assert.Equal(ns.Each(func([]byte, []byte) error {
		t.Fatal("expired namespace invoked Each callback")
		return nil
	}), ErrTxClosed)
	if write, ok := ns.(WriteNS); ok {
		assert.Equal(write.Put(nil, nil), ErrTxClosed)
		assert.Equal(write.Delete(nil), ErrTxClosed)
		child, err := write.ChildForUpdate(nil)
		assert.INil(child)
		assert.Equal(err, ErrTxClosed)
		child, err = write.EnsureChild(nil)
		assert.INil(child)
		assert.Equal(err, ErrTxClosed)
	}
}
