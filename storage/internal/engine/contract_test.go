package engine

import (
	"errors"
	"runtime"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

// A backend factory owns test cleanup. C2 can run this suite on memory without
// assuming files, reopen support, or bbolt types.
func runContract(t *testing.T, open func(*testing.T) Engine) {
	t.Helper()
	t.Run("commit_and_read_own_writes", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		try.To(db.Update(func(tx WriteTx) error {
			try.To(tx.Put([]byte("one"), []byte("first")))
			try.To(tx.Put([]byte("two"), []byte("second")))
			checkRecord(t, tx, "one", "first", true)
			checkRecord(t, tx, "two", "second", true)
			return nil
		}))
		checkPair(t, db, "first", "second")
	})
	for _, tc := range rollbackCases() {
		t.Run("rollback/"+tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			runRollback(t, db, tc)
			checkRolledBack(t, db)
		})
	}
	t.Run("callback_and_operation_errors_preserved", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		callbackErr := errors.New("callback failure")
		err := db.Update(func(tx WriteTx) error {
			try.To(tx.Put([]byte("two"), []byte("pending")))
			_ = tx.Put(nil, nil)
			return callbackErr
		})
		assert.That(errors.Is(err, callbackErr))
		assert.That(errors.Is(err, ErrEmptyKey))
		try.To(db.View(func(tx ReadTx) error {
			checkRecord(t, tx, "two", "", false)
			return nil
		}))
	})
	t.Run("put_owns_inputs", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		key, value := []byte("one"), []byte("first")
		try.To(db.Update(func(tx WriteTx) error {
			try.To(tx.Put(key, value))
			key[0], value[0] = 'X', 'X'
			checkRecord(t, tx, "one", "first", true)
			return nil
		}))
		try.To(db.View(func(tx ReadTx) error {
			checkRecord(t, tx, "one", "first", true)
			checkRecord(t, tx, "Xne", "", false)
			return nil
		}))
	})
	t.Run("get_owns_results", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		try.To(db.Update(func(tx WriteTx) error {
			try.To(tx.Put([]byte("one"), []byte("first")))
			value, _ := try.To2(tx.Get([]byte("one")))
			value[0] = 'X'
			checkRecord(t, tx, "one", "first", true)
			return nil
		}))
		var retained []byte
		try.To(db.View(func(tx ReadTx) error {
			retained, _ = try.To2(tx.Get([]byte("one")))
			retained[0] = 'Y'
			checkRecord(t, tx, "one", "first", true)
			return nil
		}))
		retained[1] = 'Z'
		try.To(db.View(func(tx ReadTx) error {
			checkRecord(t, tx, "one", "first", true)
			return nil
		}))
	})
	t.Run("retained_bytes_survive_close", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		var fromWrite, fromRead []byte
		try.To(db.Update(func(tx WriteTx) error {
			try.To(tx.Put([]byte("one"), []byte("first")))
			fromWrite, _ = try.To2(tx.Get([]byte("one")))
			return nil
		}))
		try.To(db.View(func(tx ReadTx) error {
			fromRead, _ = try.To2(tx.Get([]byte("one")))
			return nil
		}))
		try.To(db.Update(func(tx WriteTx) error {
			return tx.Put([]byte("one"), []byte("replacement"))
		}))
		try.To(db.Close())
		assert.Equal(string(fromWrite), "first")
		assert.Equal(string(fromRead), "first")
		fromWrite[0], fromRead[0] = 'W', 'R'
		assert.Equal(string(fromWrite), "Wirst")
		assert.Equal(string(fromRead), "Rirst")
	})
	t.Run("absent_empty_and_delete", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		try.To(db.Update(func(tx WriteTx) error {
			checkRecord(t, tx, "absent", "", false)
			try.To(tx.Put([]byte("nil"), nil))
			try.To(tx.Put([]byte("empty"), []byte{}))
			checkRecord(t, tx, "nil", "", true)
			checkRecord(t, tx, "empty", "", true)
			return nil
		}))
		try.To(db.View(func(tx ReadTx) error {
			checkRecord(t, tx, "nil", "", true)
			checkRecord(t, tx, "empty", "", true)
			checkRecord(t, tx, "absent", "", false)
			return nil
		}))
		try.To(db.Update(func(tx WriteTx) error {
			try.To(tx.Delete([]byte("absent")))
			try.To(tx.Delete([]byte("nil")))
			checkRecord(t, tx, "nil", "", false)
			return nil
		}))
		try.To(db.View(func(tx ReadTx) error {
			checkRecord(t, tx, "nil", "", false)
			checkRecord(t, tx, "empty", "", true)
			return nil
		}))
		stop := errors.New("abort delete")
		assert.That(db.Update(func(tx WriteTx) error {
			try.To(tx.Delete([]byte("empty")))
			return stop
		}) == stop)
		try.To(db.View(func(tx ReadTx) error {
			checkRecord(t, tx, "empty", "", true)
			return nil
		}))
	})
	t.Run("empty_keys", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		for _, key := range [][]byte{nil, {}} {
			assert.That(errors.Is(db.View(func(tx ReadTx) error {
				_, _, err := tx.Get(key)
				assert.That(errors.Is(err, ErrEmptyKey))
				return nil // An ignored read error still reaches View's caller.
			}), ErrEmptyKey))
			for _, op := range []func(WriteTx) error{
				func(tx WriteTx) error { _, _, err := tx.Get(key); return err },
				func(tx WriteTx) error { return tx.Put(key, nil) },
				func(tx WriteTx) error { return tx.Delete(key) },
			} {
				assert.That(errors.Is(db.Update(func(tx WriteTx) error {
					try.To(tx.Put([]byte("pending"), []byte("value")))
					assert.That(errors.Is(op(tx), ErrEmptyKey))
					return nil
				}), ErrEmptyKey))
			}
		}
		try.To(db.View(func(tx ReadTx) error {
			checkRecord(t, tx, "pending", "", false)
			return nil
		}))
	})
	t.Run("expired_handles_and_read_capability", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		var read ReadTx
		var write WriteTx
		try.To(db.View(func(tx ReadTx) error {
			read = tx
			_, writable := tx.(WriteTx)
			assert.ThatNot(writable)
			return nil
		}))
		_, _, err := read.Get([]byte("one"))
		assert.That(errors.Is(err, ErrTxClosed))
		try.To(db.Update(func(tx WriteTx) error { write = tx; return nil }))
		checkExpired(t, write)
		stop := errors.New("view failure")
		assert.That(db.View(func(tx ReadTx) error { read = tx; return stop }) == stop)
		_, _, err = read.Get([]byte("one"))
		assert.That(errors.Is(err, ErrTxClosed))
	})
	t.Run("terminal_close", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		try.To(db.Close())
		try.To(db.Close())
		called := false
		assert.That(errors.Is(db.View(func(ReadTx) error { called = true; return nil }), ErrClosed))
		assert.That(errors.Is(db.Update(func(WriteTx) error { called = true; return nil }), ErrClosed))
		assert.ThatNot(called)
	})
}

type rollbackCase struct {
	name      string
	finish    func(WriteTx) error
	wantErr   error
	wantPanic any
	runtime   bool
}

func rollbackCases() []rollbackCase {
	stop := errors.New("injected callback failure")
	marker := &struct{ message string }{"unexpected callback panic"}
	return []rollbackCase{
		{name: "callback_error", finish: func(WriteTx) error { return stop }, wantErr: stop},
		{name: "invalid_put", finish: func(tx WriteTx) error { return tx.Put(nil, nil) }, wantErr: ErrEmptyKey},
		{name: "ignored_invalid_put", finish: func(tx WriteTx) error { _ = tx.Put(nil, nil); return nil }, wantErr: ErrEmptyKey},
		{name: "err2_error_panic", finish: func(WriteTx) error { try.To(stop); return nil }, wantErr: stop},
		{name: "unexpected_panic", finish: func(WriteTx) error { panic(marker) }, wantPanic: marker},
		{
			name: "runtime_panic",
			finish: func(WriteTx) error {
				data := []byte{0}
				_ = data[len(data)] // Deliberate bounds panic: test rollback.
				return nil
			},
			runtime: true,
		},
	}
}

func runRollback(t *testing.T, db Engine, tc rollbackCase) {
	t.Helper()
	try.To(db.Update(func(tx WriteTx) error { return tx.Put([]byte("one"), []byte("original")) }))
	var leaked WriteTx
	var err error
	panicked := capturePanic(func() {
		err = db.Update(func(tx WriteTx) error {
			leaked = tx
			try.To(tx.Put([]byte("one"), []byte("replacement")))
			try.To(tx.Put([]byte("two"), []byte("pending")))
			return tc.finish(tx)
		})
	})
	if tc.runtime {
		_, ok := panicked.(runtime.Error)
		assert.That(ok, "runtime panic must propagate")
	} else {
		assert.That(panicked == tc.wantPanic, "unexpected panic result")
	}
	if tc.wantErr != nil {
		assert.That(errors.Is(err, tc.wantErr), "update must preserve the original error")
		assert.That(err == tc.wantErr, "error identity must survive")
	}
	checkExpired(t, leaked)
}

func capturePanic(fn func()) (value any) {
	defer func() { value = recover() }()
	fn()
	return nil
}

func checkRecord(t *testing.T, tx ReadTx, key, want string, present bool) {
	t.Helper()
	value, found := try.To2(tx.Get([]byte(key)))
	assert.Equal(found, present)
	assert.Equal(string(value), want)
}

func checkPair(t *testing.T, db Engine, one, two string) {
	t.Helper()
	try.To(db.View(func(tx ReadTx) error {
		checkRecord(t, tx, "one", one, true)
		checkRecord(t, tx, "two", two, true)
		return nil
	}))
}

func checkRolledBack(t *testing.T, db Engine) {
	t.Helper()
	try.To(db.View(func(tx ReadTx) error {
		checkRecord(t, tx, "one", "original", true)
		checkRecord(t, tx, "two", "", false)
		return nil
	}))
}

func checkExpired(t *testing.T, tx WriteTx) {
	t.Helper()
	assert.INotNil(tx)
	_, _, err := tx.Get([]byte("one"))
	assert.That(errors.Is(err, ErrTxClosed))
	assert.That(errors.Is(tx.Put([]byte("one"), nil), ErrTxClosed))
	assert.That(errors.Is(tx.Delete([]byte("one")), ErrTxClosed))
}
