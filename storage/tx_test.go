package storage

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/engine"
	"github.com/lainio/ic/storage/internal/record"
)

func TestVaultRecords(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) *Database
	}{
		{"memory", func(t *testing.T) *Database { return NewMemory() }},
		{"bbolt", func(t *testing.T) *Database {
			return try.To1(OpenBolt(filepath.Join(t.TempDir(), "records.db")))
		}},
	} {
		t.Run(backend.name, func(t *testing.T) {
			t.Run("data", func(t *testing.T) { vaultRecordsData(t, backend.open) })
			t.Run("isolation", func(t *testing.T) { vaultRecordsIsolation(t, backend.open) })
			t.Run("atomic", func(t *testing.T) { vaultRecordsAtomic(t, backend.open) })
			t.Run("no_repair", func(t *testing.T) { vaultRecordsNoRepair(t, backend.open) })
			t.Run("lifecycle", func(t *testing.T) { vaultRecordsLifecycle(t, backend.open) })
			t.Run("separate_databases", func(t *testing.T) { vaultRecordsDatabases(t, backend.open) })
		})
	}
}

func newRecordVault(t *testing.T, db *Database, vault VaultID, allowance uint32) (*Vault, *lifecycleProvider) {
	t.Helper()
	p := newLifecycleProvider(t, allowance+1) // One manifest plus explicit data allowance.
	try.To(db.CreateVault(context.Background(), vault, KeyID{7}, p))
	v := try.To1(db.OpenVault(context.Background(), vault, KeyID{7}, p, allowance))
	return v, p
}

func checkRecord(t *testing.T, tx ReadTx, key, want []byte, present bool) []byte {
	t.Helper()
	value, found := try.To2(tx.Get(key))
	assert.Equal(found, present)
	assert.Equal(bytes.Equal(value, want), true)
	if !present {
		assert.SNil(value)
	}
	return value
}

// Test-only inspection uses the expected physical and cryptographic layout,
// independently of production constants. It returns owned ciphertext bytes.
func rawVaultRecord(t *testing.T, v *Vault, prefix byte, key []byte) []byte {
	t.Helper()
	token := try.To1(v.scope.Token([][]byte{{prefix}}, key))
	var envelope []byte
	try.To(v.db.engine.View(func(root engine.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		collection := try.To1(root.Child([]byte("vaults")))
		state := try.To1(collection.Child(v.vault[:]))
		assert.ThatNot(try.To1(state.HasChild([]byte{2})))
		ns := try.To1(state.Child([]byte{prefix}))
		var found bool
		envelope, found = try.To2(ns.Get(token[:]))
		assert.That(found)
		return nil
	}))
	return envelope
}

func vaultRecordsData(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	db := open(t)
	t.Cleanup(func() { _ = db.Close() })
	v, p := newRecordVault(t, db, VaultID{1}, 3)
	manifest := rawVaultRecord(t, v, 3, []byte("manifest"))
	key, value := []byte("vaults/manifest\x00\x01\x03"), []byte("original")
	originalKey := bytes.Clone(key)
	var read ReadTx
	try.To(v.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		read = tx
		_, writable := tx.(WriteTx)
		assert.ThatNot(writable)
		_, raw := any(tx).(engine.ReadNS)
		assert.ThatNot(raw)
		checkRecord(t, tx, key, nil, false)
		return nil
	}))
	try.To(v.Update(func(tx WriteTx) error { return tx.Delete(key) }))
	try.To(db.engine.View(func(root engine.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		collection := try.To1(root.Child([]byte("vaults")))
		state := try.To1(collection.Child(v.vault[:]))
		assert.ThatNot(try.To1(state.HasChild([]byte{1})), "empty reads/deletes do not create records")
		return nil
	}))
	assert.Equal(p.spent, uint32(1))
	var write WriteTx
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		write = tx
		_, raw := any(tx).(engine.WriteNS)
		assert.ThatNot(raw)
		try.To(tx.Put(key, value))
		assert.Equal(string(key), string(originalKey))
		assert.Equal(string(value), "original")
		key[0], value[0] = 'X', 'X'
		owned := checkRecord(t, tx, originalKey, []byte("original"), true)
		owned[0] = 'Y'
		checkRecord(t, tx, originalKey, []byte("original"), true)
		try.To(tx.Put([]byte("manifest"), nil))
		checkRecord(t, tx, []byte("manifest"), nil, true)
		return nil
	}))
	assert.Equal(ErrTxClosed, engine.ErrTxClosed)
	_, _, err := read.Get(nil)
	assert.Equal(err, ErrTxClosed)
	assert.Equal(write.Put(nil, nil), ErrTxClosed)
	assert.Equal(write.Delete(nil), ErrTxClosed)
	var retained []byte
	try.To(v.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		retained = checkRecord(t, tx, originalKey, []byte("original"), true)
		checkRecord(t, tx, []byte("manifest"), nil, true)
		return nil
	}))
	// Inspect both committed records: raw 32-byte tokens and full authenticated
	// envelopes, including the exact requested logical key under context [01].
	try.To(db.engine.View(func(root engine.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		collection := try.To1(root.Child([]byte("vaults")))
		state := try.To1(collection.Child(v.vault[:]))
		records := try.To1(state.Child([]byte{1}))
		count := 0
		try.To(records.Each(func(token, envelope []byte) (err error) {
			defer err2.Handle(&err, nil)
			assert.SLen(token, 32)
			wantKey, wantValue := originalKey, []byte("original")
			emptyToken := try.To1(v.scope.Token([][]byte{{1}}, []byte("manifest")))
			if [32]byte(token) == emptyToken {
				wantKey, wantValue = []byte("manifest"), nil
			}
			assert.Equal([32]byte(token), try.To1(v.scope.Token([][]byte{{1}}, wantKey)))
			openedKey, openedValue := try.To2(v.scope.Open([][]byte{{1}}, [32]byte(token), wantKey, envelope))
			assert.Equal(bytes.Equal(openedKey, wantKey), true)
			assert.Equal(bytes.Equal(openedValue, wantValue), true)
			assert.ThatNot(bytes.Equal(envelope, wantValue))
			count++
			return nil
		}))
		assert.Equal(count, 2)
		return nil
	}))
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(tx.Put(originalKey, []byte("replacement")))
		checkRecord(t, tx, originalKey, []byte("replacement"), true)
		return nil
	}))
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, originalKey, []byte("replacement"), true)
		try.To(tx.Delete(originalKey))
		checkRecord(t, tx, originalKey, nil, false)
		return tx.Delete([]byte("manifest"))
	}))
	try.To(v.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, originalKey, nil, false)
		checkRecord(t, tx, []byte("manifest"), nil, false)
		return nil
	}))
	assert.Equal(p.spent, uint32(4), "reads and deletes spend nothing, including at exhaustion")
	assert.Equal(p.reserves, 2, "data operations never reserve again")
	assert.Equal(bytes.Equal(rawVaultRecord(t, v, 3, []byte("manifest")), manifest), true)
	try.To(v.Close())
	assert.Equal(string(retained), "original")
	try.To(db.Close())
	assert.Equal(string(retained), "original")
	_, _, err = read.Get(originalKey)
	assert.Equal(err, ErrTxClosed)
	assert.Equal(write.Put(originalKey, value), ErrTxClosed)
	assert.Equal(write.Delete(originalKey), ErrTxClosed)
}

func vaultRecordsIsolation(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	db := open(t)
	t.Cleanup(func() { _ = db.Close() })
	a, pa := newRecordVault(t, db, VaultID{1}, 1)
	b, pb := newRecordVault(t, db, VaultID{2}, 1)
	key := []byte("same key")
	for i, v := range []*Vault{a, b} {
		try.To(v.Update(func(tx WriteTx) error { return tx.Put(key, []byte{byte(i)}) }))
	}
	for i, v := range []*Vault{a, b} {
		try.To(v.View(func(tx ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			checkRecord(t, tx, key, []byte{byte(i)}, true)
			return nil
		}))
	}
	assert.NotEqual(try.To1(a.scope.Token([][]byte{{1}}, key)), try.To1(b.scope.Token([][]byte{{1}}, key)))
	assert.Equal(pa.spent, uint32(2))
	assert.Equal(pb.spent, uint32(2))
	try.To(a.Update(func(tx WriteTx) error { return tx.Delete(key) }))
	try.To(b.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, key, []byte{1}, true)
		return nil
	}))
	try.To(db.Close())
}

func checkExpiredRecordTx(t *testing.T, tx ReadTx) {
	t.Helper()
	value, found, err := tx.Get(nil)
	assert.SNil(value)
	assert.ThatNot(found)
	assert.Equal(err, ErrTxClosed)
	if write, ok := tx.(WriteTx); ok {
		assert.Equal(write.Put(nil, nil), ErrTxClosed)
		assert.Equal(write.Delete(nil), ErrTxClosed)
	}
}

func vaultRecordsAtomic(t *testing.T, open func(*testing.T) *Database) {
	for _, mode := range []string{"returned", "err2", "panic", "runtime_panic"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			t.Cleanup(func() { _ = db.Close() })
			v, p := newRecordVault(t, db, VaultID{1}, 4)
			key := []byte("prior")
			try.To(v.Update(func(tx WriteTx) error { return tx.Put(key, []byte("original")) }))
			callbackErr := errors.New("callback abort")
			var marker any = &struct{ message string }{"unexpected panic"}
			if mode == "runtime_panic" {
				func() {
					defer func() { marker = recover() }()
					data := []byte{0}
					_ = data[len(data)] // Deliberate bounds panic: test rollback.
				}()
			}
			var saved WriteTx
			var caught any
			var result error
			calls := 0
			func() {
				defer func() { caught = recover() }()
				// Deliberately no recovery in the callback: the adapter must
				// recover err2 before expiry and the backend commit decision.
				result = v.Update(func(tx WriteTx) error {
					calls++
					saved = tx
					try.To(tx.Put(key, []byte("pending")))
					try.To(tx.Put([]byte("new"), []byte("pending")))
					switch mode {
					case "returned":
						return callbackErr
					case "err2":
						try.To(callbackErr)
					default:
						panic(marker)
					}
					return nil
				})
			}()
			assert.Equal(calls, 1)
			if mode == "returned" || mode == "err2" {
				assert.INil(caught)
				assert.Equal(result, callbackErr)
			} else {
				assert.Equal(caught, marker)
			}
			checkExpiredRecordTx(t, saved)
			assert.Equal(p.spent, uint32(4), "aborted seals are never refunded")
			try.To(v.View(func(tx ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				checkRecord(t, tx, key, []byte("original"), true)
				checkRecord(t, tx, []byte("new"), nil, false)
				return nil
			}))
			try.To(v.Update(func(tx WriteTx) error { return tx.Put(key, []byte("later")) }))
			try.To(v.View(func(tx ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				checkRecord(t, tx, key, []byte("later"), true)
				return nil
			}))
			assert.Equal(p.spent, uint32(5))
			try.To(db.Close())
			checkExpiredRecordTx(t, saved)
		})
	}
	t.Run("ignored_budget_failure", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		t.Cleanup(func() { _ = db.Close() })
		v, p := newRecordVault(t, db, VaultID{1}, 2)
		key := []byte("prior")
		try.To(v.Update(func(tx WriteTx) error { return tx.Put(key, []byte("original")) }))
		var first error
		var saved WriteTx
		result := v.Update(func(tx WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			saved = tx
			try.To(tx.Put(key, []byte("pending")))
			first = tx.Put([]byte("new"), []byte("exhausted"))
			assert.ErrorIs(first, errLifecycleBudget)
			value, found, next := tx.Get(key)
			assert.SNil(value)
			assert.ThatNot(found)
			assert.Equal(next, first)
			assert.Equal(tx.Put(nil, nil), first)
			assert.Equal(tx.Delete(key), first)
			return nil // Ignoring the codec error must still roll back the first Put.
		})
		assert.Equal(result, first)
		checkExpiredRecordTx(t, saved)
		assert.Equal(p.spent, uint32(3))
		assert.Equal(p.remaining, uint32(0))
		assert.Equal(p.reserves, 2)
		assert.Equal(len(p.calls), 2)
		try.To(v.View(func(tx ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			checkRecord(t, tx, key, []byte("original"), true)
			checkRecord(t, tx, []byte("new"), nil, false)
			return nil
		}))
		assert.ErrorIs(v.Update(func(tx WriteTx) error { return tx.Put(key, nil) }), errLifecycleBudget)
		try.To(v.Update(func(tx WriteTx) error { return tx.Delete(key) }))
		assert.Equal(p.spent, uint32(3))
		try.To(db.Close())
	})
	t.Run("joined_propagation", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		t.Cleanup(func() { _ = db.Close() })
		v, p := newRecordVault(t, db, VaultID{1}, 1)
		callbackErr := errors.New("independent callback cause")
		var first error
		var saved WriteTx
		result := v.Update(func(tx WriteTx) error {
			saved = tx
			try.To(tx.Put([]byte("pending"), nil))
			first = tx.Put(nil, nil)
			try.To(callbackErr) // Intentionally recovered only by the adapter.
			return nil
		})
		assert.Error(first)
		assert.ErrorIs(result, first)
		assert.ErrorIs(result, callbackErr)
		checkExpiredRecordTx(t, saved)
		try.To(v.View(func(tx ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			checkRecord(t, tx, []byte("pending"), nil, false)
			return nil
		}))
		assert.Equal(p.spent, uint32(2))
		try.To(db.Close())
	})
	t.Run("view_unwinding", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		t.Cleanup(func() { _ = db.Close() })
		v, p := newRecordVault(t, db, VaultID{1}, 0)
		callbackErr := errors.New("view callback abort")
		for _, mode := range []string{"returned", "err2", "ignored"} {
			var saved ReadTx
			var first error
			result := v.View(func(tx ReadTx) error {
				saved = tx
				switch mode {
				case "returned":
					return callbackErr
				case "err2":
					try.To(callbackErr)
				case "ignored":
					value, found, err := tx.Get(nil)
					first = err
					assert.SNil(value)
					assert.ThatNot(found)
					assert.Error(first)
					_, _, next := tx.Get([]byte("missing"))
					assert.Equal(next, first)
				}
				return nil
			})
			if mode == "ignored" {
				assert.Equal(result, first)
			} else {
				assert.Equal(result, callbackErr)
			}
			checkExpiredRecordTx(t, saved)
		}
		try.To(v.View(func(tx ReadTx) error { return nil }))
		assert.Equal(p.spent, uint32(1))
		try.To(db.Close())
	})
}

func vaultRecordsNoRepair(t *testing.T, open func(*testing.T) *Database) {
	for _, mode := range []string{"tampered", "relocated"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			t.Cleanup(func() { _ = db.Close() })
			v, p := newRecordVault(t, db, VaultID{1}, 2)
			key := []byte("original key")
			try.To(v.Update(func(tx WriteTx) error { return tx.Put(key, []byte("original value")) }))
			envelope := rawVaultRecord(t, v, 1, key)
			if mode == "tampered" {
				envelope[len(envelope)-1] ^= 1
			} else {
				key = []byte("another expected key")
			}
			token := try.To1(v.scope.Token([][]byte{{1}}, key))
			_, _, cause := v.scope.Open([][]byte{{1}}, token, key, envelope)
			assert.Error(cause)
			try.To(db.engine.Update(func(root engine.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				collection := try.To1(root.ChildForUpdate([]byte("vaults")))
				state := try.To1(collection.ChildForUpdate(v.vault[:]))
				records := try.To1(state.ChildForUpdate([]byte{1}))
				return records.Put(token[:], envelope)
			}))
			for _, operation := range []string{"get", "put", "delete"} {
				t.Run(operation, func(t *testing.T) {
					defer assert.PushTester(t)()
					var result error
					switch operation {
					case "get":
						result = v.View(func(tx ReadTx) error {
							value, found, err := tx.Get(key)
							assert.SNil(value)
							assert.ThatNot(found)
							return err
						})
					case "put":
						result = v.Update(func(tx WriteTx) error { return tx.Put(key, []byte("replacement")) })
					case "delete":
						result = v.Update(func(tx WriteTx) error { return tx.Delete(key) })
					}
					assert.Equal(result, cause)
					assert.Equal(bytes.Equal(rawVaultRecord(t, v, 1, key), envelope), true)
					assert.Equal(p.spent, uint32(2), "verification failures consume no seal")
				})
			}
			if mode == "relocated" {
				try.To(v.View(func(tx ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					checkRecord(t, tx, []byte("original key"), []byte("original value"), true)
					return nil
				}))
			}
			try.To(db.Close())
		})
	}
	t.Run("invalid_keys_in_empty_root", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		t.Cleanup(func() { _ = db.Close() })
		v, p := newRecordVault(t, db, VaultID{1}, 1)
		for _, key := range [][]byte{nil, {}, bytes.Repeat([]byte{1}, 4097)} {
			_, want := v.scope.Token([][]byte{{1}}, key)
			assert.Error(want)
			assert.Equal(v.View(func(tx ReadTx) error {
				value, found, err := tx.Get(key)
				assert.SNil(value)
				assert.ThatNot(found)
				return err
			}), want)
			assert.Equal(v.Update(func(tx WriteTx) error { return tx.Put(key, nil) }), want)
			assert.Equal(v.Update(func(tx WriteTx) error { return tx.Delete(key) }), want)
		}
		assert.Equal(p.spent, uint32(1))
		try.To(db.Close())
	})
	t.Run("missing_and_wrong_kind", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			depth  int
			record bool
			want   error
		}{
			{"missing_collection", 0, false, ErrVaultNotFound},
			{"missing_vault", 1, false, ErrVaultNotFound},
			{"collection_record", 0, true, engine.ErrConflict},
			{"vault_record", 1, true, engine.ErrConflict},
			{"records_record", 2, true, engine.ErrConflict},
			{"token_child", 4, false, engine.ErrConflict},
		} {
			t.Run(tc.name, func(t *testing.T) {
				defer assert.PushTester(t)()
				db := open(t)
				t.Cleanup(func() { _ = db.Close() })
				v, p := newRecordVault(t, db, VaultID{1}, 1)
				// Substitute raw state after authenticated publication to model
				// loss/conflict without adding namespace deletion to the engine.
				fixture := open(t)
				t.Cleanup(func() { _ = fixture.Close() })
				original := db.engine
				db.engine = fixture.engine
				defer func() { db.engine = original }()
				key := []byte("key")
				token := try.To1(v.scope.Token([][]byte{{1}}, key))
				path := [][]byte{[]byte("vaults"), v.vault[:], {1}, token[:]}
				try.To(db.engine.Update(func(root engine.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					var ns engine.WriteNS = root
					for _, name := range path[:tc.depth] {
						ns = try.To1(ns.EnsureChild(name))
					}
					if tc.record {
						return ns.Put(path[tc.depth], nil)
					}
					return nil
				}))
				assert.Equal(v.View(func(tx ReadTx) error {
					value, found, err := tx.Get(key)
					assert.SNil(value)
					assert.ThatNot(found)
					return err
				}), tc.want)
				assert.Equal(v.Update(func(tx WriteTx) error { return tx.Put(key, nil) }), tc.want)
				assert.Equal(v.Update(func(tx WriteTx) error { return tx.Delete(key) }), tc.want)
				try.To(db.engine.View(func(root engine.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					var ns engine.ReadNS = root
					for _, name := range path[:tc.depth] {
						ns = try.To1(ns.Child(name))
					}
					if tc.record {
						value, found := try.To2(ns.Get(path[tc.depth]))
						assert.That(found)
						assert.SLen(value, 0)
					} else if tc.depth < len(path) {
						assert.ThatNot(try.To1(ns.HasChild(path[tc.depth])))
					}
					return nil
				}))
				assert.Equal(p.spent, uint32(1))
			})
		}
	})
}

// Hold only the return from a real engine transaction. The adapter has expired
// and the backend has committed/rolled back, but the scope must remain pinned
// until the engine call returns. This is a concrete completion-boundary probe.
type recordCompletionEngine struct {
	engine.Engine
	finished, resume chan struct{}
}

func (e *recordCompletionEngine) Update(fn func(engine.WriteTx) error) error {
	err := e.Engine.Update(fn)
	close(e.finished)
	<-e.resume
	return err
}

func vaultRecordsLifecycle(t *testing.T, open func(*testing.T) *Database) {
	for _, mode := range []string{"commit", "rollback"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			db := open(t)
			t.Cleanup(func() { _ = db.Close() })
			v, p := newRecordVault(t, db, VaultID{1}, 1)
			scope, lease := v.scope, v.lease.(*lifecycleLease)
			probe := &recordCompletionEngine{
				Engine: db.engine, finished: make(chan struct{}), resume: make(chan struct{}),
			}
			db.engine = probe
			entered, resume, workDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(resume) })
			finishEngine := sync.OnceFunc(func() { close(probe.resume) })
			workResult := make(chan error, 1)
			callbackErr := errors.New("held callback rollback")
			var saved WriteTx
			go func() {
				defer close(workDone)
				workResult <- v.Update(func(tx WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					defer assert.PushAsserter(assert.Plain)()
					saved = tx
					close(entered)
					<-resume
					try.To(tx.Put([]byte("held"), []byte("committed")))
					if mode == "rollback" {
						return callbackErr
					}
					return nil
				})
			}()
			t.Cleanup(func() { unblock(); finishEngine(); lifecycleSignal(t, workDone) })
			lifecycleSignal(t, entered)
			stopResult, stopDone := make(chan error, 1), make(chan struct{})
			go func() { defer close(stopDone); stopResult <- v.Close() }()
			t.Cleanup(func() { unblock(); finishEngine(); lifecycleSignal(t, stopDone) })
			lifecycleStopped(t, db, v)
			p.mu.Lock()
			checks, releases := lease.checks, lease.releases
			lease.checkErr = errors.New("revoked after admission")
			p.mu.Unlock()
			assert.Equal(releases, 0)
			called := false
			assert.ErrorIs(v.View(func(ReadTx) error { called = true; return nil }), ErrVaultClosed)
			assert.ErrorIs(v.Update(func(WriteTx) error { called = true; return nil }), ErrVaultClosed)
			assert.ThatNot(called)
			select {
			case <-stopDone:
				t.Fatal("Vault.Close finished while public callback was held")
			default:
			}
			unblock()
			lifecycleSignal(t, probe.finished)
			checkExpiredRecordTx(t, saved)
			try.To1(scope.Token([][]byte{{1}}, []byte("held")))
			p.mu.Lock()
			releases = lease.releases
			p.mu.Unlock()
			assert.Equal(releases, 0, "engine return remains pinned after adapter cleanup")
			select {
			case <-stopDone:
				t.Fatal("Vault.Close finished before engine return")
			default:
			}
			finishEngine()
			result := lifecycleResult(t, workResult)
			if mode == "rollback" {
				assert.Equal(result, callbackErr)
			} else {
				assert.NoError(result)
			}
			try.To(lifecycleResult(t, stopResult))
			_, err := scope.Token([][]byte{{1}}, []byte("held"))
			assert.Equal(err, record.ErrCleared)
			assert.Equal(lease.releases, 1)
			assert.Equal(lease.checks, checks, "no authorization check inside admitted work")
			assert.Equal(p.spent, uint32(2))
			assert.Equal(p.reserves, 2)
			assert.Equal(len(p.calls), 2)
			checkExpiredRecordTx(t, saved)
			reader := try.To1(db.OpenVault(context.Background(), v.vault, KeyID{7}, p, 0))
			try.To(reader.View(func(tx ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				want := []byte("committed")
				if mode == "rollback" {
					want = nil
				}
				checkRecord(t, tx, []byte("held"), want, mode == "commit")
				return nil
			}))
			try.To(db.Close())
			assert.Equal(reader.View(func(ReadTx) error { called = true; return nil }), ErrClosed)
			assert.Equal(reader.Update(func(WriteTx) error { called = true; return nil }), ErrClosed)
			assert.ThatNot(called)
			checkExpiredRecordTx(t, saved)
		})
	}
	t.Run("admission_denied", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		t.Cleanup(func() { _ = db.Close() })
		v, p := newRecordVault(t, db, VaultID{1}, 1)
		scope, lease := v.scope, v.lease.(*lifecycleLease)
		denied := errors.New("lease expired before public admission")
		lease.checkErr = denied
		called := false
		assert.ErrorIs(v.View(func(ReadTx) error { called = true; return nil }), denied)
		result := v.Update(func(WriteTx) error { called = true; return nil })
		assert.ErrorIs(result, ErrVaultClosed)
		assert.ErrorIs(result, denied)
		assert.ThatNot(called)
		assert.Equal(lease.releases, 1)
		_, err := scope.Token([][]byte{{1}}, []byte("key"))
		assert.Equal(err, record.ErrCleared)
		assert.Equal(p.spent, uint32(1))
		assert.ErrorIs(db.Close(), denied)
	})
}

func vaultRecordsDatabases(t *testing.T, open func(*testing.T) *Database) {
	defer assert.PushTester(t)()
	a, b := open(t), open(t)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	// Identical public IDs in distinct databases do not select each other's data.
	va, _ := newRecordVault(t, a, VaultID{1}, 1)
	vb, _ := newRecordVault(t, b, VaultID{1}, 1)
	key := []byte("same key")
	try.To(va.Update(func(tx WriteTx) error { return tx.Put(key, []byte("database A")) }))
	try.To(vb.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, key, nil, false)
		return nil
	}))
	try.To(vb.Update(func(tx WriteTx) error { return tx.Put(key, []byte("database B")) }))
	try.To(va.Update(func(tx WriteTx) error { return tx.Delete(key) }))
	try.To(a.Close())
	try.To(vb.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, key, []byte("database B"), true)
		return nil
	}))
	try.To(b.Close())
}

func TestVaultRecordsReopen(t *testing.T) {
	defer assert.PushTester(t)()
	path := filepath.Join(t.TempDir(), "reopen.db")
	db := try.To1(OpenBolt(path))
	t.Cleanup(func() { _ = db.Close() })
	v, p := newRecordVault(t, db, VaultID{1}, 2)
	key := []byte("persistent")
	try.To(v.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(tx.Put(key, []byte("saved")))
		return tx.Put([]byte("empty"), nil)
	}))
	assert.Equal(p.remaining, uint32(0))
	assert.Equal(p.spent, uint32(3))
	try.To(db.Close())
	reopened := try.To1(OpenBolt(path))
	t.Cleanup(func() { _ = reopened.Close() })
	// Same provider and immutable generation; reopening does not reset its budget.
	reader := try.To1(reopened.OpenVault(context.Background(), VaultID{1}, KeyID{7}, p, 0))
	try.To(reader.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, key, []byte("saved"), true)
		checkRecord(t, tx, []byte("empty"), nil, true)
		return nil
	}))
	assert.ErrorIs(reader.Update(func(tx WriteTx) error { return tx.Put(key, []byte("denied")) }), errLifecycleBudget)
	try.To(reader.Update(func(tx WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, key, []byte("saved"), true)
		return tx.Delete(key)
	}))
	assert.Equal(p.remaining, uint32(0))
	assert.Equal(p.reserved, uint32(3))
	assert.Equal(p.spent, uint32(3))
	try.To(reopened.Close())
	final := try.To1(OpenBolt(path))
	t.Cleanup(func() { _ = final.Close() })
	last := try.To1(final.OpenVault(context.Background(), VaultID{1}, KeyID{7}, p, 0))
	try.To(last.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, key, nil, false)
		checkRecord(t, tx, []byte("empty"), nil, true)
		return nil
	}))
	assert.Equal(p.reserved, uint32(3))
	assert.Equal(p.spent, uint32(3))
	try.To(final.Close())
}
