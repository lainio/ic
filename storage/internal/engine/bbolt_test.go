package engine

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	bolt "go.etcd.io/bbolt"
	berrors "go.etcd.io/bbolt/errors"
)

func openTestBolt(t *testing.T, path string) Engine {
	t.Helper()
	db := try.To1(OpenBolt(path))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close engine: %v", err)
		}
	})
	return db
}

func TestBoltContract(t *testing.T) {
	runContract(t, func(t *testing.T) Engine {
		return openTestBolt(t, filepath.Join(t.TempDir(), "engine.db"))
	})
}

func TestBoltCommitReopen(t *testing.T) {
	defer assert.PushTester(t)()
	path := filepath.Join(t.TempDir(), "engine.db")
	db := openTestBolt(t, path)
	try.To(db.Update(func(tx WriteTx) error {
		try.To(tx.Put([]byte("one"), []byte("first")))
		return tx.Put([]byte("two"), []byte("second"))
	}))
	checkPair(t, db, "first", "second")
	try.To(db.Close())
	reopened := openTestBolt(t, path)
	checkPair(t, reopened, "first", "second")
	// Reopening creates a distinct instance; the old one remains terminal even
	// while the new instance owns the file lock.
	assert.ErrorIs(db.View(func(ReadTx) error { t.Fatal("closed View called"); return nil }), ErrClosed)
	assert.ErrorIs(db.Update(func(WriteTx) error { t.Fatal("closed Update called"); return nil }), ErrClosed)
	try.To(db.Close())
	checkPair(t, reopened, "first", "second")
}

func TestBoltRollbackReopen(t *testing.T) {
	for _, tc := range rollbackCases() {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			path := filepath.Join(t.TempDir(), "engine.db")
			db := openTestBolt(t, path)
			runRollback(t, db, tc)
			checkRolledBack(t, db)
			try.To(db.Close())
			checkRolledBack(t, openTestBolt(t, path))
		})
	}
}

func TestBoltBackendErrorRollback(t *testing.T) {
	defer assert.PushTester(t)()
	path := filepath.Join(t.TempDir(), "engine.db")
	db := openTestBolt(t, path)
	// Exercise a bbolt operation error, beyond the engine's empty-key check.
	err := db.Update(func(tx WriteTx) error {
		try.To(tx.Put([]byte("one"), []byte("pending")))
		assert.ErrorIs(tx.Put(make([]byte, bolt.MaxKeySize+1), nil), berrors.ErrKeyTooLarge)
		return nil
	})
	assert.ErrorIs(err, berrors.ErrKeyTooLarge)
	try.To(db.Close())
	try.To(openTestBolt(t, path).View(func(tx ReadTx) error {
		checkRecord(t, tx, "one", "", false)
		return nil
	}))
}

func TestBoltOpen(t *testing.T) {
	t.Run("permissions", func(t *testing.T) {
		defer assert.PushTester(t)()
		path := filepath.Join(t.TempDir(), "engine.db")
		openTestBolt(t, path)
		info := try.To1(os.Stat(path))
		assert.Equal(info.Mode().Perm()&0077, os.FileMode(0))
	})
	t.Run("missing_parent", func(t *testing.T) {
		defer assert.PushTester(t)()
		db, err := OpenBolt(filepath.Join(t.TempDir(), "absent", "engine.db"))
		assert.INil(db)
		assert.ErrorIs(err, os.ErrNotExist)
	})
	t.Run("invalid_file", func(t *testing.T) {
		defer assert.PushTester(t)()
		path := filepath.Join(t.TempDir(), "engine.db")
		try.To(os.WriteFile(path, []byte("not a bbolt database"), 0600))
		db, err := OpenBolt(path)
		assert.INil(db)
		assert.Error(err)
	})
}
