package engine

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	bolt "go.etcd.io/bbolt"
)

// This bucket is a C1 implementation detail, not a Vault schema or stable format.
const rootBucket = "engine"

type boltEngine struct {
	mu       sync.RWMutex
	db       *bolt.DB
	closeErr error
}

// OpenBolt explicitly opens a file, creating it with mode 0600 if necessary.
// Existing file permissions are unchanged. Parents must already exist. A file
// lock conflict returns an error after one second instead of waiting forever.
// No instance reopens itself after Close.
func OpenBolt(path string) (Engine, error) {
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(rootBucket))
		return err
	}); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, errors.Join(err, closeErr)
		}
		return nil, err
	}
	glog.V(3).Info("storage engine opened")
	return &boltEngine{db: db}, nil
}

func (e *boltEngine) View(fn func(ReadTx) error) error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.db == nil {
		return ErrClosed
	}
	return e.db.View(func(tx *bolt.Tx) (err error) {
		read := &boltReadTx{txState: &txState{}, bucket: tx.Bucket([]byte(rootBucket))}
		defer read.finish(&err)
		// Recover err2 error panics before returning to bbolt; unexpected panics
		// continue through finish and bbolt's rollback defer.
		defer err2.Handle(&err, nil)
		return fn(read)
	})
}

func (e *boltEngine) Update(fn func(WriteTx) error) error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.db == nil {
		return ErrClosed
	}
	return e.db.Update(func(tx *bolt.Tx) (err error) {
		read := &boltReadTx{txState: &txState{}, bucket: tx.Bucket([]byte(rootBucket))}
		defer read.finish(&err)
		defer err2.Handle(&err, nil)
		return fn(&boltWriteTx{boltReadTx: read})
	})
}

func (e *boltEngine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.db == nil {
		return e.closeErr
	}
	e.closeErr = e.db.Close()
	e.db = nil
	glog.V(3).Info("storage engine closed")
	return e.closeErr
}

// Separate concrete types prevent a View handle from asserting to WriteTx.
type boltReadTx struct {
	*txState
	bucket *bolt.Bucket
}

type boltWriteTx struct {
	*boltReadTx
}

func (tx *boltReadTx) checkKey(key []byte) error {
	if err := tx.checkName(key, ErrEmptyKey); err != nil {
		return err
	}
	if tx.bucket.Bucket(key) != nil {
		return tx.fail(ErrConflict)
	}
	return nil
}

func (tx *boltReadTx) Get(key []byte) ([]byte, bool, error) {
	if err := tx.checkKey(key); err != nil {
		return nil, false, err
	}
	value := tx.bucket.Get(key)
	if value == nil {
		return nil, false, nil
	}
	return bytes.Clone(value), true, nil
}

func (tx *boltReadTx) child(name []byte) (*boltReadTx, error) {
	if err := tx.checkName(name, ErrEmptyName); err != nil {
		return nil, err
	}
	if tx.bucket.Get(name) != nil {
		return nil, tx.fail(ErrConflict)
	}
	bucket := tx.bucket.Bucket(name)
	if bucket == nil {
		return nil, tx.fail(ErrNamespaceNotFound)
	}
	return &boltReadTx{txState: tx.txState, bucket: bucket}, nil
}

func (tx *boltReadTx) Child(name []byte) (ns ReadNS, err error) {
	defer err2.Handle(&err, nil)
	return try.To1(tx.child(name)), nil
}

func (tx *boltReadTx) HasChild(name []byte) (bool, error) {
	if err := tx.checkName(name, ErrEmptyName); err != nil {
		return false, err
	}
	if tx.bucket.Get(name) != nil {
		return false, tx.fail(ErrConflict)
	}
	return tx.bucket.Bucket(name) != nil, nil
}

func (tx *boltReadTx) Each(fn func(key, value []byte) error) error {
	if err := tx.check(); err != nil {
		return err
	}
	return tx.fail(tx.bucket.ForEach(func(key, value []byte) error {
		// bbolt cursors return nil values for buckets. Put stores non-nil
		// empty values, so those records are still visited.
		if value == nil {
			return nil
		}
		return tx.fail(fn(bytes.Clone(key), bytes.Clone(value)))
	}))
}

func (tx *boltWriteTx) ChildForUpdate(name []byte) (ns WriteNS, err error) {
	defer err2.Handle(&err, nil)
	child := try.To1(tx.child(name))
	return &boltWriteTx{boltReadTx: child}, nil
}

func (tx *boltWriteTx) EnsureChild(name []byte) (WriteNS, error) {
	if err := tx.checkName(name, ErrEmptyName); err != nil {
		return nil, err
	}
	if tx.bucket.Get(name) != nil {
		return nil, tx.fail(ErrConflict)
	}
	bucket, err := tx.bucket.CreateBucketIfNotExists(bytes.Clone(name))
	if err != nil {
		return nil, tx.fail(err)
	}
	return &boltWriteTx{boltReadTx: &boltReadTx{txState: tx.txState, bucket: bucket}}, nil
}

func (tx *boltWriteTx) Put(key, value []byte) error {
	if err := tx.checkKey(key); err != nil {
		return err
	}
	// bbolt retains values until commit. A non-nil copy also makes a nil input
	// distinguishable from an absent key when read inside this transaction.
	owned := make([]byte, len(value))
	copy(owned, value)
	return tx.fail(tx.bucket.Put(bytes.Clone(key), owned))
}

func (tx *boltWriteTx) Delete(key []byte) error {
	if err := tx.checkKey(key); err != nil {
		return err
	}
	return tx.fail(tx.bucket.Delete(key))
}
