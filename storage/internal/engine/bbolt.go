package engine

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/lainio/err2"
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
		read := &boltReadTx{bucket: tx.Bucket([]byte(rootBucket))}
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
		read := &boltReadTx{bucket: tx.Bucket([]byte(rootBucket))}
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
	bucket *bolt.Bucket
	err    error
}

type boltWriteTx struct {
	*boltReadTx
}

func (tx *boltReadTx) finish(err *error) {
	tx.bucket = nil
	if *err == nil {
		*err = tx.err
	} else if tx.err != nil && !errors.Is(*err, tx.err) {
		*err = errors.Join(*err, tx.err)
	}
}

func (tx *boltReadTx) fail(err error) error {
	if tx.err == nil {
		tx.err = err
	}
	return err
}

func (tx *boltReadTx) check(key []byte) error {
	if tx.bucket == nil {
		return ErrTxClosed
	}
	if tx.err != nil {
		return tx.err
	}
	if len(key) == 0 {
		return tx.fail(ErrEmptyKey)
	}
	return nil
}

func (tx *boltReadTx) Get(key []byte) ([]byte, bool, error) {
	if err := tx.check(key); err != nil {
		return nil, false, err
	}
	value := tx.bucket.Get(key)
	if value == nil {
		return nil, false, nil
	}
	return bytes.Clone(value), true, nil
}

func (tx *boltWriteTx) Put(key, value []byte) error {
	if err := tx.check(key); err != nil {
		return err
	}
	// bbolt retains values until commit. A non-nil copy also makes a nil input
	// distinguishable from an absent key when read inside this transaction.
	owned := make([]byte, len(value))
	copy(owned, value)
	return tx.fail(tx.bucket.Put(bytes.Clone(key), owned))
}

func (tx *boltWriteTx) Delete(key []byte) error {
	if err := tx.check(key); err != nil {
		return err
	}
	return tx.fail(tx.bucket.Delete(key))
}
