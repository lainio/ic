package nodevault

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage"
	bolt "go.etcd.io/bbolt"
)

// Fixed local implementation limits, not caller allowances. Each opening
// charges at most 4096 of 2^24 lifetime encryptions before enabling sealing.
// Unused capacity is lost on close/error/crash. There is no automatic refill:
// an explicit later Open may charge another block from uncharged capacity.
const (
	encryptionLimit uint64 = 1 << 24
	reservationSize uint64 = 4096
	usageBucket            = "nodevault"
)

type provider struct {
	mu        sync.Mutex
	secret    []byte
	binding   Binding
	remaining uint64
}

func newProvider(secret []byte, expected Binding) (*provider, error) {
	if len(secret) != 32 || len(expected.Root) == 0 ||
		len(expected.Child) == 0 {
		return nil, errors.New(
			"require a 32-byte storage secret and nonempty binding",
		)
	}
	expected.Root = bytes.Clone(expected.Root)
	expected.Child = bytes.Clone(expected.Child)
	return &provider{secret: bytes.Clone(secret), binding: expected}, nil
}

func (p *provider) Acquire(ctx context.Context, vault storage.VaultID,
	id storage.KeyID) (storage.Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if vault != p.binding.VaultID || id != p.binding.KeyID {
		return nil, storage.ErrProvider
	}
	return &lease{p}, nil
}

type lease struct{ p *provider }

// Storage borrows the secret until Release; Store clears it only after draining
// the Database. Authorization is fixed for this local provider's lifetime.
func (l *lease) Secret() []byte { return l.p.secret }
func (l *lease) Check() error   { return nil }
func (l *lease) Release() error { return nil }

// ConsumeEncryption is strictly memory-only, shared by all leases. Failed
// writes and rollbacks never refund a debit. Exhaustion does not revoke reads.
func (l *lease) ConsumeEncryption() error {
	l.p.mu.Lock()
	defer l.p.mu.Unlock()
	if l.p.remaining == 0 {
		return storage.ErrKeyUsageExhausted
	}
	l.p.remaining--
	return nil
}

// reserve runs once during construction, before publication, never in Acquire
// or ConsumeEncryption. A failed/uncertain synchronized commit grants nothing;
// there is no retry here. The next explicit Open reloads the disk high-water mark.
func (p *provider) reserve(ctx context.Context, db *bolt.DB) (err error) {
	defer err2.Handle(&err, nil)

	try.To(ctx.Err())
	var reserved uint64
	try.To(db.Update(func(tx *bolt.Tx) (err error) {
		defer err2.Handle(&err, nil)

		charged := try.To1(loadUsage(tx, p.binding))
		reserved = min(reservationSize, encryptionLimit-charged)
		try.To(ctx.Err())
		if reserved == 0 {
			return nil
		}
		return tx.Bucket([]byte(usageBucket)).Put([]byte("charged"),
			binary.BigEndian.AppendUint64(nil, charged+reserved))
	}))
	try.To(ctx.Err())
	p.mu.Lock()
	p.remaining = reserved
	p.mu.Unlock()
	return nil
}

func initializeUsage(db *bolt.DB, b Binding) (err error) {
	defer err2.Handle(&err, nil)

	return db.Update(func(tx *bolt.Tx) (err error) {
		defer err2.Handle(&err, nil)

		bucket := try.To1(tx.CreateBucket([]byte(usageBucket)))
		for name, value := range map[string][]byte{
			"version": {1}, "vault": b.VaultID[:], "key": b.KeyID[:],
			"root": b.Root, "child": b.Child, "charged": make([]byte, 8),
		} {
			try.To(bucket.Put([]byte(name), value))
		}
		return nil
	})
}

func readUsage(db *bolt.DB, b Binding) (charged uint64, err error) {
	defer err2.Handle(&err, nil)

	try.To(db.View(func(tx *bolt.Tx) (err error) {
		defer err2.Handle(&err, nil)

		charged = try.To1(loadUsage(tx, b))
		return nil
	}))
	return charged, nil
}

func loadUsage(tx *bolt.Tx, b Binding) (uint64, error) {
	bucket := tx.Bucket([]byte(usageBucket))
	if bucket == nil {
		return 0, errors.New("missing usage metadata")
	}
	for name, value := range map[string][]byte{
		"version": {1}, "vault": b.VaultID[:], "key": b.KeyID[:],
		"root": b.Root, "child": b.Child,
	} {
		if !bytes.Equal(bucket.Get([]byte(name)), value) {
			return 0, errors.New("invalid usage version or binding")
		}
	}
	value := bucket.Get([]byte("charged"))
	if len(value) != 8 {
		return 0, errors.New("missing or invalid usage counter")
	}
	charged := binary.BigEndian.Uint64(value)
	if charged > encryptionLimit {
		return 0, errors.New("usage counter exceeds lifetime limit")
	}
	return charged, nil
}
