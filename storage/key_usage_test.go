package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestVaultKeyUsage(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) *Database
	}{
		{"memory", func(_ *testing.T) *Database { return NewMemory() }},
		{"bbolt", func(t *testing.T) *Database {
			return try.To1(OpenBolt(filepath.Join(t.TempDir(), "usage.db")))
		}},
	} {
		t.Run(backend.name, func(t *testing.T) {
			t.Run("shared_handles_and_databases", func(t *testing.T) {
				defer assert.PushTester(t)()
				a, b := backend.open(t), backend.open(t)
				t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
				ctx := context.Background()
				vault, id := VaultID{1}, KeyID{7}
				p := newLifecycleProvider(t, 4)
				// Both databases use the same actual key and shared pool.
				try.To(a.CreateVault(ctx, vault, id, p))
				assert.Equal(p.consumeCalls, 1)
				assert.Equal(p.spent, uint32(1))
				try.To(b.CreateVault(ctx, vault, id, p))
				assert.ErrorIs(a.CreateVault(ctx, vault, id, p), ErrVaultExists)
				first := try.To1(a.OpenVault(ctx, vault, id, p))
				second := try.To1(a.OpenVault(ctx, vault, id, p))
				unused := try.To1(a.OpenVault(ctx, vault, id, p))
				otherDB := try.To1(b.OpenVault(ctx, vault, id, p))
				try.To(unused.Close())
				assert.Equal(p.consumeCalls, 2, "duplicate/open/close consume nothing")
				assert.Equal(p.remainingEncryptions, uint32(2))
				key := []byte("shared")
				for _, v := range []*Vault{first, second} {
					try.To(v.Update(func(tx WriteTx) error {
						return tx.Put(key, []byte("value"))
					}))
				}
				assert.Equal(p.spent, uint32(4))
				assert.Equal(p.remainingEncryptions, uint32(0))
				for _, v := range []*Vault{first, second, otherDB} {
					assert.ErrorIs(v.Update(func(tx WriteTx) error {
						return tx.Put(key, nil)
					}), ErrKeyUsageExhausted)
				}
				try.To(first.Close())
				try.To(second.Close())
				calls := p.consumeCalls
				reopened := try.To1(a.OpenVault(ctx, vault, id, p))
				assert.Equal(p.consumeCalls, calls)
				try.To(reopened.View(func(tx ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					checkRecord(t, tx, key, []byte("value"), true)
					return nil
				}))
				try.To(reopened.Update(func(tx WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					try.To1(tx.EnsureChild([]byte("allowed")))
					return tx.Delete(key)
				}))
				try.To(reopened.View(func(tx ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					assert.That(try.To1(tx.HasChild([]byte("allowed"))))
					checkRecord(t, tx, key, nil, false)
					return nil
				}))
				assert.Equal(p.consumeCalls, calls, "reads and metadata need no debit")
				try.To(a.Close())
				try.To(b.Close())
				assert.Equal(p.consumeCalls, calls)
				for _, lease := range p.leases {
					assert.Equal(lease.releases, 1)
				}
			})
			t.Run("consume_failure", func(t *testing.T) {
				defer assert.PushTester(t)()
				db := backend.open(t)
				t.Cleanup(func() { _ = db.Close() })
				v, p := newRecordVault(t, db, VaultID{1}, 1)
				cause := errors.New("injected consumption failure")
				p.consumeErr = cause
				result := v.Update(func(tx WriteTx) error {
					return tx.Put([]byte("key"), nil)
				})
				assert.ErrorIs(result, cause)
				assert.ThatNot(errors.Is(result, ErrKeyUsageExhausted))
				assert.Equal(p.consumeCalls, 2)
				assert.Equal(p.spent, uint32(1))
				assert.Equal(p.remainingEncryptions, uint32(1))
				p.consumeErr = nil
				try.To(v.View(func(tx ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					checkRecord(t, tx, []byte("key"), nil, false)
					return nil
				}))
				try.To(v.Update(func(tx WriteTx) error {
					return tx.Put([]byte("key"), nil)
				}))
				assert.Equal(p.consumeCalls, 3)
				assert.Equal(p.spent, uint32(2))
			})
			// Reuse the existing rejection and rollback assertions.
			t.Run("reject_before_seal", func(t *testing.T) {
				vaultRecordsNoRepair(t, backend.open)
			})
			t.Run("failed_open", func(t *testing.T) {
				lifecycleVerificationFailure(t, backend.open)
			})
			t.Run("ignored_exhaustion", func(t *testing.T) {
				vaultKeyUsageAbort(t, backend.open)
			})
		})
	}
	// The existing file reopen test keeps the provider and binding alive.
	t.Run("file_reopen", vaultKeyUsageReopen)
	t.Run("concurrent_counter", func(t *testing.T) {
		defer assert.PushTester(t)()
		const budget, attempts = 3, 8
		p := newLifecycleProvider(t, budget)
		var leases [2]Lease
		for i := range leases {
			leases[i] = try.To1(p.Acquire(context.Background(), VaultID{1}, KeyID{7}))
		}
		start := make(chan struct{})
		results := make(chan error, attempts)
		for i := range attempts {
			go func(lease Lease) {
				<-start
				// Direct calls: no database writer lock can serialize this test.
				results <- lease.ConsumeEncryption()
			}(leases[i%len(leases)])
		}
		close(start)
		successes := 0
		for range attempts {
			if err := lifecycleResult(t, results); err != nil {
				assert.ErrorIs(err, ErrKeyUsageExhausted)
			} else {
				successes++
			}
		}
		assert.Equal(successes, budget)
		assert.Equal(p.consumeCalls, attempts)
		assert.Equal(p.spent, uint32(budget))
		assert.Equal(p.remainingEncryptions, uint32(0))
		for _, lease := range leases {
			try.To(lease.Release())
		}
		assert.Equal(p.remainingEncryptions, uint32(0))
	})
}

func vaultKeyUsageAbort(t *testing.T, open func(*testing.T) *Database) {
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
		assert.ErrorIs(first, ErrKeyUsageExhausted)
		value, found, next := tx.Get(key)
		assert.SNil(value)
		assert.ThatNot(found)
		assert.Equal(next, first)
		assert.Equal(tx.Put(nil, nil), first)
		assert.Equal(tx.Delete(key), first)
		checkNamespaceFailure(t, tx, first)
		return nil // Ignoring the codec error must still roll back the first Put.
	})
	assert.Equal(result, first)
	checkExpiredRecordTx(t, saved)
	assert.Equal(p.spent, uint32(3))
	assert.Equal(p.remainingEncryptions, uint32(0))
	assert.Equal(p.consumeCalls, int(p.spent)+1)
	assert.Equal(len(p.calls), 2)
	try.To(v.View(func(tx ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		checkRecord(t, tx, key, []byte("original"), true)
		checkRecord(t, tx, []byte("new"), nil, false)
		return nil
	}))
	assert.ErrorIs(v.Update(func(tx WriteTx) error { return tx.Put(key, nil) }), ErrKeyUsageExhausted)
	try.To(v.Update(func(tx WriteTx) error { return tx.Delete(key) }))
	assert.Equal(p.spent, uint32(3))
	try.To(db.Close())
}
