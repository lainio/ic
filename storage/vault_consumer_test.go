package storage_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage"
)

var _ io.Closer = (*storage.Vault)(nil)

// A finite smoke-test provider only; it makes no durable accounting claim.
type consumerProvider struct {
	mu     sync.Mutex      // Protects counters, not Vault permissions.
	secret []byte          // Random 32-byte secret; storage derives keys from it.
	vault  storage.VaultID // ID of the vault served; not a secret.
	id     storage.KeyID   // Key version ID; not a secret or cipher selector.
	// Remaining permitted encryptions for this secret/vault/key binding.
	// All leases share it, and reopening a file does not reset it.
	remainingEncryptions uint32
}

// exampleEncryptionBudget follows the existing 2^24 development policy.
// It is a finite in-process test default, independent of application workload;
// it supplies no lifetime enforcement across process restarts, copies or restores.
const exampleEncryptionBudget uint32 = 1 << 24

func newConsumerProvider(vault storage.VaultID, id storage.KeyID,
	secret []byte) *consumerProvider {
	return &consumerProvider{
		vault: vault, id: id, secret: secret,
		remainingEncryptions: exampleEncryptionBudget,
	}
}

type consumerLease struct{ p *consumerProvider }

func (p *consumerProvider) Acquire(ctx context.Context, vault storage.VaultID, id storage.KeyID) (storage.Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if vault != p.vault || id != p.id {
		return nil, storage.ErrProvider
	}
	return &consumerLease{p}, nil
}

func (l *consumerLease) Secret() []byte { return l.p.secret }
func (l *consumerLease) Check() error   { return nil }
func (l *consumerLease) Release() error { return nil }

func (l *consumerLease) ConsumeEncryption() error {
	p := l.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.remainingEncryptions == 0 {
		return storage.ErrKeyUsageExhausted
	}
	p.remainingEncryptions--
	return nil
}

// The consumer receives only its designated Vault, with no routing/key access.
func consumeVault(v *storage.Vault) (records map[string]string, err error) {
	defer err2.Handle(&err, nil)
	try.To(v.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		wallet := try.To1(tx.EnsureChild([]byte("wallet")))
		received := try.To1(wallet.EnsureChild([]byte("received")))
		return received.Put([]byte("key"), []byte("designated"))
	}))
	records = make(map[string]string)
	err = v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		defer assert.PushAsserter(assert.Plain)()
		wallet := try.To1(tx.Child([]byte("wallet")))
		received := try.To1(wallet.Child([]byte("received")))
		value, found := try.To2(received.Get([]byte("key")))
		assert.That(found, errors.New("consumer record missing"))
		assert.Equal(string(value), "designated", errors.New("consumer record differs"))
		return received.Each(func(key, value []byte) error {
			records[string(key)] = string(value)
			return nil
		})
	})
	return records, err
}

func TestVaultConsumer(t *testing.T) {
	for _, backend := range []string{"memory", "bbolt"} {
		t.Run(backend, func(t *testing.T) {
			defer assert.PushTester(t)()
			var db *storage.Database
			if backend == "memory" {
				db = storage.NewMemory()
			} else {
				db = try.To1(storage.OpenBolt(filepath.Join(t.TempDir(), "consumer.db")))
			}
			t.Cleanup(func() { _ = db.Close() })
			var vaults [2]*storage.Vault
			for i := range vaults {
				p := newConsumerProvider(storage.VaultID{byte(i + 1)}, storage.KeyID{7}, make([]byte, 32))
				try.To1(rand.Read(p.secret)) // Independent random secret per vault.
				t.Cleanup(func() { clear(p.secret) })
				try.To(db.CreateVault(context.Background(), p.vault, p.id, p))
				vaults[i] = try.To1(db.OpenVault(context.Background(), p.vault, p.id, p))
			}
			try.To(vaults[1].Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				wallet := try.To1(tx.EnsureChild([]byte("wallet")))
				received := try.To1(wallet.EnsureChild([]byte("received")))
				return received.Put([]byte("key"), []byte("other Vault"))
			}))
			records := try.To1(consumeVault(vaults[0]))
			assert.Equal(len(records), 1)
			assert.Equal(records["key"], "designated")
			try.To(vaults[1].View(func(tx storage.ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				wallet := try.To1(tx.Child([]byte("wallet")))
				received := try.To1(wallet.Child([]byte("received")))
				value, found := try.To2(received.Get([]byte("key")))
				assert.That(found)
				assert.Equal(string(value), "other Vault")
				return nil
			}))
			inspect := func(ns storage.ReadNS) (err error) {
				defer err2.Handle(&err, nil)
				wallet := try.To1(ns.Child([]byte("wallet")))
				received := try.To1(wallet.Child([]byte("received")))
				for _, read := range []storage.ReadNS{wallet, received} {
					_, writable := read.(storage.WriteNS)
					assert.ThatNot(writable)
				}
				return nil
			}
			try.To(vaults[0].View(func(tx storage.ReadTx) error { return inspect(tx) }))
			try.To(vaults[0].Update(func(tx storage.WriteTx) error { return inspect(tx) }))
			try.To(db.Close())
		})
	}
}
