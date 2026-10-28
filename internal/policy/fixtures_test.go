package policy

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func newPublic(t *testing.T) key.Public {
	t.Helper()
	defer assert.PushTester(t)()
	private := try.To1(ecdh.P256().GenerateKey(rand.Reader))
	point := private.PublicKey().Bytes()
	return try.To1(wire.Marshal(map[int]any{
		1: 2, 3: -7, -1: 1, -2: point[1:33], -3: point[33:],
	}))
}

// Real encrypted Bolt with finite shared usage, as in pw/device/ads fixtures.
// Failure hooks are changed only when no operation is running.
type testLease struct {
	secret    []byte
	remaining atomic.Int64
	sealErr   error
	checkErr  error
	onCheck   func()
}

func (p *testLease) Acquire(ctx context.Context, vault storage.VaultID,
	id storage.KeyID,
) (storage.Lease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if vault != (storage.VaultID{1}) || id != (storage.KeyID{7}) {
		return nil, storage.ErrProvider
	}
	return p, nil
}

func (p *testLease) Secret() []byte { return p.secret }
func (*testLease) Release() error   { return nil }
func (p *testLease) Check() error {
	if p.onCheck != nil {
		p.onCheck()
	}
	return p.checkErr
}
func (p *testLease) ConsumeEncryption() error {
	if p.sealErr != nil {
		return p.sealErr
	}
	for {
		remaining := p.remaining.Load()
		if remaining == 0 {
			return storage.ErrKeyUsageExhausted
		}
		if p.remaining.CompareAndSwap(remaining, remaining-1) {
			return nil
		}
	}
}

type vaultFixture struct {
	vault *storage.Vault
	db    *storage.Database
	lease *testLease
	path  string
}

func newVault(t *testing.T) vaultFixture {
	t.Helper()
	defer assert.PushTester(t)()
	p := &testLease{secret: make([]byte, 32)}
	try.To1(rand.Read(p.secret))
	p.remaining.Store(256)
	t.Cleanup(func() { clear(p.secret) })
	f := vaultFixture{lease: p, path: filepath.Join(t.TempDir(), "vault.db")}
	f.db = try.To1(storage.OpenBolt(f.path))
	db := f.db
	t.Cleanup(func() {
		if p.checkErr != nil {
			assert.ErrorIs(db.Close(), p.checkErr)
		} else {
			assert.NoError(db.Close())
		}
	})
	try.To(db.CreateVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, p))
	f.vault = try.To1(
		db.OpenVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, p),
	)
	return f
}

func (f vaultFixture) unchanged(t *testing.T, fn func()) {
	t.Helper()
	defer assert.PushTester(t)()
	before, remaining := try.To1(os.ReadFile(f.path)), f.lease.remaining.Load()
	fn()
	assert.Equal(f.lease.remaining.Load(), remaining)
	assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
}

func (f *vaultFixture) reopen(t *testing.T) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(f.db.Close())
	f.db = try.To1(storage.OpenBolt(f.path))
	db := f.db
	t.Cleanup(func() { assert.NoError(db.Close()) })
	f.vault = try.To1(
		db.OpenVault(
			t.Context(),
			storage.VaultID{1},
			storage.KeyID{7},
			f.lease,
		),
	)
}

func rawPolicy(t *testing.T, v *storage.Vault) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	var raw []byte
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		raw, _ = try.To2(tx.Get([]byte(deniedKey)))
		return nil
	}))
	return raw
}
