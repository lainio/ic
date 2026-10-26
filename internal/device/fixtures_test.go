package device

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Same encrypted temporary Bolt/finite-lease pattern as storage integration
// tests. The separate restart test uses the production nodevault binding.
type vaultFixture struct {
	vault    *storage.Vault
	provider *testProvider
	path     string
}

func newVault(t *testing.T) vaultFixture {
	t.Helper()
	defer assert.PushTester(t)()

	p := &testProvider{secret: make([]byte, 32)}
	try.To1(rand.Read(p.secret))
	p.remaining.Store(128)
	t.Cleanup(func() { clear(p.secret) })
	path := filepath.Join(t.TempDir(), "vault.db")
	db := try.To1(storage.OpenBolt(path))
	t.Cleanup(func() { assert.NoError(db.Close()) })
	try.To(db.CreateVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, p))
	vault := try.To1(db.OpenVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, p))
	return vaultFixture{vault, p, path}
}

func (f vaultFixture) readOnly(t *testing.T, fn func()) {
	t.Helper()
	defer assert.PushTester(t)()

	before := try.To1(os.ReadFile(f.path))
	remaining := f.provider.remaining.Load()
	fn()
	assert.Equal(f.provider.remaining.Load(), remaining)
	assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
}

type testProvider struct {
	secret    []byte
	remaining atomic.Int64
}

func (p *testProvider) Acquire(ctx context.Context, vault storage.VaultID,
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

func (p *testProvider) Secret() []byte { return p.secret }
func (*testProvider) Check() error     { return nil }
func (*testProvider) Release() error   { return nil }
func (p *testProvider) ConsumeEncryption() error {
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

type savedSigner struct {
	dir, unlock string
	handle      key.Handle
	public      key.Public
}

func newSavedSigner(t *testing.T) savedSigner {
	t.Helper()
	defer assert.PushTester(t)()

	parent := t.TempDir()
	dir, unlock := filepath.Join(parent, "node"), filepath.Join(parent, "unlock")
	try.To(os.Mkdir(dir, 0700))
	secret := make([]byte, 32)
	defer clear(secret)
	try.To1(rand.Read(secret))
	try.To(os.WriteFile(unlock, secret, 0600))
	try.To1(nodeidentity.Create(filepath.Join(dir, "identity.json"), secret))
	restored := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	return savedSigner{dir, unlock, restored, try.To1(restored.CBORPublicKey())}
}

func (s savedSigner) material() (_ [][]byte, err error) {
	defer err2.Handle(&err, nil)
	return [][]byte{
		try.To1(os.ReadFile(filepath.Join(s.dir, "identity.json"))),
		try.To1(os.ReadFile(s.unlock)),
	}, nil
}

// ID and Verify must never be authority. Observe probe inputs and inject
// operational failures without generating substitute identities in the API.
type probeSigner struct {
	key.Handle
	publicErr, signErr error
	public             key.Public
	sign               func([]byte) ([]byte, error)
	probes             [][]byte
}

func (*probeSigner) ID() []byte                 { panic("device must not access wrapped handle") }
func (*probeSigner) Verify([]byte, []byte) bool { panic("device must verify independently") }
func (s *probeSigner) CBORPublicKey() ([]byte, error) {
	if s.publicErr != nil || s.public != nil {
		return s.public, s.publicErr
	}
	return s.Handle.CBORPublicKey()
}
func (s *probeSigner) Sign(data []byte) ([]byte, error) {
	s.probes = append(s.probes, append([]byte(nil), data...))
	if s.signErr != nil {
		return []byte("partial signature"), s.signErr
	}
	if s.sign != nil {
		return s.sign(data)
	}
	return s.Handle.Sign(data)
}

func namespaceRecords(vault *storage.Vault, names ...string) (
	_ map[string]map[string][]byte, err error,
) {
	defer err2.Handle(&err, nil)
	result := make(map[string]map[string][]byte)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for _, name := range names {
			if !try.To1(tx.HasChild([]byte(name))) {
				continue
			}
			records := try.To1(tx.Child([]byte(name)))
			result[name] = make(map[string][]byte)
			try.To(records.Each(func(k, v []byte) error {
				result[name][string(k)] = v
				return nil
			}))
		}
		return nil
	}))
	return result, nil
}
