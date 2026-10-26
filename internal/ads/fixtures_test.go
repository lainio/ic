package ads

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

var fixedNow = time.Date(2026, 10, 26, 12, 0, 0, 123456789, time.UTC)

const endpoint = "http://127.0.0.1:8080/peer/introduction"

type savedSigner struct {
	dir, unlock string
	handle      key.Handle
	public      key.Public
}

func newSigner(t *testing.T) savedSigner {
	t.Helper()
	defer assert.PushTester(t)()

	parent := t.TempDir()
	dir, unlock := filepath.Join(
		parent,
		"node",
	), filepath.Join(
		parent,
		"unlock",
	)
	try.To(os.Mkdir(dir, 0700))
	secret := make([]byte, 32)
	defer clear(secret)
	try.To1(rand.Read(secret))
	try.To(os.WriteFile(unlock, secret, 0600))
	try.To1(nodeidentity.Create(filepath.Join(dir, "identity.json"), secret))
	handle := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	return savedSigner{dir, unlock, handle, try.To1(handle.CBORPublicKey())}
}

// Use the existing encrypted Bolt/finite lease fixture pattern. Tests are
// caller-serialized, including the accounting and injected local seal failure.
type vaultFixture struct {
	vault *storage.Vault
	lease *testLease
	path  string
}

func newVault(t *testing.T) vaultFixture {
	t.Helper()
	defer assert.PushTester(t)()

	lease := &testLease{secret: make([]byte, 32), remaining: 256}
	try.To1(rand.Read(lease.secret))
	t.Cleanup(func() { clear(lease.secret) })
	path := filepath.Join(t.TempDir(), "vault.db")
	db := try.To1(storage.OpenBolt(path))
	t.Cleanup(func() { assert.NoError(db.Close()) })
	try.To(
		db.CreateVault(
			t.Context(),
			storage.VaultID{1},
			storage.KeyID{7},
			lease,
		),
	)
	vault := try.To1(
		db.OpenVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, lease),
	)
	return vaultFixture{vault, lease, path}
}

func (f vaultFixture) unchanged(t *testing.T, fn func()) {
	t.Helper()
	defer assert.PushTester(t)()
	before := try.To1(os.ReadFile(f.path))
	remaining := f.lease.remaining
	fn()
	assert.Equal(f.lease.remaining, remaining)
	assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
}

type testLease struct {
	secret    []byte
	remaining int
	sealErr   error
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
func (*testLease) Check() error     { return nil }
func (*testLease) Release() error   { return nil }
func (p *testLease) ConsumeEncryption() error {
	if p.sealErr != nil {
		return p.sealErr
	}
	if p.remaining == 0 {
		return storage.ErrKeyUsageExhausted
	}
	p.remaining--
	return nil
}

// Neither publishing nor usability checks may inspect handle IDs or delegate
// verification to the supplied signer. Observe both probe and final signature.
type observedSigner struct {
	key.Handle
	calls int
	sign  func(int, []byte) ([]byte, error)
}

func (*observedSigner) ID() []byte { panic("must not read handle ID") }
func (*observedSigner) Verify([]byte, []byte) bool {
	panic("must verify with expected public key")
}
func (s *observedSigner) Sign(data []byte) ([]byte, error) {
	s.calls++
	if s.sign != nil {
		return s.sign(s.calls, data)
	}
	return s.Handle.Sign(data)
}

func ownEvidence(vault *storage.Vault, root, local savedSigner,
	stage string,
) (err error) {
	defer err2.Handle(&err, nil)
	path := intro.New(key.Info{Public: root.public}).Introduce(
		root.handle, key.Info{Public: local.public})
	acceptance := try.To1(onboarding.SignAfterStoredChoice(
		vault, local.handle, root.public, root.public, path))
	if stage == "choice" {
		return nil
	}
	try.To2(
		onboarding.SaveIntroduction(
			vault,
			root.public,
			path.Bytes(),
			acceptance,
		),
	)
	if stage == "known" {
		try.To1(onboarding.VerifyReceived(vault, root.public))
	}
	return nil
}

func records(vault *storage.Vault, names ...string) (
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
			ns := try.To1(tx.Child([]byte(name)))
			result[name] = make(map[string][]byte)
			try.To(ns.Each(func(k, v []byte) error {
				result[name][string(k)] = v
				return nil
			}))
		}
		return nil
	}))
	return result, nil
}
