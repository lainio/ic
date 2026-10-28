package pw

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
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Follow device/ads' real encrypted Bolt and finite encryption lease fixtures.
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
	p.remaining.Store(128)
	t.Cleanup(func() { clear(p.secret) })
	f := vaultFixture{lease: p, path: filepath.Join(t.TempDir(), "vault.db")}
	f.db = try.To1(storage.OpenBolt(f.path))
	db := f.db
	t.Cleanup(func() { assert.NoError(db.Close()) })
	try.To(db.CreateVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, p))
	f.vault = try.To1(db.OpenVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, p))
	return f
}

func (f vaultFixture) unchanged(t *testing.T, fn func()) {
	t.Helper()
	defer assert.PushTester(t)()
	before := try.To1(os.ReadFile(f.path))
	remaining := f.lease.remaining.Load()
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
	f.vault = try.To1(db.OpenVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, f.lease))
}

type testLease struct {
	secret    []byte
	remaining atomic.Int64
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

func newSigner(t *testing.T) savedSigner {
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
	handle := try.To1(nodeidentity.OpenDirectory(dir, unlock))
	return savedSigner{dir, unlock, handle, try.To1(handle.CBORPublicKey())}
}

type probeSigner struct {
	key.Handle
	publicCalls, signCalls atomic.Int64
	publicErr, signErr     error
	public                 key.Public
	sign                   func([]byte) ([]byte, error)
}

func (*probeSigner) ID() []byte { panic("must not access handle ID") }
func (*probeSigner) Verify([]byte, []byte) bool {
	panic("must verify with independent public key")
}
func (s *probeSigner) CBORPublicKey() ([]byte, error) {
	s.publicCalls.Add(1)
	if s.publicErr != nil || s.public != nil {
		return s.public, s.publicErr
	}
	return s.Handle.CBORPublicKey()
}
func (s *probeSigner) Sign(data []byte) ([]byte, error) {
	s.signCalls.Add(1)
	if s.signErr != nil {
		return []byte("partial signature must not escape"), s.signErr
	}
	if s.sign != nil {
		return s.sign(data)
	}
	return s.Handle.Sign(data)
}

func savePath(t *testing.T, vault *storage.Vault, root key.Public,
	path intro.Path, subject savedSigner,
) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To2(onboarding.SaveIntroduction(vault, root, path.Bytes(),
		try.To1(path.SignAcceptance(subject.handle))))
}

type scenario struct {
	f                 vaultFixture
	root, local, peer savedSigner
}

func ready(t *testing.T) scenario {
	t.Helper()
	defer assert.PushTester(t)()
	s := scenario{newVault(t), newSigner(t), newSigner(t), newSigner(t)}
	base := intro.New(key.Info{Public: s.root.public})
	own := base.Introduce(s.root.handle, key.Info{Public: s.local.public})
	acceptance := try.To1(onboarding.SignAfterStoredChoice(s.f.vault,
		s.local.handle, s.root.public, s.root.public, own))
	try.To2(onboarding.SaveIntroduction(s.f.vault, s.root.public, own.Bytes(), acceptance))
	savePath(t, s.f.vault, s.root.public,
		base.Introduce(s.root.handle, key.Info{Public: s.peer.public}), s.peer)
	assert.Equal(try.To1(onboarding.VerifyReceived(s.f.vault, s.root.public)), 2)
	try.To1(device.BootstrapLocal(s.f.vault, s.root.public, s.local.public, s.local.handle))
	return s
}

func (s scenario) check(t *testing.T, signer key.Handle, want error) {
	t.Helper()
	defer assert.PushTester(t)()
	s.f.unchanged(t, func() {
		err := CheckLocalAcceptor(s.f.vault, s.root.public, s.local.public, s.peer.public, signer)
		assert.Equal(err, want) // Only fixed, sanitized errors cross this boundary.
	})
}

const (
	knownNS    = "known-introductions-v1"
	receivedNS = "received-introductions-v1"
	authNS     = "local-device-auth-v1"
	authKey    = "local-software-signer"
)

func readRecord(t *testing.T, v *storage.Vault, name string, subject []byte) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	var record []byte
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.Child([]byte(name)))
		var found bool
		record, found = try.To2(ns.Get(subject))
		assert.That(found)
		return nil
	}))
	return record
}

func putRecord(t *testing.T, v *storage.Vault, name string, subject, record []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(v.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.EnsureChild([]byte(name)))
		return ns.Put(subject, record)
	}))
}

func deleteRecord(t *testing.T, v *storage.Vault, name string, subject []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(v.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.ChildForUpdate([]byte(name)))
		return ns.Delete(subject)
	}))
}
