// Package nodevault owns one local encrypted Vault and conservative restart
// accounting. It adds no introduction, Known, trust, or recovery transition.
package nodevault

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
	bolt "go.etcd.io/bbolt"
)

// Binding is independently configured by the caller, never learned from a
// proposal. Root and Child must be nonempty; IDs identify one fixed storage key.
type Binding struct {
	VaultID storage.VaultID
	KeyID   storage.KeyID
	Root    key.Public
	Child   key.Public
}

// Store owns its provider, Database, Vault and exclusive usage-file lock.
// Use constructed pointers only. Lifecycle calls must be caller-serialized and
// must not run inside Vault callbacks. Vault operations retain storage's rules.
// Copies, restores, deletion or mixing of files, and reuse of the secret outside
// this Store are unsupported. This is not rollback-resistant accounting or a
// complete power-loss recovery protocol; development upgrades are unsupported.
type Store struct {
	provider *provider
	db       *storage.Database
	vault    *storage.Vault
	usage    *bolt.DB
	closed   bool
	closeErr error
}

const lockTimeout = time.Second

// Create exclusively creates a dedicated mode-0700 state subdirectory under
// an existing trusted parent, with private vault.db and usage.db files.
// Supply a fresh independent random 32-byte secret used only for this Store,
// never an identity-wrapping key, signing key or owner token. The component
// neither provisions nor persists secrets and cannot detect reuse elsewhere.
// Errors return nil and may leave partial state for explicit operator inspection.
// Retrying never overwrites it. Retained inputs are copied.
func Create(ctx context.Context, dir string, secret []byte,
	expected Binding) (store *Store, err error) {
	s := &Store{}
	defer func() {
		if store == nil {
			err = errors.Join(err, s.Close())
		}
	}()
	defer err2.Handle(&err)

	try.To(ctx.Err())
	s.provider = try.To1(newProvider(secret, expected))
	try.To(validDirectoryName(dir))
	try.To(os.Mkdir(dir, 0700))
	s.usage = try.To1(bolt.Open(filepath.Join(dir, "usage.db"), 0600,
		&bolt.Options{Timeout: lockTimeout, OpenFile: createFile}))
	try.To(initializeUsage(s.usage, s.provider.binding))
	try.To(s.provider.reserve(ctx, s.usage))

	path := filepath.Join(dir, "vault.db")
	file := try.To1(createFile(path, os.O_RDWR|os.O_CREATE, 0600))
	try.To(file.Close())
	s.db = try.To1(storage.OpenBolt(path))
	b := s.provider.binding
	try.To(s.db.CreateVault(ctx, b.VaultID, b.KeyID, s.provider))
	s.vault = try.To1(s.db.OpenVault(ctx, b.VaultID, b.KeyID, s.provider))
	try.To(ctx.Err())
	return s, nil
}

// Open requires complete existing state, the same secret and complete binding.
// It never creates or repairs files or choice records. It authenticates the
// existing Vault with zero spending before reserving one fixed block. An
// inspection-only opening can therefore charge capacity; reads do not seal.
// Exhausted lifetime capacity still permits reads and completed-result reuse.
func Open(ctx context.Context, dir string, secret []byte,
	expected Binding) (store *Store, err error) {
	s := &Store{}
	defer func() {
		if store == nil {
			err = errors.Join(err, s.Close())
		}
	}()
	defer err2.Handle(&err)

	try.To(ctx.Err())
	s.provider = try.To1(newProvider(secret, expected))
	try.To(validDirectoryName(dir))
	info := try.To1(os.Lstat(dir))
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("state must be a private directory")
	}
	usagePath := filepath.Join(dir, "usage.db")
	vaultPath := filepath.Join(dir, "vault.db")
	try.To1(existingFile(usagePath))
	try.To1(existingFile(vaultPath))
	s.usage = try.To1(bolt.Open(usagePath, 0600,
		&bolt.Options{Timeout: lockTimeout, OpenFile: openFile}))
	b := s.provider.binding
	charged := try.To1(readUsage(s.usage, b))
	if charged == 0 {
		return nil, errors.New("missing initial usage reservation")
	}
	try.To(checkExistingVault(vaultPath))
	try.To(ctx.Err())
	s.db = try.To1(storage.OpenBolt(vaultPath))
	s.vault = try.To1(s.db.OpenVault(ctx, b.VaultID, b.KeyID, s.provider))
	try.To(s.provider.reserve(ctx, s.usage))
	try.To(ctx.Err())
	return s, nil
}

// Vault borrows the existing handle; the caller applies onboarding operations
// with its independently expected identities. No signing handle belongs here.
func (s *Store) Vault() *storage.Vault { return s.vault }

// Close is terminal and idempotent under caller-serialized lifecycle use.
// Database.Close drains work and releases leases before clearing the owned
// secret, then the usage lock is released. All cleanup is attempted and errors
// retained. Files remain; unused capacity is discarded, never refunded.
func (s *Store) Close() error {
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	if s.db != nil {
		s.closeErr = s.db.Close()
	}
	if s.provider != nil {
		clear(s.provider.secret)
		s.provider.remaining = 0
	}
	if s.usage != nil {
		s.closeErr = errors.Join(s.closeErr, s.usage.Close())
	}
	return s.closeErr
}

func validDirectoryName(dir string) error {
	if strings.TrimSpace(dir) == "" || filepath.Clean(dir) != dir {
		return errors.New("state directory must be a nonempty clean path")
	}
	return nil
}

func createFile(
	path string,
	flag int,
	mode os.FileMode,
) (_ *os.File, err error) {
	defer err2.Handle(&err, nil)

	return os.OpenFile(path, flag|os.O_EXCL|syscall.O_NOFOLLOW, mode)
}

func existingFile(path string) (_ os.FileInfo, err error) {
	defer err2.Handle(&err)

	info := try.To1(os.Lstat(path))
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() == 0 {
		return nil, errors.New(
			"database must be a nonempty private regular file",
		)
	}
	return info, nil
}

func openFile(
	path string,
	flag int,
	mode os.FileMode,
) (file *os.File, err error) {
	var opened *os.File
	defer func() {
		if file == nil && opened != nil {
			err = errors.Join(err, opened.Close())
		}
	}()
	defer err2.Handle(&err)

	info := try.To1(existingFile(path))
	opened = try.To1(os.OpenFile(path,
		flag & ^os.O_CREATE | syscall.O_NOFOLLOW | syscall.O_NONBLOCK, mode))
	actual := try.To1(opened.Stat())
	if !os.SameFile(info, actual) || actual.Mode().Perm()&0077 != 0 ||
		actual.Size() == 0 {
		return nil, errors.New("database changed while opening")
	}
	return opened, nil
}

// Guard the existing adapter's create-if-absent bucket before OpenBolt can
// initialize it. This only checks completeness; OpenVault authenticates using
// caller IDs. OpenBolt may update bbolt bookkeeping, but rewrites no records.
// As with nodeidentity, hostile same-user path replacement is outside scope.
func checkExistingVault(path string) (err error) {
	defer err2.Handle(&err)

	db := try.To1(bolt.Open(path, 0600, &bolt.Options{
		Timeout: lockTimeout, ReadOnly: true, OpenFile: openFile,
	}))
	defer func() { err = errors.Join(err, db.Close()) }()
	return db.View(func(tx *bolt.Tx) (err error) {
		defer err2.Handle(&err, nil)

		// The existing name comes from storage/internal/engine/bbolt.go.
		bucket := tx.Bucket([]byte("engine"))
		if bucket == nil {
			return errors.New("missing storage engine state")
		}
		first, _ := bucket.Cursor().First()
		if first == nil {
			return errors.New("empty storage engine state")
		}
		return nil
	})
}
