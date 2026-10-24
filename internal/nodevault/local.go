package nodevault

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// CreateForNode provisions <nodeDir>/state and a new, separate private file
// containing a fresh 32-byte storage secret. The private node directory and
// both parents must already exist. Neither existing path is overwritten,
// including symlinks. Errors may leave exclusive partial files for inspection.
// The caller restores Child independently and supplies expected Root bytes;
// this binding creates no authority. No signing identity is loaded here.
func CreateForNode(ctx context.Context, nodeDir, keyFile string,
	expectedRoot, expectedChild key.Public) (_ *Store, err error) {
	defer err2.Handle(&err)

	try.To(ctx.Err())
	state, keyFile := try.To2(localPaths(nodeDir, keyFile))
	binding := try.To1(localBinding(expectedRoot, expectedChild))
	try.To(localAbsent(state))
	try.To(localAbsent(keyFile))

	secret := make([]byte, 32)
	defer clear(secret)
	try.To1(rand.Read(secret))
	try.To(writeLocalSecret(keyFile, secret))
	return Create(ctx, state, secret, binding)
}

// OpenForNode opens only existing state and a private regular 32-byte secret
// file. It never provisions, repairs or replaces material. Each successful
// opening retains Store's fixed-block charge, even for inspection or reuse.
// The Store owns a secret copy; local raw buffers are cleared on return.
func OpenForNode(ctx context.Context, nodeDir, keyFile string,
	expectedRoot, expectedChild key.Public) (_ *Store, err error) {
	defer err2.Handle(&err)

	try.To(ctx.Err())
	state, keyFile := try.To2(localPaths(nodeDir, keyFile))
	binding := try.To1(localBinding(expectedRoot, expectedChild))
	secret := try.To1(readLocalSecret(keyFile))
	defer clear(secret)
	return Open(ctx, state, secret, binding)
}

func localPaths(nodeDir, keyFile string) (_ string, _ string, err error) {
	defer err2.Handle(&err)

	nodeDir, keyFile = try.To2(nodeidentity.ResolvePaths(nodeDir, keyFile))
	info := try.To1(os.Lstat(nodeDir))
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return "", "", errors.New(
			"node directory must be a private directory",
		)
	}
	return filepath.Join(nodeDir, "state"), keyFile, nil
}

func localBinding(root, child key.Public) (Binding, error) {
	if len(root) == 0 || len(child) == 0 {
		return Binding{}, errors.New(
			"expected Root and Child must be nonempty",
		)
	}
	// Private layout identifiers for this independently keyed Store, neither
	// secrets nor global node IDs. Every initialization generates its own key.
	return Binding{
		VaultID: storage.VaultID{1}, KeyID: storage.KeyID{7},
		Root: root, Child: child,
	}, nil
}

func localAbsent(path string) error {
	_, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		return os.ErrExist
	}
	return err
}

func writeLocalSecret(path string, secret []byte) (err error) {
	var file *os.File
	closed := false
	defer func() {
		if file != nil && !closed {
			err = errors.Join(err, file.Close())
		}
	}()
	defer err2.Handle(&err)

	file = try.To1(os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600))
	n := try.To1(file.Write(secret))
	if n != len(secret) {
		return io.ErrShortWrite
	}
	closed = true
	try.To(file.Close())
	return nil
}

func readLocalSecret(path string) (_ []byte, err error) {
	var file *os.File
	closed := false
	defer func() {
		if file != nil && !closed {
			err = errors.Join(err, file.Close())
		}
	}()
	defer err2.Handle(&err)

	info := try.To1(os.Lstat(path))
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("storage key must be a private regular file")
	}
	file = try.To1(os.OpenFile(path,
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0))

	opened := try.To1(file.Stat())
	if !os.SameFile(info, opened) || !opened.Mode().IsRegular() ||
		opened.Mode().Perm()&0077 != 0 {
		return nil, errors.New("storage key changed while opening")
	}
	secret, readErr := io.ReadAll(io.LimitReader(file, 33))
	closed = true
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(secret) != 32 {
		clear(secret)
		try.To(errors.Join(readErr, closeErr))
		return nil, errors.New("storage key must contain exactly 32 bytes")
	}
	return secret, nil
}
