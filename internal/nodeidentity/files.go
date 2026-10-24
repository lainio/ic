package nodeidentity

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

// OpenDirectory restores an existing identity with a separate private unlock
// file. It never creates, repairs, or replaces files and returns nil on error.
func OpenDirectory(dir, unlockPath string) (handle key.Handle, err error) {
	defer err2.Handle(&err)

	dir, unlockPath = try.To2(ResolvePaths(dir, unlockPath))
	info := try.To1(os.Lstat(dir))
	if !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("node directory must be a private directory")
	}
	unlock := try.To1(readUnlock(unlockPath))
	defer clear(unlock)
	restored := try.To1(Open(filepath.Join(dir, "identity.json"), unlock))
	return restored, nil
}

// ResolvePaths normalizes separate node/unlock paths under existing parents.
// Final components are retained for exclusive creation or symlink rejection.
func ResolvePaths(dir, unlock string) (_ string, _ string, err error) {
	defer err2.Handle(&err)

	if strings.TrimSpace(dir) == "" || strings.TrimSpace(unlock) == "" {
		return "", "", errors.New("--dir and --unlock-file must be nonempty")
	}
	dir = try.To1(filepath.Abs(dir))
	unlock = try.To1(filepath.Abs(unlock))
	try.To(requireSeparate(dir, unlock))

	// Resolve existing parents to detect aliases, while retaining the final
	// components for exclusive creation or Lstat symlink rejection.
	dir = try.To1(resolveParent(dir))
	unlock = try.To1(resolveParent(unlock))
	try.To(requireSeparate(dir, unlock))
	return dir, unlock, nil
}

func resolveParent(path string) (_ string, err error) {
	defer err2.Handle(&err)

	parent := try.To1(filepath.EvalSymlinks(filepath.Dir(path)))
	if !try.To1(os.Stat(parent)).IsDir() {
		return "", errors.New("path parent must be an existing directory")
	}
	return filepath.Join(parent, filepath.Base(path)), nil
}

func requireSeparate(dir, unlock string) (err error) {
	defer err2.Handle(&err)

	rel := try.To1(filepath.Rel(dir, unlock))
	if rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("unlock file must be outside the node directory")
	}
	return nil
}

func readUnlock(path string) (_ []byte, err error) {
	defer err2.Handle(&err)

	info := try.To1(os.Lstat(path))
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unlock file must be a private regular file")
	}
	file := try.To1(os.OpenFile(path,
		os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0))
	closed := false
	defer func() {
		if !closed {
			try.Out(file.Close()).Logf()
		}
	}()

	opened := try.To1(file.Stat())
	if !os.SameFile(info, opened) || opened.Mode().Perm()&0077 != 0 {
		return nil, errors.New("unlock file changed while opening")
	}
	unlock := try.To1(io.ReadAll(io.LimitReader(file, 33)))
	closed = true
	closeErr := file.Close()
	if closeErr != nil || len(unlock) != 32 {
		clear(unlock)
		try.To(closeErr)
		return nil, errors.New("unlock file must contain exactly 32 bytes")
	}
	return unlock, nil
}
