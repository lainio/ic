package policy

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"golang.org/x/sys/unix"
)

func TestBackendCommitFailureReportsNoChange(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, peer, extra := newPublic(
		t,
	), newPublic(
		t,
	), newPublic(
		t,
	), newPublic(
		t,
	)
	for _, operation := range []string{"first deny", "deny", "allow"} {
		t.Run(operation, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			if operation != "first deny" {
				assert.That(try.To1(DenyLocal(f.vault, root, local, peer)))
			}
			before, remaining := try.To1(
				os.ReadFile(f.path),
			), f.lease.remaining.Load()
			want := rawPolicy(t, f.vault)
			restore := readOnlyVaultDescriptor(t, f.path)
			var changed bool
			var err error
			if operation == "allow" {
				changed, err = AllowLocal(f.vault, root, local, peer)
			} else {
				changed, err = DenyLocal(f.vault, root, local, extra)
			}
			restore()
			assert.ThatNot(changed)
			assert.ErrorIs(err, unix.EBADF)
			assert.Equal(f.lease.remaining.Load(), remaining-1)
			assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
			assert.DeepEqual(rawPolicy(t, f.vault), want)
			f.reopen(t)
			assert.DeepEqual(rawPolicy(t, f.vault), want)
		})
	}
}

// Inject an actual bbolt commit WriteAt failure without a production hook or
// mock transaction. Only this test's temporary Vault descriptor is replaced.
// Keep the original open description (and its lock) alive, and restore it
// before any close/reopen. No parallel test uses this file.
func readOnlyVaultDescriptor(t *testing.T, path string) func() {
	t.Helper()
	defer assert.PushTester(t)()
	fd := -1
	for _, entry := range try.To1(os.ReadDir("/proc/self/fd")) {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err == nil && target == path {
			assert.Equal(fd, -1)
			fd = try.To1(strconv.Atoi(entry.Name()))
		}
	}
	assert.That(fd >= 0)
	saved := try.To1(unix.Dup(fd))
	readOnly := try.To1(os.Open(path))
	restored := false
	restore := func() {
		if !restored {
			assert.NoError(unix.Dup3(saved, fd, unix.O_CLOEXEC))
			assert.NoError(unix.Close(saved))
			assert.NoError(readOnly.Close())
			restored = true
		}
	}
	t.Cleanup(restore)
	try.To(unix.Dup3(int(readOnly.Fd()), fd, unix.O_CLOEXEC))
	return restore
}
