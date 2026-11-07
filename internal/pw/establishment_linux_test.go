package pw

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"golang.org/x/sys/unix"
)

func TestBobAcceptBackendCommitFailure(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishment(t, false)
	before := try.To1(os.ReadFile(f.f.path))
	restore := readOnlyVaultDescriptor(t, f.f.path)
	err := f.accept(f.raw, f.local.handle)
	restore()
	assert.Equal(err, ErrEstablishment)
	assert.DeepEqual(try.To1(os.ReadFile(f.f.path)), before)
	f.unconsumed(t)
	f.f.reopen(t)
	f.unconsumed(t)
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

func TestRequesterBackendCommitFailure(t *testing.T) {
	for _, phase := range []string{"save", "receive"} {
		t.Run(phase, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			var response []byte
			if phase == "receive" {
				response = f.response(t)
			}
			records := requesterRecords(t, f.alice.vault)
			before := try.To1(os.ReadFile(f.alice.path))
			restore := readOnlyVaultDescriptor(t, f.alice.path)
			var err error
			if phase == "save" {
				_, err = f.save()
			} else {
				_, err = f.receive(response)
			}
			restore()
			assert.Equal(err, ErrEstablishment)
			assert.DeepEqual(try.To1(os.ReadFile(f.alice.path)), before)
			assert.DeepEqual(requesterRecords(t, f.alice.vault), records)
			f.alice.reopen(t)
			assert.DeepEqual(requesterRecords(t, f.alice.vault), records)
		})
	}
}

func TestRequesterV2BackendCommitFailure(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	before := try.To1(os.ReadFile(f.alice.path))
	restore := readOnlyVaultDescriptor(t, f.alice.path)
	saved, err := f.saveV2(aliceServiceOrigin)
	restore()
	assert.Equal(err, ErrEstablishment)
	assert.DeepEqual(saved, SavedAttemptV2{})
	assert.DeepEqual(try.To1(os.ReadFile(f.alice.path)), before)
	assert.DeepEqual(requesterRecords(t, f.alice.vault), [3][]byte{})
	f.alice.reopen(t)
	assert.DeepEqual(requesterRecords(t, f.alice.vault), [3][]byte{})
	try.To1(f.saveV2(aliceServiceOrigin))
}
