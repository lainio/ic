package node

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"golang.org/x/sys/unix"
)

func TestServeMessageV2InboxCommitFailure(t *testing.T) {
	defer assert.PushTester(t)()
	alice, bob := readyMessagePairV2(t)
	before := try.To1(firstUseState(bob.service.store.Vault()))
	disk := nodeMessageDisk(t, bob)
	done, posts := observeNodeMessages(t, alice, bob, "")
	restore := readOnlyNodeMessageVault(t, bob)
	result := sendNodeMessageV2(t, alice, "uncommitted receiver")
	restore()
	assert.NoError(result.err)
	assert.Equal(result.status, 502)
	exchange := <-done
	assert.NoError(exchange.err)
	assert.Equal(string(exchange.receipt), "Conflict\n")
	assert.Equal(posts.Load(), 1)
	assert.DeepEqual(exchange.receiver, before)
	assert.DeepEqual(nodeMessageDisk(t, bob), disk)
	assert.ThatNot(readNodeInboxV2(t, bob).Present)
	for _, name := range nodeMessageRows[:3] {
		assert.SNotEmpty(exchange.sender["root"][name])
	}
	assert.SNil(exchange.sender["root"][nodeMessageRows[3]])
	assert.DeepEqual(try.To1(firstUseState(alice.service.store.Vault())),
		exchange.sender)
}

// As in pw's backend-failure regressions, replace only this temporary Vault's
// descriptor to make bbolt WriteAt fail. Keep the lock's open description alive
// and restore before cleanup. No other test or service uses this file.
func readOnlyNodeMessageVault(t *testing.T, n *verificationNode) func() {
	t.Helper()
	defer assert.PushTester(t)()
	path := filepath.Join(n.fixture.dir, "state", "vault.db")
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
