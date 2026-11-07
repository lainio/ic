package pw

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestReceiveAcceptanceV2BackendFailure(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	response := f.responseV2(t)
	before := try.To1(os.ReadFile(f.alice.path))
	records := requesterRecords(t, f.alice.vault)
	restore := readOnlyVaultDescriptor(t, f.alice.path)
	held, err := f.receiveV2(response)
	restore()
	assert.Equal(err, ErrEstablishment)
	assert.ThatNot(held)
	assert.DeepEqual(try.To1(os.ReadFile(f.alice.path)), before)
	f.alice.reopen(t)
	assert.DeepEqual(requesterRecords(t, f.alice.vault), records)
	assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
		f.root.public, f.peer.public)), "")
	assert.That(try.To1(f.receiveV2(response)))

	// Duplicate and historical reads need no backend write permission.
	restore = readOnlyVaultDescriptor(t, f.alice.path)
	f.alice.unchanged(t, func() {
		assert.That(try.To1(f.receiveV2(response)))
		assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
			f.root.public, f.peer.public)), "http://127.0.0.1:12345")
	})
	restore()
}
