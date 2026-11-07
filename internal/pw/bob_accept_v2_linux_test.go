package pw

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestBobAcceptV2BackendCommitFailure(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	before := try.To1(os.ReadFile(f.f.path))
	restore := readOnlyVaultDescriptor(t, f.f.path)
	err := f.acceptV2(saved.request, f.local.handle)
	restore()
	assert.Equal(err, ErrEstablishment)
	assert.DeepEqual(try.To1(os.ReadFile(f.f.path)), before)
	f.unconsumed(t)
	f.f.reopen(t)
	f.unconsumed(t)
	f.f.unchanged(t, func() {
		response, err := f.replyV2(saved.request, f.local.handle)
		assert.Equal(err, ErrEstablishment)
		assert.SNil(response)
	})
	assert.DeepEqual(requesterRecords(t, f.alice.vault),
		[3][]byte{saved.request, nil, nil})
	try.To(f.acceptV2(saved.request, f.local.handle))
	f.f.reopen(t)
	try.To1(f.replyV2(saved.request, f.local.handle))
}
