package pw

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestMessageTransmitBackendFailureAndReadOnlyRepeat(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, _ := transmitTest(t, sender)
		before := outgoingTestState(t, n.own.vault)
		disk := try.To1(os.ReadFile(n.own.path))
		remaining := n.own.lease.remaining.Load()
		n.other.unchanged(t, func() {
			restore := readOnlyVaultDescriptor(t, n.own.path)
			saved, err := saveMessageTransmit(n.own.vault, f.root.public,
				n.local, n.signer)
			restore()
			assert.Equal(err, errMessageTransmit)
			assert.Equal(saved, savedMessageTransmit{})
		})
		assert.Equal(n.own.lease.remaining.Load(), remaining-1)
		assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		n.own.reopen(t)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)

		saved := try.To1(saveMessageTransmit(n.own.vault, f.root.public,
			n.local, n.signer))
		n.own.lease.remaining.Store(0)
		restore := readOnlyVaultDescriptor(t, n.own.path)
		n.other.unchanged(t, func() {
			n.own.unchanged(t, func() {
				assert.Equal(try.To1(saveMessageTransmit(n.own.vault,
					f.root.public, n.local, n.signer)), saved)
			})
		})
		restore()
	}
}
