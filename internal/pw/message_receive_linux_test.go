package pw

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestAcceptMessageAndReceiptReadOnlyBackendRetry(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTest(t, receiver, "read-only exact retry")
		try.To1(AcceptMessageAndReceipt(n.own.vault, f.root.public,
			n.local, n.signer, raw))
		n.own.reopen(t)
		n.own.lease.remaining.Store(0)
		restore := readOnlyVaultDescriptor(t, n.own.path)
		n.other.unchanged(t, func() {
			n.own.unchanged(t, func() {
				receipt := try.To1(AcceptMessageAndReceipt(n.own.vault,
					f.root.public, n.local, n.signer, raw))
				try.To(ValidateLocalMessageReceipt(raw, receipt))
			})
		})
		restore()
	}
}
