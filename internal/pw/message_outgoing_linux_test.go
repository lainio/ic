package pw

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestOutgoingBackendCommitFailure(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	for _, n := range outgoingTestNodes(f) {
		before := outgoingTestState(t, n.own.vault)
		disk := try.To1(os.ReadFile(n.own.path))
		n.other.unchanged(t, func() {
			restore := readOnlyVaultDescriptor(t, n.own.path)
			raw, err := createOutgoing(n.own.vault, f.root.public,
				n.local, n.signer, "backend failure")
			restore()
			assert.Equal(err, errOutgoing)
			assert.SNil(raw)
		})
		assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		n.own.reopen(t)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
	}
}
