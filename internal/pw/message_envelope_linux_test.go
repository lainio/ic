package pw

import (
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestMessageEnvelopeBackendCommitFailure(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	for _, n := range outgoingTestNodes(f) {
		try.To1(createOutgoing(n.own.vault, f.root.public, n.local,
			n.signer, "backend failure"))
		before := outgoingTestState(t, n.own.vault)
		disk := try.To1(os.ReadFile(n.own.path))
		signer := &probeSigner{Handle: n.signer}
		n.other.unchanged(t, func() {
			restore := readOnlyVaultDescriptor(t, n.own.path)
			raw, err := prepareOutgoingEnvelope(n.own.vault, f.root.public,
				n.local, signer)
			restore()
			assert.Equal(err, errMessageEnvelope)
			assert.SNil(raw)
			assert.Equal(signer.signCalls.Load(), 2) // No automatic retry.
		})
		assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		n.own.reopen(t)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
	}
}
