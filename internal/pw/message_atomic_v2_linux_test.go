package pw

import (
	"fmt"
	"os"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestMessageBackendCommitFailureV2(t *testing.T) {
	for _, envelope := range []bool{false, true} {
		t.Run(fmt.Sprint(envelope), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			for _, n := range outgoingTestNodes(f.requesterFixture) {
				runtime := f.messageRuntime(n)
				if envelope {
					try.To1(
						CreateOutgoingV2(
							n.own.vault,
							f.root.public,
							n.local,
							n.signer,
							runtime,
							"backend failure",
						),
					)
				}
				before := outgoingTestState(t, n.own.vault)
				disk := try.To1(os.ReadFile(n.own.path))
				n.other.unchanged(t, func() {
					restore := readOnlyVaultDescriptor(t, n.own.path)
					var raw []byte
					var err error
					if envelope {
						raw, err = PrepareOutgoingEnvelopeV2(
							n.own.vault,
							f.root.public,
							n.local,
							n.signer,
							runtime,
						)
					} else {
						raw, err = CreateOutgoingV2(n.own.vault, f.root.public, n.local,
							n.signer, runtime, "backend failure")
					}
					restore()
					assert.Error(err)
					assert.SNil(raw)
				})
				assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.own.reopen(t)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			}
		})
	}
}
