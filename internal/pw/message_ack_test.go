package pw

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// n is the sender, unlike receiptTest. These are two independent real Vaults
// with acceptance, successful first use, saved outgoing/envelope and inbox.
func ackTest(t *testing.T, sender int,
) (*requesterFixture, outgoingTestNode, []byte, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	f, receiver, envelope, _ := receiptTest(t, 1-sender)
	receipt := try.To1(issueMessageReceipt(receiver.own.vault, f.root.public,
		receiver.local, receiver.signer, envelope))
	return f, outgoingTestNodes(f)[sender], envelope, receipt
}

func refuseMessageACK(t *testing.T, f *requesterFixture, n outgoingTestNode,
	raw []byte,
) {
	t.Helper()
	defer assert.PushTester(t)()
	before, other := outgoingTestState(t, n.own.vault),
		outgoingTestState(t, n.other.vault)
	n.other.unchanged(t, func() {
		n.own.unchanged(t, func() {
			saved, err := observeMessageReceipt(n.own.vault, f.root.public,
				n.local, raw)
			assert.Equal(err, errMessageACK)
			assert.ThatNot(saved)
		})
	})
	assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
	assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
}

func TestMessageACKEitherSenderFirstAndEquivalentRepeats(t *testing.T) {
	for sender := range 2 {
		t.Run(fmt.Sprint(sender), func(t *testing.T) {
			defer assert.PushTester(t)()
			f, n, envelope, first := ackTest(t, sender)
			receiver := outgoingTestNodes(f)[1-sender]
			second := try.To1(issueMessageReceipt(n.other.vault, f.root.public,
				n.peer, receiver.signer, envelope))
			assert.ThatNot(bytes.Equal(first, second))
			before, other := outgoingTestState(t, n.own.vault),
				outgoingTestState(t, n.other.vault)
			assert.SNil(before["root"][inboxKey])
			assert.SNil(other["root"][outgoingKey])
			assert.SNil(other["root"][messageEnvelopeKey])
			remaining := n.own.lease.remaining.Load()
			// Observation cannot depend on an available receiver or its Vault.
			try.To(n.other.db.Close())
			n.other.unchanged(t, func() {
				assert.That(try.To1(observeMessageReceipt(n.own.vault,
					f.root.public, n.local, first)))
			})
			assert.Equal(n.own.lease.remaining.Load(), remaining-1)
			before["root"][messageACKKey] = try.To1(wire.Marshal(messageACK{
				Version: 1, Receipt: first,
			}))
			assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			for _, reopen := range []bool{false, true} {
				if reopen {
					n.own.reopen(t)
				}
				n.own.lease.remaining.Store(0)
				for _, raw := range [][]byte{second, first} {
					n.other.unchanged(t, func() {
						n.own.unchanged(t, func() {
							assert.ThatNot(try.To1(observeMessageReceipt(
								n.own.vault, f.root.public, n.local, raw)))
						})
					})
					assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				}
			}
			n.other.reopen(t)
			assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
		})
	}
}

func TestMessageACKLateLocalInvalidation(t *testing.T) {
	for sender := range 2 {
		for _, guard := range []string{"deny", "delete", "own Known",
			"peer Known", "authorization", "signer"} {
			t.Run(fmt.Sprint(sender, "/", guard), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, _, receipt := ackTest(t, sender)
				receiver := outgoingTestNodes(f)[1-sender]
				try.To1(createOutgoing(n.other.vault, f.root.public, n.peer,
					receiver.signer, "reverse message for admission guard"))
				reverse := try.To1(prepareOutgoingEnvelope(n.other.vault,
					f.root.public, n.peer, receiver.signer))
				// Expired with verified retained success is still history.
				assert.That(try.To1(f.expireUse(true)))
				signer := &probeSigner{Handle: n.signer}
				if guard == "signer" {
					signer.signErr = errors.New("private unavailable signer")
				} else {
					try.To(mutateEnvelopeGuard(n, f.root.public, guard))
				}
				before, other := outgoingTestState(t, n.own.vault),
					outgoingTestState(t, n.other.vault)
				n.other.unchanged(t, func() {
					assert.That(try.To1(observeMessageReceipt(n.own.vault,
						f.root.public, n.local, receipt)))
				})
				assert.Equal(signer.signCalls.Load(), 0)
				assert.Equal(signer.publicCalls.Load(), 0)
				before["root"][messageACKKey] = try.To1(wire.Marshal(messageACK{
					Version: 1, Receipt: receipt,
				}))
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.own.reopen(t)
				n.own.unchanged(t, func() {
					assert.ThatNot(try.To1(observeMessageReceipt(n.own.vault,
						f.root.public, n.local, receipt)))
					// Even exact preparation remains forbidden. ACK observation
					// neither restores permission nor permits a new admission.
					raw, err := createOutgoing(n.own.vault, f.root.public,
						n.local, signer, "private receipt test plaintext")
					assert.Equal(err, errOutgoing)
					assert.SNil(raw)
					raw, err = prepareOutgoingEnvelope(n.own.vault,
						f.root.public, n.local, signer)
					assert.Equal(err, errMessageEnvelope)
					assert.SNil(raw)
					refuseIncoming(t, f, n, signer, reverse)
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
			})
		}
	}
}

func TestMessageACKOwnerSerialization(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, _, receipt := ackTest(t, 0)
	var owner sync.Mutex
	type result struct {
		saved bool
		err   error
	}
	results := make(chan result, 2)
	remaining := n.own.lease.remaining.Load()
	n.other.unchanged(t, func() {
		for range 2 {
			go func() {
				owner.Lock()
				defer owner.Unlock()
				saved, err := observeMessageReceipt(n.own.vault, f.root.public,
					n.local, receipt)
				results <- result{saved, err}
			}()
		}
		a, b := <-results, <-results
		try.To(a.err)
		try.To(b.err)
		assert.That(a.saved != b.saved)
	})
	assert.Equal(n.own.lease.remaining.Load(), remaining-1)
}

func TestMessageACKPinnedInputs(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, _, receipt := ackTest(t, 1)
	foreign := newOutgoing(t)
	for _, tc := range []struct {
		vault       *storage.Vault
		root, local key.Public
	}{
		{nil, f.root.public, n.local},
		{n.own.vault, nil, n.local},
		{n.own.vault, f.root.public, nil},
		{n.own.vault, n.peer, n.local},
		{n.own.vault, f.root.public, n.peer},
		{n.other.vault, f.root.public, n.local},
		{foreign.alice.vault, f.root.public, n.local},
	} {
		foreign.alice.unchanged(t, func() {
			n.other.unchanged(t, func() {
				n.own.unchanged(t, func() {
					saved, err := observeMessageReceipt(tc.vault, tc.root,
						tc.local, receipt)
					assert.Equal(err, errMessageACK)
					assert.ThatNot(saved)
				})
			})
		})
	}
}

func TestMessageACKSensitiveRefusal(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, _, receipt := ackTest(t, 0)
	for _, bad := range [][]byte{[]byte("sensitive CBOR keys IDs signatures"),
		{0xa1, 0x69, 's', 'e', 'n', 's', 'i', 't', 'i', 'v', 'e', 0xf6}} {
		refuseMessageACK(t, f, n, bad)
	}
	n.own.lease.remaining.Store(0)
	refuseMessageACK(t, f, n, receipt)
}

func TestMessageACKDiagnostics(t *testing.T) {
	defer assert.PushTester(t)()
	cmd := exec.CommandContext(t.Context(), try.To1(os.Executable()),
		"-test.run=^TestMessageACKSensitiveRefusal$", "-test.count=1",
		"-test.timeout=30s", "-v=1", "-logtostderr=true")
	output, err := cmd.CombinedOutput()
	assert.NoError(err, "ACK diagnostic subprocess failed")
	assert.ThatNot(strings.Contains(string(output), "sensitive"))
	assert.ThatNot(
		strings.Contains(string(output), "private receipt test plaintext"),
	)
	assert.ThatNot(strings.Contains(string(output), "op=message"))
}
