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
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func receiptTest(t *testing.T, receiver int,
) (*requesterFixture, outgoingTestNode, []byte, outgoingBinding) {
	t.Helper()
	defer assert.PushTester(t)()
	f, n, raw := incomingTest(t, receiver, "private receipt test plaintext")
	// This reads the SENDER's authenticated history, independent of the
	// receiver's inbox and of any receipt. Orient it for the original message.
	expected := envelopePeerBinding(t, f.root.public, n)
	expected.Sender, expected.Receiver = expected.Receiver, expected.Sender
	expected.Requester = !expected.Requester
	assert.DeepEqual(raw,
		outgoingTestState(t, n.other.vault)["root"][messageEnvelopeKey])
	assert.That(try.To1(admitIncomingEnvelope(n.own.vault, f.root.public,
		n.local, n.signer, raw)))
	return f, n, raw, expected
}

func refuseMessageReceipt(t *testing.T, f *requesterFixture,
	n outgoingTestNode, signer key.Handle, raw []byte,
) {
	t.Helper()
	defer assert.PushTester(t)()
	before, other := outgoingTestState(t, n.own.vault),
		outgoingTestState(t, n.other.vault)
	n.other.unchanged(t, func() {
		n.own.unchanged(t, func() {
			got, err := issueMessageReceipt(n.own.vault, f.root.public,
				n.local, signer, raw)
			assert.Equal(err, errMessageReceipt)
			assert.SNil(got)
		})
	})
	assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
	assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
}

func TestMessageReceiptEitherSenderFirstRepeatAndReopen(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		t.Run(fmt.Sprint(receiver), func(t *testing.T) {
			defer assert.PushTester(t)()
			f, n, raw, expected := receiptTest(t, receiver)
			before, other := outgoingTestState(t, n.own.vault),
				outgoingTestState(t, n.other.vault)
			assert.SNil(before["root"][outgoingKey])
			assert.SNil(before["root"][messageEnvelopeKey])
			assert.SNil(other["root"][inboxKey])
			n.own.lease.remaining.Store(0)
			signer := &probeSigner{Handle: n.signer}
			var first []byte
			for i := range 3 {
				if i == 2 {
					n.own.reopen(t)
				}
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						got := try.To1(issueMessageReceipt(n.own.vault,
							f.root.public, n.local, signer, raw))
						receipt := try.To1(
							decodeMessageReceipt(got, raw, expected),
						)
						assert.That(len(got) <= maxMessageReceiptBytes)
						assert.ThatNot(bytes.Contains(got,
							[]byte("private receipt test plaintext")))
						assert.Equal(receipt.Version, uint8(1))
						digest := key.HashTagged(
							messageReceiptEnvelopePurpose,
							raw,
						)
						assert.DeepEqual(
							receipt.Payload.EnvelopeDigest,
							digest[:],
						)
						assert.DeepEqual(receipt.Payload.Binding, expected)
						if first == nil {
							first = bytes.Clone(got)
						} else {
							previous := try.To1(decodeMessageReceipt(first, raw, expected))
							assert.DeepEqual(receipt.Payload, previous.Payload)
							// Real ECDSA emits different signatures for this payload.
							assert.ThatNot(bytes.Equal(receipt.Signature, previous.Signature))
						}
						// The verifier returns owned data; corrupting it or the
						// response cannot mutate the exact saved envelope/history.
						clear(receipt.Payload.Binding.Receiver)
						clear(receipt.Payload.ID)
						clear(got)
					})
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
			}
			assert.Equal(signer.signCalls.Load(), 9)
		})
	}
}

func TestMessageReceiptCurrentGuardsAndHistoricalVerification(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, guard := range []string{"deny", "delete", "own Known",
			"peer Known", "authorization", "history", "first use", "signer"} {
			// 0: before call; 1: first probe; 2: receipt sign; 3: final probe.
			for call := range int64(4) {
				t.Run(
					fmt.Sprint(receiver, "/", guard, "/", call),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f, n, raw, expected := receiptTest(t, receiver)
						prior := try.To1(issueMessageReceipt(n.own.vault,
							f.root.public, n.local, n.signer, raw))
						history := outgoingTestState(t, n.own.vault)["root"][inboxKey]
						signer := &probeSigner{Handle: n.signer}
						mutate := func() error {
							if guard == "signer" {
								signer.signErr = errors.New(
									"private provider failure",
								)
								return nil
							}
							return mutateEnvelopeGuard(n, f.root.public, guard)
						}
						if call == 0 {
							try.To(mutate())
							refuseMessageReceipt(t, f, n, signer, raw)
						} else {
							var before map[string]map[string][]byte
							var disk []byte
							var remaining int64
							signer.sign = func(d []byte) (_ []byte, err error) {
								defer err2.Handle(&err, nil)
								if signer.signCalls.Load() == call {
									// A successful Update also proves callbacks run
									// outside Vault transactions. No other write is allowed.
									try.To(mutate())
									before = outgoingTestState(t, n.own.vault)
									disk = try.To1(os.ReadFile(n.own.path))
									remaining = n.own.lease.remaining.Load()
									if guard == "signer" && call == 3 {
										return nil, signer.signErr
									}
								}
								return n.signer.Sign(d)
							}
							n.other.unchanged(t, func() {
								got, err := issueMessageReceipt(n.own.vault,
									f.root.public, n.local, signer, raw)
								assert.Equal(err, errMessageReceipt)
								assert.SNil(got)
							})
							assert.Equal(n.own.lease.remaining.Load(), remaining)
							assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
							assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
						}
						assert.DeepEqual(
							outgoingTestState(t, n.own.vault)["root"][inboxKey],
							history,
						)
						n.own.reopen(t)
						refuseMessageReceipt(t, f, n, signer, raw)
						n.own.unchanged(t, func() {
							try.To1(decodeMessageReceipt(prior, raw, expected))
						})
						// Mathematical verification cannot restore permission.
						refuseMessageReceipt(t, f, n, signer, raw)
					},
				)
			}
		}
	}
}

func TestMessageReceiptNoFreshTTLOrSenderPermission(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw, expected := receiptTest(t, receiver)
		f.now = f.now.Add(24 * time.Hour)
		assert.That(try.To1(f.expireUse(false)))
		for _, node := range outgoingTestNodes(f) {
			try.To(node.own.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				if try.To1(tx.HasChild([]byte("local-current-ad-v1"))) {
					try.To(
						try.To1(tx.ChildForUpdate([]byte("local-current-ad-v1"))).
							Delete([]byte("slot-1")),
					)
				}
				return tx.Delete([]byte("verified-ad-claims-v1"))
			}))
		}
		sender := outgoingTestNodes(f)[1-receiver]
		for _, guard := range []string{"deny", "delete", "authorization"} {
			try.To(mutateEnvelopeGuard(sender, f.root.public, guard))
		}
		before, other := outgoingTestState(t, n.own.vault),
			outgoingTestState(t, n.other.vault)
		n.other.unchanged(t, func() {
			n.own.unchanged(t, func() {
				got := try.To1(issueMessageReceipt(n.own.vault, f.root.public,
					n.local, n.signer, raw))
				try.To1(decodeMessageReceipt(got, raw, expected))
			})
		})
		assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
	}
}

func TestMessageReceiptOwnsInputsAndOwnerSerialization(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw, expected := receiptTest(t, receiver)
		original := bytes.Clone(raw)
		root, local := bytes.Clone(f.root.public), bytes.Clone(n.local)
		signer := &probeSigner{Handle: n.signer}
		signer.sign = func(d []byte) ([]byte, error) {
			clear(root)
			clear(local)
			clear(raw)
			return n.signer.Sign(d)
		}
		n.other.unchanged(t, func() {
			n.own.unchanged(t, func() {
				got := try.To1(
					issueMessageReceipt(n.own.vault, root, local, signer, raw),
				)
				try.To1(decodeMessageReceipt(got, original, expected))
			})
		})

		var owner sync.Mutex
		type result struct {
			raw []byte
			err error
		}
		results := make(chan result, 2)
		n.own.unchanged(t, func() {
			for range 2 {
				go func() {
					owner.Lock()
					defer owner.Unlock()
					got, err := issueMessageReceipt(n.own.vault, f.root.public,
						n.local, n.signer, original)
					results <- result{got, err}
				}()
			}
			first, second := <-results, <-results
			try.To(first.err)
			try.To(second.err)
			a := try.To1(decodeMessageReceipt(first.raw, original, expected))
			b := try.To1(decodeMessageReceipt(second.raw, original, expected))
			assert.DeepEqual(a.Payload, b.Payload)
		})
	}
}

func TestMessageReceiptSensitiveRefusal(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, raw, expected := receiptTest(t, 0)
	for index := range int64(3) {
		call := index + 1
		signer := &probeSigner{Handle: n.signer}
		signer.sign = func(d []byte) ([]byte, error) {
			if signer.signCalls.Load() == call {
				return raw, fmt.Errorf("sensitive provider %x %x", raw, n.local)
			}
			return n.signer.Sign(d)
		}
		refuseMessageReceipt(t, f, n, signer, raw)
		assert.Equal(signer.signCalls.Load(), call) // No automatic retry.
	}
	for _, bad := range [][]byte{[]byte("sensitive CBOR keys IDs signatures"),
		{0xa1, 0x69, 's', 'e', 'n', 's', 'i', 't', 'i', 'v', 'e', 0xf6}} {
		_, err := decodeMessageReceipt(bad, raw, expected)
		assert.Equal(err, errMessageReceipt)
		refuseMessageReceipt(t, f, n, n.signer, bad)
	}
}

func TestMessageReceiptDiagnostics(t *testing.T) {
	defer assert.PushTester(t)()
	cmd := exec.CommandContext(t.Context(), try.To1(os.Executable()),
		"-test.run=^TestMessageReceiptSensitiveRefusal$", "-test.count=1",
		"-test.timeout=30s", "-v=1", "-logtostderr=true")
	output, err := cmd.CombinedOutput()
	assert.NoError(err, "diagnostic subprocess failed")
	assert.ThatNot(strings.Contains(string(output), "sensitive"))
	assert.ThatNot(
		strings.Contains(string(output), "private receipt test plaintext"),
	)
	assert.ThatNot(strings.Contains(string(output), "op=message"))
}
