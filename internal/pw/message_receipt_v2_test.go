package pw

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestMessageReceiptCurrentGuardsAndHistoricalVerificationV2(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, guard := range []string{"deny", "delete", "own Known",
			"peer Known", "authorization", "history", "first use", "signer"} {
			// 0: before call; 1: first probe; 2: receipt sign; 3: final probe.
			for call := range int64(4) {
				t.Run(
					fmt.Sprint(receiver, "/", guard, "/", call),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f, n, raw, expected := receiptTestV2(t, receiver)
						prior := try.To1(IssueMessageReceiptV2(
							n.own.vault,
							f.root.public,
							n.local,
							n.signer,
							f.messageRuntime(n),
							raw,
						))
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
							refuseMessageReceiptV2(t, f, n, signer, raw)
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
								got, err := IssueMessageReceiptV2(n.own.vault,
									f.root.public, n.local, signer, f.messageRuntime(n), raw)
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
						refuseMessageReceiptV2(t, f, n, signer, raw)
						n.own.unchanged(t, func() {
							try.To1(
								decodeMessageReceiptV2(prior, raw, expected),
							)
						})
						// Mathematical verification cannot restore permission.
						refuseMessageReceiptV2(t, f, n, signer, raw)
					},
				)
			}
		}
	}
}

func TestMessageReceiptOwnsInputsAndOwnerSerializationV2(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw, expected := receiptTestV2(t, receiver)
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
					IssueMessageReceiptV2(
						n.own.vault,
						root,
						local,
						signer,
						f.messageRuntime(n),
						raw,
					),
				)
				try.To1(decodeMessageReceiptV2(got, original, expected))
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
					got, err := IssueMessageReceiptV2(
						n.own.vault,
						f.root.public,
						n.local,
						n.signer,
						f.messageRuntime(n),
						original,
					)
					results <- result{got, err}
				}()
			}
			first, second := <-results, <-results
			try.To(first.err)
			try.To(second.err)
			a := try.To1(decodeMessageReceiptV2(first.raw, original, expected))
			b := try.To1(decodeMessageReceiptV2(second.raw, original, expected))
			assert.DeepEqual(a.Payload, b.Payload)
		})
	}
}

func TestMessageReceiptSensitiveRefusalV2(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, raw, expected := receiptTestV2(t, 0)
	for index := range int64(3) {
		call := index + 1
		signer := &probeSigner{Handle: n.signer}
		signer.sign = func(d []byte) ([]byte, error) {
			if signer.signCalls.Load() == call {
				return raw, fmt.Errorf("sensitive provider %x %x", raw, n.local)
			}
			return n.signer.Sign(d)
		}
		refuseMessageReceiptV2(t, f, n, signer, raw)
		assert.Equal(signer.signCalls.Load(), call) // No automatic retry.
	}
	for _, bad := range [][]byte{[]byte("sensitive CBOR keys IDs signatures"),
		{0xa1, 0x69, 's', 'e', 'n', 's', 'i', 't', 'i', 'v', 'e', 0xf6}} {
		_, err := decodeMessageReceiptV2(bad, raw, expected)
		assert.Equal(err, errMessageReceipt)
		refuseMessageReceiptV2(t, f, n, n.signer, bad)
	}
}
