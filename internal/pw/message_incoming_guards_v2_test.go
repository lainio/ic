package pw

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func TestIncomingCurrentGuardsAndProbeRecheckV2(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, guard := range []string{"deny", "delete", "own Known",
			"peer Known", "authorization", "history", "first use", "signer"} {
			for _, phase := range []string{"before", "probe", "retry probe"} {
				t.Run(fmt.Sprint(receiver, guard, phase), func(t *testing.T) {
					defer assert.PushTester(t)()
					f, n, raw := incomingTestV2(t, receiver, "guarded inbox")
					runtime := f.messageRuntime(n)
					if phase == "retry probe" {
						try.To1(AdmitIncomingEnvelopeV2(n.own.vault,
							f.root.public, n.local, n.signer, runtime, raw))
					}
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
					if phase == "before" {
						try.To(mutate())
						refuseIncomingV2(t, f, n, signer, raw)
					} else {
						var changed map[string]map[string][]byte
						var disk []byte
						signer.sign = func(d []byte) (_ []byte, err error) {
							defer err2.Handle(&err, nil)
							try.To(mutate())
							changed = outgoingTestState(t, n.own.vault)
							disk = try.To1(os.ReadFile(n.own.path))
							if guard == "signer" {
								return nil, signer.signErr
							}
							return n.signer.Sign(d)
						}
						n.other.unchanged(t, func() {
							saved, err := AdmitIncomingEnvelopeV2(n.own.vault,
								f.root.public, n.local, signer, runtime, raw)
							assert.Equal(err, errIncoming)
							assert.ThatNot(saved)
						})
						assert.Equal(signer.signCalls.Load(), 1)
						assert.DeepEqual(outgoingTestState(t, n.own.vault), changed)
						assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
					}
					refuseMessageReceiptV2(t, f, n, signer, raw)
				})
			}
		}
	}
}

func TestIncomingOwnRuntimeAndCommitGuardsV2(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTestV2(t, receiver, "own signed origin")
		runtime := f.messageRuntime(n)
		bad := []ContactRuntimeV2{{}, {false, runtime.BoundOrigin},
			{true, "http://127.0.0.1:8888"},
			{true, runtime.BoundOrigin + "/peer/pw/message"},
			f.messageRuntime(outgoingTestNodes(f.requesterFixture)[1-receiver])}
		for _, committed := range []bool{false, true} {
			if committed {
				try.To1(AdmitIncomingEnvelopeV2(n.own.vault, f.root.public,
					n.local, n.signer, runtime, raw))
				n.own.reopen(t)
			}
			for _, invalid := range bad {
				n.own.unchanged(t, func() {
					saved, err := AdmitIncomingEnvelopeV2(n.own.vault,
						f.root.public, n.local, n.signer, invalid, raw)
					assert.Equal(err, errIncoming)
					assert.ThatNot(saved)
					receipt, err := IssueMessageReceiptV2(n.own.vault,
						f.root.public, n.local, n.signer, invalid, raw)
					assert.Equal(err, errMessageReceipt)
					assert.SNil(receipt)
					assert.Error(
						n.own.vault.Update(func(tx storage.WriteTx) error {
							return commitIncomingV2(
								tx,
								f.root.public,
								n.local,
								invalid,
								raw,
							)
						}),
					)
				})
			}
		}
	}
}

func TestIncomingExactLocalRelationshipV2(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, mode := range []string{"acceptance signature", "request signature",
			"requester contact", "target contact"} {
			for _, committed := range []bool{false, true} {
				t.Run(
					fmt.Sprint(receiver, mode, committed),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f, n, raw := incomingTestV2(
							t,
							receiver,
							"exact relationship",
						)
						if committed {
							try.To1(
								AdmitIncomingEnvelopeV2(
									n.own.vault,
									f.root.public,
									n.local,
									n.signer,
									f.messageRuntime(n),
									raw,
								),
							)
						}
						old := messageBindingV2(
							t,
							n.other.vault,
							f.root.public,
							n.peer,
						)
						// Independently authentic replacement evidence, same keys. Its
						// signed contacts and runtime agree, but it is another relation.
						runtime := replaceMessageHistoryV2(t, f, n, mode)
						var current outgoingBindingV2
						try.To(
							n.own.vault.View(
								func(tx storage.ReadTx) (err error) {
									defer err2.Handle(&err, nil)
									current = try.To1(
										incomingPrerequisitesV2(tx,
											f.root.public, n.local, runtime),
									)
									return nil
								},
							),
						)
						assert.ThatNot(
							bytes.Equal(
								old.AcceptedDigest,
								current.AcceptedDigest,
							),
						)
						n.other.unchanged(t, func() {
							n.own.unchanged(t, func() {
								saved, err := AdmitIncomingEnvelopeV2(
									n.own.vault,
									f.root.public,
									n.local,
									n.signer,
									runtime,
									raw,
								)
								assert.Equal(err, errIncoming)
								assert.ThatNot(saved)
								receipt, err := IssueMessageReceiptV2(
									n.own.vault,
									f.root.public,
									n.local,
									n.signer,
									runtime,
									raw,
								)
								assert.Equal(err, errMessageReceipt)
								assert.SNil(receipt)
							})
						})
					},
				)
			}
		}
	}
}

func TestIncomingCompositionRetainsInboxAfterSigningFailureV2(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		// Admission probe is call 1. Receipt probe/sign/final probe are 2..4.
		for index := range int64(3) {
			call := index + 2
			t.Run(fmt.Sprint(receiver, call), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, raw := incomingTestV2(
					t,
					receiver,
					"committed before receipt",
				)
				expected := messageBindingV2(
					t,
					n.other.vault,
					f.root.public,
					n.peer,
				)
				before := outgoingTestState(t, n.own.vault)
				signer := &probeSigner{Handle: n.signer}
				signer.sign = func(d []byte) ([]byte, error) {
					if signer.signCalls.Load() == call {
						return []byte(
								"partial signature",
							), errors.New(
								"private failure",
							)
					}
					return n.signer.Sign(d)
				}
				n.other.unchanged(t, func() {
					receipt, err := AcceptMessageAndReceiptV2(
						n.own.vault,
						f.root.public,
						n.local,
						signer,
						f.messageRuntime(n),
						raw,
					)
					assert.Equal(err, errMessageReceipt)
					assert.SNil(receipt)
				})
				assert.Equal(signer.signCalls.Load(), call)
				before["root"][inboxKey] = try.To1(wire.Marshal(inboxMessage{
					Version: 2, Envelope: raw,
				}))
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.own.reopen(t)
				n.own.lease.remaining.Store(0)
				n.own.unchanged(t, func() {
					receipt := try.To1(IssueMessageReceiptV2(
						n.own.vault,
						f.root.public,
						n.local,
						n.signer,
						f.messageRuntime(n),
						raw,
					))
					try.To1(decodeMessageReceiptV2(receipt, raw, expected))
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			})
		}
	}
}
