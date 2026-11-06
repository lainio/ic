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
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// n is the receiver. Only its peer saves an outgoing message/envelope.
func incomingTest(t *testing.T, receiver int, text string,
) (*requesterFixture, outgoingTestNode, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	nodes := outgoingTestNodes(f)
	n, sender := nodes[receiver], nodes[1-receiver]
	try.To1(createOutgoing(sender.own.vault, f.root.public, sender.local,
		sender.signer, text))
	raw := try.To1(prepareOutgoingEnvelope(sender.own.vault, f.root.public,
		sender.local, sender.signer))
	return f, n, raw
}

func refuseIncoming(t *testing.T, f *requesterFixture, n outgoingTestNode,
	signer key.Handle, raw []byte,
) {
	t.Helper()
	defer assert.PushTester(t)()
	before, other := outgoingTestState(t, n.own.vault),
		outgoingTestState(t, n.other.vault)
	n.other.unchanged(t, func() {
		n.own.unchanged(t, func() {
			saved, err := admitIncomingEnvelope(n.own.vault, f.root.public,
				n.local, signer, raw)
			assert.Equal(err, errIncoming)
			assert.ThatNot(saved)
		})
	})
	assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
	assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
}

func TestIncomingEitherSenderFirstAndReopen(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, text := range []string{"a", strings.Repeat("é", 512)} {
			t.Run(fmt.Sprint(receiver, "/", len(text)), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, raw := incomingTest(t, receiver, text)
				before, other := outgoingTestState(t, n.own.vault),
					outgoingTestState(t, n.other.vault)
				assert.SNil(before["root"][outgoingKey])
				assert.SNil(before["root"][messageEnvelopeKey])
				assert.SNil(before["root"][inboxKey])
				assert.SNil(other["root"][inboxKey])
				signer := &probeSigner{Handle: n.signer}
				remaining := n.own.lease.remaining.Load()
				n.other.unchanged(t, func() {
					assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
						f.root.public, n.local, signer, raw)))
				})
				assert.Equal(
					signer.signCalls.Load(),
					1,
				) // Discarded probe only.
				assert.Equal(n.own.lease.remaining.Load(), remaining-1)
				before["root"][inboxKey] = try.To1(wire.Marshal(inboxMessage{
					Version: 1, Envelope: raw,
				}))
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.DeepEqual(outgoingTestState(t, n.other.vault), other)

				// The caller can lose the first result. Reopen and explicitly
				// repeat exact wire bytes; storage is the durable evidence.
				n.own.reopen(t)
				n.own.lease.remaining.Store(0)
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						assert.ThatNot(
							try.To1(admitIncomingEnvelope(
								n.own.vault,
								f.root.public,
								n.local,
								signer,
								bytes.Clone(raw),
							)),
						)
					})
				})
				assert.Equal(signer.signCalls.Load(), 2)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			})
		}
	}
}

func TestIncomingCurrentGuards(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, guard := range []string{"deny", "delete", "own Known",
			"peer Known", "authorization", "history", "first use", "signer"} {
			for _, repeat := range []bool{false, true} {
				for _, during := range []bool{false, true} {
					t.Run(
						fmt.Sprint(
							receiver,
							"/",
							guard,
							"/",
							repeat,
							"/",
							during,
						),
						func(t *testing.T) {
							defer assert.PushTester(t)()
							f, n, raw := incomingTest(t, receiver, "guarded")
							if repeat {
								assert.That(
									try.To1(admitIncomingEnvelope(n.own.vault,
										f.root.public, n.local, n.signer, raw)),
								)
							}
							history := outgoingTestState(t, n.own.vault)["root"][inboxKey]
							signer := &probeSigner{Handle: n.signer}
							mutate := func() error {
								if guard == "signer" {
									signer.signErr = errors.New(
										"private provider failure",
									)
									return nil
								}
								return mutateEnvelopeGuard(
									n,
									f.root.public,
									guard,
								)
							}
							if !during {
								try.To(mutate())
								refuseIncoming(t, f, n, signer, raw)
							} else {
								var before map[string]map[string][]byte
								var disk []byte
								var remaining int64
								signer.sign = func(d []byte) (_ []byte, err error) {
									defer err2.Handle(&err, nil)
									// Successful mutation proves the probe is outside
									// any Vault transaction. Only this change may persist.
									try.To(mutate())
									before = outgoingTestState(t, n.own.vault)
									disk = try.To1(os.ReadFile(n.own.path))
									remaining = n.own.lease.remaining.Load()
									if signer.signErr != nil {
										return nil, signer.signErr
									}
									return n.signer.Sign(d)
								}
								n.other.unchanged(t, func() {
									saved, err := admitIncomingEnvelope(n.own.vault,
										f.root.public, n.local, signer, raw)
									assert.Equal(err, errIncoming)
									assert.ThatNot(saved)
								})
								assert.Equal(signer.signCalls.Load(), 1)
								assert.Equal(n.own.lease.remaining.Load(), remaining)
								assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
								assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
							}
							assert.DeepEqual(
								outgoingTestState(t, n.own.vault)["root"][inboxKey],
								history,
							)
							if repeat {
								n.own.reopen(t)
								refuseIncoming(t, f, n, signer, raw)
							}
							assert.DeepEqual(
								outgoingTestState(t, n.own.vault)["root"][inboxKey],
								history,
							)
						},
					)
				}
			}
		}
	}
}

func TestIncomingHistoricalSuccessHasNoFreshTTLOrRemoteGuard(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		t.Run(fmt.Sprint(receiver), func(t *testing.T) {
			defer assert.PushTester(t)()
			f, n, raw := incomingTest(
				t,
				receiver,
				"delayed authenticated bytes",
			)
			f.now = f.now.Add(24 * time.Hour)
			assert.That(try.To1(f.expireUse(false)))
			for _, node := range outgoingTestNodes(f) {
				try.To(
					node.own.vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						if try.To1(tx.HasChild([]byte("local-current-ad-v1"))) {
							try.To(
								try.To1(tx.ChildForUpdate([]byte("local-current-ad-v1"))).
									Delete([]byte("slot-1")),
							)
						}
						return tx.Delete([]byte("verified-ad-claims-v1"))
					}),
				)
			}
			sender := outgoingTestNodes(f)[1-receiver]
			try.To(mutateEnvelopeGuard(sender, f.root.public, "deny"))
			try.To(mutateEnvelopeGuard(sender, f.root.public, "delete"))
			try.To(mutateEnvelopeGuard(sender, f.root.public, "authorization"))
			n.other.unchanged(t, func() {
				assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
					f.root.public, n.local, n.signer, raw)))
			})
		})
	}
}

func TestIncomingOwnerSerialization(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTest(t, receiver, "serialized admission")
		var owner sync.Mutex
		type result struct {
			saved bool
			err   error
		}
		results := make(chan result, 2)
		signer := &probeSigner{Handle: n.signer}
		remaining := n.own.lease.remaining.Load()
		n.other.unchanged(t, func() {
			for range 2 {
				go func() {
					owner.Lock()
					defer owner.Unlock()
					saved, err := admitIncomingEnvelope(n.own.vault,
						f.root.public, n.local, signer, raw)
					results <- result{saved, err}
				}()
			}
			first, second := <-results, <-results
			try.To(first.err)
			try.To(second.err)
			assert.That(first.saved != second.saved)
		})
		assert.Equal(n.own.lease.remaining.Load(), remaining-1)
		assert.Equal(signer.signCalls.Load(), 2)
	}
}

func TestIncomingSensitiveRefusal(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, raw := incomingTest(t, 0, "sensitive inbox plaintext")
	signer := &probeSigner{Handle: n.signer,
		signErr: fmt.Errorf("sensitive provider %x %x", raw, n.local)}
	refuseIncoming(t, f, n, signer, raw)
	for _, bad := range [][]byte{append(bytes.Clone(raw), 0),
		[]byte("sensitive CBOR keys IDs signatures")} {
		refuseIncoming(t, f, n, n.signer, bad)
	}
}

func TestIncomingDiagnostics(t *testing.T) {
	defer assert.PushTester(t)()
	cmd := exec.CommandContext(t.Context(), try.To1(os.Executable()),
		"-test.run=^TestIncomingSensitiveRefusal$", "-test.count=1",
		"-test.timeout=30s", "-v=1", "-logtostderr=true")
	output, err := cmd.CombinedOutput()
	assert.NoError(err, "diagnostic subprocess failed")
	assert.ThatNot(strings.Contains(string(output), "sensitive"))
	assert.ThatNot(strings.Contains(string(output), "op=incoming"))
}
