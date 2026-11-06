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

// Test-only access to private sender actions for the real peerapi HTTP fixture.
var SaveMessageTransmitForTest = saveMessageTransmit
var SendMessageOnceForTest = sendMessageOnce
var ObserveMessageReceiptForTest = observeMessageReceipt
var MessageNotDispatchedForTest = errMessageNotDispatched
var MessageOutcomeUnknownForTest = errMessageOutcomeUnknown

type SavedMessageTransmitForTest = savedMessageTransmit

func transmitTest(t *testing.T, sender int,
) (*requesterFixture, outgoingTestNode, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	n := outgoingTestNodes(f)[sender]
	try.To1(createOutgoing(n.own.vault, f.root.public, n.local,
		n.signer, "sensitive transmission text"))
	raw := try.To1(prepareOutgoingEnvelope(n.own.vault, f.root.public,
		n.local, n.signer))
	return f, n, raw
}

func refuseMessageTransmit(t *testing.T, f *requesterFixture,
	n outgoingTestNode, signer key.Handle,
) {
	t.Helper()
	defer assert.PushTester(t)()
	before, other := outgoingTestState(t, n.own.vault),
		outgoingTestState(t, n.other.vault)
	n.other.unchanged(t, func() {
		n.own.unchanged(t, func() {
			saved, err := saveMessageTransmit(n.own.vault, f.root.public,
				n.local, signer)
			assert.Equal(err, errMessageTransmit)
			assert.Equal(saved, savedMessageTransmit{})
		})
	})
	assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
	assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
}

func TestMessageTransmitEitherSenderAndExactReopen(t *testing.T) {
	for sender := range 2 {
		t.Run(fmt.Sprint(sender), func(t *testing.T) {
			defer assert.PushTester(t)()
			f, n, raw := transmitTest(t, sender)
			before, other := outgoingTestState(t, n.own.vault),
				outgoingTestState(t, n.other.vault)
			assert.SNil(other["root"][outgoingKey])
			assert.SNil(other["root"][inboxKey])
			remaining := n.own.lease.remaining.Load()
			signer := &probeSigner{Handle: n.signer}
			var owner sync.Mutex
			owner.Lock()
			saved, err := saveMessageTransmit(n.own.vault, f.root.public,
				n.local, signer)
			owner.Unlock()
			try.To(err)
			assert.Equal(signer.signCalls.Load(), 1) // Discarded probe only.
			assert.Equal(n.own.lease.remaining.Load(), remaining-1)
			assert.Equal(saved.envelope, string(raw))
			digest := key.HashTagged(messageSentEnvelopePurpose, raw)
			before["root"][messageSentKey] = try.To1(wire.Marshal(messageSent{
				Version: 1, EnvelopeDigest: digest[:],
			}))
			assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
			clear(raw) // Neither input nor a converted output aliases storage.
			converted := []byte(saved.envelope)
			clear(converted)
			n.own.reopen(t)
			n.other.reopen(t)
			n.own.lease.remaining.Store(0)
			n.other.unchanged(t, func() {
				n.own.unchanged(t, func() {
					assert.Equal(try.To1(saveMessageTransmit(n.own.vault,
						f.root.public, n.local, signer)), saved)
				})
			})
			assert.Equal(signer.signCalls.Load(), 2)
			assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
		})
	}
}

func TestMessageTransmitCurrentGuards(t *testing.T) {
	for _, guard := range []string{"deny", "delete", "own Known", "peer Known",
		"authorization", "history", "first use", "signer"} {
		for _, repeat := range []bool{false, true} {
			for _, during := range []bool{false, true} {
				t.Run(fmt.Sprint(guard, "/", repeat, "/", during),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f := newOutgoing(t)
						for _, n := range outgoingTestNodes(f) {
							try.To1(createOutgoing(n.own.vault, f.root.public,
								n.local, n.signer, "guarded attempt"))
							try.To1(prepareOutgoingEnvelope(n.own.vault,
								f.root.public, n.local, n.signer))
							if repeat {
								try.To1(saveMessageTransmit(n.own.vault,
									f.root.public, n.local, n.signer))
							}
							signer := &probeSigner{Handle: n.signer}
							mutate := func() error {
								if guard == "signer" {
									return errors.New(
										"sensitive signer failure",
									)
								}
								return mutateEnvelopeGuard(
									n,
									f.root.public,
									guard,
								)
							}
							if !during {
								if guard == "signer" {
									signer.signErr = mutate()
								} else {
									try.To(mutate())
								}
								refuseMessageTransmit(t, f, n, signer)
								continue
							}
							var after map[string]map[string][]byte
							signer.sign = func(d []byte) ([]byte, error) {
								err := mutate() // Would deadlock inside a transaction.
								after = outgoingTestState(t, n.own.vault)
								if err != nil {
									return nil, err
								}
								return n.signer.Sign(d)
							}
							n.other.unchanged(t, func() {
								saved, err := saveMessageTransmit(n.own.vault,
									f.root.public, n.local, signer)
								assert.Equal(err, errMessageTransmit)
								assert.Equal(saved, savedMessageTransmit{})
							})
							assert.Equal(signer.signCalls.Load(), 1)
							assert.DeepEqual(
								outgoingTestState(t, n.own.vault),
								after,
							)
						}
					})
			}
		}
	}
}

func TestMessageTransmitHistoricalSuccessNoTTLOrRemotePermission(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, _ := transmitTest(t, sender)
		f.now = f.now.Add(24 * time.Hour)
		assert.That(try.To1(f.expireUse(false)))
		other := outgoingTestNodes(f)[1-sender]
		try.To(mutateEnvelopeGuard(other, f.root.public, "deny"))
		try.To(mutateEnvelopeGuard(other, f.root.public, "delete"))
		try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
			return tx.Delete([]byte("verified-ad-claims-v1"))
		}))
		n.other.unchanged(t, func() {
			try.To1(saveMessageTransmit(n.own.vault, f.root.public,
				n.local, n.signer))
		})
	}
}

func TestMessageTransmitRejectsStoredEvidence(t *testing.T) {
	for sender := range 2 {
		for _, repeat := range []bool{false, true} {
			for _, mode := range []string{"missing outgoing", "changed outgoing",
				"missing envelope", "corrupt envelope", "resigned envelope",
				"foreign acceptance", "resigned acceptance", "role",
				"first use response", "no historical response"} {
				t.Run(
					fmt.Sprint(sender, "/", repeat, "/", mode),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f, n, _ := transmitTest(t, sender)
						if repeat {
							try.To1(
								saveMessageTransmit(n.own.vault, f.root.public,
									n.local, n.signer),
							)
						}
						rows := outgoingTestState(t, n.own.vault)["root"]
						name, bad := changedACKHistory(t, f, n, rows, mode)
						// Change after the initial read so even a valid replacement
						// signature cannot silently substitute the selected envelope.
						signer := &probeSigner{Handle: n.signer}
						var after map[string]map[string][]byte
						signer.sign = func(d []byte) (_ []byte, err error) {
							defer err2.Handle(&err, nil)
							try.To(
								n.own.vault.Update(
									func(tx storage.WriteTx) error {
										if bad == nil {
											return tx.Delete([]byte(name))
										}
										return tx.Put([]byte(name), bad)
									},
								),
							)
							after = outgoingTestState(t, n.own.vault)
							return n.signer.Sign(d)
						}
						n.other.unchanged(t, func() {
							saved, err := saveMessageTransmit(
								n.own.vault,
								f.root.public,
								n.local,
								signer,
							)
							assert.Equal(err, errMessageTransmit)
							assert.Equal(saved, savedMessageTransmit{})
						})
						assert.DeepEqual(
							outgoingTestState(t, n.own.vault),
							after,
						)
						if mode != "resigned envelope" || repeat {
							refuseMessageTransmit(t, f, n, n.signer)
						}
					},
				)
			}
		}
	}
}

func TestMessageTransmitInvalidSentRow(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, _ := transmitTest(t, sender)
		try.To1(
			saveMessageTransmit(n.own.vault, f.root.public, n.local, n.signer),
		)
		original := outgoingTestState(t, n.own.vault)["root"][messageSentKey]
		var row messageSent
		try.To(wire.UnmarshalCanonical(&row, original))
		foreignFixture, foreign, _ := transmitTest(t, sender)
		try.To1(saveMessageTransmit(foreign.own.vault,
			foreignFixture.root.public, foreign.local,
			foreign.signer))
		invalid := map[string][]byte{
			"empty": {}, "corrupt": {0xff},
			"oversize":     make([]byte, maxMessageSentBytes+1),
			"noncanonical": append([]byte{0x98, 2}, original[1:]...),
			"trailing":     append(bytes.Clone(original), 0),
			"version": try.To1(wire.Marshal(messageSent{Version: 2,
				EnvelopeDigest: row.EnvelopeDigest})),
			"wrong digest": try.To1(wire.Marshal(messageSent{Version: 1,
				EnvelopeDigest: make([]byte, key.HashSize)})),
			"foreign": outgoingTestState(t, foreign.own.vault)["root"][messageSentKey],
		}
		for name, bad := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(messageSentKey), bad)
				}))
				refuseMessageTransmit(t, f, n, n.signer)
			})
		}
	}
}

func TestMessageTransmitAtomicFailure(t *testing.T) {
	for sender := range 2 {
		for _, mode := range []string{"write", "callback", "seal"} {
			t.Run(fmt.Sprint(sender, "/", mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, envelope := transmitTest(t, sender)
				before := outgoingTestState(t, n.own.vault)
				disk := try.To1(os.ReadFile(n.own.path))
				n.other.unchanged(t, func() {
					if mode == "seal" {
						n.own.lease.remaining.Store(0)
						refuseMessageTransmit(t, f, n, n.signer)
						return
					}
					cause := errors.New("sensitive pending sent failure")
					err := n.own.vault.Update(
						func(tx storage.WriteTx) (err error) {
							defer err2.Handle(&err, nil)
							if mode == "write" {
								failed := &failingAcceptanceTx{WriteTx: tx,
									failAfter: 1, cause: cause}
								err = commitMessageTransmit(
									failed,
									f.root.public,
									n.local,
									envelope,
								)
								assert.Equal(failed.writes, 1)
								return err
							}
							try.To(commitMessageTransmit(tx, f.root.public,
								n.local, envelope))
							return cause
						},
					)
					assert.ErrorIs(err, cause)
				})
				assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.own.reopen(t)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			})
		}
	}
}

func TestMessageTransmitCompetingCommit(t *testing.T) {
	defer assert.PushTester(t)()
	for sender := range 2 {
		f, n, envelope := transmitTest(t, sender)
		// Model the same preflight/commit interleaving without production hooks.
		try.To(n.own.vault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			_, saved := try.To2(
				checkMessageTransmit(tx, f.root.public, n.local),
			)
			assert.ThatNot(saved)
			return nil
		}))
		try.To1(
			saveMessageTransmit(n.own.vault, f.root.public, n.local, n.signer),
		)
		n.own.lease.remaining.Store(0)
		n.own.unchanged(t, func() {
			err := n.own.vault.Update(func(tx storage.WriteTx) error {
				return commitMessageTransmit(
					tx,
					f.root.public,
					n.local,
					envelope,
				)
			})
			assert.Equal(err, errSentUnchanged)
		})
	}
}

func TestMessageTransmitSensitiveRefusal(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, envelope := transmitTest(t, 0)
	refuseMessageTransmit(t, f, n, &probeSigner{Handle: n.signer,
		signErr: fmt.Errorf("sensitive %x %x", envelope, n.local)})
	for _, binding := range [][2]key.Public{
		{nil, n.local}, {f.root.public, nil}, {n.local, n.local},
		{f.root.public, n.peer},
	} {
		n.own.unchanged(t, func() {
			saved, err := saveMessageTransmit(
				n.own.vault,
				binding[0],
				binding[1],
				n.signer,
			)
			assert.Equal(err, errMessageTransmit)
			assert.Equal(saved, savedMessageTransmit{})
		})
	}
}

func TestMessageTransmitDiagnostics(t *testing.T) {
	defer assert.PushTester(t)()
	cmd := exec.CommandContext(
		t.Context(),
		try.To1(os.Executable()),
		"-test.run=^(TestMessageTransmitSensitiveRefusal|TestMessageClientSensitiveRefusal)$",
		"-test.count=1",
		"-test.timeout=30s",
		"-v=1",
		"-logtostderr=true",
	)
	output, err := cmd.CombinedOutput()
	assert.NoError(err, "transmission diagnostic subprocess failed")
	assert.ThatNot(strings.Contains(string(output), "sensitive"))
}

func TestMessageTransmitFinalSentRevalidation(t *testing.T) {
	for _, repeat := range []bool{false, true} {
		for _, mode := range []string{"corrupt", "version", "removed"} {
			if !repeat && mode == "removed" {
				continue
			}
			t.Run(fmt.Sprint(repeat, "/", mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, envelope := transmitTest(t, 0)
				if repeat {
					try.To1(saveMessageTransmit(n.own.vault, f.root.public,
						n.local, n.signer))
				}
				signer := &probeSigner{Handle: n.signer}
				var after map[string]map[string][]byte
				signer.sign = func(d []byte) (_ []byte, err error) {
					defer err2.Handle(&err, nil)
					try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						if mode == "removed" {
							return tx.Delete([]byte(messageSentKey))
						}
						raw := []byte{0xff}
						if mode == "version" {
							digest := key.HashTagged(
								messageSentEnvelopePurpose,
								envelope,
							)
							raw = try.To1(wire.Marshal(messageSent{
								Version: 2, EnvelopeDigest: digest[:],
							}))
						}
						return tx.Put([]byte(messageSentKey), raw)
					}))
					after = outgoingTestState(t, n.own.vault)
					return n.signer.Sign(d)
				}
				n.other.unchanged(t, func() {
					saved, err := saveMessageTransmit(
						n.own.vault,
						f.root.public,
						n.local,
						signer,
					)
					assert.Equal(err, errMessageTransmit)
					assert.Equal(saved, savedMessageTransmit{})
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), after)
			})
		}
	}
}
