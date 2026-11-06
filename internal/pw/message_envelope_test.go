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
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Derive the expected sender's binding solely from the other participant's
// independently retained and authenticated acceptance, never the envelope.
func envelopePeerBinding(t *testing.T, root key.Public, n outgoingTestNode,
) (binding outgoingBinding) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(n.other.vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		p := try.To1(firstUseHistory(tx, root, n.peer, n.name == "Bob"))
		sender, receiver := p.Binding.Target, p.Binding.Requester
		if n.name == "Alice" {
			sender, receiver = receiver, sender
		}
		history, _ := try.To2(tx.Get([]byte(acceptedKey)))
		digest := key.HashTagged(outgoingHistoryPurpose, history)
		binding = outgoingBinding{Root: p.Binding.Root,
			Sender: sender, Receiver: receiver, Requester: n.name == "Alice",
			RequestDigest: p.RequestDigest, AcceptedDigest: digest[:]}
		return nil
	}))
	return binding
}

func TestMessageEnvelopeEitherRoleAndExactReopen(t *testing.T) {
	for _, name := range []string{"Bob", "Alice"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoing(t)
			for _, n := range outgoingTestNodes(f) {
				if n.name != name {
					continue
				}
				message := try.To1(createOutgoing(n.own.vault, f.root.public,
					n.local, n.signer, strings.Repeat("é", 512)))
				before, other := outgoingTestState(t, n.own.vault),
					outgoingTestState(t, n.other.vault)
				assert.SNil(other["root"][outgoingKey])
				expected := envelopePeerBinding(t, f.root.public, n)
				signer := &probeSigner{Handle: n.signer}
				remaining := n.own.lease.remaining.Load()
				var raw []byte
				n.other.unchanged(t, func() {
					raw = try.To1(prepareOutgoingEnvelope(n.own.vault,
						f.root.public, n.local, signer))
				})
				assert.Equal(signer.signCalls.Load(), 2) // Probe + envelope.
				assert.Equal(n.own.lease.remaining.Load(), remaining-1)
				var envelope messageEnvelope
				try.To(wire.UnmarshalCanonical(&envelope, raw))
				assert.Equal(envelope.Version, uint8(1))
				assert.DeepEqual(envelope.Message, message)
				digest := key.HashTagged(messageAuthPurpose, message)
				assert.That(envelope.Signature.Verify(n.local, digest[:]))
				assert.ThatNot(envelope.Signature.Verify(n.peer, digest[:]))
				assert.DeepEqual(try.To1(decodeMessageEnvelope(raw, expected)),
					envelope)
				before["root"][messageEnvelopeKey] = bytes.Clone(raw)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.DeepEqual(outgoingTestState(t, n.other.vault), other)

				n.own.reopen(t)
				n.own.lease.remaining.Store(0)
				n.own.unchanged(t, func() {
					again := try.To1(prepareOutgoingEnvelope(n.own.vault,
						f.root.public, n.local, signer))
					assert.DeepEqual(again, raw)
					assert.Equal(signer.signCalls.Load(), 3)
					again[0] ^= 1
					decoded := try.To1(decodeMessageEnvelope(raw, expected))
					decoded.Message[0] ^= 1
					decoded.Signature[0] ^= 1
					assert.DeepEqual(
						try.To1(prepareOutgoingEnvelope(n.own.vault,
							f.root.public, n.local, signer)),
						raw,
					)
					assert.Equal(signer.signCalls.Load(), 4)
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			}
		})
	}
}

func TestMessageEnvelopeHistoryHasNoRemotePermissionOrTTL(t *testing.T) {
	for _, name := range []string{"Bob", "Alice"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoing(t)
			f.now = f.now.Add(24 * time.Hour)
			assert.That(try.To1(f.expireUse(false)))
			for _, n := range outgoingTestNodes(f) {
				if n.name != name {
					continue
				}
				try.To1(createOutgoing(n.own.vault, f.root.public,
					n.local, n.signer, "historical success"))
				try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					if try.To1(tx.HasChild([]byte("local-current-ad-v1"))) {
						try.To(
							try.To1(tx.ChildForUpdate([]byte("local-current-ad-v1"))).
								Delete([]byte("slot-1")),
						)
					}
					return tx.Delete([]byte("verified-ad-claims-v1"))
				}))
				try.To1(policy.DenyLocal(n.other.vault, f.root.public,
					n.peer, n.local))
				try.To1(DeleteHeldLocal(n.other.vault, f.root.public, n.peer))
				n.other.unchanged(t, func() {
					try.To1(prepareOutgoingEnvelope(n.own.vault, f.root.public,
						n.local, n.signer))
				})
			}
		})
	}
}

func mutateEnvelopeGuard(n outgoingTestNode, root key.Public, guard string,
) (err error) {
	defer err2.Handle(&err, nil)
	switch guard {
	case "deny":
		_, err = policy.DenyLocal(n.own.vault, root, n.local, n.peer)
		return err
	case "delete":
		_, err = DeleteHeldLocal(n.own.vault, root, n.local)
		return err
	}
	return n.own.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		switch guard {
		case "own Known":
			return try.To1(tx.ChildForUpdate([]byte(knownNS))).Delete(n.local)
		case "peer Known":
			return try.To1(tx.ChildForUpdate([]byte(knownNS))).Delete(n.peer)
		case "authorization":
			return try.To1(tx.ChildForUpdate([]byte(authNS))).
				Delete([]byte(authKey))
		case "history":
			return tx.Delete([]byte(acceptedKey))
		default:
			name := useSeenKey
			if n.name == "Alice" {
				name = firstUseKey
			}
			return tx.Delete([]byte(name))
		}
	})
}

func TestMessageEnvelopeCurrentGuards(t *testing.T) {
	for _, guard := range []string{"deny", "delete", "own Known", "peer Known",
		"authorization", "history", "first use", "signer"} {
		for _, repeat := range []bool{false, true} {
			for _, during := range []bool{false, true} {
				t.Run(
					fmt.Sprint(guard, "/", repeat, "/", during),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f := newOutgoing(t)
						for _, n := range outgoingTestNodes(f) {
							try.To1(createOutgoing(n.own.vault, f.root.public,
								n.local, n.signer, "guarded"))
							if repeat {
								try.To1(prepareOutgoingEnvelope(n.own.vault,
									f.root.public, n.local, n.signer))
							}
							signer := &probeSigner{Handle: n.signer}
							mutate := func() error {
								if guard == "signer" {
									signer.signErr = errors.New(
										"private provider error",
									)
									return nil
								}
								return mutateEnvelopeGuard(
									n,
									f.root.public,
									guard,
								)
							}
							before := outgoingTestState(t, n.own.vault)
							if during {
								signer.sign = func(d []byte) (_ []byte, err error) {
									defer err2.Handle(&err, nil)
									// Repeat probes; a new envelope mutates during its
									// actual signature, after the last read preflight.
									if repeat || signer.signCalls.Load() == 2 {
										try.To(mutate())
										before = outgoingTestState(
											t,
											n.own.vault,
										)
										if signer.signErr != nil {
											return nil, signer.signErr
										}
									}
									return n.signer.Sign(d)
								}
							} else {
								try.To(mutate())
								before = outgoingTestState(t, n.own.vault)
							}
							n.other.unchanged(t, func() {
								raw, err := prepareOutgoingEnvelope(n.own.vault,
									f.root.public, n.local, signer)
								assert.Equal(err, errMessageEnvelope)
								assert.SNil(raw)
							})
							assert.DeepEqual(
								outgoingTestState(t, n.own.vault),
								before,
							)
						}
					},
				)
			}
		}
	}
}

func TestMessageEnvelopeCompetingCommitAndLostResult(t *testing.T) {
	for _, call := range []int64{1, 2} {
		for _, corrupt := range []bool{false, true} {
			t.Run(fmt.Sprint(call, "/", corrupt), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newOutgoing(t)
				for _, n := range outgoingTestNodes(f) {
					try.To1(createOutgoing(n.own.vault, f.root.public,
						n.local, n.signer, "lost response"))
					signer := &probeSigner{Handle: n.signer}
					var committed map[string]map[string][]byte
					var disk []byte
					signer.sign = func(d []byte) (_ []byte, err error) {
						defer err2.Handle(&err, nil)
						if signer.signCalls.Load() == call {
							// Simulate the winning explicit operation; lose its result.
							try.To1(prepareOutgoingEnvelope(n.own.vault,
								f.root.public, n.local, n.signer))
							if corrupt {
								try.To(
									n.own.vault.Update(
										func(tx storage.WriteTx) error {
											return tx.Put(
												[]byte(messageEnvelopeKey),
												[]byte{0xff},
											)
										},
									),
								)
							}
							committed = outgoingTestState(t, n.own.vault)
							disk = try.To1(os.ReadFile(n.own.path))
							n.own.lease.remaining.Store(0)
						}
						return n.signer.Sign(d)
					}
					n.other.unchanged(t, func() {
						raw, err := prepareOutgoingEnvelope(n.own.vault,
							f.root.public, n.local, signer)
						if corrupt {
							assert.Equal(err, errMessageEnvelope)
							assert.SNil(raw)
						} else {
							try.To(err)
							assert.DeepEqual(raw, committed["root"][messageEnvelopeKey])
						}
					})
					assert.Equal(signer.signCalls.Load(), call)
					assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
					assert.DeepEqual(
						outgoingTestState(t, n.own.vault),
						committed,
					)
					n.own.reopen(t)
					n.own.unchanged(t, func() {
						raw, err := prepareOutgoingEnvelope(n.own.vault,
							f.root.public, n.local, n.signer)
						if corrupt {
							assert.Equal(err, errMessageEnvelope)
							assert.SNil(raw)
						} else {
							try.To(err)
							assert.DeepEqual(raw, committed["root"][messageEnvelopeKey])
						}
					})
				}
			})
		}
	}
}

func TestMessageEnvelopeOwnerSerialization(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	for _, n := range outgoingTestNodes(f) {
		try.To1(createOutgoing(n.own.vault, f.root.public, n.local,
			n.signer, "serialized preparation"))
		var owner sync.Mutex
		type result struct {
			raw []byte
			err error
		}
		results := make(chan result, 2)
		signer := &probeSigner{Handle: n.signer}
		remaining := n.own.lease.remaining.Load()
		for range 2 {
			go func() {
				owner.Lock()
				defer owner.Unlock()
				raw, err := prepareOutgoingEnvelope(n.own.vault,
					f.root.public, n.local, signer)
				results <- result{raw, err}
			}()
		}
		first, second := <-results, <-results
		try.To(first.err)
		try.To(second.err)
		assert.DeepEqual(first.raw, second.raw)
		assert.Equal(signer.signCalls.Load(), 3)
		assert.Equal(n.own.lease.remaining.Load(), remaining-1)
	}
}

func TestMessageEnvelopeAtomicFailure(t *testing.T) {
	for _, mode := range []string{"write", "seal"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoing(t)
			for _, n := range outgoingTestNodes(f) {
				message := try.To1(createOutgoing(n.own.vault, f.root.public,
					n.local, n.signer, "atomic envelope"))
				before := outgoingTestState(t, n.own.vault)
				disk := try.To1(os.ReadFile(n.own.path))
				n.other.unchanged(t, func() {
					if mode == "seal" {
						n.own.lease.remaining.Store(0)
						signer := &probeSigner{Handle: n.signer}
						raw, err := prepareOutgoingEnvelope(n.own.vault,
							f.root.public, n.local, signer)
						assert.Equal(err, errMessageEnvelope)
						assert.SNil(raw)
						assert.Equal(signer.signCalls.Load(), 2)
					} else {
						prepared := signMessageEnvelope(t, message, n.signer)
						cause := errors.New("write failed after pending envelope put")
						err := n.own.vault.Update(func(tx storage.WriteTx) (err error) {
							defer err2.Handle(&err, nil)
							_, err = commitMessageEnvelope(&failingAcceptanceTx{
								WriteTx: tx, failAfter: 1, cause: cause,
							}, f.root.public, n.local, message, prepared)
							return err
						})
						assert.ErrorIs(err, cause)
					}
				})
				assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				n.own.reopen(t)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			}
		})
	}
}

func TestMessageEnvelopeSensitiveRefusal(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	n := outgoingTestNodes(f)[0]
	message := try.To1(createOutgoing(n.own.vault, f.root.public,
		n.local, n.signer, "sensitive plaintext"))
	expected := envelopePeerBinding(t, f.root.public, n)
	raw := signMessageEnvelope(t, message, n.signer)
	secretError := fmt.Errorf("sensitive %x %x %x", message, raw, n.local)
	for _, call := range []int64{1, 2} {
		signer := &probeSigner{Handle: n.signer}
		signer.sign = func(d []byte) ([]byte, error) {
			if signer.signCalls.Load() == call {
				return raw, secretError
			}
			return n.signer.Sign(d)
		}
		n.own.unchanged(t, func() {
			result, err := prepareOutgoingEnvelope(n.own.vault,
				f.root.public, n.local, signer)
			assert.Equal(err, errMessageEnvelope)
			assert.SNil(result)
		})
	}
	for _, invalid := range [][]byte{append(raw, 0), []byte("sensitive CBOR")} {
		_, err := decodeMessageEnvelope(invalid, expected)
		assert.Equal(err, errMessageEnvelope)
	}
}

func TestMessageEnvelopeDiagnostics(t *testing.T) {
	defer assert.PushTester(t)()
	cmd := exec.CommandContext(t.Context(), try.To1(os.Executable()),
		"-test.run=^TestMessageEnvelopeSensitiveRefusal$", "-test.count=1",
		"-test.timeout=30s", "-v=1", "-logtostderr=true")
	output, err := cmd.CombinedOutput()
	assert.NoError(err, "diagnostic subprocess failed")
	assert.ThatNot(strings.Contains(string(output), "sensitive"))
	assert.ThatNot(strings.Contains(string(output), "op=message"))
}
