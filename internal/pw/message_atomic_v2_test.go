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
	"github.com/lainio/ic/storage"
)

func TestMessageSingleRecordRollbackV2(t *testing.T) {
	for _, envelope := range []bool{false, true} {
		for _, mode := range []string{"put", "encryption"} {
			t.Run(fmt.Sprint(envelope, mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newOutgoingV2(t)
				for _, n := range outgoingTestNodes(f.requesterFixture) {
					runtime := f.messageRuntime(n)
					binding := messageBindingV2(
						t,
						n.own.vault,
						f.root.public,
						n.local,
					)
					var message, prepared []byte
					if envelope {
						message = try.To1(
							CreateOutgoingV2(n.own.vault, f.root.public,
								n.local, n.signer, runtime, "atomic"),
						)
						prepared = signMessageEnvelopeV2(
							t,
							message,
							n.signer,
						)
					}
					before, disk := outgoingTestState(t, n.own.vault),
						try.To1(os.ReadFile(n.own.path))
					n.other.unchanged(t, func() {
						if mode == "put" {
							cause := errors.New(
								"abort after pending record put",
							)
							err := n.own.vault.Update(
								func(tx storage.WriteTx) (err error) {
									defer err2.Handle(&err, nil)
									failing := &failingAcceptanceTx{
										WriteTx:   tx,
										failAfter: 1,
										cause:     cause,
									}
									if envelope {
										_, err = commitMessageEnvelopeV2(
											failing,
											f.root.public,
											n.local,
											runtime,
											message,
											prepared,
										)
									} else {
										_, err = commitOutgoingV2(failing, f.root.public,
											n.local, runtime, binding, "atomic")
									}
									return err
								},
							)
							assert.ErrorIs(err, cause)
						} else {
							n.own.lease.remaining.Store(0)
							var got []byte
							var err error
							if envelope {
								got, err = PrepareOutgoingEnvelopeV2(n.own.vault,
									f.root.public, n.local, n.signer, runtime)
								assert.Equal(err, errMessageEnvelope)
							} else {
								got, err = CreateOutgoingV2(n.own.vault, f.root.public,
									n.local, n.signer, runtime, "atomic")
								assert.Equal(err, errOutgoing)
							}
							assert.SNil(got)
						}
					})
					assert.DeepEqual(
						try.To1(os.ReadFile(n.own.path)),
						disk,
					)
					assert.DeepEqual(
						outgoingTestState(t, n.own.vault),
						before,
					)
					n.own.reopen(t)
					assert.DeepEqual(
						outgoingTestState(t, n.own.vault),
						before,
					)
				}
			})
		}
	}
}

func TestMessageSeparateCommitsAndSignerFailureV2(t *testing.T) {
	for _, failure := range []string{"probe", "sign", "lost usability", "wrong signature",
		"malformed signature", "oversize signature"} {
		t.Run(failure, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			for _, n := range outgoingTestNodes(f.requesterFixture) {
				runtime := f.messageRuntime(n)
				message := try.To1(
					CreateOutgoingV2(n.own.vault, f.root.public,
						n.local, n.signer, runtime, "separate"),
				)
				signer := &probeSigner{Handle: n.signer}
				signer.sign = func(d []byte) ([]byte, error) {
					call := signer.signCalls.Load()
					if failure == "probe" ||
						(failure == "sign" && call == 2) {
						return []byte(
								"partial result",
							), errors.New(
								"private provider error",
							)
					}
					if call == 2 {
						switch failure {
						case "lost usability":
							signer.signErr = errors.New(
								"provider lost after signing",
							)
						case "wrong signature":
							return f.root.handle.Sign(d)
						case "malformed signature":
							return []byte{1}, nil
						case "oversize signature":
							return make([]byte, 73), nil
						}
					}
					return n.signer.Sign(d)
				}
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						got, err := PrepareOutgoingEnvelopeV2(n.own.vault,
							f.root.public, n.local, signer, runtime)
						assert.Equal(err, errMessageEnvelope)
						assert.SNil(got)
					})
				})
				n.own.reopen(t)
				state := outgoingTestState(t, n.own.vault)
				assert.DeepEqual(state["root"][outgoingKey], message)
				assert.SNil(state["root"][messageEnvelopeKey])
				// Only a later explicit preparation completes the existing message.
				raw := try.To1(
					PrepareOutgoingEnvelopeV2(n.own.vault, f.root.public,
						n.local, n.signer, runtime),
				)
				state["root"][messageEnvelopeKey] = raw
				assert.DeepEqual(outgoingTestState(t, n.own.vault), state)
			}
		})
	}
}

func TestMessageGuardInvalidationDuringCallbacksV2(t *testing.T) {
	for _, phase := range []string{"create", "repeat outgoing", "probe", "sign",
		"final probe", "repeat envelope"} {
		for _, guard := range []string{"deny", "delete", "own Known", "peer Known",
			"authorization", "history", "first use"} {
			t.Run(phase+"/"+guard, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newOutgoingV2(t)
				for _, n := range outgoingTestNodes(f.requesterFixture) {
					runtime := f.messageRuntime(n)
					if phase != "create" {
						try.To1(
							CreateOutgoingV2(n.own.vault, f.root.public,
								n.local, n.signer, runtime, "guarded"),
						)
					}
					if phase == "repeat envelope" {
						try.To1(
							PrepareOutgoingEnvelopeV2(
								n.own.vault,
								f.root.public,
								n.local,
								n.signer,
								runtime,
							),
						)
					}
					call := int64(1)
					switch phase {
					case "sign":
						call = 2
					case "final probe":
						call = 3
					}
					var changed map[string]map[string][]byte
					var disk []byte
					signer := &probeSigner{Handle: n.signer}
					signer.sign = func(d []byte) (_ []byte, err error) {
						defer err2.Handle(&err, nil)
						if signer.signCalls.Load() == call {
							try.To(
								mutateEnvelopeGuard(
									n,
									f.root.public,
									guard,
								),
							)
							changed = outgoingTestState(t, n.own.vault)
							disk = try.To1(os.ReadFile(n.own.path))
						}
						return n.signer.Sign(d)
					}
					n.other.unchanged(t, func() {
						var got []byte
						var err error
						if phase == "create" ||
							phase == "repeat outgoing" {
							got, err = CreateOutgoingV2(
								n.own.vault,
								f.root.public,
								n.local,
								signer,
								runtime,
								"guarded",
							)
							assert.Equal(err, errOutgoing)
						} else {
							got, err = PrepareOutgoingEnvelopeV2(n.own.vault,
								f.root.public, n.local, signer, runtime)
							assert.Equal(err, errMessageEnvelope)
						}
						assert.SNil(got)
					})
					assert.MNotNil(changed)
					assert.DeepEqual(
						outgoingTestState(t, n.own.vault),
						changed,
					)
					assert.DeepEqual(
						try.To1(os.ReadFile(n.own.path)),
						disk,
					)
				}
			})
		}
	}
}

func TestMessageCompetingCommitAndLostResultV2(t *testing.T) {
	for _, phase := range []string{"create", "probe", "sign", "final probe"} {
		for _, conflict := range []bool{false, true} {
			t.Run(fmt.Sprint(phase, conflict), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newOutgoingV2(t)
				for _, n := range outgoingTestNodes(f.requesterFixture) {
					runtime := f.messageRuntime(n)
					if phase != "create" {
						try.To1(
							CreateOutgoingV2(
								n.own.vault,
								f.root.public,
								n.local,
								n.signer,
								runtime,
								"lost result",
							),
						)
					}
					call := int64(1)
					switch phase {
					case "sign":
						call = 2
					case "final probe":
						call = 3
					}
					var committed map[string]map[string][]byte
					var disk []byte
					signer := &probeSigner{Handle: n.signer}
					signer.sign = func(d []byte) (_ []byte, err error) {
						defer err2.Handle(&err, nil)
						if signer.signCalls.Load() == call {
							if phase == "create" {
								text := "lost result"
								if conflict {
									text = "conflict"
								}
								try.To1(
									CreateOutgoingV2(
										n.own.vault,
										f.root.public,
										n.local,
										n.signer,
										runtime,
										text,
									),
								)
							} else {
								try.To1(PrepareOutgoingEnvelopeV2(n.own.vault, f.root.public,
									n.local, n.signer, runtime))
								if conflict {
									try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
										return tx.Put([]byte(messageEnvelopeKey), []byte{0xff})
									}))
								}
							}
							committed = outgoingTestState(t, n.own.vault)
							disk = try.To1(os.ReadFile(n.own.path))
							n.own.lease.remaining.Store(0)
						}
						return n.signer.Sign(d)
					}
					var got []byte
					var err error
					n.other.unchanged(t, func() {
						if phase == "create" {
							got, err = CreateOutgoingV2(
								n.own.vault,
								f.root.public,
								n.local,
								signer,
								runtime,
								"lost result",
							)
						} else {
							got, err = PrepareOutgoingEnvelopeV2(n.own.vault,
								f.root.public, n.local, signer, runtime)
						}
					})
					if conflict {
						assert.Error(err)
						assert.SNil(got)
					} else {
						try.To(err)
						name := messageEnvelopeKey
						if phase == "create" {
							name = outgoingKey
						}
						assert.DeepEqual(got, committed["root"][name])
					}
					assert.DeepEqual(
						outgoingTestState(t, n.own.vault),
						committed,
					)
					assert.DeepEqual(
						try.To1(os.ReadFile(n.own.path)),
						disk,
					)
					n.own.reopen(t)
					assert.DeepEqual(
						outgoingTestState(t, n.own.vault),
						committed,
					)
				}
			})
		}
	}
}

func TestMessageOwnerSerializationV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoingV2(t)
	for _, n := range outgoingTestNodes(f.requesterFixture) {
		var owner sync.Mutex
		type result struct {
			message, envelope []byte
			err               error
		}
		results := make(chan result, 2)
		runtime := f.messageRuntime(n)
		remaining := n.own.lease.remaining.Load()
		for range 2 {
			go func() {
				owner.Lock()
				defer owner.Unlock()
				m, err := CreateOutgoingV2(
					n.own.vault,
					f.root.public,
					n.local,
					n.signer,
					runtime,
					"serialized",
				)
				var e []byte
				if err == nil {
					e, err = PrepareOutgoingEnvelopeV2(
						n.own.vault,
						f.root.public,
						n.local,
						n.signer,
						runtime,
					)
				}
				results <- result{m, e, err}
			}()
		}
		first, second := <-results, <-results
		try.To(first.err)
		try.To(second.err)
		assert.That(bytes.Equal(first.message, second.message))
		assert.That(bytes.Equal(first.envelope, second.envelope))
		assert.Equal(n.own.lease.remaining.Load(), remaining-2)
	}
}

func TestMessageFinalSourceAndRepeatSignatureV2(t *testing.T) {
	for _, mode := range []string{"changed ID", "changed body", "deleted source",
		"repeat signature"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			for _, n := range outgoingTestNodes(f.requesterFixture) {
				runtime := f.messageRuntime(n)
				message := try.To1(
					CreateOutgoingV2(n.own.vault, f.root.public,
						n.local, n.signer, runtime, "exact source"),
				)
				call := int64(2)
				if mode == "repeat signature" {
					try.To1(
						PrepareOutgoingEnvelopeV2(
							n.own.vault,
							f.root.public,
							n.local,
							n.signer,
							runtime,
						),
					)
					call = 1
				}
				var changed map[string]map[string][]byte
				var disk []byte
				signer := &probeSigner{Handle: n.signer}
				signer.sign = func(d []byte) (_ []byte, err error) {
					defer err2.Handle(&err, nil)
					if signer.signCalls.Load() == call {
						var raw []byte
						name := outgoingKey
						if mode == "repeat signature" {
							name = messageEnvelopeKey
							raw = signMessageEnvelopeV2(
								t,
								message,
								n.signer,
							)
							assert.ThatNot(bytes.Equal(
								raw,
								outgoingTestState(t, n.own.vault)["root"][name],
							))
						} else if mode != "deleted source" {
							raw = changedEnvelopeMessages(t, message)[mode]
						}
						try.To(
							n.own.vault.Update(
								func(tx storage.WriteTx) error {
									if mode == "deleted source" {
										return tx.Delete([]byte(name))
									}
									return tx.Put([]byte(name), raw)
								},
							),
						)
						changed = outgoingTestState(t, n.own.vault)
						disk = try.To1(os.ReadFile(n.own.path))
					}
					return n.signer.Sign(d)
				}
				n.other.unchanged(t, func() {
					got, err := PrepareOutgoingEnvelopeV2(n.own.vault,
						f.root.public, n.local, signer, runtime)
					assert.Equal(err, errMessageEnvelope)
					assert.SNil(got)
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), changed)
				assert.DeepEqual(try.To1(os.ReadFile(n.own.path)), disk)
			}
		})
	}
}

func TestMessageCommitRuntimeV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoingV2(t)
	for _, n := range outgoingTestNodes(f.requesterFixture) {
		binding := messageBindingV2(t, n.own.vault, f.root.public, n.local)
		runtime := f.messageRuntime(n)
		bad := []ContactRuntimeV2{{}, {false, runtime.BoundOrigin},
			{
				true,
				"http://127.0.0.1:8888",
			}, {true, runtime.BoundOrigin + "/message"}}
		for _, invalid := range bad {
			n.own.unchanged(t, func() {
				assert.Error(
					n.own.vault.Update(func(tx storage.WriteTx) error {
						_, err := commitOutgoingV2(
							tx,
							f.root.public,
							n.local,
							invalid,
							binding,
							"runtime",
						)
						return err
					}),
				)
			})
		}
		message := try.To1(CreateOutgoingV2(n.own.vault, f.root.public,
			n.local, n.signer, runtime, "runtime"))
		prepared := signMessageEnvelopeV2(t, message, n.signer)
		for _, invalid := range bad {
			n.own.unchanged(t, func() {
				assert.Error(
					n.own.vault.Update(func(tx storage.WriteTx) error {
						_, err := commitMessageEnvelopeV2(
							tx,
							f.root.public,
							n.local,
							invalid,
							message,
							prepared,
						)
						return err
					}),
				)
			})
		}
	}
}
