package pw

import (
	"bytes"
	"fmt"
	"strings"
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

func newOutgoingV2(t *testing.T) *firstUseFixtureV2 {
	t.Helper()
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	saved := try.To1(f.startUseV2())
	response := try.To1(f.bobUseV2(saved.request, f.local.handle))
	assert.That(try.To1(f.receiveUseV2(response)))
	return f
}

func (f *firstUseFixtureV2) messageRuntime(
	n outgoingTestNode,
) ContactRuntimeV2 {
	if n.name == "Alice" {
		return f.aliceRuntime
	}
	return f.bobRuntime
}

func messageBindingV2(
	t *testing.T,
	vault *storage.Vault,
	root, local key.Public,
) (binding outgoingBindingV2) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		binding, _ = try.To2(outgoingHistoryV2(tx, root, local))
		return nil
	}))
	return binding
}

func TestMessageEitherSenderAndExactRepeatV2(t *testing.T) {
	for _, first := range []int{0, 1} {
		t.Run(fmt.Sprint(first), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			nodes := outgoingTestNodes(f.requesterFixture)
			var ids [][]byte
			for _, index := range []int{first, 1 - first} {
				n := nodes[index]
				runtime := f.messageRuntime(n)
				expected := messageBindingV2(
					t,
					n.other.vault,
					f.root.public,
					n.peer,
				)
				expected.Sender, expected.Receiver = expected.Receiver, expected.Sender
				expected.Requester = !expected.Requester
				before := outgoingTestState(t, n.own.vault)
				remaining := n.own.lease.remaining.Load()
				signer := &probeSigner{Handle: n.signer}
				text := strings.Repeat("é", 512)
				var message, envelope []byte
				n.other.unchanged(t, func() {
					message = try.To1(
						CreateOutgoingV2(n.own.vault, f.root.public,
							n.local, signer, runtime, text),
					)
					assert.Equal(
						signer.signCalls.Load(),
						1,
					) // Only usability.
					envelope = try.To1(
						PrepareOutgoingEnvelopeV2(n.own.vault,
							f.root.public, n.local, signer, runtime),
					)
				})
				assert.Equal(
					signer.signCalls.Load(),
					4,
				) // Probe, sign, final probe.
				assert.Equal(n.own.lease.remaining.Load(), remaining-2)
				record := try.To1(decodeOutgoingV2(message, expected))
				assert.Equal(record.Version, 2)
				assert.Equal(record.Text, text)
				assert.Equal(len(record.ID), 16)
				assert.Equal(record.ID[6]&0xf0, byte(0x40))
				assert.Equal(record.ID[8]&0xc0, byte(0x80))
				ids = append(ids, record.ID)
				assert.DeepEqual(record.Binding.Sender, n.local)
				assert.DeepEqual(record.Binding.Receiver, n.peer)
				assert.Equal(record.Binding.Requester, n.name == "Alice")
				var accepted acceptedRecord
				try.To(
					wire.UnmarshalCanonical(
						&accepted,
						before["root"][acceptedKey],
					),
				)
				digest := key.HashTagged(requestPurposeV2, accepted.Request)
				assert.DeepEqual(record.Binding.RequestDigest, digest[:])
				digest = key.HashTagged(
					outgoingHistoryPurposeV2,
					before["root"][acceptedKey],
				)
				assert.DeepEqual(record.Binding.AcceptedDigest, digest[:])
				verified := try.To1(
					decodeMessageEnvelopeV2(envelope, expected),
				)
				assert.DeepEqual(verified.Message, message)
				digest = key.HashTagged(messageAuthPurposeV2, message)
				assert.That(verified.Signature.Verify(n.local, digest[:]))
				before["root"][outgoingKey] = bytes.Clone(message)
				before["root"][messageEnvelopeKey] = bytes.Clone(envelope)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.SNil(before["root"][messageSentKey])
				assert.SNil(before["root"][inboxKey])

				n.own.reopen(t)
				n.own.lease.remaining.Store(0)
				n.own.unchanged(t, func() {
					for range 2 {
						again := try.To1(
							CreateOutgoingV2(n.own.vault, f.root.public,
								n.local, signer, runtime, text),
						)
						assert.DeepEqual(again, message)
						again[0] ^= 1
						again = try.To1(
							PrepareOutgoingEnvelopeV2(
								n.own.vault,
								f.root.public,
								n.local,
								signer,
								runtime,
							),
						)
						assert.DeepEqual(again, envelope)
						again[0] ^= 1
					}
					assert.Equal(
						signer.signCalls.Load(),
						8,
					) // Repeat probes only.
					got, err := CreateOutgoingV2(
						n.own.vault,
						f.root.public,
						n.local,
						signer,
						runtime,
						"different",
					)
					assert.Equal(err, errOutgoing)
					assert.SNil(got)
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			}
			assert.ThatNot(bytes.Equal(ids[0], ids[1]))
		})
	}
}

func TestMessageHistoricalFirstUseRequiredV2(t *testing.T) {
	for _, state := range []string{"no acceptance", "holding only", "Await",
		"Expired", "Ready", "Expired Ready", "forged Ready"} {
		t.Run(state, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUseV2(t)
			if state == "no acceptance" {
				for _, n := range outgoingTestNodes(f.requesterFixture) {
					try.To(
						n.own.vault.Update(
							func(tx storage.WriteTx) (err error) {
								defer err2.Handle(&err, nil)
								try.To(tx.Delete([]byte(heldKey)))
								return tx.Delete([]byte(acceptedKey))
							},
						),
					)
				}
			} else if state != "holding only" {
				saved := try.To1(f.startUseV2())
				if state == "Ready" || state == "Expired Ready" || state == "forged Ready" {
					response := try.To1(f.bobUseV2(saved.request, f.local.handle))
					assert.That(try.To1(f.receiveUseV2(response)))
				}
				if strings.HasPrefix(state, "Expired") {
					assert.That(try.To1(f.expireUseV2(true)))
				}
				if state == "forged Ready" {
					for _, n := range outgoingTestNodes(f.requesterFixture) {
						name := useSeenKey
						if n.name == "Alice" {
							name = firstUseKey
						}
						try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
							defer err2.Handle(&err, nil)
							raw, _ := try.To2(tx.Get([]byte(name)))
							raw[len(raw)-1] ^= 1
							return tx.Put([]byte(name), raw)
						}))
					}
				}
			}
			for _, n := range outgoingTestNodes(f.requesterFixture) {
				n.other.unchanged(t, func() {
					if state == "Ready" || state == "Expired Ready" {
						try.To1(
							CreateOutgoingV2(
								n.own.vault,
								f.root.public,
								n.local,
								n.signer,
								f.messageRuntime(n),
								"historical",
							),
						)
						try.To1(
							PrepareOutgoingEnvelopeV2(
								n.own.vault,
								f.root.public,
								n.local,
								n.signer,
								f.messageRuntime(n),
							),
						)
						return
					}
					n.own.unchanged(t, func() {
						got, err := CreateOutgoingV2(
							n.own.vault,
							f.root.public,
							n.local,
							n.signer,
							f.messageRuntime(n),
							"historical",
						)
						assert.Equal(err, errOutgoing)
						assert.SNil(got)
					})
				})
			}
		})
	}
}

func TestMessageNoBootstrapRefreshOrRemotePermissionV2(t *testing.T) {
	for _, index := range []int{0, 1} {
		t.Run(fmt.Sprint(index), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			f.now = f.now.Add(24 * time.Hour)
			assert.That(try.To1(f.expireUseV2(false)))
			n := outgoingTestNodes(f.requesterFixture)[index]
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
			try.To1(
				policy.DenyLocal(
					n.other.vault,
					f.root.public,
					n.peer,
					n.local,
				),
			)
			try.To1(DeleteHeldLocal(n.other.vault, f.root.public, n.peer))
			n.other.unchanged(t, func() {
				try.To1(
					CreateOutgoingV2(
						n.own.vault,
						f.root.public,
						n.local,
						n.signer,
						f.messageRuntime(n),
						"local permission only",
					),
				)
				try.To1(
					PrepareOutgoingEnvelopeV2(n.own.vault, f.root.public,
						n.local, n.signer, f.messageRuntime(n)),
				)
			})
		})
	}
}

func TestMessageCurrentGuardsV2(t *testing.T) {
	for _, guard := range []string{"deny", "delete", "own Known", "peer Known",
		"authorization", "history", "first use", "stopped", "origin", "path"} {
		for _, phase := range []string{"create", "repeat outgoing", "prepare", "repeat envelope"} {
			t.Run(guard+"/"+phase, func(t *testing.T) {
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
					switch guard {
					case "stopped":
						runtime.Running = false
					case "origin":
						runtime.BoundOrigin = "http://127.0.0.1:8888"
					case "path":
						runtime.BoundOrigin += "/peer/pw/message"
					default:
						try.To(
							mutateEnvelopeGuard(n, f.root.public, guard),
						)
					}
					n.other.unchanged(t, func() {
						n.own.unchanged(t, func() {
							got, err := CreateOutgoingV2(
								n.own.vault,
								f.root.public,
								n.local,
								n.signer,
								runtime,
								"guarded",
							)
							assert.Equal(err, errOutgoing)
							assert.SNil(got)
							got, err = PrepareOutgoingEnvelopeV2(
								n.own.vault,
								f.root.public,
								n.local,
								n.signer,
								runtime,
							)
							assert.Equal(err, errMessageEnvelope)
							assert.SNil(got)
						})
					})
				}
			})
		}
	}
}

func TestMessageTextBoundsV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoingV2(t)
	for _, n := range outgoingTestNodes(f.requesterFixture) {
		for _, text := range []string{"", string([]byte{0xff}),
			strings.Repeat("x", 1025), strings.Repeat("é", 513)} {
			n.own.unchanged(t, func() {
				raw, err := CreateOutgoingV2(
					n.own.vault,
					f.root.public,
					n.local,
					n.signer,
					f.messageRuntime(n),
					text,
				)
				assert.Equal(err, errOutgoing)
				assert.SNil(raw)
			})
		}
		try.To1(CreateOutgoingV2(n.own.vault, f.root.public, n.local,
			n.signer, f.messageRuntime(n), "a"))
	}
	assert.Equal(maxOutgoingTextBytes, 1024)
	assert.Equal(maxOutgoingBytes, 2048)
	assert.Equal(maxMessageEnvelopeBytes, 2176)
}
