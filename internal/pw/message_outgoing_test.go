package pw

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

func newOutgoing(t *testing.T) *requesterFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := newFirstUse(t)
	saved := try.To1(f.startUse())
	response := try.To1(f.bobUse(saved.request, f.local.handle))
	assert.That(try.To1(f.receiveUse(response)))
	for _, n := range outgoingTestNodes(f) {
		try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			try.To(tx.Put([]byte("unrelated-root"), []byte("retained")))
			return try.To1(tx.EnsureChild([]byte("unrelated"))).
				Put([]byte("sentinel"), []byte("retained"))
		}))
	}
	return f
}

// Extend the existing whole-fixture snapshot to include the published ad's
// namespace as well as every root record and unrelated sentinel.
func outgoingTestState(t *testing.T, vault *storage.Vault,
) map[string]map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	state := heldTestState(t, vault)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		const name = "local-current-ad-v1"
		if !try.To1(tx.HasChild([]byte(name))) {
			return nil
		}
		state[name] = make(map[string][]byte)
		return try.To1(tx.Child([]byte(name))).Each(func(k, v []byte) error {
			state[name][string(k)] = v
			return nil
		})
	}))
	return state
}

type outgoingTestNode struct {
	name        string
	local, peer key.Public
	signer      key.Handle
	own, other  *vaultFixture
}

func outgoingTestNodes(f *requesterFixture) []outgoingTestNode {
	return []outgoingTestNode{
		{"Bob", f.local.public, f.peer.public, f.local.handle, &f.f, &f.alice},
		{"Alice", f.peer.public, f.local.public, f.peer.handle, &f.alice, &f.f},
	}
}

func TestOutgoingEitherParticipantFirstAndExactRepeat(t *testing.T) {
	for _, name := range []string{"Bob", "Alice"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoing(t)
			for _, n := range outgoingTestNodes(f) {
				if n.name != name {
					continue
				}
				before, other := outgoingTestState(t, n.own.vault),
					outgoingTestState(t, n.other.vault)
				assert.SNil(before["root"][outgoingKey])
				assert.SNil(other["root"][outgoingKey])
				remaining := n.own.lease.remaining.Load()
				signer := &probeSigner{Handle: n.signer}
				var raw []byte
				n.other.unchanged(t, func() {
					raw = try.To1(createOutgoing(n.own.vault, f.root.public,
						n.local, signer, "local text"))
				})
				assert.Equal(n.own.lease.remaining.Load(), remaining-1)
				assert.Equal(
					signer.signCalls.Load(),
					1,
				) // Usability probe only.
				var record outgoingMessage
				try.To(wire.UnmarshalCanonical(&record, raw))
				assert.Equal(record.Version, uint8(1))
				assert.Equal(record.Text, "local text")
				assert.Equal(len(record.ID), 16)
				assert.Equal(record.ID[6]&0xf0, byte(0x40))
				assert.Equal(record.ID[8]&0xc0, byte(0x80))
				assert.DeepEqual(record.Binding.Root, f.root.public)
				assert.DeepEqual(record.Binding.Sender, n.local)
				assert.DeepEqual(record.Binding.Receiver, n.peer)
				assert.Equal(record.Binding.Requester, name == "Alice")
				var accepted acceptedRecord
				try.To(
					wire.UnmarshalCanonical(
						&accepted,
						before["root"][acceptedKey],
					),
				)
				digest := key.HashTagged(requestPurpose, accepted.Request)
				assert.DeepEqual(record.Binding.RequestDigest, digest[:])
				digest = key.HashTagged(
					outgoingHistoryPurpose,
					before["root"][acceptedKey],
				)
				assert.DeepEqual(record.Binding.AcceptedDigest, digest[:])
				before["root"][outgoingKey] = bytes.Clone(raw)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.DeepEqual(outgoingTestState(t, n.other.vault), other)

				n.own.reopen(t)
				n.own.lease.remaining.Store(0)
				n.own.unchanged(t, func() {
					again := try.To1(createOutgoing(n.own.vault, f.root.public,
						n.local, signer, "local text"))
					assert.DeepEqual(again, raw)
					assert.Equal(signer.signCalls.Load(), 2)
					again[0] ^= 1 // The caller owns its returned bytes.
					assert.DeepEqual(try.To1(createOutgoing(n.own.vault,
						f.root.public, n.local, signer, "local text")), raw)
					result, err := createOutgoing(n.own.vault, f.root.public,
						n.local, signer, "conflicting text")
					assert.Equal(err, errOutgoing)
					assert.SNil(result)
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			}
		})
	}
}

func TestOutgoingRequiresHistoricalSuccess(t *testing.T) {
	for _, state := range []string{"absent", "Await", "Expired", "Ready",
		"Expired success", "forged expired response"} {
		t.Run(state, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUse(t)
			if state != "absent" {
				saved := try.To1(f.startUse())
				if state == "Ready" || state == "Expired success" ||
					state == "forged expired response" {
					response := try.To1(f.bobUse(saved.request, f.local.handle))
					assert.That(try.To1(f.receiveUse(response)))
				}
				if state != "Await" && state != "Ready" {
					assert.That(try.To1(f.expireUse(true)))
				}
				if state == "forged expired response" {
					record := useRecord(t, f)
					record.Response[len(record.Response)-1] ^= 1
					try.To(
						f.alice.vault.Update(
							func(tx storage.WriteTx) (err error) {
								defer err2.Handle(&err, nil)
								return tx.Put(
									[]byte(firstUseKey),
									try.To1(wire.Marshal(record)),
								)
							},
						),
					)
				}
			}
			f.f.unchanged(t, func() {
				if state == "Ready" || state == "Expired success" {
					try.To1(createOutgoing(f.alice.vault, f.root.public,
						f.peer.public, f.signer, "historical success"))
				} else {
					f.alice.unchanged(t, func() {
						raw, err := createOutgoing(f.alice.vault, f.root.public,
							f.peer.public, f.signer, "historical success")
						assert.Equal(err, errOutgoing)
						assert.SNil(raw)
					})
				}
			})
		})
	}
}

func TestOutgoingCurrentGuardsIncludingRepeatAndProbeMutation(t *testing.T) {
	for _, name := range []string{"Alice", "Bob"} {
		for _, guard := range []string{"deny", "delete", "own Known",
			"peer Known", "authorization", "history", "first use", "signer"} {
			for _, repeat := range []bool{false, true} {
				for _, during := range []bool{false, true} {
					t.Run(
						fmt.Sprint(name, "/", guard, "/", repeat, "/", during),
						func(t *testing.T) {
							defer assert.PushTester(t)()
							f := newOutgoing(t)
							for _, n := range outgoingTestNodes(f) {
								if n.name != name {
									continue
								}
								if repeat {
									try.To1(
										createOutgoing(
											n.own.vault,
											f.root.public,
											n.local,
											n.signer,
											"guarded",
										),
									)
								}
								signer := &probeSigner{Handle: n.signer}
								mutate := func() (err error) {
									defer err2.Handle(&err, nil)
									if guard == "signer" {
										signer.signErr = errors.New(
											"private signer diagnostic",
										)
										return signer.signErr
									}
									if guard == "deny" {
										try.To1(
											policy.DenyLocal(
												n.own.vault,
												f.root.public,
												n.local,
												n.peer,
											),
										)
										return nil
									}
									if guard == "delete" {
										try.To1(
											DeleteHeldLocal(
												n.own.vault,
												f.root.public,
												n.local,
											),
										)
										return nil
									}
									return n.own.vault.Update(
										func(tx storage.WriteTx) (err error) {
											defer err2.Handle(&err, nil)
											switch guard {
											case "own Known", "peer Known":
												subject := n.local
												if guard == "peer Known" {
													subject = n.peer
												}
												return try.To1(tx.ChildForUpdate([]byte(knownNS))).
													Delete(subject)
											case "authorization":
												return try.To1(tx.ChildForUpdate([]byte(authNS))).
													Delete([]byte(authKey))
											case "history":
												return tx.Delete(
													[]byte(acceptedKey),
												)
											default:
												key := firstUseKey
												if name == "Bob" {
													key = useSeenKey
												}
												return tx.Delete([]byte(key))
											}
										},
									)
								}
								var expected map[string]map[string][]byte
								if during {
									// A successful Update here also proves probing is outside
									// the outgoing transaction. Only the mutation may persist.
									signer.sign = func(d []byte) ([]byte, error) {
										err := mutate()
										expected = outgoingTestState(
											t,
											n.own.vault,
										)
										if err != nil {
											return nil, err
										}
										return n.signer.Sign(d)
									}
								} else {
									err := mutate()
									if guard != "signer" {
										try.To(err)
									}
									expected = outgoingTestState(t, n.own.vault)
								}
								n.other.unchanged(t, func() {
									run := func() {
										raw, err := createOutgoing(
											n.own.vault,
											f.root.public,
											n.local,
											signer,
											"guarded",
										)
										assert.Equal(err, errOutgoing)
										assert.SNil(raw)
									}
									if during {
										run()
										assert.Equal(signer.signCalls.Load(), 1)
									} else {
										n.own.unchanged(t, run)
									}
								})
								assert.DeepEqual(
									outgoingTestState(t, n.own.vault),
									expected,
								)
							}
						},
					)
				}
			}
		}
	}
}

func TestOutgoingRejectsCorruptHistory(t *testing.T) {
	for _, name := range []string{"Alice", "Bob"} {
		for _, recordKey := range []string{acceptedKey, heldKey, attemptKey,
			invitationKey, firstUseKey, useSeenKey} {
			for _, mode := range []string{"malformed", "noncanonical", "signature",
				"namespace"} {
				t.Run(name+"/"+recordKey+"/"+mode, func(t *testing.T) {
					defer assert.PushTester(t)()
					f := newOutgoing(t)
					for _, n := range outgoingTestNodes(f) {
						if n.name != name {
							continue
						}
						try.To(
							n.own.vault.Update(
								func(tx storage.WriteTx) (err error) {
									defer err2.Handle(&err, nil)
									old, _ := try.To2(tx.Get([]byte(recordKey)))
									raw := []byte{0xff}
									switch mode {
									case "namespace":
										try.To(tx.Delete([]byte(recordKey)))
										try.To1(
											tx.EnsureChild([]byte(recordKey)),
										)
										return nil
									case "noncanonical":
										if len(old) > 0 {
											raw = append(
												[]byte{0x98, old[0] & 0x1f},
												old[1:]...)
										}
									case "signature":
										if len(old) > 0 {
											raw = old
											raw[len(raw)-1] ^= 1
										}
									}
									return tx.Put([]byte(recordKey), raw)
								},
							),
						)
						n.other.unchanged(t, func() {
							n.own.unchanged(t, func() {
								raw, err := createOutgoing(
									n.own.vault,
									f.root.public,
									n.local,
									n.signer,
									"reject corrupt history",
								)
								assert.Equal(err, errOutgoing)
								assert.SNil(raw)
							})
						})
					}
				})
			}
		}
	}
}

func TestOutgoingSavedRecordValidation(t *testing.T) {
	changes := map[string]func(*outgoingMessage){
		"version":         func(r *outgoingMessage) { r.Version++ },
		"short ID":        func(r *outgoingMessage) { r.ID = r.ID[:15] },
		"ID version":      func(r *outgoingMessage) { r.ID[6] = 0 },
		"ID variant":      func(r *outgoingMessage) { r.ID[8] = 0 },
		"root":            func(r *outgoingMessage) { r.Binding.Root = r.Binding.Sender },
		"sender":          func(r *outgoingMessage) { r.Binding.Sender = r.Binding.Receiver },
		"receiver":        func(r *outgoingMessage) { r.Binding.Receiver = r.Binding.Root },
		"role":            func(r *outgoingMessage) { r.Binding.Requester = !r.Binding.Requester },
		"request digest":  func(r *outgoingMessage) { r.Binding.RequestDigest[0] ^= 1 },
		"accepted digest": func(r *outgoingMessage) { r.Binding.AcceptedDigest[0] ^= 1 },
		"empty text":      func(r *outgoingMessage) { r.Text = "" },
		"long text":       func(r *outgoingMessage) { r.Text = strings.Repeat("x", 1025) },
		"invalid UTF8":    func(r *outgoingMessage) { r.Text = string([]byte{0xff}) },
	}
	f := newOutgoing(t)
	defer assert.PushTester(t)()
	for _, n := range outgoingTestNodes(f) {
		original := try.To1(createOutgoing(n.own.vault, f.root.public,
			n.local, n.signer, "immutable"))
		invalid := map[string][]byte{
			"empty": {}, "malformed": {0xff}, "oversize": make([]byte, maxOutgoingBytes+1),
			"noncanonical": append([]byte{0x98, 4}, original[1:]...),
			"tag":          append([]byte{0xc0}, original...),
			"trailing":     append(bytes.Clone(original), 0),
		}
		for name, change := range changes {
			var record outgoingMessage
			try.To(wire.UnmarshalCanonical(&record, original))
			change(&record)
			invalid[name] = try.To1(wire.Marshal(record))
		}
		for name, raw := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(outgoingKey), raw)
				}))
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						result, err := createOutgoing(
							n.own.vault,
							f.root.public,
							n.local,
							n.signer,
							"immutable",
						)
						assert.Equal(err, errOutgoing)
						assert.SNil(result)
					})
				})
			})
		}
	}
}

func TestOutgoingHistoricalEvidenceHasNoRemotePermissionOrTTL(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	f.now = f.now.Add(24 * time.Hour)
	assert.That(try.To1(f.expireUse(false)))
	// The initial ping, ad and invitation are all expired. Remove current ad
	// caches as well: only the authenticated historical ad belongs to binding.
	for _, n := range outgoingTestNodes(f) {
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
	}
	assert.That(try.To1(policy.DenyLocal(f.f.vault, f.root.public,
		f.local.public, f.peer.public)))
	assert.That(
		try.To1(DeleteHeldLocal(f.f.vault, f.root.public, f.local.public)),
	)
	f.f.unchanged(t, func() {
		try.To1(createOutgoing(f.alice.vault, f.root.public,
			f.peer.public, f.signer, "submitted locally only"))
	})
	assert.Equal(useRecord(t, f).State, useExpired)
}

func TestOutgoingInputsAndByteBounds(t *testing.T) {
	for _, text := range []string{"", string([]byte{0xff}), strings.Repeat("x", 1025),
		strings.Repeat("é", 513), "a", strings.Repeat("é", 512)} {
		t.Run(fmt.Sprint(len(text)), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoing(t)
			if text == "a" || text == strings.Repeat("é", 512) {
				try.To1(createOutgoing(f.alice.vault, f.root.public,
					f.peer.public, f.signer, text))
				return
			}
			f.alice.unchanged(t, func() {
				raw, err := createOutgoing(f.alice.vault, f.root.public,
					f.peer.public, f.signer, text)
				assert.Equal(err, errOutgoing)
				assert.SNil(raw)
			})
		})
	}
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	var typedNil *probeSigner
	for _, tc := range []struct {
		v           *storage.Vault
		root, local key.Public
		signer      key.Handle
	}{
		{nil, f.root.public, f.peer.public, f.signer},
		{f.alice.vault, nil, f.peer.public, f.signer},
		{f.alice.vault, f.root.public, nil, f.signer},
		{f.alice.vault, f.local.public, f.peer.public, f.signer},
		{f.alice.vault, f.root.public, f.local.public, f.local.handle},
		{f.alice.vault, f.root.public, f.peer.public, nil},
		{f.alice.vault, f.root.public, f.peer.public, typedNil},
		{f.alice.vault, f.root.public, f.peer.public, f.local.handle},
	} {
		f.alice.unchanged(t, func() {
			raw, err := createOutgoing(
				tc.v,
				tc.root,
				tc.local,
				tc.signer,
				"text",
			)
			assert.Equal(err, errOutgoing)
			assert.SNil(raw)
		})
	}
}

func TestOutgoingSensitiveRefusal(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	text := "sensitive outgoing text never in diagnostics"
	f.signer.signErr = errors.New("sensitive provider keys and identifiers")
	f.alice.unchanged(t, func() {
		raw, err := createOutgoing(f.alice.vault, f.root.public,
			f.peer.public, f.signer, text)
		assert.Equal(err, errOutgoing)
		assert.SNil(raw)
	})
}

func TestOutgoingDiagnostics(t *testing.T) {
	defer assert.PushTester(t)()
	cmd := exec.CommandContext(t.Context(), try.To1(os.Executable()),
		"-test.run=^TestOutgoingSensitiveRefusal$", "-test.count=1",
		"-test.timeout=30s", "-v=1", "-logtostderr=true")
	output, err := cmd.CombinedOutput()
	assert.NoError(err, "diagnostic subprocess failed")
	assert.ThatNot(strings.Contains(string(output), "sensitive"))
	// This domain slice adds no glog events; setup emits only existing events.
	assert.ThatNot(strings.Contains(string(output), "op=outgoing"))
}

func TestOutgoingCrossVaultAndChangedRelationship(t *testing.T) {
	for _, mode := range []string{"foreign history", "opposite role",
		"changed accepted result"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f, foreign := newOutgoing(t), newOutgoing(t)
			for _, n := range outgoingTestNodes(f) {
				// Even an exact text repeat must authenticate its current history.
				try.To1(createOutgoing(n.own.vault, f.root.public,
					n.local, n.signer, "bound text"))
				history := requesterRecords(t, foreign.alice.vault)[1]
				if mode == "changed accepted result" {
					var record acceptedRecord
					try.To(wire.UnmarshalCanonical(&record,
						requesterRecords(t, n.own.vault)[1]))
					var response SignedAccepted
					try.To(wire.UnmarshalCanonical(&response, record.Response))
					digest := key.HashTagged(AcceptedPurpose,
						try.To1(wire.Marshal(response.Payload)))
					response.Signature = try.To1(f.local.handle.Sign(digest[:]))
					changed := try.To1(wire.Marshal(response))
					assert.ThatNot(bytes.Equal(changed, record.Response))
					record.Response = changed
					history = try.To1(wire.Marshal(record))
				}
				try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					if mode == "opposite role" {
						if n.name == "Alice" {
							return tx.Delete([]byte(attemptKey))
						}
						var record acceptedRecord
						raw, _ := try.To2(tx.Get([]byte(acceptedKey)))
						try.To(wire.UnmarshalCanonical(&record, raw))
						return tx.Put([]byte(attemptKey), record.Request)
					}
					return tx.Put([]byte(acceptedKey), history)
				}))
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						raw, err := createOutgoing(n.own.vault, f.root.public,
							n.local, n.signer, "bound text")
						assert.Equal(err, errOutgoing)
						assert.SNil(raw)
					})
				})
			}
		})
	}
}

func TestOutgoingAtomicFailure(t *testing.T) {
	for _, mode := range []string{"callback", "seal"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoing(t)
			for _, n := range outgoingTestNodes(f) {
				before := outgoingTestState(t, n.own.vault)
				disk := try.To1(os.ReadFile(n.own.path))
				n.other.unchanged(t, func() {
					if mode == "seal" {
						n.own.lease.remaining.Store(0)
						raw, err := createOutgoing(n.own.vault, f.root.public,
							n.local, n.signer, "atomic text")
						assert.Equal(err, errOutgoing)
						assert.SNil(raw)
					} else {
						var binding outgoingBinding
						try.To(n.own.vault.View(func(tx storage.ReadTx) (err error) {
							defer err2.Handle(&err, nil)
							binding = try.To1(outgoingPrerequisites(tx, f.root.public, n.local))
							return nil
						}))
						cause := errors.New("abort after pending message put")
						err := n.own.vault.Update(func(tx storage.WriteTx) (err error) {
							defer err2.Handle(&err, nil)
							_, err = commitOutgoing(&failingAcceptanceTx{
								WriteTx: tx, failAfter: 1, cause: cause,
							}, f.root.public, n.local, binding, "atomic text")
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

func TestOutgoingInspectsCommitAfterLostResult(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	for _, n := range outgoingTestNodes(f) {
		// Simulate another explicit call committing while the outer call probes.
		// Discard its returned bytes: storage, not the lost result, is authority.
		signer := &probeSigner{Handle: n.signer}
		var committed map[string]map[string][]byte
		var allowance int64
		signer.sign = func(d []byte) (_ []byte, err error) {
			defer err2.Handle(&err, nil)
			try.To1(createOutgoing(n.own.vault, f.root.public,
				n.local, n.signer, "saved before lost result"))
			committed = outgoingTestState(t, n.own.vault)
			allowance = n.own.lease.remaining.Load()
			return n.signer.Sign(d)
		}
		n.other.unchanged(t, func() {
			raw := try.To1(createOutgoing(n.own.vault, f.root.public,
				n.local, signer, "saved before lost result"))
			assert.DeepEqual(raw, committed["root"][outgoingKey])
		})
		assert.Equal(n.own.lease.remaining.Load(), allowance)
		assert.DeepEqual(outgoingTestState(t, n.own.vault), committed)
		n.own.reopen(t)
		n.own.unchanged(t, func() {
			raw := try.To1(createOutgoing(n.own.vault, f.root.public,
				n.local, n.signer, "saved before lost result"))
			assert.DeepEqual(raw, committed["root"][outgoingKey])
		})
	}
}
