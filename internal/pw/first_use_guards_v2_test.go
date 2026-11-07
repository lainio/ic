package pw

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Mutations also run from the signer callback. A nested Vault.Update succeeding
// there proves no signer is called in a Vault transaction; the subsequent
// transition must reread the changed durable guard before its sole write.
func TestFirstUseCurrentLocalGuardsV2(t *testing.T) {
	for _, phase := range []string{"Await", "useSeen", "Ready"} {
		for _, guard := range []string{"deny", "delete", "known self", "known peer", "device", "history", "held binding", "unusable"} {
			for _, during := range []bool{false, true} {
				t.Run(
					fmt.Sprint(phase, "/", guard, "/", during),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f := newFirstUseV2(t)
						var saved SavedFirstUseV2
						var response []byte
						if phase != "Await" {
							saved = try.To1(f.startUseV2())
						}
						if phase == "Ready" {
							response = try.To1(
								f.bobUseV2(saved.request, f.local.handle),
							)
						}
						v, local, peer := f.alice.vault, f.peer.public, f.local.public
						signer := f.signer
						fixture := &f.alice
						if phase == "useSeen" {
							v, local, peer = f.f.vault, f.local.public, f.peer.public
							signer = &probeSigner{Handle: f.local.handle}
							fixture = &f.f
						}
						invalidate := func() (err error) {
							defer err2.Handle(&err, nil)
							switch guard {
							case "deny":
								try.To1(
									policy.DenyLocal(
										v,
										f.root.public,
										local,
										peer,
									),
								)
							case "unusable":
								return errors.New("private provider diagnostic")
							default:
								return v.Update(
									func(tx storage.WriteTx) (err error) {
										defer err2.Handle(&err, nil)
										switch guard {
										case "delete":
											return tx.Delete([]byte(heldKey))
										case "known self":
											return try.To1(tx.ChildForUpdate([]byte(knownNS))).
												Delete(local)
										case "known peer":
											return try.To1(tx.ChildForUpdate([]byte(knownNS))).
												Delete(peer)
										case "device":
											return try.To1(tx.ChildForUpdate([]byte(authNS))).
												Delete([]byte(authKey))
										case "history":
											return tx.Put(
												[]byte(acceptedKey),
												[]byte{0xff},
											)
										case "held binding":
											return tx.Put(
												[]byte(heldKey),
												try.To1(
													wire.Marshal(
														heldRecord{
															Version: 2,
															RequestDigest: make(
																[]byte,
																32,
															),
														},
													),
												),
											)
										}
										return nil
									},
								)
							}
							return nil
						}
						if during || guard == "unusable" {
							signer.sign = func(d []byte) ([]byte, error) {
								if err := invalidate(); err != nil {
									return nil, err
								}
								return signer.Handle.Sign(d)
							}
						} else {
							try.To(invalidate())
						}
						before := useRecords(t, v)
						run := func() {
							var err error
							switch phase {
							case "Await":
								_, err = f.startUseV2()
							case "useSeen":
								var result []byte
								result, err = f.bobUseV2(saved.request, signer)
								assert.SNil(result)
							case "Ready":
								var ready bool
								ready, err = f.receiveUseV2(response)
								assert.ThatNot(ready)
							}
							assert.Equal(err, ErrFirstUse)
						}
						if during {
							run()
						} else {
							fixture.unchanged(t, run)
						}
						assert.DeepEqual(useRecords(t, v), before)
					},
				)
			}
		}
	}
}

func TestFirstUseRechecksAfterSigningV2(t *testing.T) {
	for _, bob := range []bool{false, true} {
		for _, mode := range []string{"deny", "delete", "expiry", "wrong signature", "failure"} {
			t.Run(fmt.Sprint(bob, mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUseV2(t)
				var saved SavedFirstUseV2
				if bob {
					saved = try.To1(f.startUseV2())
				}
				v, local, peer := f.alice.vault, f.peer.public, f.local.public
				handle := f.peer.handle
				if bob {
					v, local, peer = f.f.vault, f.local.public, f.peer.public
					handle = f.local.handle
				}
				signer := &probeSigner{Handle: handle}
				signer.sign = func(d []byte) ([]byte, error) {
					if signer.signCalls.Load() == 2 {
						switch mode {
						case "deny":
							if _, err := policy.DenyLocal(v, f.root.public, local, peer); err != nil {
								return nil, err
							}
						case "delete":
							if err := v.Update(func(tx storage.WriteTx) error { return tx.Delete([]byte(heldKey)) }); err != nil {
								return nil, err
							}
						case "expiry":
							f.now = f.now.Add(FirstUseLifetime)
						case "wrong signature":
							return []byte{1}, nil
						case "failure":
							return nil, errors.New("secret signer detail")
						}
					}
					return handle.Sign(d)
				}
				if bob {
					result, err := f.bobUseV2(saved.request, signer)
					assert.Equal(err, ErrFirstUse)
					assert.SNil(result)
				} else {
					f.signer = signer
					result, err := f.startUseV2()
					assert.Equal(err, ErrFirstUse)
					assert.SNil(result.request)
				}
				assert.DeepEqual(useRecords(t, v), [2][]byte{})
			})
		}
	}
}

func TestFirstUseCorruptStoredBindingAndSessionV2(t *testing.T) {
	for _, bob := range []bool{false, true} {
		for _, record := range []string{attemptKey, acceptedKey, heldKey, firstUseKey, useSeenKey} {
			if bob && record == attemptKey {
				continue
			}
			for _, mode := range []string{"malformed", "namespace", "noncanonical"} {
				t.Run(fmt.Sprint(bob, record, mode), func(t *testing.T) {
					defer assert.PushTester(t)()
					f := newFirstUseV2(t)
					saved := try.To1(f.startUseV2())
					response := try.To1(
						f.bobUseV2(saved.request, f.local.handle),
					)
					fixture := &f.alice
					if bob {
						fixture = &f.f
					}
					try.To(
						fixture.vault.Update(
							func(tx storage.WriteTx) (err error) {
								defer err2.Handle(&err, nil)
								if mode == "namespace" {
									try.To(tx.Delete([]byte(record)))
									try.To1(tx.EnsureChild([]byte(record)))
									return nil
								}
								raw := []byte{0xff}
								if mode == "noncanonical" {
									old, _ := try.To2(tx.Get([]byte(record)))
									if len(old) > 0 {
										raw = append(
											[]byte{0x98, old[0] & 0x1f},
											old[1:]...)
									}
								}
								return tx.Put([]byte(record), raw)
							},
						),
					)
					fixture.unchanged(t, func() {
						if bob {
							_, err := f.bobUseV2(saved.request, f.local.handle)
							assert.Equal(err, ErrFirstUse)
						} else {
							_, err := f.receiveUseV2(response)
							assert.Equal(err, ErrFirstUse)
						}
					})
				})
			}
		}
	}
}

func TestFirstUseHistoryAuthenticatesSavedAdAndRequestV2(t *testing.T) {
	// Alter the historical signed ad, and even re-sign request and acceptance.
	// The ad's independently pinned Bob signature must still reject corruption.
	for _, bob := range []bool{false, true} {
		t.Run(fmt.Sprint(bob), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUseV2(t)
			saved := try.To1(f.startUseV2())
			v := f.alice.vault
			if bob {
				v = f.f.vault
			}
			var history acceptedRecord
			raw := requesterRecords(t, v)[1]
			try.To(wire.UnmarshalCanonical(&history, raw))
			var req SignedEstablishmentV2
			try.To(wire.UnmarshalCanonical(&req, history.Request))
			req.Payload.Ad[len(req.Payload.Ad)-1] ^= 1
			history.Request = signEstablishmentV2(
				t,
				req.Payload,
				f.peer.handle,
				EstablishPurposeV2,
			)
			p := acceptedPayloadV2(req.Payload, history.Request)
			digest := key.HashTagged(
				AcceptedPurposeV2,
				try.To1(wire.Marshal(p)),
			)
			history.Response = try.To1(
				wire.Marshal(
					SignedAcceptedV2{
						Payload:   p,
						Signature: try.To1(f.local.handle.Sign(digest[:])),
					},
				),
			)
			try.To(v.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				try.To(
					tx.Put([]byte(acceptedKey), try.To1(wire.Marshal(history))),
				)
				if !bob {
					try.To(tx.Put([]byte(attemptKey), history.Request))
				}
				return tx.Put(
					[]byte(heldKey),
					try.To1(
						wire.Marshal(
							heldRecord{
								Version:       1,
								RequestDigest: bytes.Clone(p.RequestDigest),
							},
						),
					),
				)
			}))
			if bob {
				_, err := f.bobUseV2(saved.request, f.local.handle)
				assert.Equal(err, ErrFirstUse)
			} else {
				_, err := f.startUseV2()
				assert.Equal(err, ErrFirstUse)
				_, err = f.expireUseV2(true)
				assert.Equal(err, ErrFirstUse)
			}
		})
	}
}

func TestFirstUseRuntimeGuardsV2(t *testing.T) {
	for _, phase := range []string{useAwait, "useSeen", useReady} {
		for _, runtime := range []ContactRuntimeV2{
			{}, {false, aliceServiceOrigin}, {true, "http://127.0.0.1:4041"},
			{true, "http://127.0.0.1:0"}, {true, aliceServiceOrigin + "/"},
		} {
			t.Run(fmt.Sprint(phase, runtime), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUseV2(t)
				saved := try.To1(f.startUseV2())
				var response []byte
				node, local := &f.alice, f.peer.public
				if phase == "useSeen" {
					node, local = &f.f, f.local.public
					var request SignedFirstUseV2
					try.To(wire.UnmarshalCanonical(&request, saved.request))
					response = signUseResponseV2(
						t,
						firstUseResponsePayloadV2(
							request.Payload,
							saved.request,
						),
						f.local.handle,
					)
				} else {
					response = try.To1(f.bobUseV2(saved.request, f.local.handle))
					if phase == useAwait {
						// Test-only rollback to the pre-Await fixture, retaining
						// signed input to exercise the transaction directly.
						try.To(node.vault.Update(func(tx storage.WriteTx) error {
							return tx.Delete([]byte(firstUseKey))
						}))
					}
				}
				node.unchanged(t, func() {
					var err error
					switch phase {
					case useAwait:
						f.aliceRuntime = runtime
						_, err = f.startUseV2()
					case "useSeen":
						f.bobRuntime = runtime
						_, err = f.bobUseV2(saved.request, f.local.handle)
					case useReady:
						f.aliceRuntime = runtime
						_, err = f.receiveUseV2(response)
					}
					assert.Equal(err, ErrFirstUse)
					// Check commit entry too: prepared signatures cannot bypass
					// the caller's trusted running/bound-origin snapshot.
					assert.Error(
						node.vault.Update(func(tx storage.WriteTx) error {
							switch phase {
							case useAwait:
								return commitFirstUseAwaitV2(
									tx,
									f.root.public,
									local,
									runtime,
									saved.request,
									f.useClock,
								)
							case "useSeen":
								return commitFirstUseReceiptV2(
									tx,
									f.root.public,
									local,
									runtime,
									saved.request,
									response,
									f.useClock,
								)
							default:
								return commitFirstUseReadyV2(
									tx,
									f.root.public,
									local,
									runtime,
									response,
									f.useClock,
								)
							}
						}),
					)
				})
			})
		}
	}
}

func TestFirstUsePinnedIdentityAndSignerV2(t *testing.T) {
	for _, phase := range []string{useAwait, "useSeen", useReady} {
		for _, fault := range []string{"nil vault", "wrong root", "wrong role",
			"nil signer", "typed nil", "wrong signer", "bad public", "bad probe"} {
			t.Run(phase+"/"+fault, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUseV2(t)
				var saved SavedFirstUseV2
				var response []byte
				if phase != useAwait {
					saved = try.To1(f.startUseV2())
				}
				if phase == useReady {
					response = try.To1(
						f.bobUseV2(saved.request, f.local.handle),
					)
				}
				node, local, runtime := &f.alice, f.peer.public, f.aliceRuntime
				probe := &probeSigner{Handle: f.peer.handle}
				if phase == "useSeen" {
					node, local, runtime = &f.f, f.local.public, f.bobRuntime
					probe.Handle = f.local.handle
				}
				vault, root, signer := node.vault, f.root.public, key.Handle(
					probe,
				)
				switch fault {
				case "nil vault":
					vault = nil
				case "wrong root":
					root = f.local.public
				case "wrong role":
					local = f.root.public
				case "nil signer":
					signer = nil
				case "typed nil":
					signer = (*probeSigner)(nil)
				case "wrong signer":
					signer = f.root.handle
				case "bad public":
					probe.publicErr = errors.New("private provider detail")
				case "bad probe":
					probe.sign = func([]byte) ([]byte, error) { return []byte{1}, nil }
				}
				node.unchanged(t, func() {
					var err error
					switch phase {
					case useAwait:
						_, err = saveFirstUseV2(vault, root, local, signer,
							runtime, f.useClock)
					case "useSeen":
						_, err = bobFirstUseV2(vault, root, local, signer,
							runtime, saved.request, f.useClock)
					case useReady:
						_, err = receiveFirstUseV2(vault, root, local, signer,
							runtime, response, f.useClock)
					}
					assert.Equal(err, ErrFirstUse)
				})
			})
		}
	}
}
