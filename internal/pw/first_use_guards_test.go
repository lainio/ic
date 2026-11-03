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
func TestFirstUseCurrentLocalGuards(t *testing.T) {
	for _, phase := range []string{"Await", "useSeen", "Ready"} {
		for _, guard := range []string{"deny", "delete", "known self", "known peer", "device", "history", "held binding", "unusable"} {
			for _, during := range []bool{false, true} {
				t.Run(
					fmt.Sprint(phase, "/", guard, "/", during),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f := newFirstUse(t)
						var saved SavedFirstUse
						var response []byte
						if phase != "Await" {
							saved = try.To1(f.startUse())
						}
						if phase == "Ready" {
							response = try.To1(
								f.bobUse(saved.request, f.local.handle),
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
															Version: 1,
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
								_, err = f.startUse()
							case "useSeen":
								var result []byte
								result, err = f.bobUse(saved.request, signer)
								assert.SNil(result)
							case "Ready":
								var ready bool
								ready, err = f.receiveUse(response)
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

func TestFirstUseRechecksAfterSigning(t *testing.T) {
	for _, bob := range []bool{false, true} {
		for _, mode := range []string{"deny", "delete", "expiry", "wrong signature", "failure"} {
			t.Run(fmt.Sprint(bob, mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUse(t)
				var saved SavedFirstUse
				if bob {
					saved = try.To1(f.startUse())
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
					result, err := f.bobUse(saved.request, signer)
					assert.Equal(err, ErrFirstUse)
					assert.SNil(result)
				} else {
					f.signer = signer
					result, err := f.startUse()
					assert.Equal(err, ErrFirstUse)
					assert.SNil(result.request)
				}
				assert.DeepEqual(useRecords(t, v), [2][]byte{})
			})
		}
	}
}

func TestFirstUseCorruptStoredBindingAndSession(t *testing.T) {
	for _, bob := range []bool{false, true} {
		for _, record := range []string{attemptKey, acceptedKey, heldKey, firstUseKey, useSeenKey} {
			if bob && record == attemptKey {
				continue
			}
			for _, mode := range []string{"malformed", "namespace", "noncanonical"} {
				t.Run(fmt.Sprint(bob, record, mode), func(t *testing.T) {
					defer assert.PushTester(t)()
					f := newFirstUse(t)
					saved := try.To1(f.startUse())
					response := try.To1(f.bobUse(saved.request, f.local.handle))
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
							_, err := f.bobUse(saved.request, f.local.handle)
							assert.Equal(err, ErrFirstUse)
						} else {
							_, err := f.receiveUse(response)
							assert.Equal(err, ErrFirstUse)
						}
					})
				})
			}
		}
	}
}

func TestFirstUseHistoryAuthenticatesSavedAdAndRequest(t *testing.T) {
	// Alter the historical signed ad, and even re-sign request and acceptance.
	// The ad's independently pinned Bob signature must still reject corruption.
	for _, bob := range []bool{false, true} {
		t.Run(fmt.Sprint(bob), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUse(t)
			saved := try.To1(f.startUse())
			v := f.alice.vault
			if bob {
				v = f.f.vault
			}
			var history acceptedRecord
			raw := requesterRecords(t, v)[1]
			try.To(wire.UnmarshalCanonical(&history, raw))
			var req SignedEstablishment
			try.To(wire.UnmarshalCanonical(&req, history.Request))
			req.Payload.Ad[len(req.Payload.Ad)-1] ^= 1
			history.Request = signEstablishment(t, req, f.peer.handle)
			p := acceptedPayload(req.Payload, history.Request)
			digest := key.HashTagged(AcceptedPurpose, try.To1(wire.Marshal(p)))
			history.Response = try.To1(
				wire.Marshal(
					SignedAccepted{
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
				_, err := f.bobUse(saved.request, f.local.handle)
				assert.Equal(err, ErrFirstUse)
			} else {
				_, err := f.startUse()
				assert.Equal(err, ErrFirstUse)
				_, err = f.expireUse(true)
				assert.Equal(err, ErrFirstUse)
			}
		})
	}
}
