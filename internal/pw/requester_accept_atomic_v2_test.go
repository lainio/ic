package pw

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func (f *requesterFixture) invalidateAliceV2(guard string) (err error) {
	defer err2.Handle(&err, nil)
	switch guard {
	case "deny":
		try.To1(policy.DenyLocal(f.alice.vault, f.root.public,
			f.peer.public, f.local.public))
	case "expiry":
		f.now = f.now.Add(2 * ads.TTL)
	case "received", "verified":
		return f.alice.vault.Update(func(tx storage.WriteTx) error {
			return tx.Delete([]byte(guard + "-ad-claims-v1"))
		})
	default:
		ns, subject := knownNS, []byte(f.peer.public)
		switch guard {
		case "known peer":
			subject = f.local.public
		case "device":
			ns, subject = authNS, []byte(authKey)
		}
		return f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			return try.To1(tx.ChildForUpdate([]byte(ns))).Delete(subject)
		})
	}
	return nil
}

func TestReceiveAcceptanceV2CurrentGuards(t *testing.T) {
	for _, phase := range []string{"before", "probe", "duplicate probe"} {
		for _, guard := range []string{"deny", "known self", "known peer",
			"device", "received", "verified", "expiry", "replaced ad"} {
			t.Run(phase+"/"+guard, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				response := f.responseV2(t)
				if phase == "duplicate probe" {
					assert.That(try.To1(f.receiveV2(response)))
				}
				before := requesterRecords(t, f.alice.vault)
				invalidate := func() error {
					if guard == "replaced ad" {
						replaceRequesterAd(t, f, establishmentEndpoint)
						return nil
					}
					return f.invalidateAliceV2(guard)
				}
				if phase == "before" {
					try.To(invalidate())
				} else {
					f.signer.sign = func(d []byte) ([]byte, error) {
						if err := invalidate(); err != nil {
							return nil, err
						}
						return f.peer.handle.Sign(d)
					}
				}
				calls := f.signer.signCalls.Load()
				f.f.unchanged(t, func() {
					held, err := f.receiveV2(response)
					assert.Equal(err, ErrEstablishment)
					assert.ThatNot(held)
				})
				assert.That(f.signer.signCalls.Load()-calls <= 1)
				assert.DeepEqual(requesterRecords(t, f.alice.vault), before)
			})
		}
	}
}

func TestReceiveAcceptanceV2PinnedIdentityAndSigner(t *testing.T) {
	for _, fault := range []string{"nil vault", "root", "local", "nil root",
		"nil signer", "typed nil", "wrong signer", "signature", "sign failure"} {
		t.Run(fault, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			response := f.responseV2(t)
			vault, root, local, signer := f.alice.vault, f.root.public,
				f.peer.public, key.Handle(f.signer)
			switch fault {
			case "nil vault":
				vault = nil
			case "root":
				root = f.local.public
			case "local":
				local = f.local.public
			case "nil root":
				root = nil
			case "nil signer":
				signer = nil
			case "typed nil":
				signer = (*probeSigner)(nil)
			case "wrong signer":
				signer = f.local.handle
			case "signature":
				f.signer.sign = func([]byte) ([]byte, error) { return []byte{1}, nil }
			case "sign failure":
				f.signer.signErr = errors.New("private signer diagnostic")
			}
			f.alice.unchanged(t, func() {
				held, err := receiveAcceptanceV2(vault, root, local, signer,
					response, func() time.Time { return f.now })
				assert.Equal(err, ErrEstablishment)
				assert.ThatNot(held)
			})
		})
	}
}

func TestReceiveAcceptanceV2AtomicRollback(t *testing.T) {
	for _, mode := range []string{"write 1", "write 2", "seal 1", "seal 2"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			response := f.responseV2(t)
			before := heldTestState(t, f.alice.vault)
			f.f.unchanged(t, func() {
				if mode == "seal 1" || mode == "seal 2" {
					allowance := int64(0)
					if mode == "seal 2" {
						allowance = 1
					}
					f.alice.lease.remaining.Store(allowance)
					held, err := f.receiveV2(response)
					assert.Equal(err, ErrEstablishment)
					assert.ThatNot(held)
				} else {
					boundary := 1
					if mode == "write 2" {
						boundary = 2
					}
					cause := errors.New("failure after Alice write")
					err := f.alice.vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						try.To1(commitRequesterAcceptanceV2(&failingAcceptanceTx{
							WriteTx: tx, failAfter: boundary, cause: cause},
							f.root.public, f.peer.public, response,
							func() time.Time { return f.now }))
						return nil
					})
					assert.ErrorIs(err, cause)
				}
			})
			assert.DeepEqual(heldTestState(t, f.alice.vault), before)
			f.alice.reopen(t)
			assert.DeepEqual(heldTestState(t, f.alice.vault), before)
			assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
				f.root.public, f.peer.public)), "")
			f.alice.lease.remaining.Store(10)
			assert.That(try.To1(f.receiveV2(response)))
		})
	}
}

func TestReceiveAcceptanceV2RevalidatesExactHistory(t *testing.T) {
	for _, mode := range []string{"attempt", "accepted", "held", "first use",
		"concurrent commit", "commit then delete", "input alias"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			response := f.responseV2(t)
			input := bytes.Clone(response)
			var injected [3][]byte
			f.signer.sign = func(d []byte) (_ []byte, err error) {
				defer err2.Handle(&err, nil)
				switch mode {
				case "concurrent commit", "commit then delete":
					try.To1(receiveAcceptanceV2(f.alice.vault, f.root.public,
						f.peer.public, f.peer.handle, response,
						func() time.Time { return f.now }))
					if mode == "commit then delete" {
						try.To1(DeleteHeldLocal(f.alice.vault, f.root.public,
							f.peer.public))
					}
				case "input alias":
					input[0] ^= 1
				default:
					name := map[string]string{"attempt": attemptKey,
						"accepted": acceptedKey, "held": heldKey,
						"first use": firstUseKey}[mode]
					raw := []byte{0xff}
					if mode == "attempt" {
						p := try.To1(decodeEstablishmentV2(
							requesterRecords(t, f.alice.vault)[0],
							f.root.public, f.local.public)).Payload
						// Same binding, different exact signature/digest.
						raw = signEstablishmentV2(t, p, f.peer.handle,
							EstablishPurposeV2)
					}
					try.To(f.alice.vault.Update(func(tx storage.WriteTx) error {
						return tx.Put([]byte(name), raw)
					}))
				}
				injected = requesterRecords(t, f.alice.vault)
				return f.peer.handle.Sign(d)
			}
			held, err := f.receiveV2(input)
			switch mode {
			case "concurrent commit", "input alias":
				assert.NoError(err)
				assert.That(held)
			case "commit then delete":
				assert.NoError(err)
				assert.ThatNot(held)
			default:
				assert.Equal(err, ErrEstablishment)
				assert.ThatNot(held)
			}
			if mode != "input alias" {
				assert.DeepEqual(requesterRecords(t, f.alice.vault), injected)
			}
		})
	}
}

func TestReceiveAcceptanceV2OwnerSerialization(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	response := f.responseV2(t)
	var owner sync.Mutex
	results := make(chan error, 2)
	for range 2 {
		go func() {
			owner.Lock()
			defer owner.Unlock()
			_, err := f.receiveV2(response)
			results <- err
		}()
	}
	for range 2 {
		assert.NoError(<-results)
	}
	assert.That(try.To1(f.receiveV2(response)))
	assert.Equal(try.To1(RequesterContactV2(f.alice.vault,
		f.root.public, f.peer.public)), "http://127.0.0.1:12345")
}

func TestReceiveAcceptanceV2DuplicateCannotRestoreDelete(t *testing.T) {
	for _, reopened := range []bool{false, true} {
		t.Run(fmt.Sprint(reopened), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, true)
			response := f.responseV2(t)
			assert.That(try.To1(f.receiveV2(response)))
			assert.That(try.To1(DeleteHeldLocal(f.alice.vault,
				f.root.public, f.peer.public)))
			if reopened {
				f.alice.reopen(t)
			}
			f.alice.lease.remaining.Store(0)
			f.alice.unchanged(t, func() {
				assert.ThatNot(try.To1(f.receiveV2(response)))
				saved := try.To1(f.saveV2(aliceServiceOrigin))
				assert.That(saved.Accepted && !saved.Held)
				_, err := f.saveV2("http://127.0.0.1:4041")
				assert.Equal(err, ErrEstablishment)
			})
		})
	}
}
