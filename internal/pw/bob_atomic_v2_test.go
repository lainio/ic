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
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Fixture mutations exercise durable writers between preflight/probe/sign and
// commit or reply. They deliberately bypass the production owner lock.
func (f *requesterFixture) invalidateBobV2(guard string) (err error) {
	defer err2.Handle(&err, nil)
	switch guard {
	case "deny":
		try.To1(policy.DenyLocal(f.f.vault, f.root.public,
			f.local.public, f.peer.public))
	case "ad", "origin":
		endpoint := establishmentEndpoint
		if guard == "origin" {
			endpoint = "http://127.0.0.1:12346/peer/introduction"
		}
		try.To1(ads.PublishLocal(f.f.vault, f.root.public, f.local.public,
			f.local.handle, endpoint, f.now))
	case "expiry":
		f.now = time.Unix(0, f.invitation.ExpiresUnixNano)
	case "revoke":
		try.To1(RevokeInvitation(f.f.vault, f.root.public, f.local.public,
			f.invitation.ID))
		f.invitation.State = InvitationRevoked
	default:
		return f.f.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			if guard == "held" {
				// Test-only deletion: production DeleteHeldLocal is v1-only.
				return tx.Delete([]byte(heldKey))
			}
			ns, subject := knownNS, []byte(f.local.public)
			switch guard {
			case "known peer":
				subject = f.peer.public
			case "device":
				ns, subject = authNS, []byte(authKey)
			}
			return try.To1(tx.ChildForUpdate([]byte(ns))).Delete(subject)
		})
	}
	return nil
}

func TestBobAcceptV2FinalGuards(t *testing.T) {
	for _, phase := range []string{"before", "probe", "sign"} {
		for _, guard := range []string{"deny", "known self", "known peer",
			"device", "ad", "origin", "expiry", "revoke"} {
			t.Run(phase+"/"+guard, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				saved := try.To1(f.saveV2(aliceServiceOrigin))
				signer := &probeSigner{Handle: f.local.handle}
				if phase == "before" {
					try.To(f.invalidateBobV2(guard))
				} else {
					at := int64(1)
					if phase == "sign" {
						at = 2
					}
					signer.sign = func(d []byte) ([]byte, error) {
						if signer.signCalls.Load() == at {
							if err := f.invalidateBobV2(guard); err != nil {
								return nil, err
							}
						}
						return f.local.handle.Sign(d)
					}
				}
				f.alice.unchanged(t, func() {
					assert.Equal(f.acceptV2(saved.request, signer), ErrEstablishment)
				})
				f.unconsumed(t)
				if phase == "before" {
					assert.Equal(signer.signCalls.Load(), 0)
				}
				response, err := f.replyV2(saved.request, f.local.handle)
				assert.Equal(err, ErrEstablishment)
				assert.SNil(response)
			})
		}
	}
}

func TestBobAcceptV2ExpiryBoundary(t *testing.T) {
	for _, offset := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, false)
			saved := try.To1(f.saveV2(aliceServiceOrigin))
			f.now = time.Unix(0, f.invitation.ExpiresUnixNano).Add(offset)
			err := f.acceptV2(saved.request, f.local.handle)
			if offset < 0 {
				assert.NoError(err)
				try.To1(f.replyV2(saved.request, f.local.handle))
			} else {
				assert.Equal(err, ErrEstablishment)
				f.unconsumed(t)
			}
		})
	}
}

func TestBobAcceptV2FailureAtomicity(t *testing.T) {
	for _, kind := range []string{"callback", "encryption"} {
		for index := range 3 {
			t.Run(fmt.Sprint(kind, index), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				saved := try.To1(f.saveV2(aliceServiceOrigin))
				f.alice.unchanged(t, func() {
					if kind == "encryption" {
						f.f.lease.remaining.Store(int64(index))
						assert.Equal(f.acceptV2(saved.request, f.local.handle),
							ErrEstablishment)
						assert.Equal(f.f.lease.remaining.Load(), 0)
						return
					}
					p := try.To1(decodeEstablishmentV2(saved.request,
						f.root.public, f.local.public)).Payload
					payload := acceptedPayloadV2(p, saved.request)
					digest := key.HashTagged(AcceptedPurposeV2,
						try.To1(wire.Marshal(payload)))
					response := try.To1(wire.Marshal(SignedAcceptedV2{
						Payload:   payload,
						Signature: try.To1(f.local.handle.Sign(digest[:])),
					}))
					cause := errors.New("failure after encrypted acceptance write")
					err := f.f.vault.Update(func(tx storage.WriteTx) (err error) {
						defer err2.Handle(&err, nil)
						return commitAcceptanceV2(&failingAcceptanceTx{
							WriteTx: tx, failAfter: index + 1, cause: cause},
							f.root.public, f.local.public, establishmentEndpoint,
							saved.request, response, func() time.Time { return f.now })
					})
					assert.ErrorIs(err, cause)
				})
				f.unconsumed(t)
				f.f.reopen(t)
				f.unconsumed(t)
				f.f.unchanged(t, func() {
					response, err := f.replyV2(saved.request, f.local.handle)
					assert.Equal(err, ErrEstablishment)
					assert.SNil(response)
				})
				// A failed attempt retains no contact or consumption; retry can
				// commit all three writes after the fault has been removed.
				f.f.lease.remaining.Store(3)
				try.To(f.acceptV2(saved.request, f.local.handle))
				assert.Equal(f.f.lease.remaining.Load(), 0)
				f.f.reopen(t)
				try.To1(f.replyV2(saved.request, f.local.handle))
			})
		}
	}
}

func TestBobAcceptV2Competition(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	alice := try.To1(f.saveV2(aliceServiceOrigin))
	carol := newSigner(t)
	base := intro.New(key.Info{Public: f.root.public})
	savePath(t, f.f.vault, f.root.public,
		base.Introduce(f.root.handle, key.Info{Public: carol.public}), carol)
	try.To1(onboarding.VerifyReceived(f.f.vault, f.root.public))
	c := *f
	c.alice, c.peer, c.signer = newVault(t), carol, &probeSigner{Handle: carol.handle}
	for _, who := range []savedSigner{c.local, carol} {
		savePath(t, c.alice.vault, c.root.public,
			base.Introduce(c.root.handle, key.Info{Public: who.public}), who)
	}
	try.To1(onboarding.VerifyReceived(c.alice.vault, c.root.public))
	try.To1(device.BootstrapLocal(c.alice.vault, c.root.public,
		carol.public, carol.handle))
	try.To1(ads.ReceiveClaim(c.alice.vault, c.root.public,
		c.local.public, c.request.Payload.Ad))
	var verified []byte
	try.To(f.alice.vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		verified, _ = try.To2(tx.Get([]byte("verified-ad-claims-v1")))
		return nil
	}))
	try.To(c.alice.vault.Update(func(tx storage.WriteTx) error {
		return tx.Put([]byte("verified-ad-claims-v1"), verified)
	}))
	carolAttempt := try.To1(c.saveV2("http://127.0.0.1:4042"))
	start := make(chan struct{})
	results := make(chan error, 2)
	var service sync.Mutex
	for _, raw := range [][]byte{alice.request, carolAttempt.request} {
		go func() {
			<-start
			service.Lock()
			defer service.Unlock()
			results <- f.acceptV2(raw, f.local.handle)
		}()
	}
	close(start)
	first, second := <-results, <-results
	assert.That((first == nil && second == ErrEstablishment) ||
		(first == ErrEstablishment && second == nil))
	row, raw, held := f.records(t)
	assert.Equal(row.State, InvitationConsumed)
	assert.SNotEmpty(held)
	var history acceptedRecord
	try.To(wire.UnmarshalCanonical(&history, raw))
	assert.That(bytes.Equal(history.Request, alice.request) ||
		bytes.Equal(history.Request, carolAttempt.request))
	for _, request := range [][]byte{alice.request, carolAttempt.request} {
		response, err := f.replyV2(request, f.local.handle)
		if bytes.Equal(request, history.Request) {
			assert.NoError(err)
			assert.DeepEqual(response, history.Response)
		} else {
			assert.Equal(err, ErrEstablishment)
			assert.SNil(response)
		}
	}
	assert.DeepEqual(requesterRecords(t, f.alice.vault),
		[3][]byte{alice.request, nil, nil})
	assert.DeepEqual(requesterRecords(t, c.alice.vault),
		[3][]byte{carolAttempt.request, nil, nil})
}

func TestBobAcceptV2RevokeRace(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	start := make(chan struct{})
	accepted := make(chan error, 1)
	type revokeResult struct {
		changed bool
		err     error
	}
	revoked := make(chan revokeResult, 1)
	go func() {
		<-start
		accepted <- f.acceptV2(saved.request, f.local.handle)
	}()
	go func() {
		<-start
		changed, err := RevokeInvitation(f.f.vault, f.root.public,
			f.local.public, f.invitation.ID)
		revoked <- revokeResult{changed, err}
	}()
	close(start)
	a, r := <-accepted, <-revoked
	assert.NoError(r.err)
	assert.That((a == nil && !r.changed) ||
		(a == ErrEstablishment && r.changed))
	if r.changed {
		f.invitation.State = InvitationRevoked
		f.unconsumed(t)
		response, err := f.replyV2(saved.request, f.local.handle)
		assert.Equal(err, ErrEstablishment)
		assert.SNil(response)
	} else {
		try.To1(f.replyV2(saved.request, f.local.handle))
	}
}

func TestBobAcceptV2RevokeAfterCommit(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, false)
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	try.To(f.acceptV2(saved.request, f.local.handle))
	response := try.To1(f.replyV2(saved.request, f.local.handle))
	f.f.unchanged(t, func() {
		assert.ThatNot(try.To1(RevokeInvitation(f.f.vault, f.root.public,
			f.local.public, f.invitation.ID)))
		assert.DeepEqual(try.To1(f.replyV2(saved.request, f.local.handle)), response)
	})
}
