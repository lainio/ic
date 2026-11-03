package pw

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func newFirstUse(t *testing.T) *requesterFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := newRequester(t, true)
	assert.That(try.To1(f.receive(f.response(t))))
	return f
}

func (f *requesterFixture) useClock() time.Time { return f.now }
func (f *requesterFixture) startUse() (SavedFirstUse, error) {
	return saveFirstUse(f.alice.vault, f.root.public, f.peer.public,
		f.signer, f.useClock)
}

func (f *requesterFixture) bobUse(
	raw []byte,
	signer key.Handle,
) ([]byte, error) {
	return bobFirstUse(f.f.vault, f.root.public, f.local.public,
		signer, raw, f.useClock)
}
func (f *requesterFixture) receiveUse(raw []byte) (bool, error) {
	return receiveFirstUse(f.alice.vault, f.root.public, f.peer.public,
		f.signer, raw, f.useClock)
}
func (f *requesterFixture) expireUse(cancel bool) (bool, error) {
	return expireFirstUse(f.alice.vault, f.root.public, f.peer.public,
		cancel, f.useClock)
}

func useRecords(t *testing.T, v *storage.Vault) (result [2][]byte) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for i, name := range []string{firstUseKey, useSeenKey} {
			result[i], _ = try.To2(tx.Get([]byte(name)))
		}
		return nil
	}))
	return result
}

func useRecord(t *testing.T, f *requesterFixture) firstUseRecord {
	t.Helper()
	defer assert.PushTester(t)()
	var record firstUseRecord
	try.To(wire.UnmarshalCanonical(&record, useRecords(t, f.alice.vault)[0]))
	return record
}

func TestFirstUseOrderedLocalObservations(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUse(t)
	alice, bob := requesterRecords(
		t,
		f.alice.vault,
	), requesterRecords(
		t,
		f.f.vault,
	)
	assert.DeepEqual(useRecords(t, f.alice.vault), [2][]byte{})
	assert.DeepEqual(useRecords(t, f.f.vault), [2][]byte{})
	saved := try.To1(f.startUse())
	record := useRecord(t, f)
	assert.Equal(record.State, useAwait)
	assert.DeepEqual(record.Request, saved.request)
	assert.SNil(record.Response)
	assert.DeepEqual(useRecords(t, f.f.vault), [2][]byte{})
	response := try.To1(f.bobUse(saved.request, f.local.handle))
	assert.Equal(useRecord(t, f).State, useAwait)
	var receipt firstUseReceipt
	try.To(wire.UnmarshalCanonical(&receipt, useRecords(t, f.f.vault)[1]))
	assert.DeepEqual(receipt.Request, saved.request)
	assert.DeepEqual(receipt.Response, response)
	assert.That(try.To1(f.receiveUse(response)))
	assert.Equal(useRecord(t, f).State, useReady)
	assert.DeepEqual(useRecord(t, f).Response, response)
	assert.DeepEqual(requesterRecords(t, f.alice.vault), alice)
	assert.DeepEqual(requesterRecords(t, f.f.vault), bob)
	f.alice.unchanged(t, func() {
		assert.That(try.To1(f.receiveUse(response)))
		_, err := f.startUse()
		assert.Equal(err, ErrFirstUse)
	})
	f.f.unchanged(t, func() {
		result, err := f.bobUse(saved.request, f.local.handle)
		assert.Equal(err, ErrFirstUse)
		assert.SNil(result)
	})
}

func TestFirstUseRandomSessionAndRetainedBinding(t *testing.T) {
	defer assert.PushTester(t)()
	var sessions [][]byte
	for range 2 {
		f := newFirstUse(t)
		// Neither an expired publication nor consumed invitation requires renewal.
		f.now = f.now.Add(2 * ads.TTL)
		saved := try.To1(f.startUse())
		var request SignedFirstUse
		try.To(wire.UnmarshalCanonical(&request, saved.request))
		p := request.Payload
		assert.Equal(p.ExpiresUnixNano-p.IssuedUnixNano, int64(60*time.Second))
		assert.Equal(p.IssuedUnixNano, f.now.UnixNano())
		assert.Equal(len(p.SessionID), 32)
		assert.That(p.HeldEvidence)
		sessions = append(sessions, p.SessionID)
		response := try.To1(f.bobUse(saved.request, f.local.handle))
		assert.That(try.To1(f.receiveUse(response)))
	}
	assert.ThatNot(bytes.Equal(sessions[0], sessions[1]))
}

func TestFirstUseRequiresBothIndependentHoldings(t *testing.T) {
	for _, who := range []string{"Alice not accepted", "Alice deleted", "Bob deleted"} {
		t.Run(who, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, true)
			response := f.response(t)
			if who == "Alice not accepted" {
				f.alice.unchanged(t, func() {
					_, err := f.startUse()
					assert.Equal(err, ErrFirstUse)
				})
				return
			}
			try.To1(f.receive(response))
			if who == "Alice deleted" {
				try.To(f.alice.vault.Update(func(tx storage.WriteTx) error {
					return tx.Delete([]byte(heldKey))
				}))
				f.alice.unchanged(t, func() {
					_, err := f.startUse()
					assert.Equal(err, ErrFirstUse)
				})
				return
			}
			saved := try.To1(f.startUse())
			try.To(f.f.vault.Update(func(tx storage.WriteTx) error {
				return tx.Delete([]byte(heldKey))
			}))
			f.f.unchanged(t, func() {
				_, err := f.bobUse(saved.request, f.local.handle)
				assert.Equal(err, ErrFirstUse)
			})
			assert.Equal(useRecord(t, f).State, useAwait)
		})
	}
}

func signUse(t *testing.T, p FirstUse, signer key.Handle) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(FirstUsePurpose, try.To1(wire.Marshal(p)))
	return try.To1(wire.Marshal(SignedFirstUse{Payload: p,
		Signature: try.To1(signer.Sign(digest[:]))}))
}

func signUseResponse(
	t *testing.T,
	p FirstUseResponse,
	signer key.Handle,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(FirstUseResponsePurpose, try.To1(wire.Marshal(p)))
	return try.To1(wire.Marshal(SignedFirstUseResponse{Payload: p,
		Signature: try.To1(signer.Sign(digest[:]))}))
}

func TestFirstUseExactAuthenticatedBinding(t *testing.T) {
	changes := map[string]func(*FirstUse){
		"version":               func(p *FirstUse) { p.Version++ },
		"root":                  func(p *FirstUse) { p.Established.Binding.Root = p.Established.Binding.Target },
		"target":                func(p *FirstUse) { p.Established.Binding.Target = p.Established.Binding.Root },
		"requester":             func(p *FirstUse) { p.Established.Binding.Requester = p.Established.Binding.Root },
		"invitation":            func(p *FirstUse) { p.Established.Binding.InvitationID[0] ^= 1 },
		"attempt":               func(p *FirstUse) { p.Established.Binding.AttemptID[0] ^= 1 },
		"device":                func(p *FirstUse) { p.Established.Binding.Device = p.Established.Binding.Root },
		"epoch":                 func(p *FirstUse) { p.Established.Binding.Epoch++ },
		"audience":              func(p *FirstUse) { p.Established.Binding.Audience = InvitationAny },
		"recipient":             func(p *FirstUse) { p.Established.Binding.Recipient = nil },
		"ad":                    func(p *FirstUse) { p.Established.Binding.Ad[0] ^= 1 },
		"establishment digest":  func(p *FirstUse) { p.Established.RequestDigest[0] ^= 1 },
		"establishment version": func(p *FirstUse) { p.Established.Version++ },
		"short session":         func(p *FirstUse) { p.SessionID = p.SessionID[:31] },
		"held assertion":        func(p *FirstUse) { p.HeldEvidence = false },
		"expiry":                func(p *FirstUse) { p.ExpiresUnixNano++ },
		"future":                func(p *FirstUse) { p.IssuedUnixNano++; p.ExpiresUnixNano++ },
		"negative time":         func(p *FirstUse) { p.IssuedUnixNano = -1; p.ExpiresUnixNano = int64(FirstUseLifetime) - 1 },
	}
	f := newFirstUse(t)
	defer assert.PushTester(t)()
	saved := try.To1(f.startUse())
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			var req SignedFirstUse
			try.To(wire.UnmarshalCanonical(&req, saved.request))
			change(&req.Payload)
			raw := signUse(t, req.Payload, f.peer.handle)
			f.f.unchanged(t, func() {
				result, err := f.bobUse(raw, f.local.handle)
				assert.Equal(err, ErrFirstUse)
				assert.SNil(result)
			})
		})
	}
	invalid := [][]byte{nil, {0xff}, saved.request[:len(saved.request)-1],
		append(
			bytes.Clone(saved.request),
			0,
		), append([]byte{0x98, 2}, saved.request[1:]...),
		append(
			[]byte{0xc0},
			saved.request...), make([]byte, MaxEstablishmentBytes+1)}
	var req SignedFirstUse
	try.To(wire.UnmarshalCanonical(&req, saved.request))
	invalid = append(invalid, signUse(t, req.Payload, f.local.handle))
	digest := key.HashTagged(
		EstablishPurpose,
		try.To1(wire.Marshal(req.Payload)),
	)
	req.Signature = try.To1(f.peer.handle.Sign(digest[:]))
	invalid = append(invalid, try.To1(wire.Marshal(req)))
	for i, raw := range invalid {
		t.Run(fmt.Sprint("encoding", i), func(t *testing.T) {
			defer assert.PushTester(t)()
			f.f.unchanged(t, func() {
				_, err := f.bobUse(raw, f.local.handle)
				assert.Equal(err, ErrFirstUse)
			})
		})
	}
	assert.Equal(useRecord(t, f).State, useAwait)
}

func TestFirstUseResponseAndSessionMustMatch(t *testing.T) {
	f := newFirstUse(t)
	defer assert.PushTester(t)()
	saved := try.To1(f.startUse())
	response := try.To1(f.bobUse(saved.request, f.local.handle))
	for _, field := range []string{"signature", "session", "digest", "request", "version", "purpose"} {
		t.Run(field, func(t *testing.T) {
			defer assert.PushTester(t)()
			var r SignedFirstUseResponse
			try.To(wire.UnmarshalCanonical(&r, response))
			switch field {
			case "signature":
				r.Signature = []byte{1}
			case "session":
				r.Payload.Request.SessionID[0] ^= 1
			case "digest":
				r.Payload.RequestDigest[0] ^= 1
			case "request":
				r.Payload.Request.ExpiresUnixNano++
			case "version":
				r.Payload.Version++
			case "purpose":
				digest := key.HashTagged(
					AcceptedPurpose,
					try.To1(wire.Marshal(r.Payload)),
				)
				r.Signature = try.To1(f.local.handle.Sign(digest[:]))
			}
			raw := try.To1(wire.Marshal(r))
			if field != "signature" && field != "purpose" {
				raw = signUseResponse(t, r.Payload, f.local.handle)
			}
			f.alice.unchanged(t, func() {
				ready, err := f.receiveUse(raw)
				assert.Equal(err, ErrFirstUse)
				assert.ThatNot(ready)
			})
			assert.Equal(useRecord(t, f).State, useAwait)
		})
	}
	assert.That(try.To1(f.receiveUse(response)))
	var r SignedFirstUseResponse
	try.To(wire.UnmarshalCanonical(&r, response))
	// Another valid signature is conflicting evidence, not an exact duplicate.
	other := signUseResponse(t, r.Payload, f.local.handle)
	assert.ThatNot(bytes.Equal(response, other))
	f.alice.unchanged(
		t,
		func() { _, err := f.receiveUse(other); assert.Equal(err, ErrFirstUse) },
	)
}

func TestFirstUseExpiryAndCancellation(t *testing.T) {
	for _, ready := range []bool{false, true} {
		for _, cancel := range []bool{false, true} {
			t.Run(fmt.Sprint(ready, cancel), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUse(t)
				saved := try.To1(f.startUse())
				response := try.To1(f.bobUse(saved.request, f.local.handle))
				if ready {
					assert.That(try.To1(f.receiveUse(response)))
				}
				f.alice.unchanged(
					t,
					func() { assert.ThatNot(try.To1(f.expireUse(false))) },
				)
				if !cancel {
					f.now = f.now.Add(FirstUseLifetime)
				}
				assert.That(try.To1(f.expireUse(cancel)))
				record := useRecord(t, f)
				assert.Equal(record.State, useExpired)
				f.now = f.now.Add(
					-FirstUseLifetime,
				) // Explicit expiry is durable even on rollback.
				f.alice.unchanged(t, func() {
					_, err := f.receiveUse(response)
					assert.Equal(err, ErrFirstUse)
					_, err = f.startUse()
					assert.Equal(err, ErrFirstUse)
					assert.ThatNot(try.To1(f.expireUse(true)))
				})
				f.alice.reopen(t)
				assert.DeepEqual(useRecord(t, f), record)
			})
		}
	}
	for _, offset := range []time.Duration{-time.Nanosecond, FirstUseLifetime, FirstUseLifetime + time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUse(t)
			saved := try.To1(f.startUse())
			f.now = f.now.Add(offset)
			f.f.unchanged(
				t,
				func() { _, err := f.bobUse(saved.request, f.local.handle); assert.Equal(err, ErrFirstUse) },
			)
			assert.SNil(useRecords(t, f.f.vault)[1])
		})
	}
}

func TestFirstUseAlreadySentResponseDoesNotKnowBobPolicy(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUse(t)
	saved := try.To1(f.startUse())
	response := try.To1(f.bobUse(saved.request, f.local.handle))
	try.To1(
		policy.DenyLocal(
			f.f.vault,
			f.root.public,
			f.local.public,
			f.peer.public,
		),
	)
	f.f.unchanged(t, func() { assert.That(try.To1(f.receiveUse(response))) })
	assert.That(
		try.To1(
			policy.IsDenied(
				f.f.vault,
				f.root.public,
				f.local.public,
				f.peer.public,
			),
		),
	)
	assert.Equal(
		useRecord(t, f).State,
		useReady,
	) // Historical LOCAL observation only.
}

func TestFirstUseReceiveStrictDeadlineAndCanonicalBytes(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUse(t)
	saved := try.To1(f.startUse())
	response := try.To1(f.bobUse(saved.request, f.local.handle))
	for _, raw := range [][]byte{nil, {0xff}, response[:len(response)-1],
		append(bytes.Clone(response), 0), append([]byte{0x98, 2}, response[1:]...),
		append([]byte{0xc0}, response...), make([]byte, MaxEstablishmentBytes+1)} {
		f.alice.unchanged(
			t,
			func() { _, err := f.receiveUse(raw); assert.Equal(err, ErrFirstUse) },
		)
	}
	f.now = f.now.Add(FirstUseLifetime)
	f.alice.unchanged(
		t,
		func() { _, err := f.receiveUse(response); assert.Equal(err, ErrFirstUse) },
	)
	assert.Equal(useRecord(t, f).State, useAwait)
}

func TestFirstUseReceiptRefusesDifferentAuthenticatedSession(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUse(t)
	saved := try.To1(f.startUse())
	try.To1(f.bobUse(saved.request, f.local.handle))
	var request SignedFirstUse
	try.To(wire.UnmarshalCanonical(&request, saved.request))
	request.Payload.SessionID[0] ^= 1
	other := signUse(t, request.Payload, f.peer.handle)
	f.f.unchanged(t, func() {
		_, err := f.bobUse(other, f.local.handle)
		assert.Equal(err, ErrFirstUse)
	})
}
