package pw

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

type firstUseFixtureV2 struct {
	*requesterFixture
	aliceRuntime, bobRuntime ContactRuntimeV2
}

func newFirstUseV2(t *testing.T) *firstUseFixtureV2 {
	t.Helper()
	defer assert.PushTester(t)()
	f := newRequester(t, true)
	assert.That(try.To1(f.receiveV2(f.responseV2(t))))
	return &firstUseFixtureV2{f,
		ContactRuntimeV2{true, aliceServiceOrigin},
		ContactRuntimeV2{true, "http://127.0.0.1:12345"}}
}

func (f *firstUseFixtureV2) startUseV2() (SavedFirstUseV2, error) {
	return saveFirstUseV2(f.alice.vault, f.root.public, f.peer.public,
		f.signer, f.aliceRuntime, f.useClock)
}

func (f *firstUseFixtureV2) bobUseV2(
	raw []byte,
	signer key.Handle,
) ([]byte, error) {
	return bobFirstUseV2(f.f.vault, f.root.public, f.local.public,
		signer, f.bobRuntime, raw, f.useClock)
}
func (f *firstUseFixtureV2) receiveUseV2(raw []byte) (bool, error) {
	return receiveFirstUseV2(f.alice.vault, f.root.public, f.peer.public,
		f.signer, f.aliceRuntime, raw, f.useClock)
}
func (f *firstUseFixtureV2) expireUseV2(cancel bool) (bool, error) {
	return expireFirstUseV2(f.alice.vault, f.root.public, f.peer.public,
		cancel, f.useClock)
}
func useRecordV2(t *testing.T, f *firstUseFixtureV2) firstUseRecord {
	t.Helper()
	return useRecord(t, f.requesterFixture)
}

func TestFirstUseOrderedLocalObservationsV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	alice, bob := requesterRecords(
		t,
		f.alice.vault,
	), requesterRecords(
		t,
		f.f.vault,
	)
	assert.DeepEqual(useRecords(t, f.alice.vault), [2][]byte{})
	assert.DeepEqual(useRecords(t, f.f.vault), [2][]byte{})
	saved := try.To1(f.startUseV2())
	record := useRecordV2(t, f)
	assert.Equal(record.State, useAwait)
	assert.DeepEqual(record.Request, saved.request)
	assert.SNil(record.Response)
	assert.DeepEqual(useRecords(t, f.f.vault), [2][]byte{})
	response := try.To1(f.bobUseV2(saved.request, f.local.handle))
	assert.Equal(useRecordV2(t, f).State, useAwait)
	var receipt firstUseReceipt
	try.To(wire.UnmarshalCanonical(&receipt, useRecords(t, f.f.vault)[1]))
	assert.DeepEqual(receipt.Request, saved.request)
	assert.DeepEqual(receipt.Response, response)
	assert.That(try.To1(f.receiveUseV2(response)))
	assert.Equal(useRecordV2(t, f).State, useReady)
	assert.DeepEqual(useRecordV2(t, f).Response, response)
	assert.DeepEqual(requesterRecords(t, f.alice.vault), alice)
	assert.DeepEqual(requesterRecords(t, f.f.vault), bob)
	f.alice.unchanged(t, func() {
		assert.That(try.To1(f.receiveUseV2(response)))
		_, err := f.startUseV2()
		assert.Equal(err, ErrFirstUse)
	})
	f.f.unchanged(t, func() {
		result, err := f.bobUseV2(saved.request, f.local.handle)
		assert.Equal(err, ErrFirstUse)
		assert.SNil(result)
	})
}

func TestFirstUseRandomSessionAndRetainedBindingV2(t *testing.T) {
	defer assert.PushTester(t)()
	var sessions [][]byte
	for range 2 {
		f := newFirstUseV2(t)
		// Neither an expired publication nor consumed invitation requires renewal.
		f.now = f.now.Add(2 * ads.TTL)
		saved := try.To1(f.startUseV2())
		var request SignedFirstUseV2
		try.To(wire.UnmarshalCanonical(&request, saved.request))
		p := request.Payload
		assert.Equal(p.ExpiresUnixNano-p.IssuedUnixNano, int64(60*time.Second))
		assert.Equal(p.IssuedUnixNano, f.now.UnixNano())
		assert.Equal(len(p.SessionID), 32)
		assert.That(p.HeldEvidence)
		sessions = append(sessions, p.SessionID)
		response := try.To1(f.bobUseV2(saved.request, f.local.handle))
		assert.That(try.To1(f.receiveUseV2(response)))
	}
	assert.ThatNot(bytes.Equal(sessions[0], sessions[1]))
}

func TestFirstUseRequiresBothIndependentHoldingsV2(t *testing.T) {
	for _, who := range []string{"Alice not accepted", "Alice deleted", "Bob deleted"} {
		t.Run(who, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := &firstUseFixtureV2{newRequester(t, true),
				ContactRuntimeV2{true, aliceServiceOrigin},
				ContactRuntimeV2{true, "http://127.0.0.1:12345"}}
			response := f.responseV2(t)
			if who == "Alice not accepted" {
				f.alice.unchanged(t, func() {
					_, err := f.startUseV2()
					assert.Equal(err, ErrFirstUse)
				})
				return
			}
			try.To1(f.receiveV2(response))
			if who == "Alice deleted" {
				try.To(f.alice.vault.Update(func(tx storage.WriteTx) error {
					return tx.Delete([]byte(heldKey))
				}))
				f.alice.unchanged(t, func() {
					_, err := f.startUseV2()
					assert.Equal(err, ErrFirstUse)
				})
				return
			}
			saved := try.To1(f.startUseV2())
			try.To(f.f.vault.Update(func(tx storage.WriteTx) error {
				return tx.Delete([]byte(heldKey))
			}))
			f.f.unchanged(t, func() {
				_, err := f.bobUseV2(saved.request, f.local.handle)
				assert.Equal(err, ErrFirstUse)
			})
			assert.Equal(useRecordV2(t, f).State, useAwait)
		})
	}
}

func signUseV2(t *testing.T, p FirstUseV2, signer key.Handle) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(FirstUsePurposeV2, try.To1(wire.Marshal(p)))
	return try.To1(wire.Marshal(SignedFirstUseV2{Payload: p,
		Signature: try.To1(signer.Sign(digest[:]))}))
}

func signUseResponseV2(
	t *testing.T,
	p FirstUseResponseV2,
	signer key.Handle,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(
		FirstUseResponsePurposeV2,
		try.To1(wire.Marshal(p)),
	)
	return try.To1(wire.Marshal(SignedFirstUseResponseV2{Payload: p,
		Signature: try.To1(signer.Sign(digest[:]))}))
}

func TestFirstUseExactAuthenticatedBindingV2(t *testing.T) {
	changes := map[string]func(*FirstUseV2){
		"version":               func(p *FirstUseV2) { p.Version++ },
		"root":                  func(p *FirstUseV2) { p.Established.Binding.Root = p.Established.Binding.Target },
		"target":                func(p *FirstUseV2) { p.Established.Binding.Target = p.Established.Binding.Root },
		"requester":             func(p *FirstUseV2) { p.Established.Binding.Requester = p.Established.Binding.Root },
		"invitation":            func(p *FirstUseV2) { p.Established.Binding.InvitationID[0] ^= 1 },
		"attempt":               func(p *FirstUseV2) { p.Established.Binding.AttemptID[0] ^= 1 },
		"device":                func(p *FirstUseV2) { p.Established.Binding.Device = p.Established.Binding.Root },
		"epoch":                 func(p *FirstUseV2) { p.Established.Binding.Epoch++ },
		"audience":              func(p *FirstUseV2) { p.Established.Binding.Audience = InvitationAny },
		"recipient":             func(p *FirstUseV2) { p.Established.Binding.Recipient = nil },
		"ad":                    func(p *FirstUseV2) { p.Established.Binding.Ad[0] ^= 1 },
		"establishment digest":  func(p *FirstUseV2) { p.Established.RequestDigest[0] ^= 1 },
		"establishment version": func(p *FirstUseV2) { p.Established.Version++ },
		"short session":         func(p *FirstUseV2) { p.SessionID = p.SessionID[:31] },
		"held assertion":        func(p *FirstUseV2) { p.HeldEvidence = false },
		"expiry":                func(p *FirstUseV2) { p.ExpiresUnixNano++ },
		"future":                func(p *FirstUseV2) { p.IssuedUnixNano++; p.ExpiresUnixNano++ },
		"negative time":         func(p *FirstUseV2) { p.IssuedUnixNano = -1; p.ExpiresUnixNano = int64(FirstUseLifetime) - 1 },
		"binding version":       func(p *FirstUseV2) { p.Established.Binding.Version = 1 },
		"requester contact": func(p *FirstUseV2) {
			p.Established.Binding.RequesterContact = "http://127.0.0.1:4041"
		},
		"target contact": func(p *FirstUseV2) {
			p.Established.Binding.TargetContact = "http://127.0.0.1:12346"
		},
		"swapped contacts": func(p *FirstUseV2) {
			b := &p.Established.Binding
			b.RequesterContact, b.TargetContact = b.TargetContact, b.RequesterContact
		},
	}
	f := newFirstUseV2(t)
	defer assert.PushTester(t)()
	saved := try.To1(f.startUseV2())
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			var req SignedFirstUseV2
			try.To(wire.UnmarshalCanonical(&req, saved.request))
			change(&req.Payload)
			raw := signUseV2(t, req.Payload, f.peer.handle)
			f.f.unchanged(t, func() {
				result, err := f.bobUseV2(raw, f.local.handle)
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
	var req SignedFirstUseV2
	try.To(wire.UnmarshalCanonical(&req, saved.request))
	invalid = append(invalid, signUseV2(t, req.Payload, f.local.handle))
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
				_, err := f.bobUseV2(raw, f.local.handle)
				assert.Equal(err, ErrFirstUse)
			})
		})
	}
	assert.Equal(useRecordV2(t, f).State, useAwait)
}

func TestFirstUseResponseAndSessionMustMatchV2(t *testing.T) {
	f := newFirstUseV2(t)
	defer assert.PushTester(t)()
	saved := try.To1(f.startUseV2())
	response := try.To1(f.bobUseV2(saved.request, f.local.handle))
	for _, field := range []string{"signature", "session", "digest", "request", "version", "purpose"} {
		t.Run(field, func(t *testing.T) {
			defer assert.PushTester(t)()
			var r SignedFirstUseResponseV2
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
				raw = signUseResponseV2(t, r.Payload, f.local.handle)
			}
			f.alice.unchanged(t, func() {
				ready, err := f.receiveUseV2(raw)
				assert.Equal(err, ErrFirstUse)
				assert.ThatNot(ready)
			})
			assert.Equal(useRecordV2(t, f).State, useAwait)
		})
	}
	assert.That(try.To1(f.receiveUseV2(response)))
	var r SignedFirstUseResponseV2
	try.To(wire.UnmarshalCanonical(&r, response))
	// Another valid signature is conflicting evidence, not an exact duplicate.
	other := signUseResponseV2(t, r.Payload, f.local.handle)
	assert.ThatNot(bytes.Equal(response, other))
	f.alice.unchanged(
		t,
		func() { _, err := f.receiveUseV2(other); assert.Equal(err, ErrFirstUse) },
	)
}

func TestFirstUseExpiryAndCancellationV2(t *testing.T) {
	for _, ready := range []bool{false, true} {
		for _, cancel := range []bool{false, true} {
			t.Run(fmt.Sprint(ready, cancel), func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newFirstUseV2(t)
				saved := try.To1(f.startUseV2())
				response := try.To1(f.bobUseV2(saved.request, f.local.handle))
				if ready {
					assert.That(try.To1(f.receiveUseV2(response)))
				}
				f.alice.unchanged(
					t,
					func() { assert.ThatNot(try.To1(f.expireUseV2(false))) },
				)
				if !cancel {
					f.now = f.now.Add(FirstUseLifetime)
				}
				assert.That(try.To1(f.expireUseV2(cancel)))
				record := useRecordV2(t, f)
				assert.Equal(record.State, useExpired)
				f.now = f.now.Add(
					-FirstUseLifetime,
				) // Explicit expiry is durable even on rollback.
				f.alice.unchanged(t, func() {
					_, err := f.receiveUseV2(response)
					assert.Equal(err, ErrFirstUse)
					_, err = f.startUseV2()
					assert.Equal(err, ErrFirstUse)
					assert.ThatNot(try.To1(f.expireUseV2(true)))
				})
				f.alice.reopen(t)
				assert.DeepEqual(useRecordV2(t, f), record)
			})
		}
	}
	for _, offset := range []time.Duration{-time.Nanosecond, FirstUseLifetime, FirstUseLifetime + time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newFirstUseV2(t)
			saved := try.To1(f.startUseV2())
			f.now = f.now.Add(offset)
			f.f.unchanged(
				t,
				func() { _, err := f.bobUseV2(saved.request, f.local.handle); assert.Equal(err, ErrFirstUse) },
			)
			assert.SNil(useRecords(t, f.f.vault)[1])
		})
	}
}

func TestFirstUseAlreadySentResponseDoesNotKnowBobPolicyV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	saved := try.To1(f.startUseV2())
	response := try.To1(f.bobUseV2(saved.request, f.local.handle))
	try.To1(
		policy.DenyLocal(
			f.f.vault,
			f.root.public,
			f.local.public,
			f.peer.public,
		),
	)
	f.f.unchanged(t, func() { assert.That(try.To1(f.receiveUseV2(response))) })
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
		useRecordV2(t, f).State,
		useReady,
	) // Historical LOCAL observation only.
}

func TestFirstUseReceiveStrictDeadlineAndCanonicalBytesV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	saved := try.To1(f.startUseV2())
	response := try.To1(f.bobUseV2(saved.request, f.local.handle))
	for _, raw := range [][]byte{nil, {0xff}, response[:len(response)-1],
		append(bytes.Clone(response), 0), append([]byte{0x98, 2}, response[1:]...),
		append([]byte{0xc0}, response...), make([]byte, MaxEstablishmentBytes+1)} {
		f.alice.unchanged(
			t,
			func() { _, err := f.receiveUseV2(raw); assert.Equal(err, ErrFirstUse) },
		)
	}
	f.now = f.now.Add(FirstUseLifetime)
	f.alice.unchanged(
		t,
		func() { _, err := f.receiveUseV2(response); assert.Equal(err, ErrFirstUse) },
	)
	assert.Equal(useRecordV2(t, f).State, useAwait)
}

func TestFirstUseReceiptRefusesDifferentAuthenticatedSessionV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	saved := try.To1(f.startUseV2())
	try.To1(f.bobUseV2(saved.request, f.local.handle))
	var request SignedFirstUseV2
	try.To(wire.UnmarshalCanonical(&request, saved.request))
	request.Payload.SessionID[0] ^= 1
	other := signUseV2(t, request.Payload, f.peer.handle)
	f.f.unchanged(t, func() {
		_, err := f.bobUseV2(other, f.local.handle)
		assert.Equal(err, ErrFirstUse)
	})
}

func TestFirstUseVersionPurposesAndExactSignedBytesV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	saved := try.To1(f.startUseV2())
	var request SignedFirstUseV2
	try.To(wire.UnmarshalCanonical(&request, saved.request))
	for _, purpose := range []string{FirstUsePurpose, FirstUseResponsePurposeV2,
		firstUseDigestPurposeV2, EstablishPurposeV2} {
		digest := key.HashTagged(
			purpose,
			try.To1(wire.Marshal(request.Payload)),
		)
		request.Signature = try.To1(f.peer.handle.Sign(digest[:]))
		f.f.unchanged(t, func() {
			_, err := f.bobUseV2(try.To1(wire.Marshal(request)), f.local.handle)
			assert.Equal(err, ErrFirstUse)
		})
	}
	// A freshly signed establishment with the same payload has a different
	// digest. Even a valid Bob acceptance of it cannot substitute our history.
	p := request.Payload
	other := signEstablishmentV2(t, p.Established.Binding, f.peer.handle,
		EstablishPurposeV2)
	p.Established = acceptedPayloadV2(p.Established.Binding, other)
	assert.ThatNot(bytes.Equal(p.Established.RequestDigest,
		request.Payload.Established.RequestDigest))
	try.To(verifyAcceptedV2(signAcceptedV2(t, p.Established, f.local.handle,
		AcceptedPurposeV2), p.Established))
	f.f.unchanged(t, func() {
		_, err := f.bobUseV2(signUseV2(t, p, f.peer.handle), f.local.handle)
		assert.Equal(err, ErrFirstUse)
	})

	response := try.To1(f.bobUseV2(saved.request, f.local.handle))
	var reply SignedFirstUseResponseV2
	try.To(wire.UnmarshalCanonical(&reply, response))
	for _, purpose := range []string{FirstUseResponsePurpose, FirstUsePurposeV2,
		firstUseDigestPurposeV2, AcceptedPurposeV2} {
		digest := key.HashTagged(purpose, try.To1(wire.Marshal(reply.Payload)))
		reply.Signature = try.To1(f.local.handle.Sign(digest[:]))
		f.alice.unchanged(t, func() {
			_, err := f.receiveUseV2(try.To1(wire.Marshal(reply)))
			assert.Equal(err, ErrFirstUse)
		})
	}
	// The digest covers exact SIGNED first-use bytes, not just the payload.
	other = signUseV2(t, request.Payload, f.peer.handle)
	reply.Payload = firstUseResponsePayloadV2(request.Payload, other)
	f.alice.unchanged(t, func() {
		_, err := f.receiveUseV2(
			signUseResponseV2(t, reply.Payload, f.local.handle),
		)
		assert.Equal(err, ErrFirstUse)
	})
	digest := key.HashTagged(firstUseDigestPurpose, saved.request)
	reply.Payload.RequestDigest = digest[:]
	f.alice.unchanged(t, func() {
		_, err := f.receiveUseV2(
			signUseResponseV2(t, reply.Payload, f.local.handle),
		)
		assert.Equal(err, ErrFirstUse)
	})
	assert.That(try.To1(f.receiveUseV2(response)))
}

func TestFirstUseV1V2SubstitutionV2(t *testing.T) {
	defer assert.PushTester(t)()
	v1, v2 := newFirstUse(t), newFirstUseV2(t)
	one, two := try.To1(v1.startUse()), try.To1(v2.startUseV2())
	v1.f.unchanged(t, func() {
		_, err := v1.bobUse(two.request, v1.local.handle)
		assert.Equal(err, ErrFirstUse)
	})
	v2.f.unchanged(t, func() {
		_, err := v2.bobUseV2(one.request, v2.local.handle)
		assert.Equal(err, ErrFirstUse)
		_, err = v2.bobUse(two.request, v2.local.handle)
		assert.Equal(err, ErrFirstUse)
	})
	r1 := try.To1(v1.bobUse(one.request, v1.local.handle))
	r2 := try.To1(v2.bobUseV2(two.request, v2.local.handle))
	v1.alice.unchanged(t, func() {
		_, err := v1.receiveUse(r2)
		assert.Equal(err, ErrFirstUse)
		_, err = saveFirstUseV2(v1.alice.vault, v1.root.public, v1.peer.public,
			v1.signer, v2.aliceRuntime, v1.useClock)
		assert.Equal(err, ErrFirstUse)
	})
	v2.alice.unchanged(t, func() {
		_, err := v2.receiveUseV2(r1)
		assert.Equal(err, ErrFirstUse)
		_, err = v2.receiveUse(r2)
		assert.Equal(err, ErrFirstUse)
		_, err = v2.startUse()
		assert.Equal(err, ErrFirstUse)
		_, err = v2.expireUse(true)
		assert.Equal(err, ErrFirstUse)
	})
	assert.That(try.To1(v1.receiveUse(r1)))
	assert.That(try.To1(v2.receiveUseV2(r2)))
}

func TestFirstUseBoundedWireAndPublicEntryPointsV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	// Real-clock first use works with the fixture's old accepted bootstrap.
	saved := try.To1(SaveFirstUseV2(f.alice.vault, f.root.public, f.peer.public,
		f.signer, f.aliceRuntime))
	response := try.To1(BobFirstUseV2(f.f.vault, f.root.public, f.local.public,
		f.local.handle, f.bobRuntime, saved.request))
	assert.That(try.To1(ReceiveFirstUseV2(f.alice.vault, f.root.public,
		f.peer.public, f.signer, f.aliceRuntime, response)))
	assert.Equal(saved.peerOrigin, f.bobRuntime.BoundOrigin)
	assert.That(len(saved.request) <= MaxFirstUseBytesV2)
	assert.That(len(response) <= MaxFirstUseBytesV2)
	assert.Equal(MaxFirstUseBytesV2, 2048)
	assert.Equal(MaxEstablishmentBytes, 2048)
	t.Logf("directed v2 request=%d response=%d; each limit=%d bytes",
		len(saved.request), len(response), MaxFirstUseBytesV2)
	assert.That(try.To1(ExpireFirstUseV2(f.alice.vault, f.root.public,
		f.peer.public, true)))
}
