package pw

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestBobReplyV2ExactLossRestartAndExpiry(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, true)
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	try.To(f.acceptV2(saved.request, f.local.handle))
	row, raw, held := f.records(t)
	var history acceptedRecord
	try.To(wire.UnmarshalCanonical(&history, raw))
	var result SignedAcceptedV2
	try.To(wire.UnmarshalCanonical(&result, history.Response))
	digest := key.HashTagged(AcceptedPurposeV2,
		try.To1(wire.Marshal(result.Payload)))
	var probes [][]byte
	signer := &probeSigner{Handle: f.local.handle}
	signer.sign = func(d []byte) ([]byte, error) {
		if bytes.Equal(d, digest[:]) {
			return nil, errors.New("must not sign acceptance again")
		}
		probes = append(probes, bytes.Clone(d))
		return signer.Handle.Sign(d)
	}
	f.f.lease.remaining.Store(0)
	for _, restart := range []bool{false, true} {
		if restart {
			f.f.reopen(t)
			signer.Handle = try.To1(nodeidentity.OpenDirectory(
				f.local.dir, f.local.unlock))
			f.now = time.Unix(0, f.invitation.ExpiresUnixNano)
		}
		f.f.unchanged(t, func() {
			f.alice.unchanged(t, func() {
				response := try.To1(f.replyV2(saved.request, signer))
				assert.DeepEqual(response, history.Response)
				response[0] ^= 1 // Caller bytes cannot mutate saved history.
			})
		})
		gotRow, gotRaw, gotHeld := f.records(t)
		assert.DeepEqual(gotRow, row)
		assert.DeepEqual(gotRaw, raw)
		assert.DeepEqual(gotHeld, held)
	}
	assert.Equal(signer.signCalls.Load(), 2) // Fresh probes only, no acceptance.
	assert.ThatNot(bytes.Equal(probes[0], probes[1]))
	f.now = f.now.Add(time.Minute) // Current ad has now expired too.
	f.f.unchanged(t, func() {
		response, err := f.replyV2(saved.request, signer)
		assert.Equal(err, ErrEstablishment)
		assert.SNil(response)
	})
	_, after, _ := f.records(t)
	assert.DeepEqual(after, raw)
}

func TestBobReplyV2ExactBytesAndContacts(t *testing.T) {
	defer assert.PushTester(t)()
	f := newRequester(t, true)
	saved := try.To1(f.saveV2(aliceServiceOrigin))
	try.To(f.acceptV2(saved.request, f.local.handle))
	for _, field := range []string{"requester contact", "target contact",
		"signature", "attempt", "invitation", "requester", "target", "root",
		"recipient", "device", "epoch", "noncanonical", "tampered"} {
		t.Run(field, func(t *testing.T) {
			defer assert.PushTester(t)()
			request := try.To1(decodeEstablishmentV2(saved.request,
				f.root.public, f.local.public))
			p := &request.Payload
			switch field {
			case "requester contact", "tampered":
				p.RequesterContact = "http://127.0.0.1:4041"
			case "target contact":
				p.TargetContact = "http://127.0.0.1:12346"
			case "attempt":
				p.AttemptID[0] ^= 1
			case "invitation":
				p.InvitationID[0] ^= 1
			case "requester":
				p.Requester = p.Root
			case "target":
				p.Target = p.Root
			case "root":
				p.Root = p.Requester
			case "recipient":
				p.Recipient = p.Target
			case "device":
				p.Device = p.Target
			case "epoch":
				p.Epoch++
			}
			raw := signEstablishmentV2(t, *p, f.peer.handle, EstablishPurposeV2)
			if field == "signature" {
				// Authenticated identical payload with a different real signature.
				assert.ThatNot(bytes.Equal(raw, saved.request))
				try.To1(decodeEstablishmentV2(raw, f.root.public, f.local.public))
			}
			switch field {
			case "noncanonical":
				raw = append([]byte{0x98, 2}, saved.request[1:]...)
			case "tampered":
				raw = try.To1(wire.Marshal(request))
			}
			f.f.unchanged(t, func() {
				response, err := f.replyV2(raw, f.local.handle)
				assert.Equal(err, ErrEstablishment)
				assert.SNil(response)
				assert.Equal(f.acceptV2(raw, f.local.handle), ErrEstablishment)
			})
		})
	}
	try.To1(f.replyV2(saved.request, f.local.handle))
}

func TestBobReplyV2CurrentGuardsAndDeletion(t *testing.T) {
	for _, phase := range []string{"before", "probe"} {
		for _, guard := range []string{"deny", "held", "known self",
			"known peer", "device", "ad", "origin"} {
			t.Run(phase+"/"+guard, func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newRequester(t, false)
				saved := try.To1(f.saveV2(aliceServiceOrigin))
				try.To(f.acceptV2(saved.request, f.local.handle))
				row, history, held := f.records(t)
				signer := &probeSigner{Handle: f.local.handle}
				if phase == "before" {
					try.To(f.invalidateBobV2(guard))
				} else {
					signer.sign = func(d []byte) ([]byte, error) {
						if err := f.invalidateBobV2(guard); err != nil {
							return nil, err
						}
						return f.local.handle.Sign(d)
					}
				}
				response, err := f.replyV2(saved.request, signer)
				assert.Equal(err, ErrEstablishment)
				assert.SNil(response)
				f.f.reopen(t)
				f.f.unchanged(t, func() {
					response, err := f.replyV2(saved.request, f.local.handle)
					assert.Equal(err, ErrEstablishment)
					assert.SNil(response)
					assert.Equal(f.acceptV2(saved.request, f.local.handle),
						ErrEstablishment)
				})
				gotRow, gotHistory, gotHeld := f.records(t)
				assert.DeepEqual(gotRow, row)
				assert.DeepEqual(gotHistory, history)
				if guard == "held" {
					assert.SNil(gotHeld)
				} else {
					assert.DeepEqual(gotHeld, held)
				}
				assert.DeepEqual(requesterRecords(t, f.alice.vault),
					[3][]byte{saved.request, nil, nil})
			})
		}
	}
}

func TestBobReplyV2AuthenticatesEntireSuccess(t *testing.T) {
	for _, field := range []string{"signature", "wrong signer", "purpose",
		"version", "binding version", "requester contact", "target contact",
		"swap", "digest", "v1 digest", "unsigned digest", "root", "target",
		"requester", "invitation", "recipient", "attempt", "device", "epoch",
		"ad", "audience", "noncanonical", "v1 response"} {
		t.Run(field, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newRequester(t, true)
			saved := try.To1(f.saveV2(aliceServiceOrigin))
			try.To(f.acceptV2(saved.request, f.local.handle))
			_, raw, _ := f.records(t)
			var history acceptedRecord
			try.To(wire.UnmarshalCanonical(&history, raw))
			var response SignedAcceptedV2
			try.To(wire.UnmarshalCanonical(&response, history.Response))
			p := &response.Payload.Binding
			switch field {
			case "signature":
				response.Signature = nil
			case "version":
				response.Payload.Version = 1
			case "binding version":
				p.Version = 1
			case "requester contact":
				p.RequesterContact = "http://127.0.0.1:4041"
			case "target contact":
				p.TargetContact = "http://127.0.0.1:12346"
			case "swap":
				p.RequesterContact, p.TargetContact = p.TargetContact, p.RequesterContact
			case "digest":
				response.Payload.RequestDigest[0] ^= 1
			case "v1 digest":
				digest := key.HashTagged(requestPurpose, saved.request)
				response.Payload.RequestDigest = digest[:]
			case "unsigned digest":
				digest := key.HashTagged(requestPurposeV2, try.To1(wire.Marshal(*p)))
				response.Payload.RequestDigest = digest[:]
			case "root":
				p.Root = p.Requester
			case "target":
				p.Target = p.Requester
			case "requester":
				p.Requester = p.Root
			case "invitation":
				p.InvitationID[0] ^= 1
			case "recipient":
				p.Recipient = p.Root
			case "attempt":
				p.AttemptID[0] ^= 1
			case "device":
				p.Device = p.Root
			case "epoch":
				p.Epoch++
			case "ad":
				p.Ad[0] ^= 1
			case "audience":
				p.Audience, p.Recipient = InvitationAny, nil
			}
			if field != "signature" {
				purpose, signer := AcceptedPurposeV2, f.local.handle
				if field == "purpose" {
					purpose = AcceptedPurpose
				}
				if field == "wrong signer" {
					signer = f.peer.handle
				}
				digest := key.HashTagged(purpose,
					try.To1(wire.Marshal(response.Payload)))
				response.Signature = try.To1(signer.Sign(digest[:]))
			}
			history.Response = try.To1(wire.Marshal(response))
			switch field {
			case "noncanonical":
				history.Response = append([]byte{0x98, 2}, history.Response[1:]...)
			case "v1 response":
				payload := acceptedPayload(f.request.Payload, f.raw)
				digest := key.HashTagged(AcceptedPurpose,
					try.To1(wire.Marshal(payload)))
				history.Response = try.To1(wire.Marshal(SignedAccepted{
					Payload: payload, Signature: try.To1(f.local.handle.Sign(digest[:])),
				}))
			}
			try.To(f.f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				return tx.Put([]byte(acceptedKey), try.To1(wire.Marshal(history)))
			}))
			f.f.unchanged(t, func() {
				response, err := f.replyV2(saved.request, f.local.handle)
				assert.Equal(err, ErrEstablishment)
				assert.SNil(response)
			})
		})
	}
}
