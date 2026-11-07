package pw

import (
	"bytes"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Test-only replacement by another internally authentic transcript. All signing
// happens before the transaction. This is not a production migration or repair.
func replaceMessageHistoryV2(t *testing.T, f *firstUseFixtureV2,
	n outgoingTestNode, mode string,
) ContactRuntimeV2 {
	t.Helper()
	defer assert.PushTester(t)()
	var record acceptedRecord
	try.To(wire.UnmarshalCanonical(&record,
		requesterRecords(t, n.own.vault)[1]))
	var request SignedEstablishmentV2
	try.To(wire.UnmarshalCanonical(&request, record.Request))
	p := request.Payload
	switch mode {
	case "requester contact":
		p.RequesterContact = "http://127.0.0.1:4041"
	case "target contact":
		p.TargetContact = "http://127.0.0.1:12346"
		var ad ads.Current
		try.To(wire.UnmarshalCanonical(&ad, p.Ad))
		ad.Payload.PeerIntroductionURL = p.TargetContact + "/peer/introduction"
		digest := key.HashTagged(
			ads.SignaturePurpose,
			try.To1(wire.Marshal(ad.Payload)),
		)
		ad.Signature = try.To1(f.local.handle.Sign(digest[:]))
		p.Ad = try.To1(wire.Marshal(ad))
	}
	if mode != "acceptance signature" {
		record.Request = signEstablishmentV2(
			t,
			p,
			f.peer.handle,
			EstablishPurposeV2,
		)
	}
	accepted := acceptedPayloadV2(p, record.Request)
	record.Response = signAcceptedV2(
		t,
		accepted,
		f.local.handle,
		AcceptedPurposeV2,
	)
	try.To1(
		decodeEstablishmentV2(record.Request, f.root.public, f.local.public),
	)
	try.To(verifyAcceptedV2(record.Response, accepted))
	first := useRecordV2(t, f)
	var use SignedFirstUseV2
	try.To(wire.UnmarshalCanonical(&use, first.Request))
	use.Payload.Established = accepted
	first.Request = signUseV2(t, use.Payload, f.peer.handle)
	first.Response = signUseResponseV2(t,
		firstUseResponsePayloadV2(use.Payload, first.Request), f.local.handle)
	try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(tx.Put([]byte(acceptedKey), try.To1(wire.Marshal(record))))
		try.To(tx.Put([]byte(heldKey), try.To1(wire.Marshal(heldRecord{
			Version: 2, RequestDigest: accepted.RequestDigest,
		}))))
		if n.name == "Alice" {
			try.To(tx.Put([]byte(attemptKey), record.Request))
			return tx.Put([]byte(firstUseKey), try.To1(wire.Marshal(first)))
		}
		return tx.Put(
			[]byte(useSeenKey),
			try.To1(wire.Marshal(firstUseReceipt{
				Version: 2, Request: first.Request, Response: first.Response,
			})),
		)
	}))
	origin := p.TargetContact
	if n.name == "Alice" {
		origin = p.RequesterContact
	}
	return ContactRuntimeV2{Running: true, BoundOrigin: origin}
}

func TestMessageExactAcceptedIdentityV2(t *testing.T) {
	for _, mode := range []string{"acceptance signature", "request signature",
		"requester contact", "target contact"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			for _, n := range outgoingTestNodes(f.requesterFixture) {
				runtime := f.messageRuntime(n)
				message := try.To1(
					CreateOutgoingV2(n.own.vault, f.root.public,
						n.local, n.signer, runtime, "bound history"),
				)
				envelope := try.To1(PrepareOutgoingEnvelopeV2(n.own.vault,
					f.root.public, n.local, n.signer, runtime))
				old := messageBindingV2(
					t,
					n.own.vault,
					f.root.public,
					n.local,
				)
				n.other.unchanged(t, func() {
					runtime = replaceMessageHistoryV2(t, f, n, mode)
				})
				current := messageBindingV2(
					t,
					n.own.vault,
					f.root.public,
					n.local,
				)
				assert.ThatNot(
					bytes.Equal(
						old.AcceptedDigest,
						current.AcceptedDigest,
					),
				)
				assert.Equal(
					bytes.Equal(old.RequestDigest, current.RequestDigest),
					mode == "acceptance signature",
				)
				// Even when all current guards and the replacement's signatures
				// validate, the original outgoing message cannot change identity.
				try.To(
					n.own.vault.View(func(tx storage.ReadTx) (err error) {
						defer err2.Handle(&err, nil)
						try.To1(
							outgoingPrerequisitesV2(
								tx,
								f.root.public,
								n.local,
								runtime,
							),
						)
						return nil
					}),
				)
				n.own.unchanged(t, func() {
					_, err := decodeOutgoingV2(message, current)
					assert.Error(err)
					_, err = decodeMessageEnvelopeV2(envelope, current)
					assert.Equal(err, errMessageEnvelope)
					got, err := CreateOutgoingV2(
						n.own.vault,
						f.root.public,
						n.local,
						n.signer,
						runtime,
						"bound history",
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
			}
		})
	}
}

func TestMessageCorruptEstablishmentHistoryV2(t *testing.T) {
	for _, mode := range []string{"history malformed", "history noncanonical",
		"history version", "request signature", "response signature",
		"request contact", "request target", "request ad", "held digest",
		"held version", "role", "attempt", "invitation"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			for _, n := range outgoingTestNodes(f.requesterFixture) {
				runtime := f.messageRuntime(n)
				try.To1(
					CreateOutgoingV2(n.own.vault, f.root.public, n.local,
						n.signer, runtime, "saved"),
				)
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return corruptContactHistoryV2(
						tx,
						n.local,
						n.name == "Alice",
						mode,
					)
				}))
				n.own.reopen(t)
				n.own.unchanged(t, func() {
					got, err := CreateOutgoingV2(
						n.own.vault,
						f.root.public,
						n.local,
						n.signer,
						runtime,
						"saved",
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
			}
		})
	}
}

func TestMessageIncompatibleFirstUseHistoryV2(t *testing.T) {
	for _, mode := range []string{"malformed", "noncanonical", "oversize",
		"foreign version", "wrong slot", "request", "response", "missing response"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			for _, n := range outgoingTestNodes(f.requesterFixture) {
				runtime := f.messageRuntime(n)
				try.To1(
					CreateOutgoingV2(n.own.vault, f.root.public, n.local,
						n.signer, runtime, "saved"),
				)
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return corruptFirstUseV2(tx, n.name == "Alice", mode)
				}))
				n.own.unchanged(t, func() {
					got, err := CreateOutgoingV2(
						n.own.vault,
						f.root.public,
						n.local,
						n.signer,
						runtime,
						"saved",
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
			}
		})
	}
}
