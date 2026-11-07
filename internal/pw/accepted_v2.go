package pw

import (
	"bytes"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

const (
	AcceptedPurposeV2 = "pw-invitation-accepted/v2"
	requestPurposeV2  = "pw-invitation-request-digest/v2"
)

// AcceptedV2 binds the complete v2 declaration, including both service origins,
// and a digest of the exact signed request bytes (including Alice's signature).
// These canonical CBOR arrays and purposes are separate from v1 evidence.
type AcceptedV2 struct {
	_             struct{} `cbor:",toarray"`
	Version       uint8
	Binding       EstablishmentV2
	RequestDigest []byte
}

type SignedAcceptedV2 struct {
	_         struct{} `cbor:",toarray"`
	Payload   AcceptedV2
	Signature key.Signature
}

func acceptedPayloadV2(p EstablishmentV2, raw []byte) AcceptedV2 {
	digest := key.HashTagged(requestPurposeV2, raw)
	return AcceptedV2{Version: 2, Binding: p, RequestDigest: digest[:]}
}

// expected comes only from the authenticated request under pinned identities.
func verifyAcceptedV2(raw []byte, expected AcceptedV2) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(expected.Version == 2 && expected.Binding.Version == 2 &&
		validPublic(expected.Binding.Target), ErrEstablishment)
	var result SignedAcceptedV2
	try.To(decodeEstablishmentCanonical(raw, &result))
	payload := try.To1(wire.Marshal(result.Payload))
	assert.That(bytes.Equal(payload, try.To1(wire.Marshal(expected))),
		ErrEstablishment)
	digest := key.HashTagged(AcceptedPurposeV2, payload)
	assert.That(len(result.Signature) > 0 && len(result.Signature) <= 72 &&
		result.Signature.Verify(expected.Binding.Target, digest[:]),
		ErrEstablishment)
	return nil
}
