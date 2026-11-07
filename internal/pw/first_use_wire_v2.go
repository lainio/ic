package pw

import (
	"bytes"
	"math"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

const (
	FirstUsePurposeV2         = "pw-first-use-request/v2"
	FirstUseResponsePurposeV2 = "pw-first-use-response/v2"
	firstUseDigestPurposeV2   = "pw-first-use-request-digest/v2"
	// V2 fits the existing bounded canonical format; v1 limits stay unchanged.
	MaxFirstUseBytesV2 = MaxEstablishmentBytes
)

// FirstUseV2 is a separate canonical CBOR array. Established contains all of
// AcceptedV2, including both service contacts and the original signed request
// digest. HeldEvidence authenticates an assertion, not listener possession or
// remote permission. This is not an AKE or a composed message protocol.
type FirstUseV2 struct {
	_               struct{} `cbor:",toarray"`
	Version         uint8
	Established     AcceptedV2
	SessionID       []byte
	IssuedUnixNano  int64
	ExpiresUnixNano int64
	HeldEvidence    bool
}

type SignedFirstUseV2 struct {
	_         struct{} `cbor:",toarray"`
	Payload   FirstUseV2
	Signature key.Signature
}

type FirstUseResponseV2 struct {
	_             struct{} `cbor:",toarray"`
	Version       uint8
	Request       FirstUseV2
	RequestDigest []byte
}

type SignedFirstUseResponseV2 struct {
	_         struct{} `cbor:",toarray"`
	Payload   FirstUseResponseV2
	Signature key.Signature
}

// expected comes from authenticated v2 history under pinned Root/local roles.
func decodeFirstUseV2(raw []byte, expected AcceptedV2,
) (_ FirstUseV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(expected.Version == 2 && expected.Binding.Version == 2,
		ErrFirstUse)
	var request SignedFirstUseV2
	try.To(decodeEstablishmentCanonical(raw, &request))
	p := request.Payload
	assert.That(p.Version == 2 && p.HeldEvidence && len(p.SessionID) == 32,
		ErrFirstUse)
	assert.That(p.IssuedUnixNano >= 0 &&
		p.IssuedUnixNano <= math.MaxInt64-int64(FirstUseLifetime) &&
		p.ExpiresUnixNano == p.IssuedUnixNano+int64(FirstUseLifetime),
		ErrFirstUse)
	assert.That(bytes.Equal(try.To1(wire.Marshal(p.Established)),
		try.To1(wire.Marshal(expected))), ErrFirstUse)
	digest := key.HashTagged(FirstUsePurposeV2, try.To1(wire.Marshal(p)))
	assert.That(len(request.Signature) > 0 && len(request.Signature) <= 72 &&
		request.Signature.Verify(expected.Binding.Requester, digest[:]),
		ErrFirstUse)
	return p, nil
}

func firstUseResponsePayloadV2(p FirstUseV2, raw []byte) FirstUseResponseV2 {
	digest := key.HashTagged(firstUseDigestPurposeV2, raw)
	return FirstUseResponseV2{Version: 2, Request: p, RequestDigest: digest[:]}
}

func verifyFirstUseResponseV2(raw []byte, expected FirstUseResponseV2,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	var response SignedFirstUseResponseV2
	try.To(decodeEstablishmentCanonical(raw, &response))
	payload := try.To1(wire.Marshal(response.Payload))
	assert.That(bytes.Equal(payload, try.To1(wire.Marshal(expected))),
		ErrFirstUse)
	digest := key.HashTagged(FirstUseResponsePurposeV2, payload)
	assert.That(len(response.Signature) > 0 && len(response.Signature) <= 72 &&
		response.Signature.Verify(expected.Request.Established.Binding.Target,
			digest[:]), ErrFirstUse)
	return nil
}

func freshFirstUseV2(p FirstUseV2, now time.Time) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	n := try.To1(firstUseTime(now))
	assert.That(n >= p.IssuedUnixNano && n < p.ExpiresUnixNano, ErrFirstUse)
	return nil
}
