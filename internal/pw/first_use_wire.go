package pw

import (
	"bytes"
	"errors"
	"math"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

const (
	FirstUsePurpose         = "pw-first-use-request/v1"
	FirstUseResponsePurpose = "pw-first-use-response/v1"
	firstUseDigestPurpose   = "pw-first-use-request-digest/v1"
	// FirstUseLifetime is engineering policy, not a TLC-proved duration.
	FirstUseLifetime = 60 * time.Second
)

var ErrFirstUse = errors.New("pairwise first use refused")

// FirstUse is a canonical v1 CBOR array. Established includes the complete
// binding and the digest of the original SIGNED establishment request.
// HeldEvidence is Alice's authenticated assertion, not access to her Vault or
// proof of continuing permission. Only a ping is implemented in this slice.
type FirstUse struct {
	_               struct{} `cbor:",toarray"`
	Version         uint8
	Established     Accepted
	SessionID       []byte
	IssuedUnixNano  int64
	ExpiresUnixNano int64
	HeldEvidence    bool
}

type SignedFirstUse struct {
	_         struct{} `cbor:",toarray"`
	Payload   FirstUse
	Signature key.Signature
}

type FirstUseResponse struct {
	_             struct{} `cbor:",toarray"`
	Version       uint8
	Request       FirstUse
	RequestDigest []byte
}

type SignedFirstUseResponse struct {
	_         struct{} `cbor:",toarray"`
	Payload   FirstUseResponse
	Signature key.Signature
}

func decodeFirstUse(raw []byte, expected Accepted) (_ FirstUse, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	var request SignedFirstUse
	try.To(decodeEstablishmentCanonical(raw, &request))
	p := request.Payload
	assert.That(p.Version == 1 && p.HeldEvidence && len(p.SessionID) == 32,
		ErrFirstUse)
	assert.That(p.IssuedUnixNano >= 0 &&
		p.IssuedUnixNano <= math.MaxInt64-int64(FirstUseLifetime) &&
		p.ExpiresUnixNano == p.IssuedUnixNano+int64(FirstUseLifetime),
		ErrFirstUse)
	assert.That(bytes.Equal(try.To1(wire.Marshal(p.Established)),
		try.To1(wire.Marshal(expected))), ErrFirstUse)
	digest := key.HashTagged(FirstUsePurpose, try.To1(wire.Marshal(p)))
	assert.That(len(request.Signature) > 0 && len(request.Signature) <= 72 &&
		request.Signature.Verify(expected.Binding.Requester, digest[:]),
		ErrFirstUse)
	return p, nil
}

func firstUseResponsePayload(p FirstUse, raw []byte) FirstUseResponse {
	digest := key.HashTagged(firstUseDigestPurpose, raw)
	return FirstUseResponse{Version: 1, Request: p, RequestDigest: digest[:]}
}

func verifyFirstUseResponse(raw []byte, expected FirstUseResponse) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	var response SignedFirstUseResponse
	try.To(decodeEstablishmentCanonical(raw, &response))
	payload := try.To1(wire.Marshal(response.Payload))
	assert.That(
		bytes.Equal(payload, try.To1(wire.Marshal(expected))),
		ErrFirstUse,
	)
	digest := key.HashTagged(FirstUseResponsePurpose, payload)
	assert.That(len(response.Signature) > 0 && len(response.Signature) <= 72 &&
		response.Signature.Verify(expected.Request.Established.Binding.Target,
			digest[:]), ErrFirstUse)
	return nil
}

func firstUseTime(now time.Time) (_ int64, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	assert.That(!now.Before(time.Unix(0, 0)) &&
		!now.After(time.Unix(0, math.MaxInt64)), ErrFirstUse)
	return now.UTC().UnixNano(), nil
}

func freshFirstUse(p FirstUse, now time.Time) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	n := try.To1(firstUseTime(now))
	assert.That(n >= p.IssuedUnixNano && n < p.ExpiresUnixNano, ErrFirstUse)
	return nil
}
