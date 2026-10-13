package record

import (
	"bytes"
	"crypto/hmac"
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var errCollision = errors.New("record: logical key conflict")

// sealRecord computes the lookup token and encrypts the encoded key/value.
// The caller supplies paired KE/KI, the expected ID and encoded context, and a
// spend gate for this KE. Validation precedes spending; global lifetime usage
// accounting remains the caller's responsibility. No result escapes on error.
func sealRecord(ke, ki []byte, id [16]byte, context, key, value []byte,
	spend func() error) (token [32]byte, envelope []byte, err error) {
	defer err2.Handle(&err, nil)

	payload := try.To1(encodePlaintext(key, value))
	computedToken := try.To1(lookupToken(ki, context, id, key))
	sealed := try.To1(sealEnvelope(ke, id, context, computedToken, payload, spend))
	return computedToken, sealed, nil
}

// openRecord returns owned key/value bytes only after envelope authentication,
// plaintext decoding, token verification, and any requested-key comparison.
// Nil wantKey selects record-by-record iteration; a nonnil key must be nonempty.
// Paired KE/KI, ID, encoded context and location token come from the caller, never
// the envelope. This helper does not spend, authorize access, or prevent replay.
func openRecord(ke, ki []byte, id [16]byte, context []byte, token [32]byte,
	wantKey, envelope []byte) (key, value []byte, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.Equal(len(ki), 32, errFormat)
	if wantKey != nil {
		assert.That(len(wantKey) > 0 && len(wantKey) <= maxKeySize, errFormat)
	}
	payload := try.To1(openEnvelope(ke, id, context, token, envelope))
	decodedKey, decodedValue := try.To2(decodePlaintext(payload))
	computedToken := try.To1(lookupToken(ki, context, id, decodedKey))
	assert.That(hmac.Equal(computedToken[:], token[:]), errAuthentication)
	if wantKey != nil {
		assert.That(bytes.Equal(wantKey, decodedKey), errCollision)
	}
	return decodedKey, decodedValue, nil
}
