package record

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var (
	errAuthentication = errors.New("record: envelope authentication failed")
	errBudget         = errors.New("record: spending permission missing or denied")
)

// sealEnvelope encrypts an opaque encodePlaintext payload, checking its size but
// not parsing it. The caller supplies KE, KeyID, expected context, and token;
// this adapter does not compute or validate the logical-key/token relationship.
// spend must consume one previously allocated allowance tied to this actual KE.
// Validation precedes spending; a completed seal consumes its allowance even if
// discarded. There is no refund, and a new call does not reset the key's budget.
// Global lifetime accounting remains the caller's D4 responsibility.
func sealEnvelope(ke []byte, id [16]byte, context []byte, token [32]byte,
	payload []byte, spend func() error) (envelope []byte, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	aead := try.To1(newEnvelopeAEAD(ke))
	header := try.To1(encodeHeader(id, len(payload)))
	aad := try.To1(encodeAAD(header, context, token))
	assert.That(spend != nil, errBudget)
	if cause := spend(); cause != nil {
		return nil, errors.Join(errBudget, cause)
	}
	body := aead.Seal(nil, nil, payload, aad)
	return append(header, body...), nil
}

// openEnvelope returns owned payload bytes only after authentication. It is not
// the full record.Open: the later layer must decode the payload, recompute and
// compare the HMAC token, check the logical key, and authorize access before
// returning application records. KE, expected KeyID, context, and token all come
// from the caller; the untrusted header never selects a key. Open does not spend.
func openEnvelope(ke []byte, id [16]byte, context []byte, token [32]byte,
	envelope []byte) (payload []byte, err error) {
	defer err2.Handle(&err, nil)
	aead := try.To1(newEnvelopeAEAD(ke))
	header, body := try.To2(parseEnvelope(envelope, id))
	aad := try.To1(encodeAAD(header, context, token))
	defer err2.Handle(&err, func(err error) error {
		return errAuthentication
	})
	payload = try.To1(aead.Open(nil, nil, body, aad))
	return payload, nil
}

func newEnvelopeAEAD(ke []byte) (aead cipher.AEAD, err error) {
	defer err2.Handle(&err, nil)
	if len(ke) != 32 {
		return nil, errFormat
	}
	block := try.To1(aes.NewCipher(ke))
	return try.To1(cipher.NewGCMWithRandomNonce(block)), nil
}
