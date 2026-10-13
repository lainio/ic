package record

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestRecordComplete(t *testing.T) {
	defer assert.PushTester(t)()
	secret := try.To1(hex.DecodeString(fixtureSecret))
	vault := [16]byte(try.To1(hex.DecodeString(fixtureVault)))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	ke, ki := try.To2(derive(secret, vault, id))
	for _, tc := range []struct {
		name       string
		segments   [][]byte
		key, value []byte
	}{
		{"root", nil, []byte("count"), []byte("7")},
		{"nested_empty", [][]byte{[]byte("a/b"), []byte("c")}, []byte("count"), nil},
		{"nested_binary", [][]byte{[]byte("a/b"), []byte("c")}, []byte{0, 0xff, '/'}, []byte{0x80, 0, 0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			context := try.To1(encodeContext(vault, tc.segments))
			allowance := envelopeAllowance{remaining: 1}
			token, envelope := try.To2(sealRecord(ke, ki, id, context, tc.key, tc.value, allowance.spend))
			assert.Equal(token, try.To1(lookupToken(ki, context, id, tc.key)))
			assert.Equal(allowance.calls, 1)
			assert.Equal(allowance.remaining, 0)
			for _, wantKey := range [][]byte{tc.key, nil} {
				key, value := try.To2(openRecord(ke, ki, id, context, token, wantKey, envelope))
				assert.Equal(string(key), string(tc.key))
				assert.Equal(string(value), string(tc.value))
			}
			assert.Equal(allowance.calls, 1)
		})
	}

	t.Run("fixed_envelope", func(t *testing.T) {
		defer assert.PushTester(t)()
		ke := try.To1(hex.DecodeString(fixtureKE))
		ki := try.To1(hex.DecodeString(fixtureKI))
		context := try.To1(hex.DecodeString(fixtureNestedContext))
		token := [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
		envelope := try.To1(hex.DecodeString(fixtureEnvelope))
		for _, wantKey := range [][]byte{[]byte("count"), nil} {
			key, value := try.To2(openRecord(ke, ki, id, context, token, wantKey, envelope))
			assert.Equal(string(key), "count")
			assert.Equal(string(value), "7")
		}
	})
}

func TestRecordBeyondAEAD(t *testing.T) {
	defer assert.PushTester(t)()
	ke := try.To1(hex.DecodeString(fixtureKE))
	ki := try.To1(hex.DecodeString(fixtureKI))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	context := try.To1(hex.DecodeString(fixtureNestedContext))
	payload := try.To1(encodePlaintext([]byte("count"), []byte("7")))

	t.Run("token_for_different_key", func(t *testing.T) {
		defer assert.PushTester(t)()
		token := try.To1(lookupToken(ki, context, id, []byte("other")))
		assert.NotEqual(token, try.To1(lookupToken(ki, context, id, []byte("count"))))
		allowance := envelopeAllowance{remaining: 1}
		envelope := try.To1(sealEnvelope(ke, id, context, token, payload, allowance.spend))
		authenticated := try.To1(openEnvelope(ke, id, context, token, envelope))
		assert.Equal(string(authenticated), string(payload))
		// Iteration must verify tokens too; token verification also precedes
		// the exact-key guard when the requested key differs from the payload.
		for _, wantKey := range [][]byte{nil, []byte("other")} {
			key, value, err := openRecord(ke, ki, id, context, token, wantKey, envelope)
			assert.Equal(err, errAuthentication)
			assert.SNil(key)
			assert.SNil(value)
		}
	})

	t.Run("malformed_authenticated_plaintext", func(t *testing.T) {
		defer assert.PushTester(t)()
		// The LP value declares one byte, but that byte is absent. The total
		// size remains permitted by the opaque envelope adapter.
		malformed := payload[:len(payload)-1]
		token := try.To1(lookupToken(ki, context, id, []byte("count")))
		allowance := envelopeAllowance{remaining: 1}
		envelope := try.To1(sealEnvelope(ke, id, context, token, malformed, allowance.spend))
		authenticated := try.To1(openEnvelope(ke, id, context, token, envelope))
		assert.Equal(string(authenticated), string(malformed))
		key, value, err := openRecord(ke, ki, id, context, token, nil, envelope)
		assert.Equal(err, errFormat)
		assert.SNil(key)
		assert.SNil(value)
	})

	t.Run("different_index_key", func(t *testing.T) {
		defer assert.PushTester(t)()
		token := [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
		envelope := try.To1(hex.DecodeString(fixtureEnvelope))
		authenticated := try.To1(openEnvelope(ke, id, context, token, envelope))
		assert.Equal(string(authenticated), string(payload))
		otherKI := bytes.Clone(ki)
		otherKI[0] ^= 1
		key, value, err := openRecord(ke, otherKI, id, context, token, nil, envelope)
		assert.Equal(err, errAuthentication)
		assert.SNil(key)
		assert.SNil(value)
	})
}

func TestRecordRequestedKey(t *testing.T) {
	defer assert.PushTester(t)()
	ke := try.To1(hex.DecodeString(fixtureKE))
	ki := try.To1(hex.DecodeString(fixtureKI))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	context := try.To1(hex.DecodeString(fixtureNestedContext))
	token := [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
	envelope := try.To1(hex.DecodeString(fixtureEnvelope))
	key, value := try.To2(openRecord(ke, ki, id, context, token, []byte("count"), envelope))
	assert.Equal(string(key), "count")
	assert.Equal(string(value), "7")
	// Keep the matching location token and change only the requested key.
	// This exercises the exact-key guard without manufacturing an HMAC collision.
	key, value, err := openRecord(ke, ki, id, context, token, []byte("Count"), envelope)
	assert.Equal(err, errCollision)
	assert.SNil(key)
	assert.SNil(value)
}

func TestRecordFailures(t *testing.T) {
	defer assert.PushTester(t)()
	ke := try.To1(hex.DecodeString(fixtureKE))
	ki := try.To1(hex.DecodeString(fixtureKI))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	context := try.To1(hex.DecodeString(fixtureNestedContext))
	token := [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
	envelope := try.To1(hex.DecodeString(fixtureEnvelope))
	for _, tc := range []struct {
		name string
		want error
	}{
		{"empty_requested_key", errFormat},
		{"overlong_requested_key", errFormat},
		{"invalid_ki", errFormat},
		{"tampered_envelope", errAuthentication},
		{"wrong_expected_id", errIdentifier},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			indexKey, expectedID := ki, id
			wantKey, record := []byte("count"), bytes.Clone(envelope)
			switch tc.name {
			case "empty_requested_key":
				wantKey = []byte{} // Nonnil empty is not iteration mode.
			case "overlong_requested_key":
				wantKey = make([]byte, maxKeySize+1)
			case "invalid_ki":
				indexKey = ki[:31]
			case "tampered_envelope":
				record[len(record)-1] ^= 1
			case "wrong_expected_id":
				expectedID[0] ^= 1
			}
			key, value, err := openRecord(ke, indexKey, expectedID, context, token, wantKey, record)
			assert.Equal(err, tc.want)
			assert.SNil(key)
			assert.SNil(value)
		})
	}

	t.Run("missing_spend", func(t *testing.T) {
		defer assert.PushTester(t)()
		token, envelope, err := sealRecord(ke, ki, id, context, []byte("count"), []byte("7"), nil)
		assert.Equal(err, errBudget)
		assert.Equal(token, [32]byte{})
		assert.SNil(envelope)
	})

	t.Run("denied_spend", func(t *testing.T) {
		defer assert.PushTester(t)()
		cause := errors.New("test record spend denied")
		calls := 0
		spend := func() error {
			calls++
			return cause
		}
		token, envelope, err := sealRecord(ke, ki, id, context, []byte("count"), []byte("7"), spend)
		assert.ErrorIs(err, errBudget)
		assert.ErrorIs(err, cause)
		assert.Equal(token, [32]byte{})
		assert.SNil(envelope)
		assert.Equal(calls, 1)
	})

	t.Run("invalid_seal_does_not_spend", func(t *testing.T) {
		defer assert.PushTester(t)()
		allowance := envelopeAllowance{remaining: 1}
		token, envelope, err := sealRecord(ke, ki, id, context, nil, []byte("7"), allowance.spend)
		assert.Equal(err, errFormat)
		assert.Equal(token, [32]byte{})
		assert.SNil(envelope)
		assert.Equal(allowance.calls, 0)
		assert.Equal(allowance.remaining, 1)
	})
}

func TestRecordOwnership(t *testing.T) {
	defer assert.PushTester(t)()
	ke := try.To1(hex.DecodeString(fixtureKE))
	ki := try.To1(hex.DecodeString(fixtureKI))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	context := try.To1(hex.DecodeString(fixtureNestedContext))
	key, value := []byte("count"), []byte("7")
	wantKey := bytes.Clone(key)
	allowance := envelopeAllowance{remaining: 1}
	token, envelope := try.To2(sealRecord(ke, ki, id, context, key, value, allowance.spend))
	before := bytes.Clone(envelope)
	openedKey, openedValue := try.To2(openRecord(ke, ki, id, context, token, wantKey, envelope))
	assert.Equal(string(openedKey), "count")
	assert.Equal(string(openedValue), "7")
	assert.Equal(hex.EncodeToString(ke), fixtureKE)
	assert.Equal(hex.EncodeToString(ki), fixtureKI)
	assert.Equal(hex.EncodeToString(id[:]), fixtureID)
	assert.Equal(hex.EncodeToString(context), fixtureNestedContext)
	assert.Equal(hex.EncodeToString(token[:]), fixtureNestedToken)
	assert.Equal(string(envelope), string(before))
	assert.Equal(allowance.calls, 1)
	assert.Equal(allowance.remaining, 0)

	openedKey[0], openedValue[0] = 'x', 'x'
	assert.Equal(string(key), "count")
	assert.Equal(string(value), "7")
	assert.Equal(string(wantKey), "count")
	assert.Equal(string(envelope), string(before))
	deniedToken, deniedEnvelope, err := sealRecord(ke, ki, id, context, key, value, allowance.spend)
	assert.ErrorIs(err, errBudget)
	assert.Equal(deniedToken, [32]byte{})
	assert.SNil(deniedEnvelope)
	assert.Equal(allowance.calls, 2)
	assert.Equal(allowance.remaining, 0)

	// Owned results remain independent, and exhausted sealing does not block reads.
	laterKey, laterValue := try.To2(openRecord(ke, ki, id, context, token, wantKey, envelope))
	assert.Equal(string(laterKey), "count")
	assert.Equal(string(laterValue), "7")
	assert.Equal(string(envelope), string(before))
	assert.Equal(allowance.calls, 2)
}
