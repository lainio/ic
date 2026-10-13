package record

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

// Independent project-format fixture from Python cryptography, cross-checked
// with Go's standard AES-GCM. Used only for Open; Seal owns its random nonce.
const fixtureEnvelope = "0101202122232425262728292a2b2c2d2e2f0000002a" +
	"000102030405060708090a0b" +
	"46ec6c1b9f7831b197d08aaa82101b91304642546c32f08da4eaa8d4f763"

// envelopeAllowance is a finite test gate for one test KE. It cannot establish
// D4's lifetime cap across files/processes/restores, provider authorization, or
// non-replayable allowances.
type envelopeAllowance struct {
	remaining int
	calls     int
}

func (a *envelopeAllowance) spend() error {
	a.calls++
	if a.remaining == 0 {
		return errors.New("test allowance exhausted")
	}
	a.remaining--
	return nil
}

func TestEnvelopeRoundTrip(t *testing.T) {
	defer assert.PushTester(t)()
	ke := try.To1(hex.DecodeString(fixtureKE))
	ki := try.To1(hex.DecodeString(fixtureKI))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	for _, tc := range []struct {
		name, context string
		key, value    []byte
	}{
		{"root", fixtureRootContext, []byte("count"), []byte("7")},
		{"nested_empty", fixtureNestedContext, []byte("count"), nil},
		{"nested_binary", fixtureNestedContext, []byte{0, 0xff, '/'}, []byte{0x80, 0, 0xff}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			context := try.To1(hex.DecodeString(tc.context))
			token := try.To1(lookupToken(ki, context, id, tc.key))
			payload := try.To1(encodePlaintext(tc.key, tc.value))
			allowance := envelopeAllowance{remaining: 1}
			envelope := try.To1(sealEnvelope(ke, id, context, token, payload, allowance.spend))
			assert.SLen(envelope, headerSize+bodyOverhead+len(payload))
			assert.Equal(allowance.calls, 1)
			opened := try.To1(openEnvelope(ke, id, context, token, envelope))
			key, value := try.To2(decodePlaintext(opened))
			assert.Equal(string(key), string(tc.key))
			assert.Equal(string(value), string(tc.value))
		})
	}
}

func TestEnvelopeFixed(t *testing.T) {
	defer assert.PushTester(t)()
	ke := try.To1(hex.DecodeString(fixtureKE))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	context := try.To1(hex.DecodeString(fixtureNestedContext))
	token := [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
	envelope := try.To1(hex.DecodeString(fixtureEnvelope))
	assert.SLen(envelope, 64)
	payload := try.To1(openEnvelope(ke, id, context, token, envelope))
	assert.Equal(hex.EncodeToString(payload), fixturePlaintext)
}

func TestEnvelopeIntegrity(t *testing.T) {
	defer assert.PushTester(t)()
	ke := try.To1(hex.DecodeString(fixtureKE))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	context := try.To1(hex.DecodeString(fixtureNestedContext))
	token := [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
	envelope := try.To1(hex.DecodeString(fixtureEnvelope))
	for _, tc := range []struct {
		name string
		want error
	}{
		{"nonce", errAuthentication},
		{"ciphertext", errAuthentication},
		{"tag", errAuthentication},
		{"wrong_ke", errAuthentication},
		{"vault", errAuthentication},
		{"path", errAuthentication},
		{"token", errAuthentication},
		{"version", errIdentifier},
		{"expected_id", errIdentifier},
		{"header_and_expected_id", errAuthentication},
		{"truncated", errFormat},
		{"trailing", errFormat},
		{"ke_size", errFormat},
		{"invalid_context", errFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			key, expectedID := bytes.Clone(ke), id
			c, tok, record := bytes.Clone(context), token, bytes.Clone(envelope)
			switch tc.name {
			case "nonce":
				record[headerSize] ^= 1
			case "ciphertext":
				record[headerSize+12] ^= 1
			case "tag":
				record[len(record)-1] ^= 1
			case "wrong_ke":
				key[0] ^= 1
			case "vault":
				c[4] ^= 1
			case "path":
				c[len(c)-1] ^= 1
			case "token":
				tok[0] ^= 1
			case "version":
				record[0] = 2
			case "expected_id":
				expectedID[0] ^= 1
			case "header_and_expected_id":
				record[2] ^= 1
				expectedID[0] ^= 1
				try.To2(parseEnvelope(record, expectedID))
			case "truncated":
				record = record[:len(record)-1]
			case "trailing":
				record = append(record, 0)
			case "ke_size":
				key = key[:16] // Valid for AES, but not this AES-256 adapter.
			case "invalid_context":
				c = c[:23]
			}
			payload, err := openEnvelope(key, expectedID, c, tok, record)
			assert.Equal(err, tc.want)
			assert.SNil(payload)
		})
	}
}

func TestEnvelopeSpending(t *testing.T) {
	defer assert.PushTester(t)()
	ke := try.To1(hex.DecodeString(fixtureKE))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	context := try.To1(hex.DecodeString(fixtureNestedContext))
	token := [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
	payload := try.To1(hex.DecodeString(fixturePlaintext))

	t.Run("missing", func(t *testing.T) {
		defer assert.PushTester(t)()
		envelope, err := sealEnvelope(ke, id, context, token, payload, nil)
		assert.Equal(err, errBudget)
		assert.SNil(envelope)
	})

	t.Run("denied", func(t *testing.T) {
		defer assert.PushTester(t)()
		cause := errors.New("test spend denied")
		calls := 0
		spend := func() error {
			calls++
			return cause
		}
		envelope, err := sealEnvelope(ke, id, context, token, payload, spend)
		assert.ErrorIs(err, errBudget)
		assert.ErrorIs(err, cause)
		assert.SNil(envelope)
		assert.Equal(calls, 1)
	})

	t.Run("invalid_does_not_spend", func(t *testing.T) {
		defer assert.PushTester(t)()
		for _, tc := range []struct {
			name                 string
			ke, context, payload []byte
		}{
			{"ke_size", ke[:16], context, payload},
			{"context", ke, context[:23], payload},
			{"short_payload", ke, context, payload[:minPlaintextSize-1]},
			{"long_payload", ke, context, make([]byte, maxPlaintextSize+1)},
		} {
			t.Run(tc.name, func(t *testing.T) {
				defer assert.PushTester(t)()
				allowance := envelopeAllowance{remaining: 1}
				envelope, err := sealEnvelope(tc.ke, id, tc.context, token, tc.payload, allowance.spend)
				assert.Equal(err, errFormat)
				assert.SNil(envelope)
				assert.Equal(allowance.calls, 0)
				assert.Equal(allowance.remaining, 1)
			})
		}
	})

	t.Run("discard_and_exhaustion", func(t *testing.T) {
		defer assert.PushTester(t)()
		allowance := envelopeAllowance{remaining: 2}
		retained := try.To1(sealEnvelope(ke, id, context, token, payload, allowance.spend))
		assert.Equal(allowance.calls, 1)
		assert.Equal(allowance.remaining, 1)
		// Discarding a completed seal does not refund its allowance.
		_ = try.To1(sealEnvelope(ke, id, context, token, payload, allowance.spend))
		assert.Equal(allowance.calls, 2)
		assert.Equal(allowance.remaining, 0)
		// Further helper calls construct fresh AEADs but use the same KE allowance.
		for range 2 {
			envelope, err := sealEnvelope(ke, id, context, token, payload, allowance.spend)
			assert.ErrorIs(err, errBudget)
			assert.SNil(envelope)
		}
		assert.Equal(allowance.calls, 4)
		assert.Equal(allowance.remaining, 0)
		opened := try.To1(openEnvelope(ke, id, context, token, retained))
		assert.Equal(string(opened), string(payload))
		assert.Equal(allowance.calls, 4)
	})
}

func TestEnvelopeOwnership(t *testing.T) {
	defer assert.PushTester(t)()
	ke := try.To1(hex.DecodeString(fixtureKE))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	context := try.To1(hex.DecodeString(fixtureNestedContext))
	token := [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
	payload := try.To1(hex.DecodeString(fixturePlaintext))

	t.Run("success", func(t *testing.T) {
		defer assert.PushTester(t)()
		input := bytes.Clone(payload)
		allowance := envelopeAllowance{remaining: 1}
		envelope := try.To1(sealEnvelope(ke, id, context, token, input, allowance.spend))
		assert.Equal(hex.EncodeToString(ke), fixtureKE)
		assert.Equal(hex.EncodeToString(id[:]), fixtureID)
		assert.Equal(hex.EncodeToString(context), fixtureNestedContext)
		assert.Equal(hex.EncodeToString(token[:]), fixtureNestedToken)
		assert.Equal(hex.EncodeToString(input), fixturePlaintext)
		before := bytes.Clone(envelope)
		input[0] ^= 1
		assert.Equal(string(envelope), string(before))
		opened := try.To1(openEnvelope(ke, id, context, token, envelope))
		assert.Equal(hex.EncodeToString(opened), fixturePlaintext)
		assert.Equal(hex.EncodeToString(ke), fixtureKE)
		assert.Equal(hex.EncodeToString(id[:]), fixtureID)
		assert.Equal(hex.EncodeToString(context), fixtureNestedContext)
		assert.Equal(hex.EncodeToString(token[:]), fixtureNestedToken)
		assert.Equal(string(envelope), string(before))
		opened[0] ^= 1
		assert.Equal(string(envelope), string(before))
		later := try.To1(openEnvelope(ke, id, context, token, envelope))
		assert.Equal(hex.EncodeToString(later), fixturePlaintext)
	})

	t.Run("seal_failure", func(t *testing.T) {
		defer assert.PushTester(t)()
		allowance := envelopeAllowance{remaining: 0}
		envelope, err := sealEnvelope(ke, id, context, token, payload, allowance.spend)
		assert.ErrorIs(err, errBudget)
		assert.SNil(envelope)
		assert.Equal(hex.EncodeToString(ke), fixtureKE)
		assert.Equal(hex.EncodeToString(id[:]), fixtureID)
		assert.Equal(hex.EncodeToString(context), fixtureNestedContext)
		assert.Equal(hex.EncodeToString(token[:]), fixtureNestedToken)
		assert.Equal(hex.EncodeToString(payload), fixturePlaintext)
	})

	t.Run("open_failure", func(t *testing.T) {
		defer assert.PushTester(t)()
		envelope := try.To1(hex.DecodeString(fixtureEnvelope))
		envelope[len(envelope)-1] ^= 1
		before := bytes.Clone(envelope)
		opened, err := openEnvelope(ke, id, context, token, envelope)
		assert.Equal(err, errAuthentication)
		assert.SNil(opened)
		assert.Equal(hex.EncodeToString(ke), fixtureKE)
		assert.Equal(hex.EncodeToString(id[:]), fixtureID)
		assert.Equal(hex.EncodeToString(context), fixtureNestedContext)
		assert.Equal(hex.EncodeToString(token[:]), fixtureNestedToken)
		assert.Equal(string(envelope), string(before))
	})
}
