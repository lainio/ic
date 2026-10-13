package record

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

// These are independent project-format fixtures, not standard crypto vectors.
const (
	fixtureVault         = "101112131415161718191a1b1c1d1e1f"
	fixtureID            = "202122232425262728292a2b2c2d2e2f"
	fixturePlaintext     = "00000005636f756e740000000137"
	fixtureHeader        = "0101202122232425262728292a2b2c2d2e2f0000002a"
	fixtureRootContext   = "00000010101112131415161718191a1b1c1d1e1f00000000"
	fixtureNestedContext = "00000010101112131415161718191a1b1c1d1e1f0000000200000003612f620000000163"
	fixtureNestedAAD     = "0000000c6d732f76312f7265636f7264000000160101202122232425262728292a2b2c2d2e2f0000002a0000002400000010101112131415161718191a1b1c1d1e1f0000000200000003612f6200000001630000002066139daaf95cf23e867958a5498c6556240b32ac42295abf2b1760eb805a7de7"
)

func TestFormatFixed(t *testing.T) {
	defer assert.PushTester(t)()
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	plaintext := try.To1(encodePlaintext([]byte("count"), []byte("7")))
	assert.Equal(hex.EncodeToString(plaintext), fixturePlaintext)
	header := try.To1(encodeHeader(id, len(plaintext)))
	assert.Equal(hex.EncodeToString(header), fixtureHeader)
	assert.Equal(len(header), 22)
	key, value := try.To2(decodePlaintext(try.To1(hex.DecodeString(fixturePlaintext))))
	assert.Equal(string(key), "count")
	assert.Equal(string(value), "7")

	// Opaque bytes stand in for the future nonce/ciphertext/tag body.
	envelope := append(try.To1(hex.DecodeString(fixtureHeader)), make([]byte, 42)...)
	assert.Equal(len(envelope), 64)
	h, body := try.To2(parseEnvelope(envelope, id))
	assert.Equal(hex.EncodeToString(h), fixtureHeader)
	assert.Equal(len(body), 42)
}

func TestContextFixed(t *testing.T) {
	defer assert.PushTester(t)()
	vault := [16]byte(try.To1(hex.DecodeString(fixtureVault)))
	for _, tc := range []struct {
		name     string
		segments [][]byte
		want     string
	}{
		{"root", nil, fixtureRootContext},
		{"empty_path", [][]byte{}, fixtureRootContext},
		{"nested", [][]byte{[]byte("a/b"), []byte("c")}, fixtureNestedContext},
		{"binary", [][]byte{{0, 0xff, '/', 0x80}}, "00000010101112131415161718191a1b1c1d1e1f000000010000000400ff2f80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			context := try.To1(encodeContext(vault, tc.segments))
			assert.Equal(hex.EncodeToString(context), tc.want)
			try.To(checkContext(try.To1(hex.DecodeString(tc.want))))
			assert.Equal(hex.EncodeToString(try.To1(encodeContext(vault, tc.segments))), tc.want)
		})
	}
	a := try.To1(encodeContext(vault, [][]byte{[]byte("a/b"), []byte("c")}))
	b := try.To1(encodeContext(vault, [][]byte{[]byte("a"), []byte("b/c")}))
	assert.NotEqual(string(a), string(b))
	composed := try.To1(encodeContext(vault, [][]byte{{0xc3, 0xa9}}))
	decomposed := try.To1(encodeContext(vault, [][]byte{{'e', 0xcc, 0x81}}))
	assert.NotEqual(string(composed), string(decomposed))
}

func TestContextBounds(t *testing.T) {
	defer assert.PushTester(t)()
	maximumCount := make([][]byte, 64)
	for i := range maximumCount {
		maximumCount[i] = []byte("x")
	}
	maximumBytes := make([][]byte, 16)
	for i := range maximumBytes {
		maximumBytes[i] = make([]byte, 1024)
	}
	maximumBytes[15] = make([]byte, 936) // 24 + 15*(4+1024) + 4+936 = 16384.
	overBytes := append([][]byte(nil), maximumBytes...)
	overBytes[15] = make([]byte, 937)
	for _, tc := range []struct {
		name     string
		segments [][]byte
		size     int
		want     error
	}{
		{"zero_vault_root", nil, 24, nil},
		{"maximum_segment", [][]byte{make([]byte, 1024)}, 1052, nil},
		{"maximum_count", maximumCount, 344, nil},
		{"maximum_bytes", maximumBytes, 16384, nil},
		{"empty_segment", [][]byte{{}}, 0, errFormat},
		{"nil_segment", [][]byte{nil}, 0, errFormat},
		{"overlong_segment", [][]byte{make([]byte, 1025)}, 0, errFormat},
		{"excess_count", append(append([][]byte(nil), maximumCount...), []byte("x")), 0, errFormat},
		{"excess_bytes", overBytes, 0, errFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			context, err := encodeContext([16]byte{}, tc.segments)
			assert.Equal(err, tc.want)
			if tc.want != nil {
				assert.SNil(context)
			} else {
				assert.SLen(context, tc.size)
			}
			// Construct even invalid wire inputs to exercise the parser independently.
			raw := make([]byte, 24)
			binary.BigEndian.PutUint32(raw, 16)
			binary.BigEndian.PutUint32(raw[20:], uint32(len(tc.segments)))
			for _, segment := range tc.segments {
				raw = binary.BigEndian.AppendUint32(raw, uint32(len(segment)))
				raw = append(raw, segment...)
			}
			assert.Equal(checkContext(raw), tc.want)
			token, tokenErr := lookupToken(make([]byte, 32), raw, [16]byte{}, []byte("k"))
			assert.Equal(tokenErr, tc.want)
			header := try.To1(hex.DecodeString(fixtureHeader))
			aad, aadErr := encodeAAD(header, raw, token)
			assert.Equal(aadErr, tc.want)
			if tc.want != nil {
				assert.Equal(token, [32]byte{})
				assert.SNil(aad)
			} else {
				assert.SLen(aad, 82+tc.size)
			}
		})
	}
}

func TestContextMalformed(t *testing.T) {
	defer assert.PushTester(t)()
	valid := try.To1(hex.DecodeString(fixtureNestedContext))
	cases := []struct {
		name string
		data []byte
	}{
		{"trailing", append(bytes.Clone(valid), 0)},
	}
	for n := range valid {
		cases = append(cases, struct {
			name string
			data []byte
		}{"truncated_" + strconv.Itoa(n), valid[:n]})
	}
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
	}{
		{"huge_vault_length", 0, 0xffffffff},
		{"short_vault", 0, 15}, {"long_vault", 0, 17},
		{"huge_count", 20, 0xffffffff}, {"excess_count", 20, 65},
		{"missing_segment", 20, 3}, {"extra_segment", 20, 1},
		{"empty_segment", 24, 0}, {"huge_segment", 24, 0xffffffff},
		{"overlong_segment", 24, 1025},
	} {
		data := bytes.Clone(valid)
		binary.BigEndian.PutUint32(data[tc.offset:], tc.value)
		cases = append(cases, struct {
			name string
			data []byte
		}{tc.name, data})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			before := bytes.Clone(tc.data)
			assert.Equal(checkContext(tc.data), errFormat)
			token, err := lookupToken(make([]byte, 32), tc.data, [16]byte{}, []byte("k"))
			assert.Equal(err, errFormat)
			assert.Equal(token, [32]byte{})
			aad, err := encodeAAD(try.To1(hex.DecodeString(fixtureHeader)), tc.data, [32]byte{})
			assert.Equal(err, errFormat)
			assert.SNil(aad)
			assert.Equal(bytes.Equal(before, tc.data), true)
		})
	}
}

func TestAADFixedAndOwnership(t *testing.T) {
	defer assert.PushTester(t)()
	vault := [16]byte(try.To1(hex.DecodeString(fixtureVault)))
	segments := [][]byte{[]byte("a/b"), []byte("c")}
	context := try.To1(encodeContext(vault, segments))
	assert.Equal(string(segments[0]), "a/b")
	assert.Equal(string(segments[1]), "c")
	segments[0][0] = 'x'
	segments[1] = []byte("d")
	vault[0] = 0
	assert.Equal(hex.EncodeToString(context), fixtureNestedContext)
	header := try.To1(hex.DecodeString(fixtureHeader))
	token := [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
	aad1 := try.To1(encodeAAD(header, context, token))
	aad2 := try.To1(encodeAAD(header, context, token))
	assert.Equal(hex.EncodeToString(aad1), fixtureNestedAAD)
	assert.Equal(string(aad1), string(aad2))
	clear(aad1)
	assert.Equal(hex.EncodeToString(header), fixtureHeader)
	assert.Equal(hex.EncodeToString(context), fixtureNestedContext)
	assert.Equal(hex.EncodeToString(token[:]), fixtureNestedToken)
	assert.Equal(hex.EncodeToString(aad2), fixtureNestedAAD)
	aad3 := try.To1(encodeAAD(header, context, token))
	clear(header)
	clear(context)
	token[0] ^= 1
	assert.Equal(hex.EncodeToString(aad3), fixtureNestedAAD)
	vault = [16]byte(try.To1(hex.DecodeString(fixtureVault)))
	fresh := try.To1(encodeContext(vault, [][]byte{[]byte("a/b"), []byte("c")}))
	assert.Equal(hex.EncodeToString(fresh), fixtureNestedContext)
}

func TestAADValidation(t *testing.T) {
	defer assert.PushTester(t)()
	header := try.To1(hex.DecodeString(fixtureHeader))
	context := try.To1(hex.DecodeString(fixtureRootContext))
	for _, tc := range []struct {
		name            string
		header, context []byte
		want            error
	}{
		{"short_header", header[:21], context, errFormat},
		{"long_header", append(bytes.Clone(header), 0), context, errFormat},
		{"version", append([]byte{2}, header[1:]...), context, errIdentifier},
		{"suite", append([]byte{1, 2}, header[2:]...), context, errIdentifier},
		{"body_length", append(bytes.Clone(header[:18]), 0xff, 0xff, 0xff, 0xff), context, errFormat},
		{"short_context", header, context[:23], errFormat},
		{"trailing_context", header, append(bytes.Clone(context), 0), errFormat},
		{"oversized_context", header, make([]byte, 16385), errFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			aad, err := encodeAAD(tc.header, tc.context, [32]byte{})
			assert.Equal(err, tc.want)
			assert.SNil(aad)
		})
	}
}

func TestPlaintextBounds(t *testing.T) {
	defer assert.PushTester(t)()
	for _, tc := range []struct {
		name               string
		keySize, valueSize int
		want               error
	}{
		{"minimum", 1, 0, nil},
		{"maximum_key", 4096, 0, nil},
		{"maximum_plaintext", 1, 1_048_567, nil},
		{"maximum_key_and_plaintext", 4096, 1_044_472, nil},
		{"empty_key", 0, 1, errFormat},
		{"overlong_key", 4097, 0, errFormat},
		{"overlong_plaintext", 1, 1_048_568, errFormat},
		{"overlong_combined", 4096, 1_044_473, errFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			key, value := bytes.Repeat([]byte{0xa1}, tc.keySize), bytes.Repeat([]byte{0xb2}, tc.valueSize)
			out, err := encodePlaintext(key, value)
			assert.Equal(err, tc.want)
			if tc.want != nil {
				assert.SNil(out)
				return
			}
			assert.Equal(len(out), 8+tc.keySize+tc.valueSize)
			gotKey, gotValue := try.To2(decodePlaintext(out))
			assert.Equal(bytes.Equal(gotKey, key), true)
			assert.Equal(bytes.Equal(gotValue, value), true)
		})
	}
	withNil := try.To1(encodePlaintext([]byte("k"), nil))
	withEmpty := try.To1(encodePlaintext([]byte("k"), []byte{}))
	assert.Equal(hex.EncodeToString(withNil), "000000016b00000000")
	assert.Equal(string(withNil), string(withEmpty))
	key, value := try.To2(decodePlaintext(withNil))
	assert.Equal(string(key), "k")
	assert.SLen(value, 0) // A successful decode represents a present empty value.
}

func TestPlaintextMalformed(t *testing.T) {
	defer assert.PushTester(t)()
	valid := try.To1(hex.DecodeString(fixturePlaintext))
	cases := []struct {
		name string
		data []byte
	}{
		{"trailing", append(bytes.Clone(valid), 0)},
		{"zero_key", try.To1(hex.DecodeString("000000000000000137"))},
		{"huge_key", try.To1(hex.DecodeString("ffffffff636f756e740000000137"))},
		{"huge_value", try.To1(hex.DecodeString("00000005636f756e74ffffffff37"))},
		{"short_key", try.To1(hex.DecodeString("00000010636f756e740000000137"))},
		{"short_value", try.To1(hex.DecodeString("00000005636f756e740000000237"))},
		{"overlong_plaintext", make([]byte, 1_048_577)},
	}
	longKey := make([]byte, 4+4097+4)
	binary.BigEndian.PutUint32(longKey, 4097)
	cases = append(cases, struct {
		name string
		data []byte
	}{"overlong_key", longKey})
	for n := range valid {
		cases = append(cases, struct {
			name string
			data []byte
		}{"truncated_" + strconv.Itoa(n), valid[:n]})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			before := bytes.Clone(tc.data)
			key, value, err := decodePlaintext(tc.data)
			assert.Equal(err, errFormat)
			assert.SNil(key)
			assert.SNil(value)
			assert.Equal(bytes.Equal(tc.data, before), true)
		})
	}
}

func TestEnvelopeBounds(t *testing.T) {
	defer assert.PushTester(t)()
	// Zero identifiers are valid, including at both envelope size boundaries.
	for _, size := range []int{9, 1_048_576} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			defer assert.PushTester(t)()
			h := try.To1(encodeHeader([16]byte{}, size))
			assert.Equal(binary.BigEndian.Uint32(h[18:]), uint32(28+size))
			data := append(bytes.Clone(h), make([]byte, 28+size)...)
			gotHeader, body := try.To2(parseEnvelope(data, [16]byte{}))
			assert.Equal(len(data), 50+size)
			assert.Equal(string(gotHeader), string(h))
			assert.Equal(len(body), 28+size)
		})
	}
	for _, size := range []int{-1, 0, 8, 1_048_577, int(^uint(0) >> 1)} {
		t.Run("invalid_"+strconv.Itoa(size), func(t *testing.T) {
			defer assert.PushTester(t)()
			h, err := encodeHeader([16]byte{}, size)
			assert.Equal(err, errFormat)
			assert.SNil(h)
		})
	}
}

func TestEnvelopeMalformed(t *testing.T) {
	defer assert.PushTester(t)()
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	valid := append(try.To1(hex.DecodeString(fixtureHeader)), make([]byte, 42)...)
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"trailing", append(bytes.Clone(valid), 0), errFormat},
		{"oversized", make([]byte, 1_048_627), errFormat},
	}
	for n := range valid {
		cases = append(cases, struct {
			name string
			data []byte
			want error
		}{"truncated_" + strconv.Itoa(n), valid[:n], errFormat})
	}
	for _, tc := range []struct {
		name   string
		offset int
		value  byte
	}{
		{"zero_version", 0, 0}, {"future_version", 0, 2},
		{"zero_suite", 1, 0}, {"future_suite", 1, 2}, {"unexpected_id", 2, 0},
	} {
		data := bytes.Clone(valid)
		data[tc.offset] = tc.value
		cases = append(cases, struct {
			name string
			data []byte
			want error
		}{tc.name, data, errIdentifier})
	}
	for _, size := range []uint32{0, 36, 41, 43, 1_048_605, 0xffffffff} {
		data := bytes.Clone(valid)
		binary.BigEndian.PutUint32(data[18:], size)
		cases = append(cases, struct {
			name string
			data []byte
			want error
		}{"body_length_" + strconv.FormatUint(uint64(size), 10), data, errFormat})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			before := bytes.Clone(tc.data)
			header, body, err := parseEnvelope(tc.data, id)
			assert.Equal(err, tc.want)
			assert.SNil(header)
			assert.SNil(body)
			assert.Equal(bytes.Equal(tc.data, before), true)
		})
	}
	_, _, err := parseEnvelope(valid, [16]byte{})
	assert.Equal(err, errIdentifier)
}

func TestFormatOwnership(t *testing.T) {
	defer assert.PushTester(t)()
	key, value := []byte("count"), []byte("7")
	encoded := try.To1(encodePlaintext(key, value))
	assert.Equal(string(key), "count")
	assert.Equal(string(value), "7")
	key[0], value[0] = 'x', 'x'
	assert.Equal(hex.EncodeToString(encoded), fixturePlaintext)
	firstKey, firstValue := try.To2(decodePlaintext(encoded))
	secondKey, secondValue := try.To2(decodePlaintext(encoded))
	firstKey[0], firstValue[0] = 'y', 'y'
	assert.Equal(string(secondKey), "count")
	assert.Equal(string(secondValue), "7")
	assert.Equal(hex.EncodeToString(encoded), fixturePlaintext)
	thirdKey, thirdValue := try.To2(decodePlaintext(encoded))
	clear(encoded)
	assert.Equal(string(thirdKey), "count")
	assert.Equal(string(thirdValue), "7")
	assert.Equal(hex.EncodeToString(try.To1(encodePlaintext([]byte("count"), []byte("7")))), fixturePlaintext)

	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	header := try.To1(encodeHeader(id, 14))
	data := append(bytes.Clone(header), bytes.Repeat([]byte{0xa5}, 42)...)
	before := bytes.Clone(data)
	h1, b1 := try.To2(parseEnvelope(data, id))
	h2, b2 := try.To2(parseEnvelope(data, id))
	assert.Equal(bytes.Equal(data, before), true)
	h1[0], b1[0] = 0, 0
	assert.Equal(string(h2), string(header))
	assert.Equal(bytes.Equal(b2, bytes.Repeat([]byte{0xa5}, 42)), true)
	assert.Equal(bytes.Equal(data, before), true)
	h3, b3 := try.To2(parseEnvelope(data, id))
	clear(data)
	clear(header)
	id[0] = 0
	assert.Equal(hex.EncodeToString(h3), fixtureHeader)
	assert.Equal(bytes.Equal(b3, bytes.Repeat([]byte{0xa5}, 42)), true)
}
