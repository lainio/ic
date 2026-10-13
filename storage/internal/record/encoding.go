// Package record provides private encoding, keying, and full record validation
// for storage's proposed encrypted records. Record reads authenticate envelopes,
// decode payloads, verify HMAC lookup tokens, and compare any requested logical
// key before returning key/value bytes. The lower-level envelope adapter only
// encrypts and authenticates opaque payloads; AEAD success alone is not full
// record validation. Sealing requires spending permission but does not enforce
// a global key-usage budget. These helpers provide neither authorization, replay
// protection, nor a persistence API. Returned bytes are owned by the caller;
// inputs are neither changed nor retained.
package record

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
)

const (
	headerSize       = 22
	bodyOverhead     = 28 // Future 12-byte nonce and 16-byte tag.
	maxKeySize       = 4096
	minPlaintextSize = 9
	maxPlaintextSize = 1_048_576
	minEnvelopeSize  = headerSize + bodyOverhead + minPlaintextSize
	maxEnvelopeSize  = headerSize + bodyOverhead + maxPlaintextSize
	maxSegments      = 64
	maxSegmentSize   = 1024
	maxContextSize   = 16_384
)

var (
	errFormat     = errors.New("record: invalid input or format")
	errIdentifier = errors.New("record: unsupported or unexpected identifier")
)

func encodePlaintext(key, value []byte) (out []byte, err error) {
	if len(key) == 0 || len(key) > maxKeySize || len(value) > maxPlaintextSize-8-len(key) {
		return nil, errFormat
	}
	out = make([]byte, 8+len(key)+len(value))
	binary.BigEndian.PutUint32(out, uint32(len(key)))
	copy(out[4:], key)
	offset := 4 + len(key)
	binary.BigEndian.PutUint32(out[offset:], uint32(len(value)))
	copy(out[offset+4:], value)
	return out, nil
}

// decodePlaintext must only be used after successful authentication in a later
// Open implementation. Structural validity alone never makes a payload trusted.
// On error it returns neither a partial key nor a partial value.
func decodePlaintext(data []byte) (key, value []byte, err error) {
	defer err2.Handle(&err, nil)
	if len(data) < minPlaintextSize || len(data) > maxPlaintextSize {
		return nil, nil, errFormat
	}
	keyEnd := try.To1(fieldEnd(data, 0, maxKeySize))
	if keyEnd == 4 {
		return nil, nil, errFormat
	}
	valueEnd := try.To1(fieldEnd(data, keyEnd, maxPlaintextSize-8-(keyEnd-4)))
	if valueEnd != len(data) {
		return nil, nil, errFormat
	}
	return bytes.Clone(data[4:keyEnd]), bytes.Clone(data[keyEnd+4 : valueEnd]), nil
}

// fieldEnd checks an LP field before converting its length to int. It returns
// only an offset, so no borrowed input bytes escape a parser.
func fieldEnd(data []byte, offset, limit int) (end int, err error) {
	if offset < 0 || offset > len(data) || len(data)-offset < 4 || limit < 0 {
		return 0, errFormat
	}
	n := binary.BigEndian.Uint32(data[offset:])
	if uint64(n) > uint64(limit) || uint64(n) > uint64(len(data)-offset-4) {
		return 0, errFormat
	}
	return offset + 4 + int(n), nil
}

func encodeHeader(id [16]byte, plaintextSize int) (out []byte, err error) {
	if plaintextSize < minPlaintextSize || plaintextSize > maxPlaintextSize {
		return nil, errFormat
	}
	out = make([]byte, headerSize)
	out[0], out[1] = 1, 1
	copy(out[2:18], id[:])
	binary.BigEndian.PutUint32(out[18:], uint32(bodyOverhead+plaintextSize))
	return out, nil
}

func checkHeader(header []byte) (bodySize int, err error) {
	if len(header) != headerSize {
		return 0, errFormat
	}
	if header[0] != 1 || header[1] != 1 {
		return 0, errIdentifier
	}
	n := binary.BigEndian.Uint32(header[18:])
	if n < bodyOverhead+minPlaintextSize || n > bodyOverhead+maxPlaintextSize {
		return 0, errFormat
	}
	return int(n), nil
}

// parseEnvelope checks structure and the caller's expected KeyID only. Its
// returned header and opaque body are UNAUTHENTICATED, including after success.
// It never selects a key from the envelope or decodes its body as plaintext.
func parseEnvelope(data []byte, expectedID [16]byte) (header, body []byte, err error) {
	defer err2.Handle(&err, nil)
	if len(data) < minEnvelopeSize || len(data) > maxEnvelopeSize {
		return nil, nil, errFormat
	}
	n := try.To1(checkHeader(data[:headerSize]))
	if n != len(data)-headerSize {
		return nil, nil, errFormat
	}
	if [16]byte(data[2:18]) != expectedID {
		return nil, nil, errIdentifier
	}
	return bytes.Clone(data[:headerSize]), bytes.Clone(data[headerSize:]), nil
}

// encodeContext preserves literal segment bytes. A root has no segments;
// neither slashes nor Unicode have special meaning here.
func encodeContext(vault [16]byte, segments [][]byte) (out []byte, err error) {
	if len(segments) > maxSegments {
		return nil, errFormat
	}
	size := 4 + len(vault) + 4
	for _, segment := range segments {
		if len(segment) == 0 || len(segment) > maxSegmentSize || len(segment) > maxContextSize-size-4 {
			return nil, errFormat
		}
		size += 4 + len(segment)
	}
	out = make([]byte, 24, size)
	binary.BigEndian.PutUint32(out, uint32(len(vault)))
	copy(out[4:20], vault[:])
	binary.BigEndian.PutUint32(out[20:], uint32(len(segments)))
	for _, segment := range segments {
		out = binary.BigEndian.AppendUint32(out, uint32(len(segment)))
		out = append(out, segment...)
	}
	return out, nil
}

// checkContext parses the complete bounded encoding without allocating from
// any declared length. It checks structure, not the caller's authority/context.
func checkContext(data []byte) (err error) {
	defer err2.Handle(&err, nil)
	if len(data) < 24 || len(data) > maxContextSize {
		return errFormat
	}
	if binary.BigEndian.Uint32(data) != 16 {
		return errFormat
	}
	count := binary.BigEndian.Uint32(data[20:])
	if count > maxSegments {
		return errFormat
	}
	offset := 24
	for range count {
		end := try.To1(fieldEnd(data, offset, maxSegmentSize))
		if end == offset+4 {
			return errFormat
		}
		offset = end
	}
	if offset != len(data) {
		return errFormat
	}
	return nil
}

// encodeAAD constructs bytes for later authentication; it performs no
// authentication itself. Context and token must come from the expected location.
func encodeAAD(header, context []byte, token [32]byte) (out []byte, err error) {
	defer err2.Handle(&err, nil)
	try.To1(checkHeader(header))
	try.To(checkContext(context))
	const label = "ms/v1/record"
	out = make([]byte, 0, 4+len(label)+4+len(header)+4+len(context)+4+len(token))
	for _, field := range [][]byte{[]byte(label), header, context, token[:]} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(field)))
		out = append(out, field...)
	}
	return out, nil
}
