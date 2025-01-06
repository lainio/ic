package nconn

import (
	"bytes"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// CBOREncoder is a CBOR Encoder implementation for EncodedConn.
type CBOREncoder struct{}

const CBOR_DECODER = "cbor" //nolint:stylecheck

var ourCodec = &CBOREncoder{}

// Encode
func (je *CBOREncoder) Encode(subject string, v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := cbor.NewEncoder(&buf)

	err := enc.Encode(v)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Decode
func (je *CBOREncoder) Decode(subject string, data []byte, vPtr any) (err error) {
	switch arg := vPtr.(type) {
	case *string:
		// TODO: CBOR is binary protocol, study sthis an remove it?
		//
		// If they want a string and it is a CBOR string, strip quotes
		// This allows someone to send a struct but receive as a plain string
		// This cast should be efficient for Go 1.3 and beyond.
		str := string(data)
		if strings.HasPrefix(str, `"`) && strings.HasSuffix(str, `"`) {
			*arg = str[1 : len(str)-1]
		} else {
			*arg = str
		}
	case *[]byte:
		*arg = data
	default:
		r := bytes.NewReader(data)
		enc := cbor.NewDecoder(r)
		err = enc.Decode(vPtr)
	}
	return
}
