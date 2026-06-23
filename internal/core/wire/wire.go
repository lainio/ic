package wire

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var (
	EncMode cbor.EncMode
	DecMode cbor.DecMode

	ErrNonCanonicalCBOR = errors.New("non canonical CBOR")
)

func init() {
	var err error
	err2.Handle(&err)

	EncMode = try.To1(cbor.CoreDetEncOptions().EncMode())

	DecMode = try.To1(cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,

		// Tune to actual protocol limits.
		MaxNestedLevels: 16,
		MaxMapPairs:     64,
	}.DecMode())
}

func TryMarshal(v any) []byte {
	return try.To1(Marshal(v))
}

func Marshal(v any) ([]byte, error) {
	return EncMode.Marshal(v)
}

func TryUnmarshal(v any, data []byte) {
	try.To(Unmarshal(v, data))
}

func FromData[T any](d []byte) (v T) {
	try.To(DecMode.Unmarshal(d, &v))
	return v
}

func Unmarshal(v any, data []byte) error {
	return DecMode.Unmarshal(data, v)
}

func UnmarshalCanonical(v any, data []byte) (err error) {
	defer assert.PushAsserter(assert.Plain)() // asserts as errors
	defer err2.Handle(&err)

	try.To(DecMode.Unmarshal(data, v))
	canonical := try.To1(EncMode.Marshal(v))
	assert.That(bytes.Equal(data, canonical), ErrNonCanonicalCBOR)

	return nil
}
