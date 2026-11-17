package messagehttp

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

func TestMessageClientStrictJSON(t *testing.T) {
	defer assert.PushTester(t)()
	const receiptLimit = 640
	for _, version := range []int{1, 2} {
		v := fmt.Sprint(version)
		for _, data := range []string{
			`{"version":` + v + `,"receipt":"AA=="}`,
			" \n { \"receipt\":\"AA==\", \"version\":" + v + " } \t",
		} {
			assert.DeepEqual(
				try.To1(
					decodeMessageResponse([]byte(data), version, receiptLimit),
				),
				[]byte{0},
			)
		}
		invalid := []string{
			"", "null", "[]", "{}", "{", "\xff", `{"version":1}`,
			`{"receipt":"AA=="}`, `{"version":1,"receipt":"AA=="} {}`,
			`{"version":1,"receipt":"AA==","unknown":0}`,
			`{"version":1,"version":1,"receipt":"AA=="}`,
			`{"version":1,"receipt":"AA==","receipt":"AA=="}`,
			`{"Version":1,"receipt":"AA=="}`,
			`{"\u0076ersion":1,"receipt":"AA=="}`,
			`{"version":1,"rece\u0069pt":"AA=="}`,
			`{"version":1,"receipt":"AA==","rece\u0069pt":"AA=="}`,
			`{"version":1,"receipt":"AA==",}`,
			strings.Repeat(" ", maxMessageResponseBytes+1),
		}
		// Run every original malformed-object case for each selected version.
		for i, data := range invalid {
			invalid[i] = strings.ReplaceAll(data, ":1", ":"+v)
		}
		for _, badVersion := range []string{"0", fmt.Sprint(3 - version),
			v + ".0", v + "e0", "true", "null", `"` + v + `"`, "{}", "[]"} {
			invalid = append(
				invalid,
				`{"version":`+badVersion+`,"receipt":"AA=="}`,
			)
		}
		for _, receipt := range []string{"null", "false", "1", "{}", "[]",
			`""`, `"AA"`, `"AB=="`, `"_w=="`, `"AA==\n"`, `"AA== "`,
			`"` + base64.StdEncoding.EncodeToString(make([]byte, receiptLimit+1)) + `"`,
		} {
			invalid = append(invalid, `{"version":`+v+`,"receipt":`+receipt+`}`)
		}
		for i, data := range invalid {
			raw, err := decodeMessageResponse(
				[]byte(data),
				version,
				receiptLimit,
			)
			assert.Equal(err, ErrOutcomeUnknown, fmt.Sprint(i))
			assert.SNil(raw)
		}
	}
}

func TestMessageClientReceiptLimits(t *testing.T) {
	defer assert.PushTester(t)()
	for _, version := range []int{1, 2} {
		// Small limits prove the decoder uses its caller's limit. Exercise
		// both equal-length base64 overflow and the encoded-length bound.
		for _, limit := range []int{1, 2, 3, 640} {
			for _, size := range []int{0, limit, limit + 1, limit + 3} {
				want := make([]byte, size)
				data := fmt.Appendf(nil, `{"version":%d,"receipt":"%s"}`,
					version, base64.StdEncoding.EncodeToString(want))
				raw, err := decodeMessageResponse(data, version, limit)
				if size == limit {
					assert.NoError(err)
					assert.DeepEqual(raw, want)
				} else {
					assert.Equal(err, ErrOutcomeUnknown)
					assert.SNil(raw)
				}
			}
		}
	}
}
