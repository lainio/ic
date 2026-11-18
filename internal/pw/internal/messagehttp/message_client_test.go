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
			`{"\u0076ersion":` + v + `,"receipt":"AA=="}`,
			`{"version":` + v + `,"rece\u0069pt":"AA=="}`,
			`{"\u0076ersion":` + v + `,"rece\u0069pt":"AA=="}`,
			`{"version":` + v + `,"receipt":"\u0041A\u003d="}`,
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
			`{"version":1,"Receipt":"AA=="}`,
			`{"VERSION":1,"RECEIPT":"AA=="}`,
			`{"verſion":1,"receipt":"AA=="}`,
			`{"\u0056ersion":1,"receipt":"AA=="}`,
			`{"version":1,"\u0052eceipt":"AA=="}`,
			`{"version":1,"receipt":"AA==","Receipt":"/w=="}`,
			`{"version":1,"receipt":"AA==","Version":1}`,
			`{"version":1,"receipt":"AA==","\u0078":0}`,
			`{"version":1,"receipt":"AA==","version ":1}`,
			`{"version":1,"receipt":"AA==","receipt\u0000":"AA=="}`,
			`{"version":1,"receipt":"AA==","rece\u0069pt":"AA=="}`,
			`{"version":0,"version":1,"receipt":"AA=="}`,
			`{"version":1,"receipt":"AA==","receipt":"/w=="}`,
			`{"version":1,"version":null,"receipt":"AA=="}`,
			`{"version":null,"version":1,"receipt":"AA=="}`,
			`{"version":1,"receipt":"AA==","receipt":null}`,
			`{"receipt":null,"version":1,"receipt":"AA=="}`,
			`{"version":null,"receipt":null}`,
			`{"version":1,"receipt":"AA==",}`,
			`{"version" 1,"receipt":"AA=="}`,
			`{"version":1 "receipt":"AA=="}`,
			`{"version":1,"receipt":"AA=="`,
			`{"version":1,"receipt":"\x41A=="}`,
			`{"ver\ud800sion":1,"receipt":"AA=="}`,
			`{"version":1,"receipt":"\ud800"}`,
			"{\"ver\xffsion\":1,\"receipt\":\"AA==\"}",
			"{\"version\":1,\"receipt\":\"AA==\xff\"}",
			"{\"version\":1,\"receipt\":\"AA==\n\"}",
			"\xef\xbb\xbf{\"version\":1,\"receipt\":\"AA==\"}",
			"\v{\"version\":1,\"receipt\":\"AA==\"}",
			strings.Repeat(" ", maxMessageResponseBytes+1),
		}
		// Run every original malformed-object case for each selected version.
		for i, data := range invalid {
			invalid[i] = strings.ReplaceAll(data, ":1", ":"+v)
		}
		for _, badVersion := range []string{"0", fmt.Sprint(3 - version),
			v + ".0", v + "e0", v + "E+0", "+" + v, "0" + v, "-" + v,
			v + ".", "1e999", "99999999999999999999999999999999999999",
			"true", "null", `"` + v + `"`, "{}", "[]"} {
			invalid = append(
				invalid,
				`{"version":`+badVersion+`,"receipt":"AA=="}`,
			)
		}
		for _, receipt := range []string{"null", "false", "1", "{}", "[]", "[0]",
			`""`, `"AA"`, `"AB=="`, `"_w=="`, `"AA==\n"`, `"AA== "`,
			`"AAB="`, `"//=="`, `"AA-_"`, `"AA==="`, `"AA==AA=="`,
			`"AA==\r"`, `"AA==\r\n"`, `"AA==\t"`, `"A A=="`,
			`"` + base64.StdEncoding.EncodeToString(make([]byte, receiptLimit+1)) + `"`,
		} {
			invalid = append(invalid, `{"version":`+v+`,"receipt":`+receipt+`}`)
		}
		for _, tail := range []string{
			"x", "null", "[]", "0", "\x00", "\xff", "// comment",
		} {
			invalid = append(invalid,
				`{"version":`+v+`,"receipt":"AA=="}`+tail)
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

func TestMessageClientEscapedDuplicates(t *testing.T) {
	defer assert.PushTester(t)()
	for _, version := range []int{1, 2} {
		for _, names := range [][]string{
			{"version", `\u0076ersion`, `vers\u0069on`},
			{"receipt", `rece\u0069pt`, `\u0072eceipt`},
		} {
			value, other := fmt.Sprint(version), `"receipt":"AA=="`
			if names[0] == "receipt" {
				value, other = `"AA=="`, fmt.Sprintf(`"version":%d`, version)
			}
			// Every alias order, including identical spellings and nulls.
			for _, first := range names {
				for _, second := range names {
					for _, values := range [][2]string{
						{value, value}, {value, "null"}, {"null", value},
					} {
						data := fmt.Appendf(nil, `{"%s":%s,"%s":%s,%s}`,
							first, values[0], second, values[1], other)
						raw, err := decodeMessageResponse(data, version, 640)
						assert.Equal(err, ErrOutcomeUnknown, string(data))
						assert.SNil(raw)
					}
				}
			}
		}
	}
}

func TestMessageClientReceiptValues(t *testing.T) {
	defer assert.PushTester(t)()
	for _, version := range []int{1, 2} {
		for _, tc := range []struct {
			encoded string
			want    []byte
		}{
			{`/w==`, []byte{0xff}},
			{`\/w==`, []byte{0xff}},
			{`\u002fw\u003d\u003d`, []byte{0xff}},
			{`AAA=`, []byte{0, 0}},
			{`AAAA`, []byte{0, 0, 0}},
		} {
			data := fmt.Appendf(nil, `{"version":%d,"receipt":"%s"}`,
				version, tc.encoded)
			raw, err := decodeMessageResponse(data, version, 640)
			assert.NoError(err)
			assert.DeepEqual(raw, tc.want)
		}
	}
}

func TestMessageClientResponseBodyLimits(t *testing.T) {
	defer assert.PushTester(t)()
	for _, version := range []int{1, 2} {
		for _, encoded := range []string{`AA==`, `\u0041A\u003d=`} {
			body := fmt.Sprintf(`{"version":%d,"receipt":"%s"}`,
				version, encoded)
			for _, size := range []int{2047, 2048, 2049} {
				data := "\r\n\t " + body + strings.Repeat(" ", size-len(body)-4)
				raw, err := decodeMessageResponse([]byte(data), version, 640)
				if size <= maxMessageResponseBytes {
					assert.NoError(err)
					assert.DeepEqual(raw, []byte{0})
				} else {
					assert.Equal(err, ErrOutcomeUnknown)
					assert.SNil(raw)
				}
			}
		}
		// Escapes count toward the body bound before receipt unescaping.
		for _, size := range []int{240, 300} {
			want := make([]byte, size)
			encoded := base64.StdEncoding.EncodeToString(want)
			data := fmt.Appendf(nil, `{"version":%d,"receipt":"%s"}`,
				version, strings.ReplaceAll(encoded, "A", `\u0041`))
			raw, err := decodeMessageResponse(data, version, 640)
			if size == 240 {
				assert.NoError(err)
				assert.DeepEqual(raw, want)
			} else {
				assert.Equal(err, ErrOutcomeUnknown)
				assert.SNil(raw)
			}
		}
	}
}

func TestMessageClientReceiptLimits(t *testing.T) {
	defer assert.PushTester(t)()
	for _, version := range []int{1, 2} {
		// Small limits prove the decoder uses its caller's limit. Exercise
		// both equal-length base64 overflow and the encoded-length bound.
		for _, limit := range []int{1, 2, 3, 640} {
			for _, size := range []int{
				0, 1, limit - 1, limit, limit + 1, limit + 2, limit + 3,
			} {
				want := make([]byte, size)
				data := fmt.Appendf(nil, `{"version":%d,"receipt":"%s"}`,
					version, base64.StdEncoding.EncodeToString(want))
				raw, err := decodeMessageResponse(data, version, limit)
				if size > 0 && size <= limit {
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
