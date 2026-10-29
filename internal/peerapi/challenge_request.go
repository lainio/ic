package peerapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/lainio/ic/key"
)

const maxChallengeRequestBytes = 2 * 1024

func readChallengeRequest(
	w http.ResponseWriter,
	r *http.Request,
) (key.Public, []byte, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		return nil, nil, http.StatusUnsupportedMediaType
	}
	if r.Body == nil {
		return nil, nil, http.StatusBadRequest
	}
	data, err := io.ReadAll(
		http.MaxBytesReader(w, r.Body, maxChallengeRequestBytes),
	)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, nil, http.StatusRequestEntityTooLarge
		}
		return nil, nil, http.StatusBadRequest
	}
	requester, ad, ok := decodeChallengeRequest(data)
	if !ok {
		return nil, nil, http.StatusBadRequest
	}
	return requester, ad, 0
}

// Token parsing preserves integer spelling and rejects duplicate/case/unknown
// fields. Only a selector and the canonical inner ad are accepted, never a
// caller nonce, URL, clock, purpose, signing input or requester proof.
func decodeChallengeRequest(
	data []byte,
) (requester key.Public, ad []byte, ok bool) {
	if !utf8.Valid(data) {
		return nil, nil, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, nil, false
	}
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] {
			return nil, nil, false
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return nil, nil, false
		}
		switch name {
		case "version":
			if value != json.Number("1") {
				return nil, nil, false
			}
		case "requester_public_key_hex":
			encoded, valid := value.(string)
			if !valid {
				return nil, nil, false
			}
			requester, valid = decodeRequesterHex(encoded)
			if !valid {
				return nil, nil, false
			}
		case "ad":
			encoded, valid := value.(string)
			if !valid {
				return nil, nil, false
			}
			ad, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || len(ad) == 0 || len(ad) > 1024 ||
				base64.StdEncoding.EncodeToString(ad) != encoded {
				return nil, nil, false
			}
		default:
			return nil, nil, false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 3 {
		return nil, nil, false
	}
	_, err := d.Token()
	return requester, ad, err == io.EOF
}
