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

const maxAcceptanceRequestBytes = 3 * 1024

type acceptanceRequest struct {
	requester key.Public
	ad, nonce []byte
	proof     key.Signature
}

func readAcceptanceRequest(w http.ResponseWriter, r *http.Request,
) (acceptanceRequest, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		return acceptanceRequest{}, http.StatusUnsupportedMediaType
	}
	if r.Body == nil {
		return acceptanceRequest{}, http.StatusBadRequest
	}
	data, err := io.ReadAll(
		http.MaxBytesReader(w, r.Body, maxAcceptanceRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return acceptanceRequest{}, http.StatusRequestEntityTooLarge
		}
		return acceptanceRequest{}, http.StatusBadRequest
	}
	request, ok := decodeAcceptanceRequest(data)
	if !ok {
		return acceptanceRequest{}, http.StatusBadRequest
	}
	return request, 0
}

// Token parsing retains integer spelling and rejects duplicate, unknown and
// case-alias fields. Decoder diagnostics never cross this untrusted boundary.
func decodeAcceptanceRequest(data []byte) (request acceptanceRequest, ok bool) {
	if !utf8.Valid(data) {
		return request, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return request, false
	}
	seen := make(map[string]bool, 5)
	for d.More() {
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] {
			return request, false
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return request, false
		}
		switch name {
		case "version":
			if value != json.Number("1") {
				return request, false
			}
		case "requester_public_key_hex":
			encoded, valid := value.(string)
			if !valid {
				return request, false
			}
			request.requester, valid = decodeRequesterHex(encoded)
			if !valid {
				return request, false
			}
		case "ad", "challenge", "requester_proof":
			encoded, valid := value.(string)
			if !valid || encoded == "" {
				return request, false
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
				return request, false
			}
			switch name {
			case "ad":
				request.ad = decoded
			case "challenge":
				request.nonce = decoded
			case "requester_proof":
				request.proof = decoded
			}
		default:
			return request, false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 5 {
		return request, false
	}
	_, err := d.Token()
	return request, err == io.EOF && len(request.ad) <= 1024 &&
		len(request.nonce) == 32 && len(request.proof) <= 72
}
