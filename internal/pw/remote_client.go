package pw

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/lainio/ic/key"
)

// These private wire shapes mirror peerapi without importing the server, which
// itself depends on pw. Callers can supply neither messages nor transport.
type exchangeRequest struct {
	Version   int           `json:"version"`
	Requester string        `json:"requester_public_key_hex"`
	Ad        []byte        `json:"ad"`
	Challenge []byte        `json:"challenge,omitempty"`
	Proof     key.Signature `json:"requester_proof,omitempty"`
}

type exchangeResponse struct {
	nonce   []byte
	expires int64
	proof   key.Signature
}

// One direct POST, with no replayable body, cookies, credentials or proxy.
// Keep raw transport/JSON/provider diagnostics outside err2 tracing entirely.
func postExchange(ctx context.Context, client *http.Client, endpoint string,
	message exchangeRequest, limit int,
) (data []byte, err error) {
	body, err := json.Marshal(message)
	if err != nil || len(body) > limit {
		return nil, ErrRemoteAcceptance
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		bytes.NewReader(body))
	if err != nil {
		return nil, ErrRemoteAcceptance
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "")
	response, err := client.Do(request)
	if err != nil {
		return nil, ErrRemoteAcceptance
	}
	defer func() {
		if response.Body.Close() != nil {
			data, err = nil, ErrRemoteAcceptance
		}
	}()
	media, _, mediaErr := mime.ParseMediaType(
		response.Header.Get("Content-Type"),
	)
	if response.StatusCode != http.StatusOK || mediaErr != nil ||
		media != "application/json" ||
		len(response.Header.Values("Content-Type")) != 1 ||
		len(response.Header.Values("Cache-Control")) != 1 ||
		response.Header.Get("Cache-Control") != "no-store" ||
		len(response.Header.Values("Content-Encoding")) != 0 ||
		response.ContentLength > 1024 || len(response.Trailer) != 0 ||
		len(response.Header.Values("Trailer")) != 0 {
		return nil, ErrRemoteAcceptance
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(data) > 1024 || len(response.Trailer) != 0 ||
		ctx.Err() != nil {
		return nil, ErrRemoteAcceptance
	}
	return data, nil
}

// Parse only the two flat protocol objects. Token parsing retains exact integer
// version spelling and rejects duplicates, case aliases, unknown fields and
// trailing values. Canonical padded base64 excludes newline and pad-bit aliases.
func decodeExchangeResponse(
	data []byte,
	challenge bool,
) (exchangeResponse, error) {
	var result exchangeResponse
	fail := func() (exchangeResponse, error) {
		return exchangeResponse{}, ErrRemoteAcceptance
	}
	if len(data) > 1024 || !utf8.Valid(data) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return fail()
	}
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] {
			return fail()
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return fail()
		}
		switch name {
		case "version":
			if value != json.Number("1") {
				return fail()
			}
		case "expires_unix_nano":
			number, valid := value.(json.Number)
			if !challenge || !valid {
				return fail()
			}
			result.expires, err = number.Int64()
			if err != nil {
				return fail()
			}
		case "challenge", "acceptor_proof":
			encoded, valid := value.(string)
			if !valid || (name == "challenge") != challenge {
				return fail()
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil ||
				base64.StdEncoding.EncodeToString(decoded) != encoded {
				return fail()
			}
			if challenge {
				result.nonce = decoded
			} else {
				result.proof = decoded
			}
		default:
			return fail()
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return fail()
	}
	_, err := d.Token()
	if err != io.EOF || !seen["version"] ||
		(challenge && (len(seen) != 3 || len(result.nonce) != 32)) ||
		(!challenge && (len(seen) != 2 || len(result.proof) == 0 ||
			len(result.proof) > 72)) {
		return fail()
	}
	return result, nil
}
