package ads

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/lainio/ic/key"
)

// Only VerifyReceivedRemote calls this, after authenticating the canonical
// literal loopback endpoint. A fresh transport makes exactly one direct POST:
// no environment proxy, DNS, redirects, compression, reuse or automatic retries.
// Raw HTTP/JSON errors never enter err2 diagnostics or escape to the caller.
func requestCurrentProof(ctx context.Context, endpoint string, ad, nonce []byte) (
	proof key.Signature, err error,
) {
	body, err := json.Marshal(struct {
		Version   int    `json:"version"`
		Ad        []byte `json:"ad"`
		Challenge []byte `json:"challenge"`
	}{1, ad, nonce})
	if err != nil || len(body) > 2048 {
		return nil, ErrRemoteProof
	}
	transport := &http.Transport{
		DisableKeepAlives: true, DisableCompression: true, MaxResponseHeaderBytes: 1024,
		ReadBufferSize: 1024, // Also bounds net/http's chunked trailer parser.
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, ErrRemoteProof
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "")
	response, err := client.Do(request)
	if err != nil {
		return nil, ErrRemoteProof
	}
	defer func() {
		if response.Body.Close() != nil {
			proof, err = nil, ErrRemoteProof
		}
	}()
	media, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || mediaErr != nil || media != "application/json" ||
		len(response.Header.Values("Content-Type")) != 1 || len(response.Header.Values("Content-Encoding")) != 0 ||
		response.ContentLength > 1024 || len(response.Trailer) != 0 || len(response.Header.Values("Trailer")) != 0 {
		return nil, ErrRemoteProof
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, 1025))
	if readErr != nil || len(data) > 1024 || len(response.Trailer) != 0 || ctx.Err() != nil {
		return nil, ErrRemoteProof
	}
	return decodeProofResponse(data)
}

// Token parsing rejects duplicate/unknown fields and noninteger version
// spellings. Strict base64 plus reencoding rejects whitespace and pad-bit aliases.
func decodeProofResponse(data []byte) (key.Signature, error) {
	if len(data) > 1024 || !utf8.Valid(data) {
		return nil, ErrRemoteProof
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrRemoteProof
	}
	seen := make(map[string]bool, 2)
	var proof key.Signature
	for d.More() {
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] {
			return nil, ErrRemoteProof
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return nil, ErrRemoteProof
		}
		switch name {
		case "version":
			if value != json.Number("1") {
				return nil, ErrRemoteProof
			}
		case "proof":
			encoded, valid := value.(string)
			if !valid || encoded == "" {
				return nil, ErrRemoteProof
			}
			proof, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || base64.StdEncoding.EncodeToString(proof) != encoded {
				return nil, ErrRemoteProof
			}
		default:
			return nil, ErrRemoteProof
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || len(seen) != 2 {
		return nil, ErrRemoteProof
	}
	_, err := d.Token()
	if err != io.EOF || len(proof) == 0 || len(proof) > 72 {
		return nil, ErrRemoteProof
	}
	return proof, nil
}
