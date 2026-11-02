package pw

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

const maxEstablishmentEnvelopeBytes = 3 * 1024

// ErrEstablishmentExchange does not establish whether Bob committed. Never
// expose transport diagnostics or response bytes, or automatically retry it.
var ErrEstablishmentExchange = errors.New("establishment outcome unknown")

// SendEstablish sends exactly the saved bytes once. Release every service,
// signer and Vault lock before calling. Only SaveAttempt can supply its private
// endpoint/request; it authenticated the local ad and committed before return.
// This operation has no Vault or signer and performs no third message or retry.
func SendEstablish(ctx context.Context, saved SavedAttempt) ([]byte, error) {
	if ctx == nil || len(saved.request) == 0 || saved.endpoint == "" {
		return nil, ErrEstablishmentExchange
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	transport := &http.Transport{
		DisableKeepAlives: true, DisableCompression: true,
		MaxResponseHeaderBytes: 1024, ReadBufferSize: 1024,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	endpoint := strings.TrimSuffix(saved.endpoint, "/peer/introduction") +
		"/peer/pw/establish"
	data, err := postEstablishment(ctx, client, endpoint, saved.request)
	if err != nil {
		return nil, err
	}
	return decodeEstablishmentResponse(data)
}

// One direct POST, with no replayable body, cookies, credentials or proxy.
// Keep raw transport/JSON/provider diagnostics outside err2 tracing entirely.
func postEstablishment(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	raw []byte,
) (data []byte, err error) {
	body, err := json.Marshal(struct {
		Version int    `json:"version"`
		Request []byte `json:"request"`
	}{1, raw})
	if err != nil || len(body) > maxEstablishmentEnvelopeBytes {
		return nil, ErrEstablishmentExchange
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		bytes.NewReader(body))
	if err != nil {
		return nil, ErrEstablishmentExchange
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "")
	response, err := client.Do(request)
	if err != nil {
		return nil, ErrEstablishmentExchange
	}
	defer func() {
		if response.Body.Close() != nil {
			data, err = nil, ErrEstablishmentExchange
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
		response.ContentLength > maxEstablishmentEnvelopeBytes || len(response.Trailer) != 0 ||
		len(response.Header.Values("Trailer")) != 0 {
		return nil, ErrEstablishmentExchange
	}
	data, err = io.ReadAll(
		io.LimitReader(response.Body, maxEstablishmentEnvelopeBytes+1),
	)
	if err != nil || len(data) > maxEstablishmentEnvelopeBytes ||
		len(response.Trailer) != 0 ||
		ctx.Err() != nil {
		return nil, ErrEstablishmentExchange
	}
	return data, nil
}

// Exact flat versioned envelope: reject duplicates, aliases, unknown fields,
// noninteger versions, trailing values and noncanonical padded base64.
func decodeEstablishmentResponse(data []byte) ([]byte, error) {
	if len(data) > maxEstablishmentEnvelopeBytes || !utf8.Valid(data) {
		return nil, ErrEstablishmentExchange
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrEstablishmentExchange
	}
	seen := make(map[string]bool, 2)
	var response []byte
	for d.More() {
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] {
			return nil, ErrEstablishmentExchange
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return nil, ErrEstablishmentExchange
		}
		switch name {
		case "version":
			if value != json.Number("1") {
				return nil, ErrEstablishmentExchange
			}
		case "acceptance":
			encoded, valid := value.(string)
			if !valid {
				return nil, ErrEstablishmentExchange
			}
			response, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || len(response) == 0 ||
				len(response) > MaxEstablishmentBytes ||
				base64.StdEncoding.EncodeToString(response) != encoded {
				return nil, ErrEstablishmentExchange
			}
		default:
			return nil, ErrEstablishmentExchange
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 2 {
		return nil, ErrEstablishmentExchange
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrEstablishmentExchange
	}
	return response, nil
}
