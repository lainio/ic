package pw

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrFirstUseExchange never says whether Bob committed his receipt.
var ErrFirstUseExchange = errors.New("first-use peer outcome unknown")

// SendFirstUse sends exactly the saved bytes once. Release every service,
// signer and Vault lock before calling. Only SaveFirstUse can supply its private
// endpoint/request; it authenticated the saved ad and committed before return.
// This operation has no Vault or signer and performs no third message or retry.
func SendFirstUse(ctx context.Context, saved SavedFirstUse) ([]byte, error) {
	if ctx == nil || len(saved.request) == 0 || saved.endpoint == "" {
		return nil, ErrFirstUseExchange
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
		"/peer/pw/first-use"
	data, err := postEstablishment(ctx, client, endpoint, saved.request)
	if err != nil {
		return nil, ErrFirstUseExchange
	}
	return decodeFirstUseResponse(data)
}

// Exact flat versioned envelope: reject duplicates, aliases, unknown fields,
// noninteger versions, trailing values and noncanonical padded base64.
func decodeFirstUseResponse(data []byte) ([]byte, error) {
	if len(data) > maxEstablishmentEnvelopeBytes || !utf8.Valid(data) {
		return nil, ErrFirstUseExchange
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrFirstUseExchange
	}
	seen := make(map[string]bool, 2)
	var response []byte
	for d.More() {
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] {
			return nil, ErrFirstUseExchange
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return nil, ErrFirstUseExchange
		}
		switch name {
		case "version":
			if value != json.Number("1") {
				return nil, ErrFirstUseExchange
			}
		case "response":
			encoded, valid := value.(string)
			if !valid {
				return nil, ErrFirstUseExchange
			}
			response, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || len(response) == 0 ||
				len(response) > MaxEstablishmentBytes ||
				base64.StdEncoding.EncodeToString(response) != encoded {
				return nil, ErrFirstUseExchange
			}
		default:
			return nil, ErrFirstUseExchange
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 2 {
		return nil, ErrFirstUseExchange
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrFirstUseExchange
	}
	return response, nil
}
