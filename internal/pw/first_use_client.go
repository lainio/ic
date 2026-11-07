package pw

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
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
	endpoint := strings.TrimSuffix(saved.endpoint, "/peer/introduction") +
		"/peer/pw/first-use"
	return sendFirstUse(ctx, 1, endpoint, saved.request)
}

// SendFirstUseV2 sends only the opaque committed Await snapshot, once, to its
// private accepted peer origin. Release all owner/signer/Vault locks first.
// No caller-selected URL, request bytes, callback or retry is accepted.
func SendFirstUseV2(ctx context.Context, saved SavedFirstUseV2) ([]byte, error) {
	if ctx == nil || len(saved.request) == 0 ||
		!canonicalServiceContact(saved.peerOrigin) {
		return nil, ErrFirstUseExchange
	}
	return sendFirstUse(ctx, 2, saved.peerOrigin+"/peer/pw/first-use",
		saved.request)
}

func sendFirstUse(ctx context.Context, version int, endpoint string,
	raw []byte,
) ([]byte, error) {
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
	var data []byte
	var err error
	if version == 1 {
		data, err = postEstablishment(ctx, client, endpoint, raw)
	} else {
		data, err = postEstablishmentVersion(ctx, client, endpoint, raw, version)
	}
	if err != nil {
		return nil, ErrFirstUseExchange
	}
	return decodeFirstUseResponse(data, version)
}

// Exact flat versioned envelope: reject duplicates, aliases, unknown fields,
// noninteger versions, trailing values and noncanonical padded base64.
func decodeFirstUseResponse(data []byte, version int) ([]byte, error) {
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
		start := d.InputOffset()
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] ||
			bytes.Contains(data[start:d.InputOffset()], []byte{'\\'}) {
			return nil, ErrFirstUseExchange
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return nil, ErrFirstUseExchange
		}
		switch name {
		case "version":
			if value != json.Number(strconv.Itoa(version)) {
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
