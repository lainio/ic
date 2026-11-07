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
	"strconv"
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
	endpoint := strings.TrimSuffix(saved.endpoint, "/peer/introduction") +
		"/peer/pw/establish"
	return sendEstablishment(ctx, 1, endpoint, saved.request)
}

// SendEstablishV2 sends only a committed SaveAttemptV2 snapshot. Its private
// signed TargetContact supplies the destination; callers supply no URL or raw
// request. Release owner/signer/Vault locks first. Failure leaves the outcome
// unknown and the saved bytes available for a later explicit owner retry.
func SendEstablishV2(
	ctx context.Context,
	saved SavedAttemptV2,
) ([]byte, error) {
	var request SignedEstablishmentV2
	if ctx == nil ||
		decodeEstablishmentCanonical(saved.request, &request) != nil {
		return nil, ErrEstablishmentExchange
	}
	request, err := decodeEstablishmentV2(saved.request,
		request.Payload.Root, request.Payload.Target)
	if err != nil {
		return nil, ErrEstablishmentExchange
	}
	endpoint := request.Payload.TargetContact + "/peer/pw/establish"
	return sendEstablishment(ctx, 2, endpoint, saved.request)
}

func sendEstablishment(ctx context.Context, version int, endpoint string,
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
	data, err := postEstablishmentVersion(ctx, client, endpoint, raw, version)
	if err != nil {
		return nil, err
	}
	return decodeEstablishmentResponse(data, version)
}

// The existing first-use transport retains its exact version-1 envelope.
func postEstablishment(ctx context.Context, client *http.Client,
	endpoint string, raw []byte,
) ([]byte, error) {
	return postEstablishmentVersion(ctx, client, endpoint, raw, 1)
}

// One direct POST, with no replayable body, cookies, credentials or proxy.
// Keep raw transport/JSON/provider diagnostics outside err2 tracing entirely.
func postEstablishmentVersion(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	raw []byte,
	version int,
) (data []byte, err error) {
	body, err := json.Marshal(struct {
		Version int    `json:"version"`
		Request []byte `json:"request"`
	}{version, raw})
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
func decodeEstablishmentResponse(data []byte, version int) ([]byte, error) {
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
		start := d.InputOffset()
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] ||
			bytes.Contains(data[start:d.InputOffset()], []byte{'\\'}) {
			return nil, ErrEstablishmentExchange
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return nil, ErrEstablishmentExchange
		}
		switch name {
		case "version":
			if value != json.Number(strconv.Itoa(version)) {
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
