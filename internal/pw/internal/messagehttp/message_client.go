// Package messagehttp performs bounded message HTTP dispatch without protocol
// authority. Successful responses contain untrusted receipt bytes only.
package messagehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lainio/ic/internal/localhttp"
)

// Path is the fixed peer message route.
const Path = "/peer/pw/message"

const (
	maxMessageRequestBytes  = 4 * 1024
	maxMessageResponseBytes = 2 * 1024
)

var (
	// ErrNotDispatched means HTTP dispatch did not start.
	ErrNotDispatched = errors.New("message not dispatched")
	// ErrOutcomeUnknown means dispatch started; receiver commit is uncertain.
	ErrOutcomeUnknown = errors.New("message peer outcome unknown")
)

// Send requires PW to supply a non-nil, live context, a nonempty envelope
// within its domain byte bound, an endpoint accepted by ValidURL, version 1 or
// 2, and that version's positive decoded-receipt byte limit. All owner, signer
// and Vault locks must be released. Send has no protocol state or authority.
//
// It makes one POST without redirects or retries. Errors before client.Do are
// ErrNotDispatched; any failure once Do starts is ErrOutcomeUnknown and cannot
// establish whether the receiver committed. Success returns untrusted bytes.
func Send(ctx context.Context, envelope, peerMessageURL string,
	version, receiptLimit int,
) ([]byte, error) {
	body, err := json.Marshal(struct {
		Version  int    `json:"version"`
		Envelope []byte `json:"envelope"`
	}{version, []byte(envelope)})
	if err != nil || len(body) > maxMessageRequestBytes {
		return nil, ErrNotDispatched
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		peerMessageURL, bytes.NewReader(body))
	if err != nil {
		return nil, ErrNotDispatched
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "")
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
	response, err := client.Do(request)
	if err != nil {
		return nil, ErrOutcomeUnknown
	}
	return readMessageResponse(ctx, response, version, receiptLimit)
}

// ValidURL checks the exact canonical numeric loopback message URL.
func ValidURL(value string) bool {
	const prefix = "http://"
	if len(value) > 256 || !strings.HasPrefix(value, prefix) ||
		!strings.HasSuffix(value, Path) {
		return false
	}
	address := strings.TrimSuffix(
		strings.TrimPrefix(value, prefix),
		Path,
	)
	parsed, err := netip.ParseAddrPort(address)
	if err != nil || parsed.Port() == 0 || !parsed.Addr().IsLoopback() ||
		parsed.Addr().Zone() != "" ||
		address != netip.AddrPortFrom(parsed.Addr().Unmap(), parsed.Port()).
			String() {
		return false
	}
	// Prevalidate without tracing: Address's underlying parse errors can carry
	// untrusted input. Only a known canonical literal reaches the shared check.
	normalized, err := localhttp.Address(address, false)
	return err == nil && normalized == address
}

// Raw provider, URL, HTTP and JSON errors never enter err2 diagnostic tracing.
func readMessageResponse(ctx context.Context, response *http.Response,
	version, receiptLimit int,
) (receipt []byte, err error) {
	defer func() {
		if response.Body.Close() != nil {
			receipt, err = nil, ErrOutcomeUnknown
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
		response.ContentLength > maxMessageResponseBytes ||
		len(response.Trailer) != 0 ||
		len(response.Header.Values("Trailer")) != 0 {
		return nil, ErrOutcomeUnknown
	}
	data, err := io.ReadAll(io.LimitReader(response.Body,
		maxMessageResponseBytes+1))
	if err != nil || len(data) > maxMessageResponseBytes ||
		len(response.Trailer) != 0 || ctx.Err() != nil {
		return nil, ErrOutcomeUnknown
	}
	return decodeMessageResponse(data, version, receiptLimit)
}

func decodeMessageResponse(data []byte, version, receiptLimit int,
) ([]byte, error) {
	if len(data) > maxMessageResponseBytes || !utf8.Valid(data) {
		return nil, ErrOutcomeUnknown
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrOutcomeUnknown
	}
	seen := make(map[string]bool, 2)
	var receipt []byte
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] ||
			bytes.Contains(data[start:d.InputOffset()], []byte{'\\'}) {
			return nil, ErrOutcomeUnknown
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return nil, ErrOutcomeUnknown
		}
		switch name {
		case "version":
			if (version != 1 || value != json.Number("1")) &&
				(version != 2 || value != json.Number("2")) {
				return nil, ErrOutcomeUnknown
			}
		case "receipt":
			encoded, valid := value.(string)
			if !valid || len(encoded) >
				base64.StdEncoding.EncodedLen(receiptLimit) {
				return nil, ErrOutcomeUnknown
			}
			receipt, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || len(receipt) == 0 ||
				len(receipt) > receiptLimit ||
				base64.StdEncoding.EncodeToString(receipt) != encoded {
				return nil, ErrOutcomeUnknown
			}
		default:
			return nil, ErrOutcomeUnknown
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 2 {
		return nil, ErrOutcomeUnknown
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrOutcomeUnknown
	}
	return receipt, nil
}
