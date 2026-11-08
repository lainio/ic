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
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/lainio/ic/internal/localhttp"
)

const (
	messagePath             = "/peer/pw/message"
	maxMessageRequestBytes  = 4 * 1024
	maxMessageResponseBytes = 2 * 1024
)

var (
	errMessageNotDispatched  = errors.New("message not dispatched")
	errMessageOutcomeUnknown = errors.New("message peer outcome unknown")
)

// sendMessageOnce requires a fresh saveMessageTransmit result and ALL owner,
// signer and Vault locks released. It has no storage capability. An explicit
// loopback URL only routes bytes: Bob's historical ad cannot locate Alice's
// current listener. Message text is plaintext to this endpoint, suitable only
// for a trusted-host disposable demo, not production security.
//
// Exactly one POST, with no redirect, retry, proxy, cookies, credentials,
// compression or shared client state. Preflight errors mean no dispatch. Once
// Do starts, any transport/response error leaves receiver commit uncertain.
// Even HTTP 200 returns ONLY untrusted bytes: separately observeMessageReceipt
// under the sender owner lock to authenticate and save a historical ACK.
func sendMessageOnce(ctx context.Context, saved savedMessageTransmit,
	peerMessageURL string,
) ([]byte, error) {
	return sendMessageVersionOnce(ctx, saved.envelope, peerMessageURL, 1)
}

func sendMessageVersionOnce(ctx context.Context, envelope, peerMessageURL string,
	version int,
) ([]byte, error) {
	if ctx == nil || len(envelope) == 0 ||
		len(envelope) > maxMessageEnvelopeBytes ||
		(version != 1 && version != 2) ||
		!validMessageURL(peerMessageURL) || ctx.Err() != nil {
		return nil, errMessageNotDispatched
	}
	body, err := json.Marshal(struct {
		Version  int    `json:"version"`
		Envelope []byte `json:"envelope"`
	}{version, []byte(envelope)})
	if err != nil || len(body) > maxMessageRequestBytes {
		return nil, errMessageNotDispatched
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		peerMessageURL, bytes.NewReader(body))
	if err != nil {
		return nil, errMessageNotDispatched
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
		return nil, errMessageOutcomeUnknown
	}
	return readMessageResponse(ctx, response, version)
}

func validMessageURL(value string) bool {
	const prefix = "http://"
	if len(value) > 256 || !strings.HasPrefix(value, prefix) ||
		!strings.HasSuffix(value, messagePath) {
		return false
	}
	address := strings.TrimSuffix(
		strings.TrimPrefix(value, prefix),
		messagePath,
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
	version int,
) (receipt []byte, err error) {
	defer func() {
		if response.Body.Close() != nil {
			receipt, err = nil, errMessageOutcomeUnknown
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
		return nil, errMessageOutcomeUnknown
	}
	data, err := io.ReadAll(io.LimitReader(response.Body,
		maxMessageResponseBytes+1))
	if err != nil || len(data) > maxMessageResponseBytes ||
		len(response.Trailer) != 0 || ctx.Err() != nil {
		return nil, errMessageOutcomeUnknown
	}
	return decodeMessageResponse(data, version)
}

func decodeMessageResponse(data []byte, version int) ([]byte, error) {
	if len(data) > maxMessageResponseBytes || !utf8.Valid(data) {
		return nil, errMessageOutcomeUnknown
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, errMessageOutcomeUnknown
	}
	seen := make(map[string]bool, 2)
	var receipt []byte
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] ||
			bytes.Contains(data[start:d.InputOffset()], []byte{'\\'}) {
			return nil, errMessageOutcomeUnknown
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return nil, errMessageOutcomeUnknown
		}
		switch name {
		case "version":
			if (version != 1 || value != json.Number("1")) &&
				(version != 2 || value != json.Number("2")) {
				return nil, errMessageOutcomeUnknown
			}
		case "receipt":
			bound := maxMessageReceiptBytes
			if version == 2 {
				bound = maxMessageReceiptBytesV2
			}
			encoded, valid := value.(string)
			if !valid || len(encoded) >
				base64.StdEncoding.EncodedLen(bound) {
				return nil, errMessageOutcomeUnknown
			}
			receipt, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || len(receipt) == 0 ||
				len(receipt) > bound ||
				base64.StdEncoding.EncodeToString(receipt) != encoded {
				return nil, errMessageOutcomeUnknown
			}
		default:
			return nil, errMessageOutcomeUnknown
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 2 {
		return nil, errMessageOutcomeUnknown
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errMessageOutcomeUnknown
	}
	return receipt, nil
}
