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

	"github.com/lainio/ic/internal/pw"
)

const (
	maxMessageRequestBytes  = 4 * 1024
	maxMessageResponseBytes = 2 * 1024
)

// NewMessageHandler adds only POST /peer/pw/message to the opt-in loopback
// listener. The capability owns all authorization, inbox commit and signing;
// this handler receives no Vault, identities, signer or owner credentials.
// Nil disables the route. Signed envelopes carry plaintext: demo transport only.
func NewMessageHandler(
	receive func(int, []byte) ([]byte, error), next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/peer/pw/message" {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fail := func(status int) { http.Error(w, http.StatusText(status), status) }
		if receive == nil || r.URL.RawPath != "" || r.URL.Opaque != "" {
			fail(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			fail(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery ||
			r.URL.Fragment != "" || r.URL.RawFragment != "" ||
			len(r.Header.Values("Content-Encoding")) != 0 ||
			len(r.Header.Values("Transfer-Encoding")) != 0 ||
			len(r.TransferEncoding) != 0 ||
			len(r.Header.Values("Trailer")) != 0 || len(r.Trailer) != 0 {
			fail(http.StatusBadRequest)
			return
		}
		version, envelope, status := readMessageRequest(w, r)
		if status != 0 {
			fail(status)
			return
		}
		if len(r.Trailer) != 0 {
			fail(http.StatusBadRequest)
			return
		}
		// Preserve the exact request even if an internal callback mutates input.
		receipt, err := receive(version, bytes.Clone(envelope))
		if err != nil {
			fail(http.StatusConflict)
			return
		}
		if version == 2 {
			err = pw.ValidateLocalMessageReceiptV2(envelope, receipt)
		} else {
			err = pw.ValidateLocalMessageReceipt(envelope, receipt)
		}
		if err != nil {
			fail(http.StatusInternalServerError)
			return
		}
		document, err := json.Marshal(struct {
			Version int    `json:"version"`
			Receipt []byte `json:"receipt"`
		}{version, receipt})
		if err != nil || len(document) > maxMessageResponseBytes {
			fail(http.StatusInternalServerError)
			return
		}
		// Admission and signing ended, and the owner lock is released. A lost
		// reply leaves the inbox committed and sender observation unknown.
		// Never retry or undo the operation after a failed response write.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(document)
	})
}

func readMessageRequest(w http.ResponseWriter, r *http.Request) (
	int, []byte, int,
) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		return 0, nil, http.StatusUnsupportedMediaType
	}
	if r.Body == nil {
		return 0, nil, http.StatusBadRequest
	}
	data, err := io.ReadAll(
		http.MaxBytesReader(w, r.Body, maxMessageRequestBytes),
	)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return 0, nil, http.StatusRequestEntityTooLarge
		}
		return 0, nil, http.StatusBadRequest
	}
	version, envelope, ok := decodeMessageRequest(data)
	if !ok {
		return 0, nil, http.StatusBadRequest
	}
	return version, envelope, 0
}

func decodeMessageRequest(data []byte) (int, []byte, bool) {
	if !utf8.Valid(data) {
		return 0, nil, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return 0, nil, false
	}
	seen := make(map[string]bool, 2)
	var envelope []byte
	var version int
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		name, valid := token.(string)
		// Reject even a sole escaped spelling, as well as duplicate aliases.
		if err != nil || !valid || seen[name] ||
			bytes.Contains(data[start:d.InputOffset()], []byte{'\\'}) {
			return 0, nil, false
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return 0, nil, false
		}
		switch name {
		case "version":
			switch value {
			case json.Number("1"):
				version = 1
			case json.Number("2"):
				version = 2
			default:
				return 0, nil, false
			}
		case "envelope":
			encoded, valid := value.(string)
			if !valid || len(encoded) >
				base64.StdEncoding.EncodedLen(pw.MaxMessageEnvelopeBytes) {
				return 0, nil, false
			}
			envelope, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || len(envelope) == 0 ||
				len(envelope) > pw.MaxMessageEnvelopeBytes ||
				base64.StdEncoding.EncodeToString(envelope) != encoded {
				return 0, nil, false
			}
		default:
			return 0, nil, false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 2 {
		return 0, nil, false
	}
	_, err := d.Token()
	return version, envelope, err == io.EOF
}
