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
	receive func([]byte) ([]byte, error), next http.Handler,
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
		envelope, status := readMessageRequest(w, r)
		if status != 0 {
			fail(status)
			return
		}
		if len(r.Trailer) != 0 {
			fail(http.StatusBadRequest)
			return
		}
		// Preserve the exact request even if an internal callback mutates input.
		receipt, err := receive(bytes.Clone(envelope))
		if err != nil {
			fail(http.StatusConflict)
			return
		}
		if pw.ValidateLocalMessageReceipt(envelope, receipt) != nil {
			fail(http.StatusInternalServerError)
			return
		}
		document, err := json.Marshal(struct {
			Version int    `json:"version"`
			Receipt []byte `json:"receipt"`
		}{1, receipt})
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

func readMessageRequest(w http.ResponseWriter, r *http.Request) ([]byte, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		return nil, http.StatusUnsupportedMediaType
	}
	if r.Body == nil {
		return nil, http.StatusBadRequest
	}
	data, err := io.ReadAll(
		http.MaxBytesReader(w, r.Body, maxMessageRequestBytes),
	)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, http.StatusRequestEntityTooLarge
		}
		return nil, http.StatusBadRequest
	}
	envelope, ok := decodeMessageRequest(data)
	if !ok {
		return nil, http.StatusBadRequest
	}
	return envelope, 0
}

func decodeMessageRequest(data []byte) ([]byte, bool) {
	if !utf8.Valid(data) {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	seen := make(map[string]bool, 2)
	var envelope []byte
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		name, valid := token.(string)
		// Reject even a sole escaped spelling, as well as duplicate aliases.
		if err != nil || !valid || seen[name] ||
			bytes.Contains(data[start:d.InputOffset()], []byte{'\\'}) {
			return nil, false
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return nil, false
		}
		switch name {
		case "version":
			if value != json.Number("1") {
				return nil, false
			}
		case "envelope":
			encoded, valid := value.(string)
			if !valid || len(encoded) >
				base64.StdEncoding.EncodedLen(pw.MaxMessageEnvelopeBytes) {
				return nil, false
			}
			envelope, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || len(envelope) == 0 ||
				len(envelope) > pw.MaxMessageEnvelopeBytes ||
				base64.StdEncoding.EncodeToString(envelope) != encoded {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 2 {
		return nil, false
	}
	_, err := d.Token()
	return envelope, err == io.EOF
}
