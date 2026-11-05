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

	"github.com/golang/glog"
	"github.com/lainio/ic/internal/pw"
)

const maxEstablishmentEnvelopeBytes = 3 * 1024

// NewEstablishmentHandler adds only POST /peer/pw/establish to the opted-in
// peer surface. The owner-managed capability authenticates the canonical signed
// request and performs BobAccept (if new) then BobReply under its service lock.
// No signer, owner credentials or generic Vault access cross this boundary.
// A nil capability disables this route, preserving the existing proof routes.
func NewEstablishmentHandler(
	establish func([]byte) ([]byte, error), next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/peer/pw/establish" || establish == nil {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fail := func(status int) { http.Error(w, http.StatusText(status), status) }
		if r.URL.RawPath != "" || r.URL.Opaque != "" {
			fail(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			fail(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery ||
			r.URL.Fragment != "" || r.URL.RawFragment != "" {
			fail(http.StatusBadRequest)
			return
		}
		request, status := readEstablishmentRequest(w, r)
		if status != 0 {
			fail(status)
			return
		}
		glog.V(1).Info("intro_pw op=establish side=acceptor " +
			"stage=request result=accepted")
		acceptance, err := establish(request)
		if err != nil {
			glog.V(1).Info("intro_pw op=establish side=acceptor " +
				"stage=local result=refused reason=undetermined")
			fail(http.StatusConflict)
			return
		}
		if len(acceptance) == 0 || len(acceptance) > pw.MaxEstablishmentBytes {
			fail(http.StatusInternalServerError)
			return
		}
		document, err := json.Marshal(struct {
			Version    int    `json:"version"`
			Acceptance []byte `json:"acceptance"`
		}{1, acceptance})
		if err != nil || len(document) > maxEstablishmentEnvelopeBytes {
			fail(http.StatusInternalServerError)
			return
		}
		// Both local transitions and the service lock have ended. A failed
		// write cannot roll back consumption or trigger acceptance signing.
		glog.V(1).Info("intro_pw op=establish side=acceptor " +
			"stage=response result=prepared")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(document)
	})
}

func readEstablishmentRequest(w http.ResponseWriter, r *http.Request,
) ([]byte, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		return nil, http.StatusUnsupportedMediaType
	}
	if r.Body == nil {
		return nil, http.StatusBadRequest
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body,
		maxEstablishmentEnvelopeBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, http.StatusRequestEntityTooLarge
		}
		return nil, http.StatusBadRequest
	}
	request, ok := decodeEstablishmentRequest(data)
	if !ok {
		return nil, http.StatusBadRequest
	}
	return request, 0
}

func decodeEstablishmentRequest(data []byte) ([]byte, bool) {
	if !utf8.Valid(data) {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	seen := make(map[string]bool, 2)
	var request []byte
	for d.More() {
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] {
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
		case "request":
			encoded, valid := value.(string)
			if !valid {
				return nil, false
			}
			request, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || len(request) == 0 ||
				len(request) > pw.MaxEstablishmentBytes ||
				base64.StdEncoding.EncodeToString(request) != encoded {
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
	return request, err == io.EOF
}
