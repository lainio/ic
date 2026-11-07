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

type establishmentRequest struct {
	version int
	raw     []byte
}

// NewEstablishmentHandler adds only POST /peer/pw/establish to the opted-in
// peer surface. The owner-managed capability authenticates the canonical signed
// request and performs BobAccept (if new) then BobReply under its service lock.
// No signer, owner credentials or generic Vault access cross this boundary.
// A nil capability disables this route, preserving the existing proof routes.
func NewEstablishmentHandler(
	establish func(int, []byte) ([]byte, error), next http.Handler,
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
		request, status := readVersionedEstablishmentRequest(w, r)
		if status != 0 {
			fail(status)
			return
		}
		glog.V(1).Info("intro_pw op=establish side=acceptor " +
			"stage=request result=accepted")
		// The capability verifies this selected canonical signed format under
		// pinned identities before effects; the envelope alone grants nothing.
		acceptance, err := establish(request.version, request.raw)
		if err != nil {
			glog.V(1).Info("intro_pw op=establish side=acceptor " +
				"stage=local result=refused reason=undetermined")
			fail(http.StatusConflict)
			return
		}
		if len(acceptance) == 0 ||
			len(acceptance) > pw.MaxEstablishmentBytes {
			fail(http.StatusInternalServerError)
			return
		}
		document, err := json.Marshal(struct {
			Version    int    `json:"version"`
			Acceptance []byte `json:"acceptance"`
		}{request.version, acceptance})
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

func readVersionedEstablishmentRequest(w http.ResponseWriter, r *http.Request,
) (establishmentRequest, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 ||
		len(r.Header.Values("Content-Encoding")) != 0 {
		return establishmentRequest{}, http.StatusUnsupportedMediaType
	}
	if r.Body == nil {
		return establishmentRequest{}, http.StatusBadRequest
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body,
		maxEstablishmentEnvelopeBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return establishmentRequest{}, http.StatusRequestEntityTooLarge
		}
		return establishmentRequest{}, http.StatusBadRequest
	}
	request, ok := decodeEstablishmentRequest(data)
	if !ok {
		return establishmentRequest{}, http.StatusBadRequest
	}
	return request, 0
}

func decodeEstablishmentRequest(data []byte) (establishmentRequest, bool) {
	var request establishmentRequest
	if !utf8.Valid(data) {
		return request, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return request, false
	}
	seen := make(map[string]bool, 2)
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] ||
			bytes.Contains(data[start:d.InputOffset()], []byte{'\\'}) {
			return request, false
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return request, false
		}
		switch name {
		case "version":
			switch value {
			case json.Number("1"):
				request.version = 1
			case json.Number("2"):
				request.version = 2
			default:
				return request, false
			}
		case "request":
			encoded, valid := value.(string)
			if !valid {
				return request, false
			}
			request.raw, err = base64.StdEncoding.Strict().
				DecodeString(encoded)
			if err != nil || len(request.raw) == 0 ||
				len(request.raw) > pw.MaxEstablishmentBytes ||
				base64.StdEncoding.EncodeToString(request.raw) != encoded {
				return request, false
			}
		default:
			return request, false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 2 {
		return request, false
	}
	_, err := d.Token()
	return request, err == io.EOF
}
