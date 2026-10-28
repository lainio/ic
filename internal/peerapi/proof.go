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

	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const maxProofRequestBytes = 2 * 1024

// NewProofHandler adds only POST /peer/ad/proof to the unchanged public GETs.
// The capability must call ProveCurrentLocal under the service's owner mutation
// lock. It receives no request-selected identity, endpoint, or signing method.
// Construct after binding the opt-in loopback listener, before serving. This
// ephemeral publisher response is not VerifyAd or a durable state transition.
func NewProofHandler(vault *storage.Vault, root, child key.Public,
	boundPeerIntroURL string, prove func(adCBOR, challenge []byte) (key.Signature, error),
) http.Handler {
	root, child = bytes.Clone(root), bytes.Clone(child)
	next := NewAdHandler(vault, root, child, boundPeerIntroURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/peer/ad/proof" || prove == nil || boundPeerIntroURL == "" {
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
		ad, challenge, status := readProofRequest(w, r)
		if status != 0 {
			fail(status)
			return
		}
		if ads.ValidateClaim(root, child, ad) != nil {
			fail(http.StatusBadRequest)
			return
		}
		proof, err := prove(ad, challenge)
		if err != nil {
			fail(http.StatusConflict)
			return
		}
		if len(proof) == 0 || len(proof) > 72 {
			fail(http.StatusInternalServerError)
			return
		}
		document, err := json.Marshal(struct {
			Version int           `json:"version"`
			Proof   key.Signature `json:"proof"`
		}{1, proof})
		if err != nil || len(document) > 1024 {
			fail(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// A write failure must never retry signing or log remote diagnostics.
		_, _ = w.Write(document)
	})
}

func readProofRequest(w http.ResponseWriter, r *http.Request) ([]byte, []byte, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
		return nil, nil, http.StatusUnsupportedMediaType
	}
	if r.Body == nil {
		return nil, nil, http.StatusBadRequest
	}
	// Limit actual bytes, also for chunked bodies or a misleading declared size.
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxProofRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, nil, http.StatusRequestEntityTooLarge
		}
		return nil, nil, http.StatusBadRequest
	}
	ad, challenge, ok := decodeProofRequest(data)
	if !ok {
		return nil, nil, http.StatusBadRequest
	}
	return ad, challenge, 0
}

// Token decoding, as on the owner evidence boundary, detects duplicate keys and
// preserves the exact integer spelling. No raw JSON/base64 errors are traced.
func decodeProofRequest(data []byte) (ad, challenge []byte, ok bool) {
	if !utf8.Valid(data) {
		return nil, nil, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, nil, false
	}
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] {
			return nil, nil, false
		}
		seen[name] = true
		value, err := d.Token()
		if err != nil {
			return nil, nil, false
		}
		switch name {
		case "version":
			if value != json.Number("1") {
				return nil, nil, false
			}
		case "ad", "challenge":
			encoded, valid := value.(string)
			if !valid || encoded == "" {
				return nil, nil, false
			}
			decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
			if err != nil || base64.StdEncoding.EncodeToString(decoded) != encoded {
				return nil, nil, false
			}
			if name == "ad" {
				ad = decoded
			} else {
				challenge = decoded
			}
		default:
			return nil, nil, false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || len(seen) != 3 {
		return nil, nil, false
	}
	_, err := d.Token()
	return ad, challenge, err == io.EOF && len(ad) > 0 && len(ad) <= 1024 && len(challenge) == 32
}
