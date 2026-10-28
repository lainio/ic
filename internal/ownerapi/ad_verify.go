package ownerapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/key"
)

const maxAdVerificationBytes = 1024

type verificationHandler struct{ *publicationHandler }

func (h *verificationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/owner/ads/verify" {
		h.publicationHandler.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawPath != "" || r.URL.Opaque != "" {
		writeStatusError(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeStatusError(w, http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	subject, ok := readAdVerificationRequest(w, r)
	if !ok {
		return
	}
	if bytes.Equal(subject, h.child) {
		writeStatusError(w, http.StatusBadRequest)
		return
	}

	// No publisher mutations lock across outbound I/O. The verifier owns its
	// snapshots and atomically revalidates the final Known/receipt/expiry state.
	changed, err := ads.VerifyReceivedRemote(r.Context(), h.vault, h.root, h.child, subject)
	if err != nil {
		writeAdVerificationError(w, err)
		return
	}
	encoded, err := json.Marshal(struct {
		SubjectPublicKeyHex string `json:"subject_public_key_hex"`
		Verified            bool   `json:"verified"`
		Changed             bool   `json:"changed"`
	}{hex.EncodeToString(subject), true, changed})
	if err != nil || len(encoded) > maxAdVerificationBytes {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	// A lost acknowledgement can follow commit. Never retry or undo history.
	writeIntroductionResult(w, encoded)
}

func readAdVerificationRequest(w http.ResponseWriter, r *http.Request) (key.Public, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
		writeStatusError(w, http.StatusUnsupportedMediaType)
		return nil, false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAdVerificationBytes))
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeStatusError(w, status)
		return nil, false
	}
	subject, ok := decodeAdVerificationSubject(data)
	if !ok {
		writeStatusError(w, http.StatusBadRequest)
	}
	return subject, ok
}

// One exact string field: token parsing rejects duplicates and case aliases.
// Raw parser diagnostics never escape; canonical COSE checks belong to ads.
func decodeAdVerificationSubject(data []byte) (key.Public, bool) {
	if !utf8.Valid(data) {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	if token, err := d.Token(); err != nil || token != "subject_public_key_hex" {
		return nil, false
	}
	token, err := d.Token()
	value, ok := token.(string)
	if err != nil || !ok || len(value) == 0 || len(value) > 2*128 {
		return nil, false
	}
	subject, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(subject) != value {
		return nil, false
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	_, err = d.Token()
	return subject, err == io.EOF
}

func writeAdVerificationError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, ads.ErrRemoteProof), errors.Is(err, ads.ErrInvalidProof):
		// Keep the proof client's existing grouping, including transport failures.
		status = http.StatusBadGateway
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		status = http.StatusGatewayTimeout
	case errors.Is(err, ads.ErrInvalidInput):
		status = http.StatusBadRequest
	case errors.Is(err, ads.ErrSubjectNotKnown), errors.Is(err, ads.ErrNoReceivedClaim),
		errors.Is(err, ads.ErrReceivedClaimChanged), errors.Is(err, ads.ErrInvalidRecord),
		errors.Is(err, ads.ErrVerifiedClaimsFull):
		status = http.StatusConflict
	}
	writeStatusError(w, status)
}
