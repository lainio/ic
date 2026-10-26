package ownerapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"github.com/lainio/ic/internal/onboarding"
)

const maxVerifyResponseBytes = 16 * 1024

// This explicit owner operation refines V19 VerifyReceived only. Root comes
// from handler configuration; no peer, signer, or local self-evidence is added.
func (h *statusHandler) serveVerifyReceived(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawPath != "" {
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
	if !readEmptyObjectRequest(w, r) {
		return
	}
	newlyKnown, err := onboarding.VerifyReceived(h.vault, h.expectedRoot)
	if err != nil {
		writeStatusError(w, http.StatusConflict)
		return
	}
	known, err := onboarding.ListKnownIntroductions(h.vault, h.expectedRoot)
	if err != nil {
		// Promotion may already be committed: this is an unknown acknowledgement.
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	result := struct {
		NewlyKnown    int      `json:"newly_known"`
		KnownSubjects []string `json:"known_subjects"`
	}{NewlyKnown: newlyKnown, KnownSubjects: make([]string, 0, len(known))}
	for _, subject := range known {
		result.KnownSubjects = append(result.KnownSubjects, hex.EncodeToString(subject))
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maxVerifyResponseBytes {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	writeIntroductionResult(w, encoded)
}

// Only the literal empty object (with optional surrounding JSON whitespace).
// No selector, duplicate/extra property, or trailing document can reach storage.
func readEmptyObjectRequest(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
		writeStatusError(w, http.StatusUnsupportedMediaType)
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64))
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeStatusError(w, status)
		return false
	}
	if !bytes.Equal(bytes.Trim(data, " \t\r\n"), []byte("{}")) {
		writeStatusError(w, http.StatusBadRequest)
		return false
	}
	return true
}
