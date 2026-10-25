package ownerapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const maxIntroductionListBytes = 256 * 1024

type saveResponse struct {
	checkResponse
	Created bool `json:"created"`
}

func newEvidenceHandler(vault *storage.Vault, root, child key.Public) http.Handler {
	read := newReadHandler(vault, root, child)
	h := &statusHandler{
		vault: vault, expectedRoot: bytes.Clone(root), expectedChild: bytes.Clone(child),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/owner/introductions" {
			read.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		switch r.Method {
		case http.MethodPost:
			h.serveSaveIntroduction(w, r)
		case http.MethodGet:
			h.serveListIntroductions(w)
		default:
			w.Header().Set("Allow", "GET, POST")
			writeStatusError(w, http.StatusMethodNotAllowed)
		}
	})
}

func (h *statusHandler) subjectSummary(subject key.Public) checkResponse {
	return checkResponse{
		SubjectPublicKeyHex: hex.EncodeToString(subject),
		IsSelf:              bytes.Equal(subject, h.expectedChild),
	}
}

func (h *statusHandler) serveSaveIntroduction(w http.ResponseWriter, r *http.Request) {
	document, ok := readIntroductionRequest(w, r)
	if !ok {
		return
	}
	subject, created, err := onboarding.SaveIntroduction(
		h.vault, h.expectedRoot, document.Proposal, document.Acceptance,
	)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, onboarding.ErrInvalidIntroduction):
			status = http.StatusBadRequest
		case errors.Is(err, onboarding.ErrDifferentIntroduction),
			errors.Is(err, onboarding.ErrIntroductionsFull):
			status = http.StatusConflict
		}
		writeStatusError(w, status)
		return
	}
	encoded, err := json.Marshal(saveResponse{h.subjectSummary(subject), created})
	if err != nil || len(encoded) > maxCheckResponseBytes {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	writeIntroductionResult(w, encoded)
}

func (h *statusHandler) serveListIntroductions(w http.ResponseWriter) {
	subjects, err := onboarding.ListIntroductions(h.vault, h.expectedRoot)
	if err != nil {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	result := struct {
		Introductions []checkResponse `json:"introductions"`
	}{Introductions: make([]checkResponse, 0, len(subjects))}
	for _, subject := range subjects {
		summary := h.subjectSummary(subject)
		encoded, err := json.Marshal(summary)
		if err != nil || len(encoded) > maxCheckResponseBytes {
			writeStatusError(w, http.StatusInternalServerError)
			return
		}
		result.Introductions = append(result.Introductions, summary)
	}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded) > maxIntroductionListBytes {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	writeIntroductionResult(w, encoded)
}

func writeIntroductionResult(w http.ResponseWriter, encoded []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// A save may already be committed. Never emit a second response or retry.
	try.Out1(w.Write(encoded)).Logf("writing owner received introduction response")
}
