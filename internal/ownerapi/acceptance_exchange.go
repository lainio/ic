package ownerapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/lainio/ic/internal/pw"
)

type acceptanceExchangeHandler struct{ *verificationHandler }

func (h *acceptanceExchangeHandler) ServeHTTP(
	w http.ResponseWriter, r *http.Request,
) {
	if r.URL.Path != "/owner/pw/acceptance/exchange" {
		h.verificationHandler.ServeHTTP(w, r)
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
	if r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.Fragment != "" || r.URL.RawFragment != "" {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	subject, ok := readAdVerificationRequest(w, r)
	if !ok {
		return
	}

	// Borrow only this owner's pinned configuration. No service mutation lock,
	// Vault transaction or signer lock may span the outbound exchange.
	err := pw.RequestRemoteAcceptance(r.Context(), h.vault, h.root, h.child,
		subject, h.signer)
	if err != nil {
		// The peer client sanitizes transport failures to one sentinel. The
		// owner's context still distinguishes its cancellation/deadline.
		if contextErr := r.Context().Err(); contextErr != nil {
			err = contextErr
		}
		writeAcceptanceExchangeError(w, err)
		return
	}
	encoded, err := json.Marshal(struct {
		SubjectPublicKeyHex string `json:"subject_public_key_hex"`
		ExchangeVerified    bool   `json:"exchange_verified"`
	}{hex.EncodeToString(subject), true})
	if err != nil || len(encoded) > maxAdVerificationBytes {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	// Only this invocation's ephemeral proof exchange was verified. No V19
	// CreatePW transition, cached consent or reachability follows. A lost owner
	// acknowledgement must never trigger another exchange.
	writeIntroductionResult(w, encoded)
}

func writeAcceptanceExchangeError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	case errors.Is(err, pw.ErrInvalidInput):
		status = http.StatusBadRequest
	case errors.Is(err, pw.ErrNotKnown), errors.Is(err, pw.ErrDenied),
		errors.Is(err, pw.ErrUnauthorized), errors.Is(err, pw.ErrUnusableSigner),
		errors.Is(err, pw.ErrAdEvidence):
		status = http.StatusConflict
	case errors.Is(err, pw.ErrRemoteAcceptance),
		errors.Is(err, pw.ErrInvalidProof):
		status = http.StatusBadGateway
	}
	writeStatusError(w, status)
}
