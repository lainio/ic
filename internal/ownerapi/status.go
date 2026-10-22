// Package ownerapi provides unmounted handlers for an owner-control surface.
package ownerapi

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

type statusHandler struct {
	vault                       *storage.Vault
	expectedRoot, expectedChild key.Public
}

type statusResponse struct {
	Choice string `json:"choice"`
}

// NewStatusHandler serves GET /owner/status using ReadStoredChoice. It borrows
// an open, dedicated child/root Vault and copies the independently established
// expected identities without I/O. The caller owns the Vault/provider lifecycle.
// No signing handle is needed, and requests cannot change the identity binding.
//
// The labels describe saved local choice, not enrollment, trust, peer delivery,
// or V19 Known. This handler has no authentication and remains unmounted;
// authentication/access control is required before connecting an owner API.
// A local URL alone is not authorization. Never mount it on a peer surface.
func NewStatusHandler(
	vault *storage.Vault,
	expectedRoot, expectedChild key.Public,
) http.Handler {
	return &statusHandler{
		vault:         vault,
		expectedRoot:  bytes.Clone(expectedRoot),
		expectedChild: bytes.Clone(expectedChild),
	}
}

func (h *statusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path != "/owner/status" {
		writeStatusError(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeStatusError(w, http.StatusMethodNotAllowed)
		return
	}

	stored, found, err := onboarding.ReadStoredChoice(
		h.vault, h.expectedRoot, h.expectedChild,
	)
	if err != nil {
		try.Out(err).Logf("reading owner status")
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	choice := "unselected"
	if found {
		choice = "pending"
		if stored.Acceptance != nil {
			choice = "completed"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Headers are committed; a failed output must not trigger another response.
	try.Out(json.NewEncoder(w).Encode(statusResponse{Choice: choice})).Logf(
		"writing owner status response",
	)
}

func writeStatusError(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	try.Out1(w.Write([]byte(http.StatusText(status) + "\n"))).Logf(
		"writing owner status error response",
	)
}
