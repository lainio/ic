package ownerapi

import (
	"bytes"
	"net/http"

	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const maxIntroductionBytes = onboarding.MaxIntroductionBytes

type introductionResponse struct {
	Version    int    `json:"version"`
	Proposal   []byte `json:"proposal"`
	Acceptance []byte `json:"acceptance"`
}

// Used only behind the shared bearer check by NewReadCredentials. Exact route
// dispatch keeps the existing status response and unknown-route behavior.
func newReadHandler(vault *storage.Vault, root, child key.Public) http.Handler {
	status := NewStatusHandler(vault, root, child)
	h := &statusHandler{
		vault: vault, expectedRoot: bytes.Clone(root), expectedChild: bytes.Clone(child),
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/owner/introduction":
			h.serveIntroduction(w, r)
			return
		case "/owner/introduction/check":
			h.serveCheck(w, r)
			return
		}
		status.ServeHTTP(w, r)
	})
}

func (h *statusHandler) serveIntroduction(
	w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeStatusError(w, http.StatusMethodNotAllowed)
		return
	}
	stored, found, err := onboarding.ReadStoredChoice(
		h.vault, h.expectedRoot, h.expectedChild,
	)
	if err != nil {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	if !found || stored.Acceptance == nil {
		writeStatusError(w, http.StatusConflict)
		return
	}
	document, err := onboarding.EncodeIntroduction(stored)
	if err != nil {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Output failure must not initiate a second response.
	try.Out1(w.Write(document)).Logf("writing owner introduction response")
}
