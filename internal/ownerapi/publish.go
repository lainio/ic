package ownerapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/lainio/ic/internal/ads"
)

// Publication composes the device surface without expanding older credentials.
// It borrows the same signer and mutation lock; only the bound endpoint is new.
type publicationHandler struct {
	*deviceHandler
	endpoint string // Fixed by the one-shot pre-Serve closure, under mutations.
}

func (h *publicationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/owner/ads/publish" {
		h.servePublish(w, r)
		return
	}
	h.deviceHandler.ServeHTTP(w, r)
}

// Refines only the bounded local PublishAd projection. This does not bootstrap,
// promote evidence, disclose an ad to peers, or establish verified reachability.
func (h *publicationHandler) servePublish(w http.ResponseWriter, r *http.Request) {
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
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if h.endpoint == "" {
		writeStatusError(w, http.StatusConflict)
		return
	}
	current, err := ads.PublishLocal(h.vault, h.root, h.child, h.signer, h.endpoint, time.Now())
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, ads.ErrNotKnown) || errors.Is(err, ads.ErrUnusable) {
			status = http.StatusConflict
		}
		writeStatusError(w, status)
		return
	}
	encoded, err := json.Marshal(struct {
		Published           bool   `json:"published"`
		Slot                uint64 `json:"slot"`
		Epoch               uint64 `json:"epoch"`
		ExpiresUnixNano     int64  `json:"expires_unix_nano"`
		PeerIntroductionURL string `json:"peer_introduction_url"`
	}{true, current.Payload.Slot, current.Payload.Epoch,
		current.Payload.ExpiresUnixNano, current.Payload.PeerIntroductionURL})
	if err != nil {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	// A failed response can follow a committed replacement. Never retry here.
	writeIntroductionResult(w, encoded)
}
