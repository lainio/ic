package ownerapi

import (
	"context"
	"net/http"

	"github.com/lainio/ic/internal/pw"
)

const deleteHeldPath = "/owner/pw/holding/delete"

func (h *firstUseHandler) serveDeleteHeld(
	w http.ResponseWriter,
	r *http.Request,
) {
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
		r.URL.Fragment != "" || r.URL.RawFragment != "" ||
		len(r.Header.Values("Content-Encoding")) != 0 ||
		len(r.Header.Values("Trailer")) != 0 || len(r.Trailer) != 0 ||
		r.Body == nil {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	if !readEmptyObjectRequest(w, r) {
		return
	}
	if len(r.Trailer) != 0 {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	deleted, err := h.deleteHeld(r.Context())
	if err != nil {
		writeStatusError(w, http.StatusConflict)
		return
	}
	// The transaction has completed and the owner lock is released before I/O.
	if deleted {
		writeIntroductionResult(w, []byte(`{"deleted":true}`))
	} else {
		writeIntroductionResult(w, []byte(`{"deleted":false}`))
	}
}

func (h *firstUseHandler) deleteHeld(ctx context.Context) (bool, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return pw.DeleteHeldLocal(h.vault, h.root, h.child)
}
