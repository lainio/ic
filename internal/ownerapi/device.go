package ownerapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Only the operational owner surface borrows a signer. One service-scoped lock
// serializes BootstrapLocal's preflight/probe/commit with Received/Known writes.
// Read-only requests do not take it; no Vault transaction spans signing or I/O.
type deviceHandler struct {
	next        http.Handler
	vault       *storage.Vault
	root, child key.Public
	signer      key.Handle
	mutations   sync.Mutex
}

func newDeviceHandler(vault *storage.Vault, root, child key.Public, signer key.Handle) http.Handler {
	return &deviceHandler{
		next: newEvidenceHandler(vault, root, child), vault: vault,
		root: bytes.Clone(root), child: bytes.Clone(child), signer: signer,
	}
}

func (h *deviceHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/owner/device/bootstrap" {
		h.serveBootstrap(w, r)
		return
	}
	if r.Method == http.MethodPost {
		switch r.URL.Path {
		case "/owner/introductions", "/owner/introductions/fetch", "/owner/introductions/verify":
			h.mutations.Lock()
			defer h.mutations.Unlock()
		}
	}
	h.next.ServeHTTP(w, r)
}

// This explicit owner request refines V19 BootstrapDevice for the existing
// local software signer only. Usable describes this call's probe, never a saved
// live flag. A lost acknowledgement requires explicit inspection/retry; a 409
// does not prove current usability and must never trigger a retry here.
func (h *deviceHandler) serveBootstrap(w http.ResponseWriter, r *http.Request) {
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
	state, err := device.BootstrapLocal(h.vault, h.root, h.child, h.signer)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, device.ErrAlreadyAuthorized) || errors.Is(err, device.ErrNotKnown) ||
			errors.Is(err, device.ErrUnusableSigner) {
			status = http.StatusConflict
		}
		writeStatusError(w, status)
		return
	}
	encoded, err := json.Marshal(struct {
		Authorized bool `json:"authorized"`
		Usable     bool `json:"usable"`
	}{state.Authorized, state.Usable})
	if err != nil {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	writeIntroductionResult(w, encoded)
}
