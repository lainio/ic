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

	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
)

const denyPath = "/owner/policy/deny"
const maxDenyRequestBytes = 512

// Only the operational owner composition installs this local policy action.
// ChangeBob(n, "Deny") / ChangeRequester(n, "Deny") retain holding and history;
// this is not full V19 DenyPeer (there is no live pipe here to close).
func (h *firstUseHandler) serveDeny(w http.ResponseWriter, r *http.Request) {
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
	peer, status := readDenyRequest(w, r)
	if status != 0 {
		writeStatusError(w, status)
		return
	}
	changed, err := h.denyLocal(r.Context(), peer)
	if err != nil {
		status = http.StatusInternalServerError
		if errors.Is(err, policy.ErrInvalidInput) {
			status = http.StatusBadRequest
		} else if errors.Is(err, policy.ErrFull) {
			status = http.StatusConflict
		}
		writeStatusError(w, status)
		return
	}
	// The transaction has completed and the owner lock is released before I/O.
	if changed {
		writeIntroductionResult(w, []byte(`{"changed":true}`))
	} else {
		writeIntroductionResult(w, []byte(`{"changed":false}`))
	}
}

func (h *firstUseHandler) denyLocal(ctx context.Context, peer key.Public) (
	bool, error,
) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return policy.DenyLocal(h.vault, h.root, h.child, peer)
}

func readDenyRequest(w http.ResponseWriter, r *http.Request) (key.Public, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		return nil, http.StatusUnsupportedMediaType
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDenyRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, http.StatusRequestEntityTooLarge
		}
		return nil, http.StatusBadRequest
	}
	if len(r.Trailer) != 0 || !utf8.Valid(data) {
		return nil, http.StatusBadRequest
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, http.StatusBadRequest
	}
	if token, err := d.Token(); err != nil || token != "peer_public_key_hex" {
		return nil, http.StatusBadRequest
	}
	token, err := d.Token()
	value, ok := token.(string)
	if err != nil || !ok || len(value) == 0 || len(value) > 2*128 {
		return nil, http.StatusBadRequest
	}
	peer, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(peer) != value {
		return nil, http.StatusBadRequest
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, http.StatusBadRequest
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, http.StatusBadRequest
	}
	return peer, 0 // DenyLocal owns canonical COSE and self validation.
}
