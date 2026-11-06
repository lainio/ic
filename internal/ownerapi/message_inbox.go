package ownerapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/lainio/ic/internal/pw"
)

const messageInboxPath = "/owner/pw/message/inbox"
const maxMessageInboxResponseBytes = 2 * 1024

func (h *firstUseHandler) serveMessageInbox(w http.ResponseWriter,
	r *http.Request,
) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawPath != "" || r.URL.Opaque != "" {
		writeStatusError(w, http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeStatusError(w, http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.Fragment != "" || r.URL.RawFragment != "" ||
		len(r.Header.Values("Content-Encoding")) != 0 ||
		len(r.Header.Values("Transfer-Encoding")) != 0 ||
		len(r.TransferEncoding) != 0 ||
		len(r.Header.Values("Trailer")) != 0 || len(r.Trailer) != 0 ||
		r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	if r.Context().Err() != nil {
		writeStatusError(w, http.StatusConflict)
		return
	}
	inbox, err := pw.ReadMessageInbox(h.vault, h.root, h.child)
	if err != nil {
		writeStatusError(w, http.StatusConflict)
		return
	}
	response := struct {
		Present bool   `json:"present"`
		ID      string `json:"message_id_hex,omitempty"`
		Text    string `json:"text,omitempty"`
	}{Present: inbox.Present}
	if inbox.Present {
		response.ID = hex.EncodeToString(inbox.ID[:])
		response.Text = inbox.Text
	}
	encoded, err := json.Marshal(response)
	// Escaping can expand otherwise valid bounded text. Refuse before writing
	// any plaintext or success headers; never truncate or alter the message.
	if err != nil || len(encoded) > maxMessageInboxResponseBytes {
		writeStatusError(w, http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// Output failures cannot trigger another response. Do not log writer errors,
	// which may include the plaintext passed to the writer.
	_, _ = w.Write(encoded)
}
