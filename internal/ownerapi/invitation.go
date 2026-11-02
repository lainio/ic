package ownerapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const (
	invitationIssuePath       = "/owner/pw/invitations/issue"
	invitationRevokePath      = "/owner/pw/invitations/revoke"
	maxInvitationRequestBytes = 512
)

// Only NewAcceptanceCredentials installs these explicit owner operations.
// POST issue accepts exactly {"recipient_public_key_hex":null} (Any), or one
// lowercase canonical public-key hex string (Directed). POST revoke accepts
// exactly {"invitation_id_hex":"<64 lowercase hex characters>"}.
// Requests are JSON objects bounded to 512 bytes, with no additional fields,
// documents, query or fragment. Neither route accepts client expiry/time.
// Issue returns invitation_id_hex, expires_unix_nano, audience and
// recipient_public_key_hex (null for Any). Revoke returns {"revoked":bool}:
// true only for a committed transition, false for an unchanged valid row or
// absence. Errors use only fixed HTTP status text; all responses are no-store.
func (h *acceptanceExchangeHandler) serveInvitation(
	w http.ResponseWriter, r *http.Request,
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
		r.URL.Fragment != "" || r.URL.RawFragment != "" {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	issue := r.URL.Path == invitationIssuePath
	input, ok := readInvitationRequest(w, r, issue)
	if !ok {
		return
	}
	encoded, err := h.changeInvitation(input, issue)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, pw.ErrInvitationInput) {
			status = http.StatusBadRequest
		} else if errors.Is(err, pw.ErrInvitationIssued) {
			status = http.StatusConflict
		}
		writeStatusError(w, status)
		return
	}
	// Both the Vault transaction and service lock have ended. A lost response
	// never retries, rolls back, or reauthorizes the committed invitation.
	writeIntroductionResult(w, encoded)
}

func (h *acceptanceExchangeHandler) changeInvitation(input []byte, issue bool,
) ([]byte, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if !issue {
		changed, err := pw.RevokeInvitation(h.vault, h.root, h.child, input)
		if err != nil {
			return nil, err
		}
		return json.Marshal(struct {
			Revoked bool `json:"revoked"`
		}{changed})
	}
	// IssueInvitation samples the real server clock while serialized here.
	row, err := pw.IssueInvitation(h.vault, h.root, h.child, key.Public(input))
	if err != nil {
		return nil, err
	}
	var recipient *string
	if row.Recipient != nil {
		value := hex.EncodeToString(row.Recipient)
		recipient = &value
	}
	return json.Marshal(struct {
		InvitationIDHex       string  `json:"invitation_id_hex"`
		ExpiresUnixNano       int64   `json:"expires_unix_nano"`
		Audience              string  `json:"audience"`
		RecipientPublicKeyHex *string `json:"recipient_public_key_hex"`
	}{hex.EncodeToString(row.ID), row.ExpiresUnixNano, row.Audience, recipient})
}

func readInvitationRequest(w http.ResponseWriter, r *http.Request, issue bool,
) ([]byte, bool) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		writeStatusError(w, http.StatusUnsupportedMediaType)
		return nil, false
	}
	data, err := io.ReadAll(
		http.MaxBytesReader(w, r.Body, maxInvitationRequestBytes),
	)
	if err != nil {
		status := http.StatusBadRequest
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeStatusError(w, status)
		return nil, false
	}
	input, ok := decodeInvitationRequest(data, issue)
	if !ok {
		writeStatusError(w, http.StatusBadRequest)
	}
	return input, ok
}

func decodeInvitationRequest(data []byte, issue bool) ([]byte, bool) {
	if !utf8.Valid(data) {
		return nil, false
	}
	field := "invitation_id_hex"
	if issue {
		field = "recipient_public_key_hex"
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	if token, err := d.Token(); err != nil || token != field {
		return nil, false
	}
	token, err := d.Token()
	if err != nil {
		return nil, false
	}
	var input []byte
	if !issue || token != nil {
		value, ok := token.(string)
		if !ok || len(value) == 0 || len(value) > 2*128 {
			return nil, false
		}
		input, err = hex.DecodeString(value)
		if err != nil || hex.EncodeToString(input) != value ||
			(!issue && len(input) != 32) {
			return nil, false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	_, err = d.Token()
	return input, err == io.EOF
}
