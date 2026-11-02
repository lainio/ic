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

	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const invitationRedeemPath = "/owner/pw/invitations/redeem"

type redemptionHandler struct{ *acceptanceExchangeHandler }

type redemptionInput struct {
	target   key.Public
	id       []byte
	audience string
}

// Only the operational establishment credentials install this route. The exact
// 512-byte JSON shape is target_public_key_hex, invitation_id_hex, audience.
// No URL, Root, signer, recipient, clock or caller-signed payload is accepted.
func (h *redemptionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != invitationRedeemPath {
		h.acceptanceExchangeHandler.ServeHTTP(w, r)
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
	input, status := readRedemptionRequest(w, r)
	if status != 0 {
		writeStatusError(w, status)
		return
	}
	saved, err := h.saveRedemption(r.Context(), input)
	if err != nil {
		writeStatusError(w, http.StatusConflict)
		return
	}
	held := saved.Held
	if !saved.Accepted {
		// No service/signer lock or Vault transaction survives this boundary.
		response, sendErr := pw.SendEstablish(r.Context(), saved)
		if sendErr != nil {
			http.Error(
				w,
				"Establishment outcome unknown; saved attempt retained",
				http.StatusBadGateway,
			)
			return
		}
		held, err = h.receiveRedemption(response)
		if err != nil {
			http.Error(
				w,
				"Local acceptance refused; peer outcome unknown; saved attempt retained",
				http.StatusConflict,
			)
			return
		}
	}
	// Local history is enough for an owner retry, even after test-only deletion.
	// A lost owner acknowledgement cannot cause another peer confirmation.
	encoded, err := json.Marshal(struct {
		AcceptanceSaved bool `json:"acceptance_saved"`
		LocalHeld       bool `json:"local_held"`
	}{true, held})
	if err != nil {
		writeStatusError(w, http.StatusInternalServerError)
		return
	}
	writeIntroductionResult(w, encoded)
}

func (h *redemptionHandler) saveRedemption(ctx context.Context,
	input redemptionInput,
) (pw.SavedAttempt, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		return pw.SavedAttempt{}, err
	}
	return pw.SaveAttempt(h.vault, h.root, h.child, input.target, h.signer,
		input.id, input.audience)
}

func (h *redemptionHandler) receiveRedemption(response []byte) (bool, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	return pw.ReceiveAcceptance(h.vault, h.root, h.child, h.signer, response)
}

func readRedemptionRequest(w http.ResponseWriter, r *http.Request,
) (redemptionInput, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 ||
		len(r.Header.Values("Content-Encoding")) != 0 {
		return redemptionInput{}, http.StatusUnsupportedMediaType
	}
	if r.Body == nil {
		return redemptionInput{}, http.StatusBadRequest
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body,
		maxInvitationRequestBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return redemptionInput{}, http.StatusRequestEntityTooLarge
		}
		return redemptionInput{}, http.StatusBadRequest
	}
	input, ok := decodeRedemptionRequest(data)
	if !ok {
		return redemptionInput{}, http.StatusBadRequest
	}
	return input, 0
}

func decodeRedemptionRequest(data []byte) (redemptionInput, bool) {
	var input redemptionInput
	if len(data) > maxInvitationRequestBytes || !utf8.Valid(data) {
		return input, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return input, false
	}
	seen := make(map[string]bool, 3)
	for d.More() {
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] {
			return input, false
		}
		seen[name] = true
		token, err = d.Token()
		value, valid := token.(string)
		if err != nil || !valid {
			return input, false
		}
		switch name {
		case "audience":
			if value != pw.InvitationAny && value != pw.InvitationDirected {
				return input, false
			}
			input.audience = value
		case "target_public_key_hex", "invitation_id_hex":
			decoded, err := hex.DecodeString(value)
			if err != nil || len(decoded) == 0 || len(decoded) > 128 ||
				hex.EncodeToString(decoded) != value {
				return input, false
			}
			if name == "target_public_key_hex" {
				input.target = decoded // SaveAttempt validates canonical COSE.
			} else {
				if len(decoded) != 32 {
					return input, false
				}
				input.id = decoded
			}
		default:
			return input, false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 3 {
		return input, false
	}
	_, err := d.Token()
	return input, err == io.EOF
}
