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
	"strings"
	"unicode/utf8"

	"github.com/golang/glog"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

const invitationRedeemPath = "/owner/pw/invitations/redeem"

type redemptionHandler struct{ *acceptanceExchangeHandler }

type redemptionInput struct {
	version  int
	target   key.Public
	id       []byte
	audience string
}

// Only the operational establishment credentials install this route. The exact
// 512-byte JSON shape is target_public_key_hex, invitation_id_hex, audience
// for v1. Only an additional explicit integer version:2 opts into v2.
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
		glog.V(1).Info("intro_pw op=redeem side=requester " +
			"stage=request result=refused reason=input_invalid")
		writeStatusError(w, status)
		return
	}
	glog.V(1).Info("intro_pw op=redeem side=requester " +
		"stage=request result=accepted")
	var saved pw.SavedAttempt
	var savedV2 pw.SavedAttemptV2
	var accepted, held bool
	var err error
	if input.version == 2 {
		savedV2, err = h.saveRedemptionV2(r.Context(), input)
		accepted, held = savedV2.Accepted, savedV2.Held
	} else {
		saved, err = h.saveRedemption(r.Context(), input)
		accepted, held = saved.Accepted, saved.Held
	}
	if err != nil {
		writeStatusError(w, http.StatusConflict)
		return
	}
	if !accepted {
		// No service/signer lock or Vault transaction survives this boundary.
		glog.V(1).Info("intro_pw op=redeem side=requester " +
			"stage=peer_exchange result=started")
		var response []byte
		var sendErr error
		if input.version == 2 {
			response, sendErr = pw.SendEstablishV2(r.Context(), savedV2)
		} else {
			response, sendErr = pw.SendEstablish(r.Context(), saved)
		}
		if sendErr != nil {
			glog.V(1).Info("intro_pw op=redeem side=requester " +
				"stage=peer_exchange result=unknown reason=undetermined")
			http.Error(
				w,
				"Establishment outcome unknown; saved attempt retained",
				http.StatusBadGateway,
			)
			return
		}
		glog.V(1).Info("intro_pw op=redeem side=requester " +
			"stage=peer_exchange result=response_received")
		if input.version == 2 {
			held, err = h.receiveRedemptionV2(response)
		} else {
			held, err = h.receiveRedemption(response)
		}
		if err != nil {
			http.Error(
				w,
				"Local acceptance refused; peer outcome unknown; saved attempt retained",
				http.StatusConflict,
			)
			return
		}
	} else {
		glog.V(1).Info("intro_pw op=redeem side=requester " +
			"stage=acceptance result=retained")
	}
	// Local history is enough for an owner retry, even after held-half deletion.
	// A lost owner acknowledgement cannot cause another peer confirmation.
	encoded := []byte(`{"acceptance_saved":true,"local_held":false}`)
	if held {
		encoded = []byte(`{"acceptance_saved":true,"local_held":true}`)
	}
	writeIntroductionResult(w, encoded)
}

func (h *redemptionHandler) saveRedemption(ctx context.Context,
	input redemptionInput,
) (pw.SavedAttempt, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		glog.V(1).Info("intro_pw op=redeem side=requester " +
			"stage=attempt result=refused reason=request_canceled")
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

func (h *redemptionHandler) saveRedemptionV2(ctx context.Context,
	input redemptionInput,
) (pw.SavedAttemptV2, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		return pw.SavedAttemptV2{}, err
	}
	// Only the one-shot binder sets this endpoint, from the actual listener.
	// SaveAttemptV2 validates the canonical origin and rejects a changed port.
	const path = "/peer/introduction"
	if !strings.HasSuffix(h.endpoint, path) {
		return pw.SavedAttemptV2{}, pw.ErrEstablishment
	}
	origin := strings.TrimSuffix(h.endpoint, path)
	return pw.SaveAttemptV2(h.vault, h.root, h.child, input.target, h.signer,
		input.id, input.audience, origin)
}

func (h *redemptionHandler) receiveRedemptionV2(response []byte) (bool, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	return pw.ReceiveAcceptanceV2(h.vault, h.root, h.child, h.signer, response)
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
	input := redemptionInput{version: 1}
	if len(data) > maxInvitationRequestBytes || !utf8.Valid(data) {
		return input, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return input, false
	}
	seen := make(map[string]bool, 4)
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] ||
			bytes.Contains(data[start:d.InputOffset()], []byte{'\\'}) {
			return input, false
		}
		seen[name] = true
		token, err = d.Token()
		if err != nil {
			return input, false
		}
		if name == "version" {
			if token != json.Number("2") {
				return input, false
			}
			input.version = 2
			continue
		}
		value, valid := token.(string)
		if !valid {
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
		!seen["target_public_key_hex"] || !seen["invitation_id_hex"] ||
		!seen["audience"] {
		return input, false
	}
	_, err := d.Token()
	return input, err == io.EOF
}
