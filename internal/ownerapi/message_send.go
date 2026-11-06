package ownerapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"unicode/utf8"

	"github.com/golang/glog"
	"github.com/lainio/ic/internal/pw"
)

const messageSendPath = "/owner/pw/message/send"
const maxMessageSendRequestBytes = 2 * 1024

func (h *firstUseHandler) serveMessageSend(w http.ResponseWriter,
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
		len(r.Header.Values("Transfer-Encoding")) != 0 ||
		len(r.TransferEncoding) != 0 ||
		len(r.Header.Values("Trailer")) != 0 || len(r.Trailer) != 0 {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	text, peerURL, status := readMessageSendRequest(w, r)
	if status != 0 {
		writeStatusError(w, status)
		return
	}
	if len(r.Trailer) != 0 {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	prepared, err := h.prepareMessageSend(r.Context(), text)
	if err != nil {
		glog.V(1).Info("intro_pw op=message_send stage=prepare " +
			"result=refused dispatch=not_started local_state=retained")
		writeStatusError(w, http.StatusConflict)
		return
	}

	// sent authorizes an attempt; it does not prove dispatch or peer admission.
	// The preparation lock is released before HTTP, including on exact retry.
	receipt, err := pw.SendMessageOnce(r.Context(), prepared, peerURL)
	if err != nil {
		if errors.Is(err, pw.ErrMessageNotDispatched) {
			glog.V(1).Info("intro_pw op=message_send stage=exchange " +
				"result=refused dispatch=not_started local_state=retained")
			writeStatusError(w, http.StatusConflict)
		} else {
			glog.V(1).Info("intro_pw op=message_send stage=exchange " +
				"result=unknown dispatch=possible local_state=retained")
			writeStatusError(w, http.StatusBadGateway)
		}
		return
	}
	if err := h.observeMessageReceipt(receipt); err != nil {
		glog.V(1).Info("intro_pw op=message_send stage=ack " +
			"result=unknown dispatch=possible local_state=retained")
		writeStatusError(w, http.StatusBadGateway)
		return
	}
	// Observation has released the owner lock before any response write.
	writeIntroductionResult(w, []byte(`{"local_acknowledgement_saved":true}`))
}

func (h *firstUseHandler) prepareMessageSend(ctx context.Context, text string,
) (pw.PreparedMessageSend, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		return pw.PreparedMessageSend{}, err
	}
	return pw.PrepareMessageSend(h.vault, h.root, h.child, h.signer, text)
}

func (h *firstUseHandler) observeMessageReceipt(
	receipt pw.MessageSendReceipt,
) error {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	return pw.ObserveMessageReceipt(h.vault, h.root, h.child, receipt)
}

func readMessageSendRequest(w http.ResponseWriter, r *http.Request,
) (string, string, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		return "", "", http.StatusUnsupportedMediaType
	}
	if r.ContentLength > maxMessageSendRequestBytes {
		return "", "", http.StatusRequestEntityTooLarge
	}
	if r.Body == nil {
		return "", "", http.StatusBadRequest
	}
	data, err := io.ReadAll(
		http.MaxBytesReader(w, r.Body, maxMessageSendRequestBytes),
	)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return "", "", http.StatusRequestEntityTooLarge
		}
		return "", "", http.StatusBadRequest
	}
	text, peerURL, ok := decodeMessageSendRequest(data)
	if !ok {
		return "", "", http.StatusBadRequest
	}
	return text, peerURL, 0
}

func decodeMessageSendRequest(data []byte) (string, string, bool) {
	if !utf8.Valid(data) {
		return "", "", false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return "", "", false
	}
	seen := make(map[string]bool, 2)
	var text, peerURL string
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] ||
			bytes.Contains(data[start:d.InputOffset()], []byte{'\\'}) {
			return "", "", false
		}
		seen[name] = true
		token, err = d.Token()
		value, valid := token.(string)
		if err != nil || !valid {
			return "", "", false
		}
		switch name {
		case "text":
			text = value
		case "peer_message_url":
			peerURL = value
		default:
			return "", "", false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 2 || !pw.ValidMessageSendInput(text, peerURL) {
		return "", "", false
	}
	_, err := d.Token()
	return text, peerURL, err == io.EOF
}
