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
	input, status := readMessageSendRequest(w, r)
	if status != 0 {
		writeStatusError(w, status)
		return
	}
	if len(r.Trailer) != 0 {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	var prepared pw.PreparedMessageSend
	var preparedV2 pw.PreparedMessageSendV2
	var err error
	if input.version == 2 {
		preparedV2, err = h.prepareMessageSendV2(r.Context(), input.text)
	} else {
		prepared, err = h.prepareMessageSend(r.Context(), input.text)
	}
	if err != nil {
		glog.V(1).Info("intro_pw op=message_send stage=prepare " +
			"result=refused dispatch=not_started local_state=retained")
		writeStatusError(w, http.StatusConflict)
		return
	}

	// sent authorizes an attempt; it does not prove dispatch or peer admission.
	// The preparation lock is released before HTTP, including on exact retry.
	var receipt pw.MessageSendReceipt
	var receiptV2 []byte
	if input.version == 2 {
		receiptV2, err = pw.SendMessageOnceV2(r.Context(), preparedV2)
	} else {
		receipt, err = pw.SendMessageOnce(r.Context(), prepared, input.peerURL)
	}
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
	if input.version == 2 {
		err = h.observeMessageReceiptV2(receiptV2)
	} else {
		err = h.observeMessageReceipt(receipt)
	}
	if err != nil {
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

func (h *firstUseHandler) prepareMessageSendV2(ctx context.Context, text string,
) (pw.PreparedMessageSendV2, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		return pw.PreparedMessageSendV2{}, err
	}
	return pw.PrepareMessageSendV2(h.vault, h.root, h.child, h.signer,
		h.firstUseRuntimeV2(), text)
}

func (h *firstUseHandler) observeMessageReceiptV2(receipt []byte) error {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	_, err := pw.ObserveMessageReceiptV2(h.vault, h.root, h.child, receipt)
	return err
}

type messageSendInput struct {
	version       int
	text, peerURL string
}

func readMessageSendRequest(w http.ResponseWriter, r *http.Request,
) (messageSendInput, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		return messageSendInput{}, http.StatusUnsupportedMediaType
	}
	if r.ContentLength > maxMessageSendRequestBytes {
		return messageSendInput{}, http.StatusRequestEntityTooLarge
	}
	if r.Body == nil {
		return messageSendInput{}, http.StatusBadRequest
	}
	data, err := io.ReadAll(
		http.MaxBytesReader(w, r.Body, maxMessageSendRequestBytes),
	)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return messageSendInput{}, http.StatusRequestEntityTooLarge
		}
		return messageSendInput{}, http.StatusBadRequest
	}
	input, ok := decodeMessageSendRequest(data)
	if !ok {
		return messageSendInput{}, http.StatusBadRequest
	}
	return input, 0
}

func decodeMessageSendRequest(data []byte) (messageSendInput, bool) {
	if !utf8.Valid(data) {
		return messageSendInput{}, false
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return messageSendInput{}, false
	}
	seen := make(map[string]bool, 2)
	input := messageSendInput{version: 1}
	for d.More() {
		start := d.InputOffset()
		token, err := d.Token()
		name, valid := token.(string)
		if err != nil || !valid || seen[name] ||
			bytes.Contains(data[start:d.InputOffset()], []byte{'\\'}) {
			return messageSendInput{}, false
		}
		seen[name] = true
		token, err = d.Token()
		value, valid := token.(string)
		if err != nil {
			return messageSendInput{}, false
		}
		switch name {
		case "text":
			if !valid {
				return messageSendInput{}, false
			}
			input.text = value
		case "peer_message_url":
			if !valid {
				return messageSendInput{}, false
			}
			input.peerURL = value
		case "version":
			if token != json.Number("2") {
				return messageSendInput{}, false
			}
			input.version = 2
		default:
			return messageSendInput{}, false
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') ||
		len(seen) != 2 || !seen["text"] {
		return messageSendInput{}, false
	}
	if input.version == 2 {
		if !seen["version"] || seen["peer_message_url"] ||
			!pw.ValidMessageSendInputV2(input.text) {
			return messageSendInput{}, false
		}
	} else if !pw.ValidMessageSendInput(input.text, input.peerURL) {
		return messageSendInput{}, false
	}
	_, err := d.Token()
	return input, err == io.EOF
}
