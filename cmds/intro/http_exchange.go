package intro

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
)

// One disposable exchange borrows Root's handle. The mutex protects only this
// handler's proposal and signing, not enrollment or other users of the handle.
type httpExchangeHandler struct {
	mu       sync.Mutex
	root     key.Handle
	proposal coreintro.Path
}

func newHTTPExchangeHandler(root key.Handle) http.Handler {
	return &httpExchangeHandler{root: root}
}

func (h *httpExchangeHandler) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	switch r.URL.Path {
	case "/intro/offer", "/intro/acceptance":
	default:
		writeHTTPExchangeResponse(w, http.StatusNotFound, nil)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeHTTPExchangeResponse(w, http.StatusMethodNotAllowed, nil)
		return
	}
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/cbor" {
		writeHTTPExchangeResponse(w, http.StatusUnsupportedMediaType, nil)
		return
	}

	data, status, err := readHTTPExchangeBody(r.Body)
	if err == nil {
		if r.URL.Path == "/intro/offer" {
			data, status, err = h.offer(data)
		} else {
			status, err = h.acceptance(data)
		}
	}
	if err != nil {
		data = nil // Never expose an internal error or request body.
	}
	writeHTTPExchangeResponse(w, status, data)
}

func readHTTPExchangeBody(body io.Reader) (data []byte, status int, err error) {
	defer err2.Handle(&err)

	status = http.StatusBadRequest
	// Read one extra byte to detect oversize even with a false/unknown length.
	read := try.To1(io.ReadAll(io.LimitReader(body, exchangePayloadLimit+1)))
	if len(read) > exchangePayloadLimit {
		return nil, http.StatusRequestEntityTooLarge, errors.New(
			"body too large",
		)
	}
	return read, http.StatusOK, nil
}

func (h *httpExchangeHandler) offer(data []byte) (
	response []byte, status int, err error,
) {
	defer err2.Handle(&err)
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.proposal != nil {
		return nil, http.StatusConflict, errors.New("offer already retained")
	}
	// Preflight separates HTTP input errors from construction/signing failures.
	// The shared operation still owns its own canonical decoding and ID stripping.
	status = http.StatusBadRequest
	var child key.Info
	try.To(wire.UnmarshalCanonical(&child, data))
	if len(child.Public) == 0 {
		return nil, status, errors.New("empty public key")
	}

	status = http.StatusInternalServerError
	proposal := try.To1(newExchangeProposalFromBytes(h.root, data))
	h.proposal = proposal // Retain before encoding or writing the response.
	return proposal.Bytes(), http.StatusOK, nil
}

func (h *httpExchangeHandler) acceptance(data []byte) (status int, err error) {
	defer err2.Handle(&err)
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.proposal == nil {
		return http.StatusConflict, errors.New("offer required")
	}
	status = http.StatusBadRequest
	// Require a CBOR byte string; null is not a detached-signature wrapper.
	if len(data) == 0 || data[0]>>5 != 2 {
		return status, errors.New("signature byte string required")
	}
	var signature key.Signature
	try.To(wire.UnmarshalCanonical(&signature, data))

	status = http.StatusInternalServerError
	verifyErr := h.proposal.VerifyAcceptance(signature)
	if errors.Is(verifyErr, coreintro.ErrBadAcceptance) {
		return http.StatusUnprocessableEntity, verifyErr
	}
	try.To(verifyErr)
	return http.StatusNoContent, nil
}

func writeHTTPExchangeResponse(w http.ResponseWriter, status int, data []byte) {
	if status >= http.StatusBadRequest {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		data = []byte(http.StatusText(status) + "\n")
	} else if status == http.StatusOK {
		w.Header().Set("Content-Type", "application/cbor")
	}
	w.WriteHeader(status)
	if status == http.StatusNoContent {
		return
	}
	// Headers are committed. Log a failed write without another response or
	// changing the retained proposal; a later offer must still conflict.
	try.Out1(w.Write(data)).Logf("writing HTTP exchange response")
}
