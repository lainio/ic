package peerapi

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// NewAcceptanceHandler adds POST /peer/pw/accept and /peer/pw/challenge with
// exactly one shared ledger for this listener. Construct once before Serve,
// after binding the opted-in listener. The capability owns the service mutation
// lock, final exact-ad/Known/Deny/device checks and installed signer access.
// The peer authenticates requester key possession before invoking it.
// This ephemeral evidence exchange changes no modeled state: neither signature
// establishes honest remote policy, durable consent, a channel or CreatePW.
func NewAcceptanceHandler(vault *storage.Vault, root, local key.Public,
	boundPeerIntroURL string,
	accept func(key.Public, []byte, []byte) (key.Signature, error),
	next http.Handler,
) http.Handler {
	h := NewChallengeHandler(vault, root, local, boundPeerIntroURL,
		next).(*challengeHandler)
	h.accept = accept
	return h
}

func (h *challengeHandler) serveAcceptance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	fail := func(status int) { http.Error(w, http.StatusText(status), status) }
	if r.URL.RawPath != "" || r.URL.Opaque != "" {
		fail(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		fail(http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.Fragment != "" || r.URL.RawFragment != "" {
		fail(http.StatusBadRequest)
		return
	}
	request, status := readAcceptanceRequest(w, r)
	if status != 0 {
		fail(status)
		return
	}
	if bytes.Equal(request.requester, h.local) ||
		!validChallengeRequester(request.requester) ||
		!h.authenticChallengeAd(request.ad) ||
		pw.VerifyLocalAcceptanceProof(h.root, request.requester, h.local,
			request.nonce, request.proof) != nil {
		fail(http.StatusBadRequest)
		return
	}
	if status := h.currentChallengeAd(request.ad); status != 0 {
		fail(status)
		return
	}
	// Consumption linearizes competing authenticated attempts. Admission and
	// ad failures above leave a live nonce unused. Release the ledger mutex
	// before entering the service mutex; no lock is held across HTTP I/O.
	if !h.consumeChallenge(request.requester, request.ad, request.nonce) {
		fail(http.StatusConflict)
		return
	}
	// A publication/policy change while waiting for the service lock is checked
	// there again. Every callback failure leaves this nonce spent, even when
	// no signature was made. An explicit fresh challenge is the only retry.
	proof, err := h.accept(request.requester, request.ad, request.nonce)
	if err != nil {
		fail(http.StatusConflict)
		return
	}
	if pw.VerifyLocalAcceptanceProof(h.root, h.local, request.requester,
		request.nonce, proof) != nil {
		fail(http.StatusInternalServerError)
		return
	}
	document, err := json.Marshal(struct {
		Version       int           `json:"version"`
		AcceptorProof key.Signature `json:"acceptor_proof"`
	}{1, proof})
	if err != nil || len(document) > 1024 {
		fail(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// A lost reply is an unknown outcome. Never sign again or restore the nonce.
	_, _ = w.Write(document)
}
