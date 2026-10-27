package peerapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const maxAdResponseBytes = onboarding.MaxIntroductionBytes + 4096

// NewAdHandler adds development-v1 current-ad disclosure to NewHandler.
// Construct before serving, using this invocation's actual bound peer endpoint.
// It borrows the open Vault and copies the pinned public identities, with no
// signer or owner routes. This is only the publisher's disclosure half of V19
// ReadAd, not receiver state changes, VerifyAd, or proof of device usability.
func NewAdHandler(vault *storage.Vault, root, child key.Public,
	boundPeerIntroURL string,
) http.Handler {
	root, child = bytes.Clone(root), bytes.Clone(child)
	introduction := NewHandler(vault, root, child)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/peer/ad" {
			introduction.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fail := func(status int) { http.Error(w, http.StatusText(status), status) }
		if r.URL.RawPath != "" || r.URL.Opaque != "" {
			fail(http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			fail(http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery ||
			r.URL.Fragment != "" || r.URL.RawFragment != "" ||
			r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
			(r.Body != nil && r.Body != http.NoBody) {
			fail(http.StatusBadRequest)
			return
		}
		current, found, err := ads.ReadCurrentLocal(vault, root, child, time.Now())
		if err != nil {
			fail(http.StatusInternalServerError)
			return
		}
		if !found || current.Payload.PeerIntroductionURL != boundPeerIntroURL {
			fail(http.StatusConflict)
			return
		}
		stored, found, err := onboarding.ReadStoredChoice(vault, root, child)
		if err != nil {
			fail(http.StatusInternalServerError)
			return
		}
		if !found || stored.Acceptance == nil {
			fail(http.StatusConflict)
			return
		}
		if _, err := onboarding.CheckIntroduction(stored.Proposal.Bytes(), stored.Acceptance, root); err != nil {
			fail(http.StatusInternalServerError)
			return
		}
		evidence, err := onboarding.EncodeIntroduction(stored)
		if err != nil {
			fail(http.StatusInternalServerError)
			return
		}
		ad, err := wire.Marshal(current)
		if err != nil {
			fail(http.StatusInternalServerError)
			return
		}
		document, err := json.Marshal(struct {
			Version      int             `json:"version"`
			Introduction json.RawMessage `json:"introduction"`
			Ad           []byte          `json:"ad"`
		}{1, evidence, ad})
		if err != nil || len(document) > maxAdResponseBytes {
			fail(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		try.Out1(w.Write(document)).Logf("writing peer ad response")
	})
}
