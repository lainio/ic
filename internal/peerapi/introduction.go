// Package peerapi provides opt-in public introduction/ad disclosure and bounded
// current-ad challenge proofs. It provides no owner or receiver operations.
package peerapi

import (
	"bytes"
	"net/http"

	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// NewHandler borrows the Vault and copies independently configured identities.
// Mount only on an explicitly opted-in peer listener. No owner router, token,
// signing handle, subject selector, or state-changing operation is available.
func NewHandler(vault *storage.Vault, root, child key.Public) http.Handler {
	root, child = bytes.Clone(root), bytes.Clone(child)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path != "/peer/introduction" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		stored, found, err := onboarding.ReadStoredChoice(vault, root, child)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if !found || stored.Acceptance == nil {
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}
		// Apply the same bounded public admission policy as received evidence,
		// including unsupported backup/rotation options on ancestors. This
		// stateless check never calls VerifyReceived or changes Known.
		if _, err := onboarding.CheckIntroduction(stored.Proposal.Bytes(), stored.Acceptance, root); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		document, err := onboarding.EncodeIntroduction(stored)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		try.Out1(w.Write(document)).Logf("writing peer introduction response")
	})
}
