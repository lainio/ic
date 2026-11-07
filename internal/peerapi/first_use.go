package peerapi

import (
	"encoding/json"
	"net/http"

	"github.com/golang/glog"
	"github.com/lainio/ic/internal/pw"
)

// NewFirstUseHandler adds only the opt-in POST /peer/pw/first-use route.
// The narrow owner capability owns authentication, guards, signing and receipt
// commit. This handler has no Vault, signer or owner credentials. Nil disables it.
func NewFirstUseHandler(
	firstUse func(int, []byte) ([]byte, error), next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/peer/pw/first-use" || firstUse == nil {
			next.ServeHTTP(w, r)
			return
		}
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
		if len(r.Header.Values("Content-Encoding")) != 0 ||
			len(r.Header.Values("Trailer")) != 0 || len(r.Trailer) != 0 {
			fail(http.StatusBadRequest)
			return
		}
		request, status := readVersionedEstablishmentRequest(w, r)
		if status != 0 {
			fail(status)
			return
		}
		if len(r.Trailer) != 0 {
			fail(http.StatusBadRequest)
			return
		}
		glog.V(1).Info("intro_pw op=first_use side=acceptor " +
			"stage=request result=accepted")
		// The selected domain operation authenticates canonical signed bytes
		// against pinned local history before signing or committing a receipt.
		response, err := firstUse(request.version, request.raw)
		if err != nil {
			glog.V(1).Info("intro_pw op=first_use side=acceptor " +
				"stage=local result=refused reason=undetermined")
			fail(http.StatusConflict)
			return
		}
		if len(response) == 0 || len(response) > pw.MaxEstablishmentBytes {
			fail(http.StatusInternalServerError)
			return
		}
		document, err := json.Marshal(struct {
			Version  int    `json:"version"`
			Response []byte `json:"response"`
		}{request.version, response})
		if err != nil || len(document) > maxEstablishmentEnvelopeBytes {
			fail(http.StatusInternalServerError)
			return
		}
		// The receipt committed and the service lock ended before these bytes.
		// A failed write cannot roll back useSeen or trigger another success.
		glog.V(1).Info("intro_pw op=first_use side=acceptor " +
			"stage=response result=prepared")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(document)
	})
}
