package ownerapi

import (
	"bytes"
	"context"
	"net"
	"net/http"

	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const firstUsePath = "/owner/pw/first-use"

// LocalFirstUser grants only BobFirstUse for Bob's sole accepted relationship.
// It borrows the existing owner mutation/signer lock, with no generic mutation,
// signer handle, credential, caller-selected binding or remote Vault capability.
type LocalFirstUser func(request []byte) (response []byte, err error)

// NewFirstUseCredentials extends only node serve's operational composition.
// Earlier credentials retain their scopes. Bind once before serving; nil
// permanently disables peer capabilities. Startup neither signs nor writes.
func NewFirstUseCredentials(ctx context.Context, vault *storage.Vault,
	root, local key.Public, signer key.Handle, dir string,
) (http.Handler, string, func(net.Listener) (
	CurrentAdProver, LocalAcceptanceProver, LocalEstablisher, LocalFirstUser,
), error) {
	h := &publicationHandler{
		deviceHandler: newDeviceHandler(vault, root, local, signer),
	}
	handler, file, bind, err := newPublicationProofCredentials(ctx, h,
		&firstUseHandler{&redemptionHandler{
			&acceptanceExchangeHandler{&verificationHandler{h}},
		}}, dir)
	if err != nil {
		return nil, "", nil, err
	}
	configure := func(peer net.Listener) (
		CurrentAdProver, LocalAcceptanceProver, LocalEstablisher, LocalFirstUser,
	) {
		prove := bind(peer)
		if prove == nil {
			return nil, nil, nil, nil
		}
		return prove, h.proveLocalAcceptance, h.establishLocal, h.firstUseLocal
	}
	return handler, file, configure, nil
}

func (h *publicationHandler) firstUseLocal(raw []byte) ([]byte, error) {
	raw = bytes.Clone(raw)
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if h.endpoint == "" {
		return nil, pw.ErrFirstUse
	}
	return pw.BobFirstUse(h.vault, h.root, h.child, h.signer, raw)
}

type firstUseHandler struct{ *redemptionHandler }

func (h *firstUseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != firstUsePath {
		h.redemptionHandler.ServeHTTP(w, r)
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
		r.URL.Fragment != "" || r.URL.RawFragment != "" ||
		len(r.Header.Values("Content-Encoding")) != 0 ||
		len(r.Header.Values("Trailer")) != 0 || len(r.Trailer) != 0 {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	if r.Body == nil {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	if !readEmptyObjectRequest(w, r) {
		return
	}
	if len(r.Trailer) != 0 {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	saved, err := h.saveFirstUse(r.Context())
	if err != nil {
		writeStatusError(w, http.StatusConflict)
		return
	}
	// Await has committed. No lock, transaction or signer call spans HTTP.
	response, err := pw.SendFirstUse(r.Context(), saved)
	if err != nil {
		http.Error(w, "First-use peer outcome unknown; Await retained",
			http.StatusBadGateway)
		return
	}
	if !h.receiveFirstUse(response) {
		http.Error(w, "Local first use refused; peer outcome unknown",
			http.StatusConflict)
		return
	}
	writeIntroductionResult(w, []byte(`{"local_ready":true}`))
}

func (h *firstUseHandler) saveFirstUse(
	ctx context.Context,
) (pw.SavedFirstUse, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		return pw.SavedFirstUse{}, err
	}
	return pw.SaveFirstUse(h.vault, h.root, h.child, h.signer)
}

func (h *firstUseHandler) receiveFirstUse(response []byte) bool {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	ready, err := pw.ReceiveFirstUse(
		h.vault,
		h.root,
		h.child,
		h.signer,
		response,
	)
	return err == nil && ready
}
