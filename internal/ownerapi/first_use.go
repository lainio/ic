package ownerapi

import (
	"bytes"
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"

	"github.com/golang/glog"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const firstUsePath = "/owner/pw/first-use"

// LocalFirstUser grants only BobFirstUse for Bob's sole accepted relationship,
// authenticating the envelope's selected version against pinned local history.
// It borrows the existing owner mutation/signer lock, with no generic mutation,
// signer handle, credential, caller-selected binding or remote Vault capability.
type LocalFirstUser func(version int, request []byte) (response []byte, err error)

// NewFirstUseCredentials extends only node serve's operational composition.
// It also grants POST /owner/pw/holding/delete for the sole local holding;
// deletion needs no peer listener and shares the existing mutation lock.
// POST /owner/policy/deny selects only a peer, using the same local lock.
// The bound peer capability also admits a message then issues its receipt.
// POST /owner/pw/message/send prepares, sends once and observes a historical
// ACK under the same owner lock, releasing it for HTTP. Sending needs no peer
// listener on this node; its explicit routing hint grants no peer authority.
// GET /owner/pw/message/inbox reads authenticated local incoming history only;
// it needs no peer listener, current permission or signer.
// Earlier credentials retain their scopes. Bind once before serving; nil
// permanently disables peer capabilities. Startup neither signs nor writes.
func NewFirstUseCredentials(ctx context.Context, vault *storage.Vault,
	root, local key.Public, signer key.Handle, dir string,
) (http.Handler, string, func(net.Listener) (
	CurrentAdProver, LocalAcceptanceProver, LocalEstablisher, LocalFirstUser,
	LocalMessageReceiver,
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
		LocalMessageReceiver,
	) {
		prove := bind(peer)
		if prove == nil {
			return nil, nil, nil, nil, nil
		}
		return prove, h.proveLocalAcceptance, h.establishLocal, h.firstUseLocal,
			h.receiveMessageLocal
	}
	return handler, file, configure, nil
}

func (h *publicationHandler) firstUseLocal(version int, raw []byte,
) ([]byte, error) {
	raw = bytes.Clone(raw)
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if h.endpoint == "" {
		return nil, pw.ErrFirstUse
	}
	switch version {
	case 1:
		return pw.BobFirstUse(h.vault, h.root, h.child, h.signer, raw)
	case 2:
		return pw.BobFirstUseV2(h.vault, h.root, h.child, h.signer,
			h.firstUseRuntimeV2(), raw)
	default:
		return nil, pw.ErrFirstUse
	}
}

// Read only under the owner mutation/configuration/signer lock. The one-shot
// binder supplies this exact endpoint; HTTP input never supplies runtime.
func (h *publicationHandler) firstUseRuntimeV2() pw.ContactRuntimeV2 {
	return pw.ContactRuntimeV2{Running: h.endpoint != "",
		BoundOrigin: strings.TrimSuffix(h.endpoint, "/peer/introduction")}
}

type firstUseHandler struct{ *redemptionHandler }

func (h *firstUseHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == messageInboxPath {
		h.serveMessageInbox(w, r)
		return
	}
	if r.URL.Path == messageSendPath {
		h.serveMessageSend(w, r)
		return
	}
	if r.URL.Path == denyPath {
		h.serveDeny(w, r)
		return
	}
	if r.URL.Path == deleteHeldPath {
		h.serveDeleteHeld(w, r)
		return
	}
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
	version, status := readFirstUseSelector(w, r)
	if status != 0 {
		writeStatusError(w, status)
		return
	}
	if len(r.Trailer) != 0 {
		writeStatusError(w, http.StatusBadRequest)
		return
	}
	h.exchangeFirstUse(w, r, version)
}

func (h *firstUseHandler) exchangeFirstUse(w http.ResponseWriter,
	r *http.Request, version int,
) {
	glog.V(1).Info("intro_pw op=first_use side=requester " +
		"stage=request result=accepted")
	var saved pw.SavedFirstUse
	var savedV2 pw.SavedFirstUseV2
	var err error
	if version == 2 {
		savedV2, err = h.saveFirstUseV2(r.Context())
	} else {
		saved, err = h.saveFirstUse(r.Context())
	}
	if err != nil {
		writeStatusError(w, http.StatusConflict)
		return
	}
	// Await has committed. No lock, transaction or signer call spans HTTP.
	glog.V(1).Info("intro_pw op=first_use side=requester " +
		"stage=peer_exchange result=started")
	var response []byte
	if version == 2 {
		response, err = pw.SendFirstUseV2(r.Context(), savedV2)
	} else {
		response, err = pw.SendFirstUse(r.Context(), saved)
	}
	if err != nil {
		glog.V(1).Info("intro_pw op=first_use side=requester " +
			"stage=peer_exchange result=unknown reason=undetermined")
		http.Error(w, "First-use peer outcome unknown; Await retained",
			http.StatusBadGateway)
		return
	}
	glog.V(1).Info("intro_pw op=first_use side=requester " +
		"stage=peer_exchange result=response_received")
	var ready bool
	if version == 2 {
		ready = h.receiveFirstUseV2(response)
	} else {
		ready = h.receiveFirstUse(response)
	}
	if !ready {
		http.Error(w, "Local first use refused; peer outcome unknown",
			http.StatusConflict)
		return
	}
	writeIntroductionResult(w, []byte(`{"local_ready":true}`))
}

// Preserve the original literal {} selector and 64-byte bound. Only the exact
// additional object selects v2; surrounding JSON whitespace remains allowed.
func readFirstUseSelector(w http.ResponseWriter, r *http.Request) (int, int) {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" ||
		len(r.Header.Values("Content-Type")) != 1 {
		return 0, http.StatusUnsupportedMediaType
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return 0, http.StatusRequestEntityTooLarge
		}
		return 0, http.StatusBadRequest
	}
	switch string(bytes.Trim(data, " \t\r\n")) {
	case "{}":
		return 1, 0
	case `{"version":2}`:
		return 2, 0
	default:
		return 0, http.StatusBadRequest
	}
}

func (h *firstUseHandler) saveFirstUseV2(ctx context.Context,
) (pw.SavedFirstUseV2, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		return pw.SavedFirstUseV2{}, err
	}
	if h.endpoint == "" {
		return pw.SavedFirstUseV2{}, pw.ErrFirstUse
	}
	return pw.SaveFirstUseV2(h.vault, h.root, h.child, h.signer,
		h.firstUseRuntimeV2())
}

func (h *firstUseHandler) receiveFirstUseV2(response []byte) bool {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	ready, err := pw.ReceiveFirstUseV2(h.vault, h.root, h.child, h.signer,
		h.firstUseRuntimeV2(), response)
	return err == nil && ready
}

func (h *firstUseHandler) saveFirstUse(
	ctx context.Context,
) (pw.SavedFirstUse, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if err := ctx.Err(); err != nil {
		glog.V(1).Info("intro_pw op=first_use side=requester " +
			"stage=await result=refused reason=request_canceled")
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
