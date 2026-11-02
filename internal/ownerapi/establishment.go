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

// LocalEstablisher accepts one exact signed request and returns only BobReply's
// currently authorized saved response. It grants no generic signing or Vault
// writes. The owner service owns the pinned identities, endpoint and mutex.
type LocalEstablisher func(request []byte) (acceptance []byte, err error)

// NewEstablishmentCredentials adds a narrow peer establishment capability to
// NewAcceptanceCredentials' unchanged owner routes and peer proof capabilities.
// Bind once with the actual opt-in listener before Serve. Nil permanently
// disables all peer capabilities. Setup/binding never signs or writes the Vault.
// The caller must join both servers before closing the borrowed Vault/signer.
func NewEstablishmentCredentials(ctx context.Context, vault *storage.Vault,
	root, local key.Public, signer key.Handle, dir string,
) (http.Handler, string, func(net.Listener) (
	CurrentAdProver, LocalAcceptanceProver, LocalEstablisher,
), error) {
	h := &publicationHandler{
		deviceHandler: newDeviceHandler(vault, root, local, signer),
	}
	handler, file, bind, err := newPublicationProofCredentials(
		ctx, h, &acceptanceExchangeHandler{&verificationHandler{h}}, dir)
	if err != nil {
		return nil, "", nil, err
	}
	configure := func(peer net.Listener) (
		CurrentAdProver, LocalAcceptanceProver, LocalEstablisher,
	) {
		prove := bind(peer)
		if prove == nil {
			return nil, nil, nil
		}
		return prove, h.proveLocalAcceptance, h.establishLocal
	}
	return handler, file, configure, nil
}

func (h *publicationHandler) establishLocal(raw []byte) ([]byte, error) {
	raw = bytes.Clone(raw)
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if h.endpoint == "" {
		return nil, pw.ErrEstablishment
	}
	row, found, err := pw.ReadInvitation(h.vault, h.root, h.child)
	if err != nil || !found {
		return nil, pw.ErrEstablishment
	}
	switch row.State {
	case pw.InvitationActive:
		// BobAccept authenticates, checks absence of both history and holding
		// before signing, and rechecks all durable guards in its sole Update.
		// A failure is final for this invocation; never try acceptance twice.
		if err := pw.BobAccept(h.vault, h.root, h.child, h.signer,
			h.endpoint, raw); err != nil {
			return nil, pw.ErrEstablishment
		}
	case pw.InvitationConsumed:
		// Never call BobAccept again, even for missing/corrupt saved history.
	default:
		return nil, pw.ErrEstablishment
	}
	// Initial delivery and retry use the identical guarded, read-only path.
	// Commit has completed. A refused reply cannot roll that history back.
	return pw.BobReply(h.vault, h.root, h.child, h.signer, h.endpoint, raw)
}
