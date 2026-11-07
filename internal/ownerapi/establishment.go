package ownerapi

import (
	"bytes"
	"context"
	"net"
	"net/http"

	"github.com/golang/glog"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// LocalEstablisher authenticates one exact signed request in the envelope's
// selected format and returns only that version's currently authorized saved
// response. It grants no generic signing or Vault writes. The owner service
// owns the pinned identities, endpoint and mutex.
type LocalEstablisher func(version int, request []byte) (
	acceptance []byte, err error,
)

// NewEstablishmentCredentials adds a narrow peer establishment capability to
// NewAcceptanceCredentials' owner routes and peer proof capabilities, plus
// explicit POST /owner/pw/invitations/redeem for one saved requester attempt.
// Earlier constructors do not grant redemption. V1 needs no Alice listener;
// explicit v2 redemption requires her own bound peer endpoint.
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
		ctx, h, &redemptionHandler{
			&acceptanceExchangeHandler{&verificationHandler{h}},
		}, dir)
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

func (h *publicationHandler) establishLocal(version int, raw []byte,
) ([]byte, error) {
	raw = bytes.Clone(raw)
	stage, reason, retained := "guards", "undetermined", false
	defer func() {
		if retained {
			glog.V(1).Info("intro_pw op=establish side=acceptor " +
				"stage=reply result=retained")
		} else {
			glog.V(1).Infof("intro_pw op=establish side=acceptor "+
				"stage=%s result=refused reason=%s", stage, reason)
		}
	}()
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if version != 1 && version != 2 {
		return nil, pw.ErrEstablishment
	}
	if h.endpoint == "" {
		reason = "peer_listener_unavailable"
		return nil, pw.ErrEstablishment
	}
	row, found, err := pw.ReadInvitation(h.vault, h.root, h.child)
	if err != nil || !found {
		if err == nil {
			reason = "invitation_unavailable"
		}
		return nil, pw.ErrEstablishment
	}
	switch row.State {
	case pw.InvitationActive:
		// BobAccept authenticates, checks absence of both history and holding
		// before signing, and rechecks all durable guards in its sole Update.
		// A failure is final for this invocation; never try acceptance twice.
		if version == 2 {
			err = pw.BobAcceptV2(h.vault, h.root, h.child, h.signer,
				h.endpoint, raw)
		} else {
			err = pw.BobAccept(h.vault, h.root, h.child, h.signer,
				h.endpoint, raw)
		}
		if err != nil {
			return nil, pw.ErrEstablishment
		}
	case pw.InvitationConsumed:
		// Never call BobAccept again, even for missing/corrupt saved history.
	default:
		reason = "invitation_incompatible"
		return nil, pw.ErrEstablishment
	}
	// Initial delivery and retry use the identical guarded, read-only path.
	// Commit has completed. A refused reply cannot roll that history back.
	stage = "reply"
	var response []byte
	if version == 2 {
		response, err = pw.BobReplyV2(h.vault, h.root, h.child, h.signer,
			h.endpoint, raw)
	} else {
		response, err = pw.BobReply(h.vault, h.root, h.child, h.signer,
			h.endpoint, raw)
	}
	retained = err == nil
	return response, err
}
