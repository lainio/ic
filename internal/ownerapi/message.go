package ownerapi

import (
	"bytes"
	"errors"

	"github.com/lainio/ic/internal/pw"
)

// LocalMessageReceiver grants only inbox admission followed by a receipt for
// that exact envelope, using the existing pinned owner state and signer lock.
type LocalMessageReceiver func(version int, envelope []byte) (
	receipt []byte, err error,
)

func (h *publicationHandler) receiveMessageLocal(version int, raw []byte,
) ([]byte, error) {
	raw = bytes.Clone(raw)
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if h.endpoint == "" {
		return nil, errors.New("local message receiver disabled")
	}
	switch version {
	case 1:
		return pw.AcceptMessageAndReceipt(h.vault, h.root, h.child, h.signer, raw)
	case 2:
		return pw.AcceptMessageAndReceiptV2(h.vault, h.root, h.child, h.signer,
			h.firstUseRuntimeV2(), raw)
	default:
		return nil, errors.New("local message version refused")
	}
}
