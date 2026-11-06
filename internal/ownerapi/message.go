package ownerapi

import (
	"errors"

	"github.com/lainio/ic/internal/pw"
)

// LocalMessageReceiver grants only inbox admission followed by a receipt for
// that exact envelope, using the existing pinned owner state and signer lock.
type LocalMessageReceiver func(envelope []byte) (receipt []byte, err error)

func (h *publicationHandler) receiveMessageLocal(raw []byte) ([]byte, error) {
	h.mutations.Lock()
	defer h.mutations.Unlock()
	if h.endpoint == "" {
		return nil, errors.New("local message receiver disabled")
	}
	return pw.AcceptMessageAndReceipt(h.vault, h.root, h.child, h.signer, raw)
}
