package pw

import (
	"context"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// ErrMessageNotDispatched distinguishes local transport preflight refusal from
// an attempted HTTP exchange whose peer outcome is unknown. Neither undoes sent.
var ErrMessageNotDispatched = errMessageNotDispatched

// PreparedMessageSend holds only one immutable authorized attempt, with no
// Vault, signer, routing hint or continuing permission. Every explicit retry
// must prepare again under current local guards.
type PreparedMessageSend struct{ saved savedMessageTransmit }

// MessageSendReceipt holds untrusted HTTP output, not an authenticated ACK.
// Only ObserveMessageReceipt can authenticate it against local saved history.
type MessageSendReceipt struct{ raw string }

// ValidMessageSendInput checks bounded text and the existing exact numeric
// loopback route before any local writes. The URL conveys no peer authority.
func ValidMessageSendInput(text, peerMessageURL string) bool {
	return validOutgoingText(text) && validMessageURL(peerMessageURL)
}

// PrepareMessageSend composes CreateOutgoing, envelope preparation and the
// local Transmit/RetryExact boundary. The caller MUST hold its existing owner
// mutation/signer lock throughout, using its pinned identities and bound Vault.
// Each step retains its own guards and transaction: later refusal preserves
// earlier commits. No rollback, replacement, automatic retry or HTTP occurs.
func PrepareMessageSend(vault *storage.Vault, root, local key.Public,
	signer key.Handle, text string,
) (_ PreparedMessageSend, err error) {
	defer err2.Handle(&err, nil)

	try.To1(createOutgoing(vault, root, local, signer, text))
	try.To1(prepareOutgoingEnvelope(vault, root, local, signer))
	saved := try.To1(saveMessageTransmit(vault, root, local, signer))
	return PreparedMessageSend{saved: saved}, nil
}

// SendMessageOnce performs exactly the existing bounded Go-07 exchange. ALL
// owner, signer and Vault locks must be released. A successful return contains
// only untrusted receipt bytes; it makes no ACK or remote storage claim.
func SendMessageOnce(ctx context.Context, prepared PreparedMessageSend,
	peerMessageURL string,
) (MessageSendReceipt, error) {
	raw, err := sendMessageOnce(ctx, prepared.saved, peerMessageURL)
	return MessageSendReceipt{raw: string(raw)}, err
}

// ObserveMessageReceipt requires the same owner lock as preparation. It checks
// only exact authenticated history, never current permission or signer state.
// Nil means the local ACK committed or an authenticated ACK already existed.
// A failure cannot establish whether the receiver committed; never undo sent.
func ObserveMessageReceipt(vault *storage.Vault, root, local key.Public,
	receipt MessageSendReceipt,
) error {
	_, err := observeMessageReceipt(vault, root, local, []byte(receipt.raw))
	return err
}
