package pw

import (
	"context"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// PreparedMessageSendV2 owns only an immutable signed envelope and authenticated
// destination. Every explicit retry must prepare again under current guards.
type PreparedMessageSendV2 struct{ saved savedMessageTransmitV2 }

// ValidMessageSendInputV2 checks only text. Owner input cannot select a peer.
func ValidMessageSendInputV2(text string) bool {
	return validOutgoingText(text)
}

// PrepareMessageSendV2 composes three independent durable effects: outgoing,
// signed envelope, then sent authorization. Hold the owner mutation/signer/
// configuration lock with runtime from the actual bound listener, as for v2
// first use. Each operation rechecks its own guards; failures never roll back
// earlier commits. No network, automatic retry, second slot or rebind occurs.
func PrepareMessageSendV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2, text string,
) (_ PreparedMessageSendV2, err error) {
	defer err2.Handle(&err, nil)

	try.To1(CreateOutgoingV2(vault, root, local, signer, runtime, text))
	try.To1(PrepareOutgoingEnvelopeV2(vault, root, local, signer, runtime))
	saved := try.To1(saveMessageTransmitV2(vault, root, local, signer, runtime))
	return PreparedMessageSendV2{saved: saved}, nil
}

// SendMessageOnceV2 makes one bounded direct POST to the saved contact. ALL
// owner, signer and Vault locks must be released. It returns untrusted receipt
// bytes only: reacquire the owner lock and call ObserveMessageReceiptV2 to
// authenticate and commit ACK. Preflight refusal is ErrMessageNotDispatched;
// any failure after client.Do begins leaves the peer outcome unknown.
// Signed plaintext over loopback is a trusted-host demo, not encryption or AKE.
func SendMessageOnceV2(ctx context.Context, prepared PreparedMessageSendV2,
) ([]byte, error) {
	return sendMessageVersionOnce(ctx, prepared.saved.envelope,
		prepared.saved.destination, 2)
}
