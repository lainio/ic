package pw

import (
	"context"

	"github.com/lainio/ic/internal/pw/internal/messagehttp"
)

var (
	errMessageNotDispatched  = messagehttp.ErrNotDispatched
	errMessageOutcomeUnknown = messagehttp.ErrOutcomeUnknown
)

// sendMessageOnce requires a fresh saveMessageTransmit result and ALL owner,
// signer and Vault locks released. It has no storage capability. An explicit
// loopback URL only routes bytes: Bob's historical ad cannot locate Alice's
// current listener. Message text is plaintext to this endpoint, suitable only
// for a trusted-host disposable demo, not production security.
//
// Exactly one POST, with no redirect, retry, proxy, cookies, credentials,
// compression or shared client state. Preflight errors mean no dispatch. Once
// Do starts, any transport/response error leaves receiver commit uncertain.
// Even HTTP 200 returns ONLY untrusted bytes: separately observeMessageReceipt
// under the sender owner lock to authenticate and save a historical ACK.
func sendMessageOnce(ctx context.Context, saved savedMessageTransmit,
	peerMessageURL string,
) ([]byte, error) {
	return sendMessageVersionOnce(ctx, saved.envelope, peerMessageURL, 1)
}

func sendMessageVersionOnce(
	ctx context.Context,
	envelope, peerMessageURL string,
	version int,
) ([]byte, error) {
	if ctx == nil || len(envelope) == 0 ||
		len(envelope) > maxMessageEnvelopeBytes ||
		(version != 1 && version != 2) ||
		!messagehttp.ValidURL(peerMessageURL) || ctx.Err() != nil {
		return nil, errMessageNotDispatched
	}

	receiptLimit := maxMessageReceiptBytes
	if version == 2 {
		receiptLimit = maxMessageReceiptBytesV2
	}
	return messagehttp.Send(
		ctx,
		envelope,
		peerMessageURL,
		version,
		receiptLimit,
	)
}
