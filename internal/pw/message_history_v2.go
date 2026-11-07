package pw

import (
	"bytes"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const outgoingHistoryPurposeV2 = "pw-message-accepted-history/v2"

// The original requester/target orientation comes only from this node's
// authenticated history. Presence chooses a validator, never an authority.
// Historical first use is sufficient; no fresh ad, invitation, shared PWOpen,
// Trust or assertion about current remote permission belongs here.
func outgoingHistoryV2(tx storage.ReadTx, root, local key.Public,
) (_ outgoingBindingV2, _ localHistoryV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	_, alice := try.To2(tx.Get([]byte(attemptKey)))
	h := try.To1(readLocalHistoryV2(tx, root, local, alice))
	assert.That(h.version == 2 && h.accepted, errOutgoing)
	if alice {
		assert.That((h.firstUse.State == useReady ||
			h.firstUse.State == useExpired) && len(h.firstUse.Response) != 0,
			errOutgoing)
	} else {
		assert.That(h.useSeen, errOutgoing)
	}

	peer := h.binding.Requester
	if alice {
		peer = h.binding.Target
	}
	// readLocalHistoryV2 authenticated this exact canonical record in the same
	// snapshot. Hash the entire saved signed acceptance, not only its payload:
	// both contacts AND the exact response signature contribute to identity.
	raw, _ := try.To2(tx.Get([]byte(acceptedKey)))
	digest := key.HashTagged(outgoingHistoryPurposeV2, raw)
	p := acceptedPayloadV2(h.binding, h.request)
	return outgoingBindingV2{
		Root:           bytes.Clone(root),
		Sender:         bytes.Clone(local),
		Receiver:       bytes.Clone(peer),
		Requester:      alice,
		RequestDigest:  p.RequestDigest,
		AcceptedDigest: digest[:],
	}, h, nil
}

func outgoingPrerequisitesV2(tx storage.ReadTx, root, local key.Public,
	runtime ContactRuntimeV2,
) (_ outgoingBindingV2, err error) {
	defer err2.Handle(&err, nil)

	binding, history := try.To2(outgoingHistoryV2(tx, root, local))
	try.To(firstUseGuardsV2(tx, history, runtime, binding.Requester))
	return binding, nil
}
