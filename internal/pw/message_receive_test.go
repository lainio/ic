package pw

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestAcceptMessageAndReceiptCommitBeforeSigningFailure(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for index := range int64(4) {
			call := index + 1
			t.Run(fmt.Sprint(receiver, "/", call), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, raw := incomingTest(t, receiver, "private message")
				before, other := outgoingTestState(t, n.own.vault),
					outgoingTestState(t, n.other.vault)
				remaining := n.own.lease.remaining.Load()
				signer := &probeSigner{Handle: n.signer}
				signer.sign = func(d []byte) ([]byte, error) {
					if signer.signCalls.Load() == call {
						return raw, errors.New("private signing diagnostic")
					}
					return n.signer.Sign(d)
				}
				n.other.unchanged(t, func() {
					got, err := AcceptMessageAndReceipt(n.own.vault,
						f.root.public, n.local, signer, raw)
					assert.Error(err)
					assert.SNil(got)
				})
				assert.Equal(signer.signCalls.Load(), call) // No retry.
				if call > 1 {
					before["root"][inboxKey] = try.To1(
						wire.Marshal(inboxMessage{
							Version: 1, Envelope: raw,
						}),
					)
					remaining--
				}
				assert.Equal(n.own.lease.remaining.Load(), remaining)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				assert.DeepEqual(outgoingTestState(t, n.other.vault), other)
				n.own.reopen(t)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
				if call == 1 {
					return
				}
				n.own.lease.remaining.Store(0)
				n.own.unchanged(t, func() {
					got := try.To1(AcceptMessageAndReceipt(n.own.vault,
						f.root.public, n.local, n.signer, raw))
					try.To(ValidateLocalMessageReceipt(raw, got))
				})
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			})
		}
	}
}

func TestAcceptMessageAndReceiptGuardMutationDuringProbes(t *testing.T) {
	for _, guard := range []string{"deny", "delete", "history"} {
		for index := range int64(4) {
			call := index + 1
			t.Run(fmt.Sprint(guard, "/", call), func(t *testing.T) {
				defer assert.PushTester(t)()
				f, n, raw := incomingTest(t, 1, "Bob initiates")
				signer := &probeSigner{Handle: n.signer}
				var afterMutation map[string]map[string][]byte
				var remaining int64
				signer.sign = func(d []byte) (_ []byte, err error) {
					defer err2.Handle(&err, nil)
					if signer.signCalls.Load() == call {
						try.To(mutateEnvelopeGuard(n, f.root.public, guard))
						afterMutation = outgoingTestState(t, n.own.vault)
						remaining = n.own.lease.remaining.Load()
					}
					return n.signer.Sign(d)
				}
				n.other.unchanged(t, func() {
					got, err := AcceptMessageAndReceipt(n.own.vault,
						f.root.public, n.local, signer, raw)
					assert.Error(err)
					assert.SNil(got)
				})
				assert.DeepEqual(
					outgoingTestState(t, n.own.vault),
					afterMutation,
				)
				assert.Equal(n.own.lease.remaining.Load(), remaining)
				if call == 1 {
					assert.SNil(afterMutation["root"][inboxKey])
				} else {
					assert.DeepEqual(afterMutation["root"][inboxKey],
						try.To1(wire.Marshal(inboxMessage{Version: 1, Envelope: raw})))
				}
			})
		}
	}
}

func TestAcceptMessageAndReceiptOwnsExactInput(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, raw := incomingTest(t, 0, "unchanged text")
	original := bytes.Clone(raw)
	root, local := bytes.Clone(f.root.public), bytes.Clone(n.local)
	signer := &probeSigner{Handle: n.signer}
	signer.sign = func(d []byte) ([]byte, error) {
		clear(raw)
		clear(root)
		clear(local)
		return n.signer.Sign(d)
	}
	n.other.unchanged(t, func() {
		receipt := try.To1(AcceptMessageAndReceipt(n.own.vault,
			root, local, signer, raw))
		try.To(ValidateLocalMessageReceipt(original, receipt))
	})
	assert.DeepEqual(outgoingTestState(t, n.own.vault)["root"][inboxKey],
		try.To1(wire.Marshal(inboxMessage{Version: 1, Envelope: original})))
}

func TestAcceptMessageAndReceiptRejectsChangedEnvelope(t *testing.T) {
	defer assert.PushTester(t)()
	f, n, raw := incomingTest(t, 1, "saved Bob text")
	sender := outgoingTestNodes(f)[0]
	bad := incomingWireCases(t, raw, sender.signer, f.root.handle)
	for _, repeat := range []bool{false, true} {
		if repeat {
			try.To1(AcceptMessageAndReceipt(n.own.vault, f.root.public,
				n.local, n.signer, raw))
		}
		for _, name := range []string{"wrong signer", "signature",
			"signed/root", "signed/accepted digest", "signed/role",
			"mutated/changed body", "signed/changed body"} {
			if name == "signed/changed body" && !repeat {
				continue // An authenticated first message is not yet a conflict.
			}
			signer := &probeSigner{Handle: n.signer}
			n.other.unchanged(t, func() {
				n.own.unchanged(t, func() {
					got, err := AcceptMessageAndReceipt(n.own.vault,
						f.root.public, n.local, signer, bad[name])
					assert.Equal(err, errIncoming)
					assert.SNil(got)
				})
			})
			assert.Equal(signer.signCalls.Load(), 0)
		}
	}
}

// Test-only access lets external HTTP tests reuse the saved sender operations
// and independent sender-side verifier without widening production APIs.
var CreateOutgoingForTest = createOutgoing
var PrepareMessageEnvelopeForTest = prepareOutgoingEnvelope
var MessageStateForTest = outgoingTestState
var MessageWireCasesForTest = incomingWireCases

func VerifySavedMessageReceiptForTest(v *storage.Vault, root, local key.Public,
	receipt []byte,
) (_ []byte, err error) {
	defer err2.Handle(&err, nil)
	var payload []byte
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		binding, _ := try.To2(outgoingHistory(tx, root, local))
		message := try.To1(readEnvelopeMessage(tx, binding))
		envelope := try.To1(readMessageEnvelope(tx, binding, message))
		verified := try.To1(decodeMessageReceipt(receipt, envelope, binding))
		payload = try.To1(wire.Marshal(verified.Payload))
		return nil
	}))
	return payload, nil
}
