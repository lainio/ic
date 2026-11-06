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

func TestMessageReceiptRequiresExactPriorInboxCommit(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTest(t, receiver, "exact saved envelope")
		sender := outgoingTestNodes(f)[1-receiver]
		invalid := incomingWireCases(t, raw, sender.signer, f.root.handle)
		var envelope messageEnvelope
		try.To(wire.UnmarshalCanonical(&envelope, raw))
		invalid["resigned"] = signMessageEnvelope(
			t,
			envelope.Message,
			sender.signer,
		)
		assert.ThatNot(bytes.Equal(invalid["resigned"], raw))
		for _, committed := range []bool{false, true} {
			if committed {
				assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
					f.root.public, n.local, n.signer, raw)))
			} else {
				// Saved, signed and independently authenticated elsewhere is
				// insufficient: the receiver still has no committed inbox.
				try.To1(decodeMessageEnvelope(raw,
					envelopePeerBinding(t, f.root.public, sender)))
				signer := &probeSigner{Handle: n.signer}
				refuseMessageReceipt(t, f, n, signer, raw)
				assert.Equal(signer.signCalls.Load(), 0)
			}
			for name, bad := range invalid {
				t.Run(
					fmt.Sprint(n.name, "/", committed, "/", name),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						signer := &probeSigner{Handle: n.signer}
						refuseMessageReceipt(t, f, n, signer, bad)
						assert.Equal(signer.signCalls.Load(), 0)
					},
				)
			}
		}
	}
}

func TestMessageReceiptInvalidCommittedInbox(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw, _ := receiptTest(t, receiver)
		sender := outgoingTestNodes(f)[1-receiver]
		original := outgoingTestState(t, n.own.vault)["root"][inboxKey]
		_, foreign, _, _ := receiptTest(t, receiver)
		invalid := map[string][]byte{
			"missing": nil, "empty": {}, "malformed": {0xff},
			"oversize":     make([]byte, maxInboxBytes+1),
			"foreign":      outgoingTestState(t, foreign.own.vault)["root"][inboxKey],
			"noncanonical": append([]byte{0x98, 2}, original[1:]...),
			"version": try.To1(
				wire.Marshal(inboxMessage{Version: 2, Envelope: raw}),
			),
		}
		for name, bad := range incomingWireCases(t, raw, sender.signer, f.root.handle) {
			invalid["envelope/"+name] = try.To1(wire.Marshal(inboxMessage{
				Version: 1, Envelope: bad,
			}))
		}
		var envelope messageEnvelope
		try.To(wire.UnmarshalCanonical(&envelope, raw))
		invalid["resigned"] = try.To1(wire.Marshal(inboxMessage{Version: 1,
			Envelope: signMessageEnvelope(t, envelope.Message, sender.signer)}))
		for name, bad := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					if bad == nil {
						return tx.Delete([]byte(inboxKey))
					}
					return tx.Put([]byte(inboxKey), bad)
				}))
				refuseMessageReceipt(t, f, n, n.signer, raw)
			})
		}
		try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			try.To(tx.Delete([]byte(inboxKey)))
			try.To1(tx.EnsureChild([]byte(inboxKey)))
			return nil
		}))
		refuseMessageReceipt(t, f, n, n.signer, raw)
	}
}

func signTestReceipt(t *testing.T, receipt messageReceipt,
	signer key.Handle, purpose string,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(purpose, try.To1(wire.Marshal(receipt.Payload)))
	receipt.Signature = try.To1(signer.Sign(digest[:]))
	return try.To1(wire.Marshal(receipt))
}

func TestMessageReceiptBoundedCanonicalVerifier(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw, expected := receiptTest(t, receiver)
		valid := try.To1(issueMessageReceipt(n.own.vault, f.root.public,
			n.local, n.signer, raw))
		receipt := try.To1(decodeMessageReceipt(valid, raw, expected))
		invalid := map[string][]byte{
			"empty": {}, "malformed": {0xff},
			"oversize":         make([]byte, maxMessageReceiptBytes+1),
			"array":            append([]byte{0x98, 3}, valid[1:]...),
			"version encoding": append([]byte{0x83, 0x18, 1}, valid[2:]...),
			"payload encoding": append([]byte{0x83, 1, 0x98, 3}, valid[3:]...),
			"tag":              append([]byte{0xc0}, valid...),
			"trailing":         append(bytes.Clone(valid), 0),
			"wrong signer": signTestReceipt(
				t,
				receipt,
				f.root.handle,
				messageReceiptPurpose,
			),
		}
		for _, purpose := range []string{messageAuthPurpose, AcceptedPurpose,
			FirstUsePurpose, FirstUseResponsePurpose, messageReceiptEnvelopePurpose} {
			invalid["purpose/"+purpose] = signTestReceipt(
				t,
				receipt,
				n.signer,
				purpose,
			)
		}
		for name, change := range map[string]func(*messageReceipt){
			"version":       func(r *messageReceipt) { r.Version++ },
			"hash":          func(r *messageReceipt) { r.Payload.EnvelopeDigest[0] ^= 1 },
			"hash length":   func(r *messageReceipt) { r.Payload.EnvelopeDigest = nil },
			"ID":            func(r *messageReceipt) { r.Payload.ID[0] ^= 1 },
			"ID length":     func(r *messageReceipt) { r.Payload.ID = nil },
			"root":          func(r *messageReceipt) { r.Payload.Binding.Root = n.local },
			"sender":        func(r *messageReceipt) { r.Payload.Binding.Sender = n.local },
			"issuer":        func(r *messageReceipt) { r.Payload.Binding.Receiver = n.peer },
			"role":          func(r *messageReceipt) { r.Payload.Binding.Requester = !r.Payload.Binding.Requester },
			"request":       func(r *messageReceipt) { r.Payload.Binding.RequestDigest[0] ^= 1 },
			"history":       func(r *messageReceipt) { r.Payload.Binding.AcceptedDigest[0] ^= 1 },
			"signature":     func(r *messageReceipt) { r.Signature[len(r.Signature)-1] ^= 1 },
			"DER empty":     func(r *messageReceipt) { r.Signature = nil },
			"DER malformed": func(r *messageReceipt) { r.Signature = []byte{1, 2, 3} },
			"DER trailing":  func(r *messageReceipt) { r.Signature = append(r.Signature, 0) },
			"DER size":      func(r *messageReceipt) { r.Signature = make([]byte, 73) },
		} {
			var changed messageReceipt
			try.To(wire.UnmarshalCanonical(&changed, valid))
			change(&changed)
			invalid[name] = try.To1(wire.Marshal(changed))
			if name == "version" ||
				!bytes.Equal(try.To1(wire.Marshal(changed.Payload)),
					try.To1(wire.Marshal(receipt.Payload))) {
				invalid["signed/"+name] = signTestReceipt(
					t,
					changed,
					n.signer,
					messageReceiptPurpose,
				)
			}
		}
		for name, bad := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				got, err := decodeMessageReceipt(bad, raw, expected)
				assert.Equal(err, errMessageReceipt)
				assert.DeepEqual(got, messageReceipt{})
			})
		}

		// Even an authentic new signature on identical text/ID is a different
		// envelope. The sender must supply its exact saved signed bytes.
		sender := outgoingTestNodes(f)[1-receiver]
		var envelope messageEnvelope
		try.To(wire.UnmarshalCanonical(&envelope, raw))
		wrongEnvelopes := incomingWireCases(
			t,
			raw,
			sender.signer,
			f.root.handle,
		)
		wrongEnvelopes["resigned"] = signMessageEnvelope(
			t,
			envelope.Message,
			sender.signer,
		)
		for _, wrong := range wrongEnvelopes {
			_, err := decodeMessageReceipt(valid, wrong, expected)
			assert.Equal(err, errMessageReceipt)
		}
		for _, field := range []string{"root", "sender", "receiver", "role",
			"request", "history", "invalid key", "short digest"} {
			var wrong outgoingBinding
			try.To(
				wire.UnmarshalCanonical(
					&wrong,
					try.To1(wire.Marshal(expected)),
				),
			)
			switch field {
			case "root":
				wrong.Root = n.local
			case "sender":
				wrong.Sender = f.root.public
			case "receiver":
				wrong.Receiver = f.root.public
			case "role":
				wrong.Requester = !wrong.Requester
			case "request":
				wrong.RequestDigest[0] ^= 1
			case "history":
				wrong.AcceptedDigest[0] ^= 1
			case "invalid key":
				wrong.Receiver = []byte{0xff}
			case "short digest":
				wrong.AcceptedDigest = nil
			}
			_, err := decodeMessageReceipt(valid, raw, wrong)
			assert.Equal(err, errMessageReceipt)
		}
	}
}

func TestMessageReceiptPinnedIdentityAndInstalledSigner(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw, _ := receiptTest(t, receiver)
		foreign := newSigner(t)
		var typedNil *probeSigner
		for _, tc := range []struct {
			vault       *storage.Vault
			root, local key.Public
			signer      key.Handle
		}{
			{nil, f.root.public, n.local, n.signer},
			{n.own.vault, nil, n.local, n.signer},
			{n.own.vault, f.root.public, nil, n.signer},
			{n.own.vault, n.peer, n.local, n.signer},
			{n.own.vault, f.root.public, n.peer, n.signer},
			{n.other.vault, f.root.public, n.local, n.signer},
			{n.own.vault, f.root.public, n.local, nil},
			{n.own.vault, f.root.public, n.local, typedNil},
			{n.own.vault, f.root.public, n.local, foreign.handle},
			{n.own.vault, f.root.public, n.local,
				&probeSigner{Handle: foreign.handle, public: n.local}},
			{n.own.vault, f.root.public, n.local,
				&probeSigner{Handle: n.signer, publicErr: errors.New("private")}},
		} {
			n.other.unchanged(t, func() {
				n.own.unchanged(t, func() {
					got, err := issueMessageReceipt(
						tc.vault,
						tc.root,
						tc.local,
						tc.signer,
						raw,
					)
					assert.Equal(err, errMessageReceipt)
					assert.SNil(got)
				})
			})
		}
		for _, mode := range []string{"wrong signature", "malformed", "oversize", "changed digest"} {
			signer := &probeSigner{Handle: n.signer}
			signer.sign = func(d []byte) ([]byte, error) {
				if signer.signCalls.Load() == 2 {
					switch mode {
					case "wrong signature":
						return foreign.handle.Sign(d)
					case "malformed":
						return []byte{1, 2, 3}, nil
					case "oversize":
						return make([]byte, 73), nil
					case "changed digest":
						d[0] ^= 1
					}
				}
				return n.signer.Sign(d)
			}
			refuseMessageReceipt(t, f, n, signer, raw)
			assert.Equal(signer.signCalls.Load(), 2)
		}
	}
}
