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

func incomingWireCasesV2(t *testing.T, raw []byte, signer, wrong key.Handle,
) map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	var envelope messageEnvelopeV2
	try.To(wire.UnmarshalCanonical(&envelope, raw))
	invalid := map[string][]byte{
		"empty": {}, "malformed": {0xff},
		"oversize":         make([]byte, maxMessageEnvelopeBytes+1),
		"array":            append([]byte{0x98, 3}, raw[1:]...),
		"version encoding": append([]byte{0x83, 0x18, 2}, raw[2:]...),
		"tag":              append([]byte{0xc0}, raw...),
		"trailing":         append(bytes.Clone(raw), 0),
		"wrong signer":     signMessageEnvelopeV2(t, envelope.Message, wrong),
	}
	for name, message := range changedEnvelopeMessages(t, envelope.Message) {
		invalid["signed/"+name] = signMessageEnvelopeV2(t, message, signer)
		changed := envelope
		changed.Message = message
		invalid["mutated/"+name] = try.To1(wire.Marshal(changed))
	}
	for name, change := range map[string]func(*messageEnvelopeV2){
		"version":         func(e *messageEnvelopeV2) { e.Version++ },
		"signature":       func(e *messageEnvelopeV2) { e.Signature[len(e.Signature)-1] ^= 1 },
		"empty signature": func(e *messageEnvelopeV2) { e.Signature = nil },
		"DER size":        func(e *messageEnvelopeV2) { e.Signature = make([]byte, 73) },
		"DER trailing":    func(e *messageEnvelopeV2) { e.Signature = append(e.Signature, 0) },
		"DER malformed":   func(e *messageEnvelopeV2) { e.Signature = []byte{1, 2, 3} },
	} {
		var changed messageEnvelopeV2
		try.To(wire.UnmarshalCanonical(&changed, raw))
		change(&changed)
		invalid[name] = try.To1(wire.Marshal(changed))
	}
	for _, purpose := range []string{messageAuthPurpose, FirstUsePurposeV2,
		AcceptedPurposeV2, messageReceiptPurposeV2} {
		digest := key.HashTagged(purpose, envelope.Message)
		invalid["purpose/"+purpose] = try.To1(wire.Marshal(messageEnvelopeV2{
			Version: 2, Message: envelope.Message,
			Signature: try.To1(signer.Sign(digest[:])),
		}))
	}
	var message outgoingMessageV2
	try.To(wire.UnmarshalCanonical(&message, envelope.Message))
	message.Binding.Sender, message.Binding.Receiver =
		message.Binding.Receiver, message.Binding.Sender
	invalid["swapped orientation"] = signMessageEnvelopeV2(t,
		try.To1(wire.Marshal(message)), signer)
	return invalid
}

func TestIncomingRejectsWireAndAuthenticConflictsV2(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTestV2(t, receiver, "exact text")
		sender := outgoingTestNodes(f.requesterFixture)[1-receiver]
		invalid := incomingWireCasesV2(t, raw, sender.signer, f.root.handle)
		var envelope messageEnvelopeV2
		try.To(wire.UnmarshalCanonical(&envelope, raw))
		resigned := signMessageEnvelopeV2(t, envelope.Message, sender.signer)
		assert.ThatNot(bytes.Equal(raw, resigned))
		invalid["resigned"] = resigned
		for _, repeat := range []bool{false, true} {
			if repeat {
				assert.That(try.To1(AdmitIncomingEnvelopeV2(
					n.own.vault,
					f.root.public,
					n.local,
					n.signer,
					f.messageRuntime(n),
					raw,
				)))
			}
			for name, bad := range invalid {
				conflict := name == "signed/changed ID" ||
					name == "signed/changed body" || name == "resigned"
				if conflict && !repeat {
					// No receiver can know a sender's saved ID before admission.
					// These are authentic, valid messages but not exact retries.
					continue
				}
				t.Run(
					fmt.Sprint(n.name, "/", repeat, "/", name),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						if conflict {
							try.To1(decodeMessageEnvelopeV2(
								bad,
								messageBindingV2(
									t,
									sender.own.vault,
									f.root.public,
									sender.local,
								),
							))
						}
						signer := &probeSigner{Handle: n.signer}
						refuseIncomingV2(t, f, n, signer, bad)
						assert.Equal(signer.signCalls.Load(), 0)
					},
				)
			}
		}
	}
}

func TestIncomingStoredRowFailsClosedV2(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTestV2(t, receiver, "retained exact bytes")
		sender := outgoingTestNodes(f.requesterFixture)[1-receiver]
		assert.That(try.To1(AdmitIncomingEnvelopeV2(n.own.vault,
			f.root.public, n.local, n.signer, f.messageRuntime(n), raw)))
		original := outgoingTestState(t, n.own.vault)["root"][inboxKey]
		invalid := map[string][]byte{
			"empty": {}, "malformed": {0xff},
			"oversize":     make([]byte, maxInboxBytes+1),
			"noncanonical": append([]byte{0x98, 2}, original[1:]...),
			"tag":          append([]byte{0xc0}, original...),
			"trailing":     append(bytes.Clone(original), 0),
			"version": try.To1(wire.Marshal(inboxMessage{
				Version: 1, Envelope: raw,
			})),
		}
		for name, bad := range incomingWireCasesV2(t, raw, sender.signer,
			f.root.handle) {
			invalid["envelope/"+name] = try.To1(wire.Marshal(inboxMessage{
				Version: 2, Envelope: bad,
			}))
		}
		for name, bad := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(inboxKey), bad)
				}))
				refuseIncomingV2(t, f, n, n.signer, raw)
			})
		}
		try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			try.To(tx.Delete([]byte(inboxKey)))
			try.To1(tx.EnsureChild([]byte(inboxKey)))
			return nil
		}))
		refuseIncomingV2(t, f, n, n.signer, raw)
	}
}

func TestIncomingPinnedIdentityAndInstalledSignerV2(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTestV2(t, receiver, "bound identity")
		foreign := newSigner(t)
		var typedNil *probeSigner
		for _, repeat := range []bool{false, true} {
			if repeat {
				assert.That(try.To1(AdmitIncomingEnvelopeV2(
					n.own.vault,
					f.root.public,
					n.local,
					n.signer,
					f.messageRuntime(n),
					raw,
				)))
			}
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
						saved, err := AdmitIncomingEnvelopeV2(tc.vault, tc.root,
							tc.local, tc.signer, f.messageRuntime(n), raw)
						assert.Equal(err, errIncoming)
						assert.ThatNot(saved)
					})
				})
			}
		}
	}
}
