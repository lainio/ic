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

func incomingWireCases(t *testing.T, raw []byte, signer, wrong key.Handle,
) map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	var envelope messageEnvelope
	try.To(wire.UnmarshalCanonical(&envelope, raw))
	invalid := map[string][]byte{
		"empty": {}, "malformed": {0xff},
		"oversize":         make([]byte, maxMessageEnvelopeBytes+1),
		"array":            append([]byte{0x98, 3}, raw[1:]...),
		"version encoding": append([]byte{0x83, 0x18, 1}, raw[2:]...),
		"tag":              append([]byte{0xc0}, raw...),
		"trailing":         append(bytes.Clone(raw), 0),
		"wrong signer":     signMessageEnvelope(t, envelope.Message, wrong),
	}
	for name, message := range changedEnvelopeMessages(t, envelope.Message) {
		invalid["signed/"+name] = signMessageEnvelope(t, message, signer)
		changed := envelope
		changed.Message = message
		invalid["mutated/"+name] = try.To1(wire.Marshal(changed))
	}
	for name, change := range map[string]func(*messageEnvelope){
		"version":         func(e *messageEnvelope) { e.Version++ },
		"signature":       func(e *messageEnvelope) { e.Signature[len(e.Signature)-1] ^= 1 },
		"empty signature": func(e *messageEnvelope) { e.Signature = nil },
		"DER size":        func(e *messageEnvelope) { e.Signature = make([]byte, 73) },
		"DER trailing":    func(e *messageEnvelope) { e.Signature = append(e.Signature, 0) },
		"DER malformed":   func(e *messageEnvelope) { e.Signature = []byte{1, 2, 3} },
	} {
		var changed messageEnvelope
		try.To(wire.UnmarshalCanonical(&changed, raw))
		change(&changed)
		invalid[name] = try.To1(wire.Marshal(changed))
	}
	digest := key.HashTagged(FirstUsePurpose, envelope.Message)
	invalid["wrong purpose"] = try.To1(wire.Marshal(messageEnvelope{
		Version: 1, Message: envelope.Message,
		Signature: try.To1(signer.Sign(digest[:])),
	}))
	return invalid
}

func TestIncomingRejectsWireAndAuthenticConflicts(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTest(t, receiver, "exact text")
		sender := outgoingTestNodes(f)[1-receiver]
		invalid := incomingWireCases(t, raw, sender.signer, f.root.handle)
		var envelope messageEnvelope
		try.To(wire.UnmarshalCanonical(&envelope, raw))
		resigned := signMessageEnvelope(t, envelope.Message, sender.signer)
		assert.ThatNot(bytes.Equal(raw, resigned))
		invalid["resigned"] = resigned
		for _, repeat := range []bool{false, true} {
			if repeat {
				assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
					f.root.public, n.local, n.signer, raw)))
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
							try.To1(decodeMessageEnvelope(bad,
								envelopePeerBinding(t, f.root.public, sender)))
						}
						signer := &probeSigner{Handle: n.signer}
						refuseIncoming(t, f, n, signer, bad)
						assert.Equal(signer.signCalls.Load(), 0)
					},
				)
			}
		}
	}
}

func TestIncomingStoredRowFailsClosed(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTest(t, receiver, "retained exact bytes")
		sender := outgoingTestNodes(f)[1-receiver]
		assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
			f.root.public, n.local, n.signer, raw)))
		original := outgoingTestState(t, n.own.vault)["root"][inboxKey]
		invalid := map[string][]byte{
			"empty": {}, "malformed": {0xff},
			"oversize":     make([]byte, maxInboxBytes+1),
			"noncanonical": append([]byte{0x98, 2}, original[1:]...),
			"tag":          append([]byte{0xc0}, original...),
			"trailing":     append(bytes.Clone(original), 0),
			"version": try.To1(wire.Marshal(inboxMessage{
				Version: 2, Envelope: raw,
			})),
		}
		for name, bad := range incomingWireCases(t, raw, sender.signer,
			f.root.handle) {
			invalid["envelope/"+name] = try.To1(wire.Marshal(inboxMessage{
				Version: 1, Envelope: bad,
			}))
		}
		for name, bad := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(inboxKey), bad)
				}))
				refuseIncoming(t, f, n, n.signer, raw)
			})
		}
		try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			try.To(tx.Delete([]byte(inboxKey)))
			try.To1(tx.EnsureChild([]byte(inboxKey)))
			return nil
		}))
		refuseIncoming(t, f, n, n.signer, raw)
	}
}

func TestIncomingPinnedIdentityAndInstalledSigner(t *testing.T) {
	defer assert.PushTester(t)()
	for _, receiver := range []int{0, 1} {
		f, n, raw := incomingTest(t, receiver, "bound identity")
		foreign := newSigner(t)
		var typedNil *probeSigner
		for _, repeat := range []bool{false, true} {
			if repeat {
				assert.That(try.To1(admitIncomingEnvelope(n.own.vault,
					f.root.public, n.local, n.signer, raw)))
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
						saved, err := admitIncomingEnvelope(tc.vault, tc.root,
							tc.local, tc.signer, raw)
						assert.Equal(err, errIncoming)
						assert.ThatNot(saved)
					})
				})
			}
		}
	}
}
