package pw

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func signMessageEnvelope(
	t *testing.T,
	message []byte,
	signer key.Handle,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(messageAuthPurpose, message)
	return try.To1(wire.Marshal(messageEnvelope{Version: 1, Message: message,
		Signature: try.To1(signer.Sign(digest[:]))}))
}

func changedEnvelopeMessages(t *testing.T, original []byte) map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	invalid := map[string][]byte{
		"empty": {}, "malformed": {0xff},
		"oversize":     make([]byte, maxOutgoingBytes+1),
		"noncanonical": append([]byte{0x98, 4}, original[1:]...),
		"tag":          append([]byte{0xc0}, original...),
		"trailing":     append(bytes.Clone(original), 0),
	}
	for name, change := range map[string]func(*outgoingMessage){
		"version":         func(m *outgoingMessage) { m.Version++ },
		"short ID":        func(m *outgoingMessage) { m.ID = m.ID[:15] },
		"ID version":      func(m *outgoingMessage) { m.ID[6] = 0 },
		"ID variant":      func(m *outgoingMessage) { m.ID[8] = 0 },
		"changed ID":      func(m *outgoingMessage) { m.ID[0] ^= 1 },
		"changed body":    func(m *outgoingMessage) { m.Text += "changed" },
		"empty text":      func(m *outgoingMessage) { m.Text = "" },
		"long text":       func(m *outgoingMessage) { m.Text = strings.Repeat("x", 1025) },
		"invalid UTF8":    func(m *outgoingMessage) { m.Text = string([]byte{0xff}) },
		"root":            func(m *outgoingMessage) { m.Binding.Root = m.Binding.Sender },
		"sender":          func(m *outgoingMessage) { m.Binding.Sender = m.Binding.Receiver },
		"receiver":        func(m *outgoingMessage) { m.Binding.Receiver = m.Binding.Root },
		"role":            func(m *outgoingMessage) { m.Binding.Requester = !m.Binding.Requester },
		"request digest":  func(m *outgoingMessage) { m.Binding.RequestDigest[0] ^= 1 },
		"accepted digest": func(m *outgoingMessage) { m.Binding.AcceptedDigest[0] ^= 1 },
	} {
		var message outgoingMessage
		try.To(wire.UnmarshalCanonical(&message, original))
		change(&message)
		invalid[name] = try.To1(wire.Marshal(message))
	}
	return invalid
}

func TestMessageEnvelopeRejectsWireAndSavedCorruption(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	for _, n := range outgoingTestNodes(f) {
		message := try.To1(createOutgoing(n.own.vault, f.root.public,
			n.local, n.signer, "exact payload"))
		raw := try.To1(prepareOutgoingEnvelope(n.own.vault, f.root.public,
			n.local, n.signer))
		expected := envelopePeerBinding(t, f.root.public, n)
		invalid := map[string][]byte{
			"empty": {}, "malformed": {0xff},
			"oversize":         make([]byte, maxMessageEnvelopeBytes+1),
			"array":            append([]byte{0x98, 3}, raw[1:]...),
			"version encoding": append([]byte{0x83, 0x18, 1}, raw[2:]...),
			"tag":              append([]byte{0xc0}, raw...),
			"trailing":         append(bytes.Clone(raw), 0),
		}
		for name, change := range map[string]func(*messageEnvelope){
			"version":         func(e *messageEnvelope) { e.Version++ },
			"signature":       func(e *messageEnvelope) { e.Signature[len(e.Signature)-1] ^= 1 },
			"empty signature": func(e *messageEnvelope) { e.Signature = nil },
			"DER size":        func(e *messageEnvelope) { e.Signature = make([]byte, 73) },
			"DER trailing":    func(e *messageEnvelope) { e.Signature = append(e.Signature, 0) },
			"DER malformed":   func(e *messageEnvelope) { e.Signature = []byte{1, 2, 3} },
		} {
			var envelope messageEnvelope
			try.To(wire.UnmarshalCanonical(&envelope, raw))
			change(&envelope)
			invalid[name] = try.To1(wire.Marshal(envelope))
		}
		for name, changed := range changedEnvelopeMessages(t, message) {
			var envelope messageEnvelope
			try.To(wire.UnmarshalCanonical(&envelope, raw))
			envelope.Message = changed
			invalid["payload/"+name] = try.To1(wire.Marshal(envelope))
			if name != "changed ID" && name != "changed body" {
				// Even authentic mismatches/noncanonical payloads are refused.
				invalid["signed payload/"+name] = signMessageEnvelope(
					t,
					changed,
					n.signer,
				)
			}
		}
		invalid["wrong signer"] = signMessageEnvelope(t, message, f.root.handle)
		digest := key.HashTagged(FirstUsePurpose, message)
		invalid["wrong purpose"] = try.To1(wire.Marshal(messageEnvelope{
			Version: 1, Message: message,
			Signature: try.To1(n.signer.Sign(digest[:])),
		}))
		for name, bad := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				result, err := decodeMessageEnvelope(bad, expected)
				assert.Equal(err, errMessageEnvelope)
				assert.DeepEqual(result, messageEnvelope{})
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(messageEnvelopeKey), bad)
				}))
				signer := &probeSigner{Handle: n.signer}
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						got, err := prepareOutgoingEnvelope(n.own.vault,
							f.root.public, n.local, signer)
						assert.Equal(err, errMessageEnvelope)
						assert.SNil(got)
					})
				})
				assert.Equal(signer.signCalls.Load(), 0)
			})
		}
	}
}

func TestMessageEnvelopeRequiresExactSavedMessage(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(fmt.Sprint(prepared), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoing(t)
			for _, n := range outgoingTestNodes(f) {
				message := try.To1(createOutgoing(n.own.vault, f.root.public,
					n.local, n.signer, "saved source"))
				if prepared {
					try.To1(prepareOutgoingEnvelope(n.own.vault, f.root.public,
						n.local, n.signer))
				}
				changes := changedEnvelopeMessages(t, message)
				changes["missing"] = nil
				for name, changed := range changes {
					// Before signing, a valid committed v1 message is authority.
					// After signing, even valid body/ID changes conflict with it.
					if !prepared &&
						(name == "changed ID" || name == "changed body") {
						continue
					}
					try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
						if name == "missing" {
							return tx.Delete([]byte(outgoingKey))
						}
						return tx.Put([]byte(outgoingKey), changed)
					}))
					n.other.unchanged(t, func() {
						n.own.unchanged(t, func() {
							got, err := prepareOutgoingEnvelope(n.own.vault,
								f.root.public, n.local, n.signer)
							assert.Equal(err, errMessageEnvelope)
							assert.SNil(got)
						})
					})
				}
			}
		})
	}
}

func TestMessageEnvelopeAuthenticConflictingPayload(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	for _, n := range outgoingTestNodes(f) {
		message := try.To1(createOutgoing(n.own.vault, f.root.public,
			n.local, n.signer, "exact source"))
		expected := envelopePeerBinding(t, f.root.public, n)
		changes := changedEnvelopeMessages(t, message)
		for _, name := range []string{"changed ID", "changed body"} {
			conflict := signMessageEnvelope(t, changes[name], n.signer)
			// Authentication alone cannot determine a remote sender's saved ID.
			try.To1(decodeMessageEnvelope(conflict, expected))
			try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
				return tx.Put([]byte(messageEnvelopeKey), conflict)
			}))
			n.own.unchanged(t, func() {
				got, err := prepareOutgoingEnvelope(n.own.vault, f.root.public,
					n.local, n.signer)
				assert.Equal(err, errMessageEnvelope)
				assert.SNil(got)
			})
		}
	}
}

func TestMessageEnvelopeFinalSourceAndSignatureChecks(t *testing.T) {
	for _, mode := range []string{"changed ID", "changed body", "deleted source",
		"wrong signature", "malformed signature", "oversize signature"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoing(t)
			for _, n := range outgoingTestNodes(f) {
				message := try.To1(createOutgoing(n.own.vault, f.root.public,
					n.local, n.signer, "final source"))
				before := outgoingTestState(t, n.own.vault)
				signer := &probeSigner{Handle: n.signer}
				signer.sign = func(d []byte) (_ []byte, err error) {
					defer err2.Handle(&err, nil)
					if signer.signCalls.Load() == 1 {
						return n.signer.Sign(d)
					}
					switch mode {
					case "wrong signature":
						return f.root.handle.Sign(d)
					case "malformed signature":
						return []byte{1, 2, 3}, nil
					case "oversize signature":
						return make([]byte, 73), nil
					default:
						try.To(
							n.own.vault.Update(func(tx storage.WriteTx) error {
								if mode == "deleted source" {
									return tx.Delete([]byte(outgoingKey))
								}
								return tx.Put([]byte(outgoingKey),
									changedEnvelopeMessages(t, message)[mode])
							}),
						)
						before = outgoingTestState(t, n.own.vault)
						return n.signer.Sign(d)
					}
				}
				n.other.unchanged(t, func() {
					raw, err := prepareOutgoingEnvelope(
						n.own.vault,
						f.root.public,
						n.local,
						signer,
					)
					assert.Equal(err, errMessageEnvelope)
					assert.SNil(raw)
				})
				assert.Equal(signer.signCalls.Load(), 2)
				assert.DeepEqual(outgoingTestState(t, n.own.vault), before)
			}
		})
	}
}

func TestMessageEnvelopeTrustedBindingOnly(t *testing.T) {
	defer assert.PushTester(t)()
	for _, index := range []int{0, 1} {
		f := newOutgoing(t)
		n := outgoingTestNodes(f)[index]
		try.To1(createOutgoing(n.own.vault, f.root.public, n.local,
			n.signer, "trusted evidence"))
		raw := try.To1(prepareOutgoingEnvelope(n.own.vault, f.root.public,
			n.local, n.signer))
		expected := envelopePeerBinding(t, f.root.public, n)
		for _, field := range []string{"root", "sender", "target", "role",
			"request", "accepted", "invalid key", "short digest"} {
			var wrong outgoingBinding
			try.To(
				wire.UnmarshalCanonical(
					&wrong,
					try.To1(wire.Marshal(expected)),
				),
			)
			switch field {
			case "root":
				wrong.Root = n.peer
			case "sender":
				wrong.Sender = f.root.public
			case "target":
				wrong.Receiver = f.root.public
			case "role":
				wrong.Requester = !wrong.Requester
			case "request":
				wrong.RequestDigest[0] ^= 1
			case "accepted":
				wrong.AcceptedDigest[0] ^= 1
			case "invalid key":
				wrong.Sender = []byte{0xff}
			case "short digest":
				wrong.AcceptedDigest = nil
			}
			_, err := decodeMessageEnvelope(raw, wrong)
			assert.Equal(err, errMessageEnvelope)
		}
		// Pure verification is still possible after receiver-local denial and
		// deletion. It must not imply permission or write any admission state.
		try.To1(policy.DenyLocal(n.other.vault, f.root.public, n.peer, n.local))
		try.To1(DeleteHeldLocal(n.other.vault, f.root.public, n.peer))
		n.other.unchanged(t, func() {
			n.own.unchanged(t, func() {
				try.To1(decodeMessageEnvelope(raw, expected))
			})
		})
	}
}

func TestMessageEnvelopeRejectsIdentityAndSigner(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoing(t)
	foreign := newSigner(t)
	var typedNil *probeSigner
	for _, n := range outgoingTestNodes(f) {
		try.To1(createOutgoing(n.own.vault, f.root.public, n.local,
			n.signer, "bound identity"))
		for _, saved := range []bool{false, true} {
			if saved {
				try.To1(prepareOutgoingEnvelope(n.own.vault, f.root.public,
					n.local, n.signer))
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
						raw, err := prepareOutgoingEnvelope(tc.vault, tc.root,
							tc.local, tc.signer)
						assert.Equal(err, errMessageEnvelope)
						assert.SNil(raw)
					})
				})
			}
		}
	}
}

func TestMessageEnvelopeRejectsHistoryChanges(t *testing.T) {
	for _, mode := range []string{"corrupt", "foreign", "role", "resigned",
		"first use signature", "unsigned expired"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f, foreign := newOutgoing(t), newOutgoing(t)
			for _, n := range outgoingTestNodes(f) {
				try.To1(createOutgoing(n.own.vault, f.root.public, n.local,
					n.signer, "authenticated history"))
				try.To(n.own.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					raw, _ := try.To2(tx.Get([]byte(acceptedKey)))
					var history acceptedRecord
					try.To(wire.UnmarshalCanonical(&history, raw))
					switch mode {
					case "corrupt":
						return tx.Put([]byte(acceptedKey), []byte{0xff})
					case "foreign":
						return tx.Put([]byte(acceptedKey),
							requesterRecords(t, foreign.alice.vault)[1])
					case "role":
						if n.name == "Alice" {
							return tx.Delete([]byte(attemptKey))
						}
						return tx.Put([]byte(attemptKey), history.Request)
					case "resigned":
						var accepted SignedAccepted
						try.To(
							wire.UnmarshalCanonical(
								&accepted,
								history.Response,
							),
						)
						digest := key.HashTagged(AcceptedPurpose,
							try.To1(wire.Marshal(accepted.Payload)))
						accepted.Signature = try.To1(
							f.local.handle.Sign(digest[:]),
						)
						history.Response = try.To1(wire.Marshal(accepted))
						return tx.Put(
							[]byte(acceptedKey),
							try.To1(wire.Marshal(history)),
						)
					default:
						if n.name == "Bob" {
							raw, _ = try.To2(tx.Get([]byte(useSeenKey)))
							raw[len(raw)-1] ^= 1
							return tx.Put([]byte(useSeenKey), raw)
						}
						raw, _ = try.To2(tx.Get([]byte(firstUseKey)))
						var record firstUseRecord
						try.To(wire.UnmarshalCanonical(&record, raw))
						record.State = useExpired
						if mode == "unsigned expired" {
							record.Response = nil
						} else {
							record.Response[len(record.Response)-1] ^= 1
						}
						return tx.Put(
							[]byte(firstUseKey),
							try.To1(wire.Marshal(record)),
						)
					}
				}))
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						raw, err := prepareOutgoingEnvelope(n.own.vault,
							f.root.public, n.local, n.signer)
						assert.Equal(err, errMessageEnvelope)
						assert.SNil(raw)
					})
				})
			}
		})
	}
}
