package pw

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func signMessageEnvelopeV2(t *testing.T, message []byte, signer key.Handle,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(messageAuthPurposeV2, message)
	return try.To1(wire.Marshal(messageEnvelopeV2{Version: 2, Message: message,
		Signature: try.To1(signer.Sign(digest[:]))}))
}

func TestMessageWireAndStoredCorruptionV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoingV2(t)
	for _, n := range outgoingTestNodes(f.requesterFixture) {
		runtime := f.messageRuntime(n)
		message := try.To1(CreateOutgoingV2(n.own.vault, f.root.public,
			n.local, n.signer, runtime, "exact bytes"))
		raw := try.To1(PrepareOutgoingEnvelopeV2(n.own.vault, f.root.public,
			n.local, n.signer, runtime))
		expected := messageBindingV2(t, n.own.vault, f.root.public, n.local)
		invalid := map[string][]byte{
			"empty": {}, "malformed": {0xff},
			"oversize":         make([]byte, maxMessageEnvelopeBytes+1),
			"array":            append([]byte{0x98, 3}, raw[1:]...),
			"version encoding": append([]byte{0x83, 0x18, 2}, raw[2:]...),
			"huge array":       {0x9a, 0xff, 0xff, 0xff, 0xff},
			"tag":              append([]byte{0xc0}, raw...),
			"trailing":         append(bytes.Clone(raw), 0),
		}
		for name, change := range map[string]func(*messageEnvelopeV2){
			"version":         func(e *messageEnvelopeV2) { e.Version = 1 },
			"signature":       func(e *messageEnvelopeV2) { e.Signature[len(e.Signature)-1] ^= 1 },
			"empty signature": func(e *messageEnvelopeV2) { e.Signature = nil },
			"DER size":        func(e *messageEnvelopeV2) { e.Signature = make([]byte, 73) },
			"DER trailing":    func(e *messageEnvelopeV2) { e.Signature = append(e.Signature, 0) },
			"DER malformed":   func(e *messageEnvelopeV2) { e.Signature = []byte{1, 2, 3} },
		} {
			var envelope messageEnvelopeV2
			try.To(wire.UnmarshalCanonical(&envelope, raw))
			change(&envelope)
			invalid[name] = try.To1(wire.Marshal(envelope))
		}
		// The existing hostile array generator edits the common field layout,
		// without changing any v1 decoder, purpose or test semantics.
		for name, changed := range changedEnvelopeMessages(t, message) {
			var envelope messageEnvelopeV2
			try.To(wire.UnmarshalCanonical(&envelope, raw))
			envelope.Message = changed
			invalid["tampered/"+name] = try.To1(wire.Marshal(envelope))
			if name != "changed ID" && name != "changed body" {
				invalid["signed/"+name] = signMessageEnvelopeV2(
					t,
					changed,
					n.signer,
				)
			}
		}
		invalid["wrong signer"] = signMessageEnvelopeV2(
			t,
			message,
			f.root.handle,
		)
		for _, purpose := range []string{messageAuthPurpose, outgoingHistoryPurposeV2,
			FirstUsePurposeV2, FirstUseResponsePurposeV2, AcceptedPurposeV2} {
			digest := key.HashTagged(purpose, message)
			invalid[purpose] = try.To1(wire.Marshal(messageEnvelopeV2{
				Version: 2, Message: message,
				Signature: try.To1(n.signer.Sign(digest[:])),
			}))
		}
		for name, bad := range invalid {
			t.Run(n.name+"/"+name, func(t *testing.T) {
				defer assert.PushTester(t)()
				result, err := decodeMessageEnvelopeV2(bad, expected)
				assert.Equal(err, errMessageEnvelope)
				assert.DeepEqual(result, messageEnvelopeV2{})
				try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put([]byte(messageEnvelopeKey), bad)
				}))
				signer := &probeSigner{Handle: n.signer}
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						got, err := PrepareOutgoingEnvelopeV2(n.own.vault,
							f.root.public, n.local, signer, runtime)
						assert.Equal(err, errMessageEnvelope)
						assert.SNil(got)
						got, err = CreateOutgoingV2(
							n.own.vault,
							f.root.public,
							n.local,
							signer,
							runtime,
							"exact bytes",
						)
						assert.Equal(err, errOutgoing)
						assert.SNil(got)
					})
				})
				assert.Equal(signer.signCalls.Load(), 0)
			})
		}
	}
}

func TestMessageOutgoingCorruptionAndOrphanV2(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(fmt.Sprint(prepared), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			for _, n := range outgoingTestNodes(f.requesterFixture) {
				runtime := f.messageRuntime(n)
				message := try.To1(
					CreateOutgoingV2(n.own.vault, f.root.public,
						n.local, n.signer, runtime, "saved source"),
				)
				if prepared {
					try.To1(
						PrepareOutgoingEnvelopeV2(
							n.own.vault,
							f.root.public,
							n.local,
							n.signer,
							runtime,
						),
					)
				}
				changes := changedEnvelopeMessages(t, message)
				changes["huge array"] = []byte{0x9a, 0xff, 0xff, 0xff, 0xff}
				if prepared {
					changes["orphan"] = nil
				}
				for name, changed := range changes {
					if !prepared &&
						(name == "changed ID" || name == "changed body") {
						continue // Valid unsigned Vault record is the signing source.
					}
					try.To(
						n.own.vault.Update(
							func(tx storage.WriteTx) error {
								if name == "orphan" {
									return tx.Delete(
										[]byte(outgoingKey),
									)
								}
								return tx.Put(
									[]byte(outgoingKey),
									changed,
								)
							},
						),
					)
					n.other.unchanged(t, func() {
						n.own.unchanged(t, func() {
							got, err := PrepareOutgoingEnvelopeV2(
								n.own.vault,
								f.root.public,
								n.local,
								n.signer,
								runtime,
							)
							assert.Equal(err, errMessageEnvelope)
							assert.SNil(got)
							got, err = CreateOutgoingV2(
								n.own.vault,
								f.root.public,
								n.local,
								n.signer,
								runtime,
								"saved source",
							)
							assert.Equal(err, errOutgoing)
							assert.SNil(got)
						})
					})
				}
			}
		})
	}
}

func TestMessageAuthenticConflictingPayloadV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoingV2(t)
	for _, n := range outgoingTestNodes(f.requesterFixture) {
		runtime := f.messageRuntime(n)
		message := try.To1(CreateOutgoingV2(n.own.vault, f.root.public,
			n.local, n.signer, runtime, "exact source"))
		expected := messageBindingV2(t, n.own.vault, f.root.public, n.local)
		changes := changedEnvelopeMessages(t, message)
		for _, name := range []string{"changed ID", "changed body"} {
			conflict := signMessageEnvelopeV2(t, changes[name], n.signer)
			// Pure authentication cannot know the sender's committed ID/text.
			try.To1(decodeMessageEnvelopeV2(conflict, expected))
			try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
				return tx.Put([]byte(messageEnvelopeKey), conflict)
			}))
			n.own.unchanged(t, func() {
				got, err := PrepareOutgoingEnvelopeV2(
					n.own.vault,
					f.root.public,
					n.local,
					n.signer,
					runtime,
				)
				assert.Equal(err, errMessageEnvelope)
				assert.SNil(got)
			})
		}
	}
}

func TestMessageIdentityAndSignerV2(t *testing.T) {
	defer assert.PushTester(t)()
	f := newOutgoingV2(t)
	var typedNil *probeSigner
	for _, n := range outgoingTestNodes(f.requesterFixture) {
		runtime := f.messageRuntime(n)
		for _, saved := range []bool{false, true} {
			if saved {
				try.To1(
					CreateOutgoingV2(n.own.vault, f.root.public, n.local,
						n.signer, runtime, "bound"),
				)
				try.To1(
					PrepareOutgoingEnvelopeV2(n.own.vault, f.root.public,
						n.local, n.signer, runtime),
				)
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
				{n.own.vault, f.root.public, n.local, f.root.handle},
				{n.own.vault, f.root.public, n.local,
					&probeSigner{Handle: f.root.handle, public: n.local}},
				{n.own.vault, f.root.public, n.local,
					&probeSigner{Handle: n.signer, publicErr: errors.New("private")}},
				{n.own.vault, f.root.public, n.local,
					&probeSigner{Handle: n.signer, signErr: errors.New("private")}},
			} {
				n.other.unchanged(t, func() {
					n.own.unchanged(t, func() {
						got, err := CreateOutgoingV2(
							tc.vault,
							tc.root,
							tc.local,
							tc.signer,
							runtime,
							"bound",
						)
						assert.Equal(err, errOutgoing)
						assert.SNil(got)
						got, err = PrepareOutgoingEnvelopeV2(
							tc.vault,
							tc.root,
							tc.local,
							tc.signer,
							runtime,
						)
						assert.Equal(err, errMessageEnvelope)
						assert.SNil(got)
					})
				})
			}
		}
	}
}

func TestMessageVersionIsolationV2(t *testing.T) {
	defer assert.PushTester(t)()
	one, two := newOutgoing(t), newOutgoingV2(t)
	n1, n2 := outgoingTestNodes(one)[0], outgoingTestNodes(two.requesterFixture)[0]
	runtime := two.messageRuntime(n2)
	m1 := try.To1(createOutgoing(n1.own.vault, one.root.public, n1.local,
		n1.signer, "v1"))
	e1 := try.To1(prepareOutgoingEnvelope(n1.own.vault, one.root.public,
		n1.local, n1.signer))
	m2 := try.To1(CreateOutgoingV2(n2.own.vault, two.root.public, n2.local,
		n2.signer, runtime, "v2"))
	e2 := try.To1(PrepareOutgoingEnvelopeV2(n2.own.vault, two.root.public,
		n2.local, n2.signer, runtime))
	b1, b2 := envelopePeerBinding(t, one.root.public, n1),
		messageBindingV2(t, n2.own.vault, two.root.public, n2.local)
	try.To1(decodeMessageEnvelope(e1, b1))
	try.To1(decodeMessageEnvelopeV2(e2, b2))
	_, err := decodeOutgoingV2(m1, outgoingBindingV2(b1))
	assert.Error(err)
	_, err = decodeOutgoing(m2, outgoingBinding(b2))
	assert.Error(err)
	_, err = decodeMessageEnvelopeV2(e1, outgoingBindingV2(b1))
	assert.Equal(err, errMessageEnvelope)
	_, err = decodeMessageEnvelope(e2, outgoingBinding(b2))
	assert.Equal(err, errMessageEnvelope)
	n1.own.unchanged(t, func() {
		_, err := CreateOutgoingV2(n1.own.vault, one.root.public, n1.local,
			n1.signer, runtime, "v1")
		assert.Equal(err, errOutgoing)
		_, err = PrepareOutgoingEnvelopeV2(n1.own.vault, one.root.public,
			n1.local, n1.signer, runtime)
		assert.Equal(err, errMessageEnvelope)
	})
	n2.own.unchanged(t, func() {
		_, err := createOutgoing(
			n2.own.vault,
			two.root.public,
			n2.local,
			n2.signer,
			"v2",
		)
		assert.Equal(err, errOutgoing)
		_, err = prepareOutgoingEnvelope(
			n2.own.vault,
			two.root.public,
			n2.local,
			n2.signer,
		)
		assert.Equal(err, errMessageEnvelope)
		_, err = PrepareMessageSend(
			n2.own.vault,
			two.root.public,
			n2.local,
			n2.signer,
			"v2",
		)
		assert.Equal(err, errOutgoing)
	})
	// Each generation also refuses incompatible records occupying its slots,
	// even if its own establishment history is otherwise eligible.
	for _, name := range []string{outgoingKey, messageEnvelopeKey} {
		v1, v2 := e1, e2
		if name == outgoingKey {
			v1, v2 = m1, m2
		}
		try.To(
			n1.own.vault.Update(
				func(tx storage.WriteTx) error { return tx.Put([]byte(name), v2) },
			),
		)
		try.To(
			n2.own.vault.Update(
				func(tx storage.WriteTx) error { return tx.Put([]byte(name), v1) },
			),
		)
		n1.own.unchanged(t, func() {
			_, err := prepareOutgoingEnvelope(
				n1.own.vault,
				one.root.public,
				n1.local,
				n1.signer,
			)
			assert.Equal(err, errMessageEnvelope)
		})
		n2.own.unchanged(t, func() {
			_, err := PrepareOutgoingEnvelopeV2(
				n2.own.vault,
				two.root.public,
				n2.local,
				n2.signer,
				runtime,
			)
			assert.Equal(err, errMessageEnvelope)
		})
		try.To(
			n1.own.vault.Update(
				func(tx storage.WriteTx) error { return tx.Put([]byte(name), v1) },
			),
		)
		try.To(
			n2.own.vault.Update(
				func(tx storage.WriteTx) error { return tx.Put([]byte(name), v2) },
			),
		)
	}
}
