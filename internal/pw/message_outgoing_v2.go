package pw

import (
	"bytes"
	"crypto/rand"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// V2 has distinct types and explicit record versions in the SAME singleton
// slots as v1. There is no migration, replacement or second message slot.
type outgoingBindingV2 struct {
	_              struct{} `cbor:",toarray"`
	Root           key.Public
	Sender         key.Public
	Receiver       key.Public
	Requester      bool
	RequestDigest  []byte
	AcceptedDigest []byte
}

type outgoingMessageV2 struct {
	_       struct{} `cbor:",toarray"`
	Version uint8
	ID      []byte
	Binding outgoingBindingV2
	Text    string
}

// CreateOutgoingV2 implements bounded CreateOutgoing: one immutable local text
// record, without sending it. Supply independently pinned Root/local identities,
// their already-bound Vault and installed signer. The caller MUST hold its
// owner mutation/signer/configuration lock throughout, including runtime and
// reentrant signer lifecycle changes (the ContactRuntimeV2 discipline).
//
// A successful commit or authenticated existing record returns owned bytes.
// Exact repetition rechecks current local guards with a discarded usability
// probe, but creates no UUID, message signature, encryption or durable write.
// Conflicts/corruption refuse without repair. An error supplies no bytes and
// makes no durability claim; inspect on a later explicit call. Preparing the
// envelope is a separate operation/commit and cannot roll back this record.
func CreateOutgoingV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2, text string,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errOutgoing })

	assert.That(vault != nil && validPublic(root) && validPublic(local) &&
		validOutgoingText(text), errOutgoing)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var binding outgoingBindingV2
	var saved []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		binding = try.To1(outgoingPrerequisitesV2(tx, root, local, runtime))
		saved = try.To1(readOutgoingV2(tx, binding, text))
		return nil
	}))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errOutgoing)
	if saved != nil {
		try.To(vault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			current := try.To1(
				outgoingPrerequisitesV2(tx, root, local, runtime),
			)
			assert.That(bytes.Equal(try.To1(wire.Marshal(current)),
				try.To1(wire.Marshal(binding))), errOutgoing)
			assert.That(bytes.Equal(saved,
				try.To1(readOutgoingV2(tx, current, text))), errOutgoing)
			return nil
		}))
		return bytes.Clone(saved), nil
	}

	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		saved, err = commitOutgoingV2(tx, root, local, runtime, binding, text)
		return err
	})
	if updateErr != errOutgoingUnchanged {
		try.To(updateErr)
	}
	return bytes.Clone(saved), nil
}

func commitOutgoingV2(tx storage.WriteTx, root, local key.Public,
	runtime ContactRuntimeV2, expected outgoingBindingV2, text string,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(validOutgoingText(text), errOutgoing)
	binding := try.To1(outgoingPrerequisitesV2(tx, root, local, runtime))
	assert.That(bytes.Equal(try.To1(wire.Marshal(binding)),
		try.To1(wire.Marshal(expected))), errOutgoing)
	if saved := try.To1(readOutgoingV2(tx, binding, text)); saved != nil {
		return saved, errOutgoingUnchanged
	}

	// Allocate only after durable guards and the singleton conflict check.
	id := make([]byte, 16)
	try.To1(rand.Read(id))
	id[6], id[8] = (id[6]&0x0f)|0x40, (id[8]&0x3f)|0x80
	raw := try.To1(wire.Marshal(outgoingMessageV2{
		Version: 2, ID: id, Binding: binding, Text: text,
	}))
	assert.That(len(raw) <= maxOutgoingBytes, errOutgoing)
	try.To(tx.Put([]byte(outgoingKey), raw))
	return raw, nil
}

func readOutgoingV2(tx storage.ReadTx, expected outgoingBindingV2, text string,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	raw, found := try.To2(tx.Get([]byte(outgoingKey)))
	if !found {
		_, orphan := try.To2(tx.Get([]byte(messageEnvelopeKey)))
		assert.ThatNot(orphan, errOutgoing)
		return nil, nil
	}
	record := try.To1(decodeOutgoingV2(raw, expected))
	assert.That(record.Text == text, errOutgoing)
	// An existing envelope must still authenticate this exact saved message.
	// Even a text repeat cannot hide corruption or a version substitution.
	try.To1(readMessageEnvelopeV2(tx, expected, raw))
	return raw, nil
}

func decodeOutgoingV2(raw []byte, expected outgoingBindingV2,
) (_ outgoingMessageV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(len(raw) > 0 && len(raw) <= maxOutgoingBytes, errOutgoing)
	var record outgoingMessageV2
	assert.That(wire.DecMode.Unmarshal(raw, &record) == nil, errOutgoing)
	assert.That(record.Version == 2 &&
		bytes.Equal(raw, try.To1(wire.Marshal(record))) &&
		len(record.ID) == 16 && record.ID[6]&0xf0 == 0x40 &&
		record.ID[8]&0xc0 == 0x80 && validOutgoingText(record.Text), errOutgoing)
	assert.That(bytes.Equal(try.To1(wire.Marshal(record.Binding)),
		try.To1(wire.Marshal(expected))), errOutgoing)
	return record, nil
}
