package pw

import (
	"bytes"
	"crypto/rand"
	"errors"
	"unicode/utf8"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const (
	outgoingKey            = "local-pw-message-outgoing-v1"
	outgoingHistoryPurpose = "pw-message-accepted-history/v1"
	maxOutgoingTextBytes   = 1024
	maxOutgoingBytes       = 2048
)

var (
	errOutgoing          = errors.New("local outgoing message refused")
	errOutgoingUnchanged = errors.New("local outgoing message unchanged")
)

// The outgoing v1 record is unsigned; messageEnvelope authenticates its exact
// bytes. RequestDigest references the exact signed establishment request;
// AcceptedDigest additionally pins the exact canonical acceptedRecord, including
// its signed result. Requester means Alice; false means Bob. Neither role
// requires a message from the other node.
type outgoingBinding struct {
	_              struct{} `cbor:",toarray"`
	Root           key.Public
	Sender         key.Public
	Receiver       key.Public
	Requester      bool
	RequestDigest  []byte
	AcceptedDigest []byte
}

type outgoingMessage struct {
	_       struct{} `cbor:",toarray"`
	Version uint8
	ID      []byte
	Binding outgoingBinding
	Text    string
}

// createOutgoing projects only candidate PW-Msg-02 CreateOutgoing: one immutable
// message per Vault, submitted locally. The caller supplies independently
// pinned Root/local identities, their already-bound Vault and installed signer,
// and MUST hold the existing owner mutation/signer lock throughout. External
// signer lifecycle changes cannot be made atomic with Vault transactions here.
//
// Returned canonical local-record bytes are caller-owned, not permission to
// transmit. Exact repetition checks current guards, including a fresh discarded
// usability probe, but allocates no message ID, signs no message and writes
// nothing. An error leaves the outcome unknown until storage is inspected; no
// automatic retry or assumption about a lost result is made.
func createOutgoing(vault *storage.Vault, root, local key.Public,
	signer key.Handle, text string,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return errOutgoing })

	assert.That(vault != nil && validPublic(root) && validPublic(local) &&
		validOutgoingText(text), errOutgoing)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var binding outgoingBinding
	var saved []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		binding = try.To1(outgoingPrerequisites(tx, root, local))
		saved = try.To1(readOutgoing(tx, binding, text))
		return nil
	}))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, errOutgoing)
	if saved != nil {
		try.To(vault.View(func(tx storage.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			current := try.To1(outgoingPrerequisites(tx, root, local))
			assert.That(bytes.Equal(try.To1(wire.Marshal(current)),
				try.To1(wire.Marshal(binding))), errOutgoing)
			assert.That(bytes.Equal(saved,
				try.To1(readOutgoing(tx, current, text))), errOutgoing)
			return nil
		}))
		return bytes.Clone(saved), nil
	}

	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		saved, err = commitOutgoing(tx, root, local, binding, text)
		return err
	})
	if updateErr != errOutgoingUnchanged {
		try.To(updateErr)
	}
	return bytes.Clone(saved), nil
}

func commitOutgoing(tx storage.WriteTx, root, local key.Public,
	expected outgoingBinding, text string,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(validOutgoingText(text), errOutgoing)
	binding := try.To1(outgoingPrerequisites(tx, root, local))
	assert.That(bytes.Equal(try.To1(wire.Marshal(binding)),
		try.To1(wire.Marshal(expected))), errOutgoing)
	if saved := try.To1(readOutgoing(tx, binding, text)); saved != nil {
		return saved, errOutgoingUnchanged
	}

	// Allocate only after the final durable guards and empty-slot check. UUIDv4
	// identity is scoped by sender and accepted relationship, never by a clock.
	id := make([]byte, 16)
	try.To1(rand.Read(id))
	id[6], id[8] = (id[6]&0x0f)|0x40, (id[8]&0x3f)|0x80
	raw := try.To1(wire.Marshal(outgoingMessage{
		Version: 1, ID: id, Binding: binding, Text: text,
	}))
	assert.That(len(raw) <= maxOutgoingBytes, errOutgoing)
	try.To(tx.Put([]byte(outgoingKey), raw))
	return raw, nil
}

func outgoingPrerequisites(tx storage.ReadTx, root, local key.Public,
) (_ outgoingBinding, err error) {
	defer err2.Handle(&err, nil)

	binding, p := try.To2(outgoingHistory(tx, root, local))
	try.To(firstUseGuards(tx, p, binding.Requester))
	return binding, nil
}

// outgoingHistory authenticates the local role, exact accepted establishment
// and historical successful first use only. It reads no current Known, holding,
// Deny or device authority and needs no signer. The accepted payload also lets
// permission-requiring callers apply their existing guards without reparsing.
func outgoingHistory(tx storage.ReadTx, root, local key.Public,
) (_ outgoingBinding, _ Accepted, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	// Presence selects which existing role validator to run, not authority.
	// firstUseHistory authenticates that role against the exact signed history.
	_, alice := try.To2(tx.Get([]byte(attemptKey)))
	p := try.To1(firstUseHistory(tx, root, local, alice))
	row, issued := try.To2(readInvitation(tx, root, local))
	assert.That(!alice || !issued || row.State != InvitationConsumed,
		errOutgoing)
	if alice {
		record := try.To1(readFirstUse(tx, p))
		assert.That((record.State == useReady || record.State == useExpired) &&
			len(record.Response) != 0, errOutgoing)
	} else {
		raw, found := try.To2(tx.Get([]byte(useSeenKey)))
		assert.That(found && len(raw) <= 2*MaxEstablishmentBytes+16,
			errOutgoing)
		var receipt firstUseReceipt
		assert.That(wire.DecMode.Unmarshal(raw, &receipt) == nil, errOutgoing)
		assert.That(receipt.Version == 1 &&
			bytes.Equal(raw, try.To1(wire.Marshal(receipt))), errOutgoing)
		request := try.To1(decodeFirstUse(receipt.Request, p))
		try.To(verifyFirstUseResponse(receipt.Response,
			firstUseResponsePayload(request, receipt.Request)))
	}

	peer := p.Binding.Requester
	if alice {
		peer = p.Binding.Target
	}
	history, _ := try.To2(tx.Get([]byte(acceptedKey)))
	digest := key.HashTagged(outgoingHistoryPurpose, history)
	return outgoingBinding{Root: p.Binding.Root, Sender: local, Receiver: peer,
		Requester: alice, RequestDigest: p.RequestDigest,
		AcceptedDigest: digest[:]}, p, nil
}

func readOutgoing(tx storage.ReadTx, expected outgoingBinding, text string,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	raw, found := try.To2(tx.Get([]byte(outgoingKey)))
	if !found {
		return nil, nil
	}
	record := try.To1(decodeOutgoing(raw, expected))
	assert.That(record.Text == text, errOutgoing)
	return raw, nil
}

func decodeOutgoing(raw []byte, expected outgoingBinding,
) (_ outgoingMessage, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.That(len(raw) > 0 && len(raw) <= maxOutgoingBytes, errOutgoing)
	var record outgoingMessage
	assert.That(wire.DecMode.Unmarshal(raw, &record) == nil, errOutgoing)
	assert.That(record.Version == 1 &&
		bytes.Equal(raw, try.To1(wire.Marshal(record))) &&
		len(record.ID) == 16 && record.ID[6]&0xf0 == 0x40 &&
		record.ID[8]&0xc0 == 0x80 && validOutgoingText(record.Text), errOutgoing)
	assert.That(bytes.Equal(try.To1(wire.Marshal(record.Binding)),
		try.To1(wire.Marshal(expected))), errOutgoing)
	return record, nil
}

func validOutgoingText(text string) bool {
	return len(text) >= 1 && len(text) <= maxOutgoingTextBytes &&
		utf8.ValidString(text)
}
