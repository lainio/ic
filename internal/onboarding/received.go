package onboarding

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const receivedNamespace = "received-introductions-v1"
const maxReceivedSubjects = 32

var (
	ErrDifferentIntroduction = errors.New("different introduction already saved")
	ErrIntroductionsFull     = errors.New("saved introduction collection full")
	errInvalidReceived       = errors.New("invalid saved introduction")
	errIntroductionUnchanged = errors.New("saved introduction unchanged")
)

// SaveIntroduction borrows the open Vault and rechecks submitted evidence.
// One Update inserts a complete record or preserves an existing valid record.
// The full verified subject public key is the logical key. An identical proposal
// retains its original acceptance without Put or encryption, even if the caller
// submits another valid signature. A different proposal is refused locally.
// Errors return no subject or created result; failed writes retain prior data.
// This only adds received evidence, never local choice, Known, trust, or PW.
func SaveIntroduction(vault *storage.Vault, expectedRoot key.Public,
	proposal []byte, acceptance key.Signature,
) (_ key.Public, _ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	proposal, acceptance = bytes.Clone(proposal), bytes.Clone(acceptance)
	subject, checkErr := CheckIntroduction(proposal, acceptance, expectedRoot)
	if checkErr != nil {
		return nil, false, ErrInvalidIntroduction
	}
	created := false
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)

		records := try.To1(tx.EnsureChild([]byte(receivedNamespace)))
		stored, found := try.To2(records.Get(subject))
		if found {
			previous, _ := try.To2(readReceived(stored, subject, expectedRoot))
			assert.That(bytes.Equal(previous, proposal), ErrDifferentIntroduction)
			// Roll back the no-change transaction, including backend metadata.
			return errIntroductionUnchanged
		}
		count := 0
		try.To(records.Each(func(_, _ []byte) error {
			count++
			if count >= maxReceivedSubjects {
				return ErrIntroductionsFull
			}
			return nil
		}))
		// Private v1 representation: version, proposal length, exact proposal,
		// then exact detached acceptance. One record requires one seal.
		record := binary.BigEndian.AppendUint32([]byte{1}, uint32(len(proposal)))
		record = append(record, proposal...)
		record = append(record, acceptance...)
		try.To(records.Put(subject, record))
		created = true
		return nil
	})
	if updateErr != errIntroductionUnchanged {
		try.To(updateErr)
	}
	return subject, created, nil
}

// ListIntroductions returns caller-owned subject keys in byte order from one
// View. Every record is revalidated before any result is published. Absence is
// an empty list; corrupt or key-mismatched evidence fails the whole operation.
// Reading needs no encryption capacity, signer, or peer operation.
func ListIntroductions(vault *storage.Vault, expectedRoot key.Public) (
	_ []key.Public, err error,
) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	subjects := make([]key.Public, 0)
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)

		name := []byte(receivedNamespace)
		if !try.To1(tx.HasChild(name)) {
			return nil
		}
		records := try.To1(tx.Child(name))
		return records.Each(func(subject, record []byte) (err error) {
			defer err2.Handle(&err, nil)

			assert.That(len(subjects) < maxReceivedSubjects, errInvalidReceived)
			try.To2(readReceived(record, subject, expectedRoot))
			subjects = append(subjects, bytes.Clone(subject))
			return nil
		})
	}))
	slices.SortFunc(subjects, func(a, b key.Public) int { return bytes.Compare(a, b) })
	return subjects, nil
}

func readReceived(record, subject []byte, root key.Public) (
	_ []byte, _ key.Signature, err error,
) {
	defer assert.PushAsserter(assert.Plain)()
	// Invalid saved evidence is a storage-state error, never invalid input.
	defer err2.Handle(&err, func(error) error { return errInvalidReceived })

	assert.That(len(record) > 5 && record[0] == 1, errInvalidReceived)
	length := uint64(binary.BigEndian.Uint32(record[1:5]))
	assert.That(length > 0 && length < uint64(len(record)-5), errInvalidReceived)
	proposal, acceptance := record[5:5+length], record[5+length:]
	verified := try.To1(CheckIntroduction(proposal, acceptance, root))
	assert.That(bytes.Equal(verified, subject), errInvalidReceived)
	return proposal, acceptance, nil
}
