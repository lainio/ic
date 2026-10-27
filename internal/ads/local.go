// Package ads publishes one local software signer's endpoint hint and retains
// untrusted received claims. Neither is reader-verified reachability, device
// liveness, trust, or a PW.
package ads

import (
	"bytes"
	"crypto/rand"
	"errors"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const (
	// TTL is a bounded wall-clock projection, not V19's abstract Now + 1.
	TTL = 15 * time.Minute
	// SignaturePurpose separates this payload from other signed messages.
	SignaturePurpose = "local-reachability-ad/v1"
	currentNamespace = "local-current-ad-v1"
	currentSlot      = "slot-1"
)

var (
	ErrInvalidInput = errors.New("invalid local ad input")
	ErrNotKnown     = errors.New("local ad publisher is not Known-introduced")
	ErrUnusable     = errors.New(
		"local ad requires an authorized usable signer",
	)
	ErrInvalidRecord = errors.New("invalid local current ad")
)

// Payload is a version-1 canonical CBOR array in declaration order. Signatures
// cover key.HashTagged(SignaturePurpose, wire.Marshal(payload)) via key.Handle.
// ExpiresUnixNano is a UTC instant, restricted to nonnegative int64 nanoseconds.
// Only slot 1, epoch 0, and Device == Node are supported. There is no rotation.
type Payload struct {
	_                   struct{} `cbor:",toarray"`
	Version             uint8
	Root                key.Public
	Node                key.Public
	Device              key.Public
	Slot                uint64
	Epoch               uint64
	Token               []byte
	ExpiresUnixNano     int64
	PeerIntroductionURL string
}

// Current contains caller-owned public fields and a detached signature. Its
// canonical CBOR array is also the private sealed record; it contains no handle
// ID or credential. Holding an old Current does not make it current after a
// replacement. Random tokens give probabilistic non-reuse, not AuthenticAds
// history; this package retains only the current record.
type Current struct {
	_         struct{} `cbor:",toarray"`
	Payload   Payload
	Signature key.Signature
}

// PublishLocal borrows an already open, independently Root/node-bound Vault
// and restored software signer. The caller must serialize Known, device
// authorization, configuration, signer lifecycle, and publications across
// preflight and commit, including reentrant signer callbacks. No bootstrap or
// evidence promotion occurs here. The endpoint is a hint, never probed.
// Errors return zero and leave the previous current record intact.
func PublishLocal(vault *storage.Vault, root, local key.Public,
	signer key.Handle, peerIntroductionURL string, now time.Time,
) (_ Current, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	try.To(validateInputs(vault, root, local, now))
	expires := now.Add(TTL)
	try.To(validateTime(expires))
	endpoint := try.To1(normalizeEndpoint(peerIntroductionURL))
	root, local = bytes.Clone(root), bytes.Clone(local)
	if !bytes.Equal(root, local) { // V19 Init makes the pinned Root self-known.
		known := try.To1(onboarding.ListKnownIntroductions(vault, root))
		found := false
		for _, subject := range known {
			found = found || bytes.Equal(subject, local)
		}
		assert.That(found, ErrNotKnown)
	}
	state := try.To1(device.InspectLocal(vault, root, local, signer))
	assert.That(state.Authorized && state.Usable, ErrUnusable)

	ad := Payload{
		Version: 1, Root: root, Node: local, Device: bytes.Clone(local),
		Slot: 1, Epoch: 0, Token: make([]byte, 32),
		ExpiresUnixNano: expires.UnixNano(), PeerIntroductionURL: endpoint,
	}
	try.To1(rand.Read(ad.Token))
	digest := key.HashTagged(SignaturePurpose, try.To1(wire.Marshal(ad)))
	signature := bytes.Clone(try.To1(signer.Sign(bytes.Clone(digest[:]))))
	record := try.To1(wire.Marshal(Current{Payload: ad, Signature: signature}))
	// Independent verification with the expected key, before any write. This
	// also gives the result independent copies of all authenticated fields.
	current := try.To1(decodeCurrent(record, root, local))
	try.To(vault.Update(func(tx storage.WriteTx) error {
		return replaceCurrent(tx, root, local, current, record)
	}))
	return current, nil
}

func replaceCurrent(tx storage.WriteTx, root, local key.Public,
	current Current, record []byte,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	previous, found := try.To2(readStored(tx, root, local))
	// Even an expired record must authenticate before replacement.
	assert.That(!found || !bytes.Equal(previous.Payload.Token,
		current.Payload.Token), ErrInvalidRecord)
	ns := try.To1(tx.EnsureChild([]byte(currentNamespace)))
	return ns.Put([]byte(currentSlot), record)
}

// ReadCurrentLocal authenticates the saved local record before checking expiry.
// Absence or expiry returns zero, false, nil, with no writes or signing. This
// is not V19 ReadAd or VerifyAd: it does not check current device usability or
// reader Known evidence. Later serving/verification must enforce those and
// identity/currentness preconditions. Caller-supplied time must be trustworthy;
// there is no persisted clock or protection against wall-clock rollback.
func ReadCurrentLocal(vault *storage.Vault, root, local key.Public,
	now time.Time,
) (_ Current, _ bool, err error) {
	defer err2.Handle(&err, nil)

	try.To(validateInputs(vault, root, local, now))
	root, local = bytes.Clone(root), bytes.Clone(local)
	var current Current
	var found bool
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		current, found = try.To2(readStored(tx, root, local))
		return nil
	}))
	if !found || now.UnixNano() >= current.Payload.ExpiresUnixNano {
		return Current{}, false, nil
	}
	return current, true, nil
}

func readStored(tx storage.ReadTx, root, local key.Public) (
	_ Current, _ bool, err error,
) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	if !try.To1(tx.HasChild([]byte(currentNamespace))) {
		return Current{}, false, nil
	}
	ns := try.To1(tx.Child([]byte(currentNamespace)))
	record, found := try.To2(ns.Get([]byte(currentSlot)))
	// Namespace and record are created together; partial state is not absence.
	assert.That(found, ErrInvalidRecord)
	current := try.To1(decodeCurrent(record, root, local))
	try.To(ns.Each(func(name, _ []byte) error {
		if string(name) != currentSlot {
			return ErrInvalidRecord
		}
		return nil
	}))
	return current, true, nil
}
