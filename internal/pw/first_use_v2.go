package pw

import (
	"bytes"
	"crypto/rand"
	"math"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// SavedFirstUseV2 is opaque committed evidence, deliberately incompatible with
// the v1 HTTP client. peerOrigin is only the accepted target service contact;
// it supplies no application path, transport, retry or message destination.
type SavedFirstUseV2 struct {
	request    []byte
	peerOrigin string
}

// SaveFirstUseV2 implements Alice's local SendFirstUse: persist one Await before
// returning signed bytes. The caller pins Root/local and the independently
// bound Vault and MUST hold its owner mutation/configuration/signer lock for
// this entire call, including runtime changes and reentrant signer callbacks.
// Probe/sign outside transactions; revalidate history and durable guards inside
// Update. No existing session, including Expired, can start again. No HTTP.
func SaveFirstUseV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2,
) (SavedFirstUseV2, error) {
	return saveFirstUseV2(vault, root, local, signer, runtime, time.Now)
}

func saveFirstUseV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2, now func() time.Time,
) (_ SavedFirstUseV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrFirstUse })

	assert.NotNil(vault, ErrFirstUse)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var history localHistoryV2
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		history = try.To1(readLocalHistoryV2(tx, root, local, true))
		try.To(firstUseGuardsV2(tx, history, runtime, true))
		assert.That(history.firstUse.State == "", ErrFirstUse)
		return nil
	}))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, ErrFirstUse)
	n := try.To1(firstUseTime(now()))
	assert.That(n <= math.MaxInt64-int64(FirstUseLifetime), ErrFirstUse)
	established := acceptedPayloadV2(history.binding, history.request)
	p := FirstUseV2{Version: 2, Established: established,
		SessionID: make([]byte, 32), IssuedUnixNano: n,
		ExpiresUnixNano: n + int64(FirstUseLifetime), HeldEvidence: true}
	try.To1(rand.Read(p.SessionID))
	digest := key.HashTagged(FirstUsePurposeV2, try.To1(wire.Marshal(p)))
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	raw := try.To1(wire.Marshal(SignedFirstUseV2{Payload: p,
		Signature: bytes.Clone(signature)}))
	try.To1(decodeFirstUseV2(raw, established))
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitFirstUseAwaitV2(tx, root, local, runtime, raw, now)
	}))
	return SavedFirstUseV2{request: raw,
		peerOrigin: history.binding.TargetContact}, nil
}

func commitFirstUseAwaitV2(tx storage.WriteTx, root, local key.Public,
	runtime ContactRuntimeV2, raw []byte, now func() time.Time,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	h := try.To1(readLocalHistoryV2(tx, root, local, true))
	try.To(firstUseGuardsV2(tx, h, runtime, true))
	assert.That(h.firstUse.State == "", ErrFirstUse)
	p := try.To1(decodeFirstUseV2(raw, acceptedPayloadV2(h.binding, h.request)))
	try.To(freshFirstUseV2(p, now()))
	return tx.Put([]byte(firstUseKey), try.To1(wire.Marshal(firstUseRecord{
		Version: 2, State: useAwait, Request: raw,
	})))
}

// BobFirstUseV2 authenticates Alice's assertion against Bob's own history and
// current local guards. It commits the sole useSeen receipt before returning a
// signed response. Every duplicate is refused, even after response loss. Bob
// neither reads Alice's Vault nor verifies a callback listener. The caller must
// hold the same owner/configuration/signer lock as SaveFirstUseV2. No HTTP.
func BobFirstUseV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2, raw []byte,
) ([]byte, error) {
	return bobFirstUseV2(vault, root, local, signer, runtime, raw, time.Now)
}

func bobFirstUseV2(
	vault *storage.Vault,
	root, local key.Public,
	signer key.Handle,
	runtime ContactRuntimeV2,
	raw []byte,
	now func() time.Time,
) (_ []byte, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrFirstUse })

	assert.NotNil(vault, ErrFirstUse)
	assert.That(len(raw) <= MaxFirstUseBytesV2, ErrFirstUse)
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	var p FirstUseV2
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		p = try.To1(bobFirstUseGuardsV2(tx, root, local, runtime, raw, now))
		return nil
	}))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, ErrFirstUse)
	payload := firstUseResponsePayloadV2(p, raw)
	digest := key.HashTagged(FirstUseResponsePurposeV2,
		try.To1(wire.Marshal(payload)))
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	response := try.To1(wire.Marshal(SignedFirstUseResponseV2{Payload: payload,
		Signature: bytes.Clone(signature)}))
	try.To(verifyFirstUseResponseV2(response, payload))
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitFirstUseReceiptV2(
			tx,
			root,
			local,
			runtime,
			raw,
			response,
			now,
		)
	}))
	return response, nil
}

func bobFirstUseGuardsV2(tx storage.ReadTx, root, local key.Public,
	runtime ContactRuntimeV2, raw []byte, now func() time.Time,
) (_ FirstUseV2, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	h := try.To1(readLocalHistoryV2(tx, root, local, false))
	try.To(firstUseGuardsV2(tx, h, runtime, false))
	assert.ThatNot(h.useSeen, ErrFirstUse)
	p := try.To1(decodeFirstUseV2(raw, acceptedPayloadV2(h.binding, h.request)))
	try.To(freshFirstUseV2(p, now()))
	return p, nil
}

func commitFirstUseReceiptV2(tx storage.WriteTx, root, local key.Public,
	runtime ContactRuntimeV2, raw, response []byte, now func() time.Time,
) (err error) {
	defer err2.Handle(&err, nil)
	p := try.To1(bobFirstUseGuardsV2(tx, root, local, runtime, raw, now))
	try.To(
		verifyFirstUseResponseV2(response, firstUseResponsePayloadV2(p, raw)),
	)
	return tx.Put([]byte(useSeenKey), try.To1(wire.Marshal(firstUseReceipt{
		Version: 2, Request: raw, Response: response,
	})))
}

// ReceiveFirstUseV2 commits only Alice's local Ready, under her own current
// guards. An eligible exact duplicate is read-only. A valid already-sent Bob
// response cannot be recalled by his later policy changes. No third handshake,
// shared PWOpen, Trust or knowledge of Bob's current state follows. Hold the
// owner/configuration/signer lock throughout, as for SaveFirstUseV2. No HTTP.
func ReceiveFirstUseV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2, response []byte,
) (bool, error) {
	return receiveFirstUseV2(
		vault,
		root,
		local,
		signer,
		runtime,
		response,
		time.Now,
	)
}

func receiveFirstUseV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2, response []byte,
	now func() time.Time,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrFirstUse })

	assert.NotNil(vault, ErrFirstUse)
	assert.That(len(response) <= MaxFirstUseBytesV2, ErrFirstUse)
	root, local = bytes.Clone(root), bytes.Clone(local)
	response = bytes.Clone(response)
	var record firstUseRecord
	read := func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		record = try.To1(requesterFirstUseGuardsV2(tx, root, local,
			runtime, response, now))
		return nil
	}
	try.To(vault.View(read))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	assert.That(state.Authorized && state.Usable, ErrFirstUse)
	if record.State == useReady {
		try.To(vault.View(read))
		return true, nil
	}
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitFirstUseReadyV2(tx, root, local, runtime, response, now)
	})
	if updateErr != errRequesterUnchanged {
		try.To(updateErr)
	}
	return true, nil
}

func requesterFirstUseGuardsV2(tx storage.ReadTx, root, local key.Public,
	runtime ContactRuntimeV2, response []byte, now func() time.Time,
) (_ firstUseRecord, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	h := try.To1(readLocalHistoryV2(tx, root, local, true))
	try.To(firstUseGuardsV2(tx, h, runtime, true))
	record := h.firstUse
	assert.That(
		record.State == useAwait || record.State == useReady,
		ErrFirstUse,
	)
	p := try.To1(decodeFirstUseV2(record.Request,
		acceptedPayloadV2(h.binding, h.request)))
	try.To(verifyFirstUseResponseV2(response,
		firstUseResponsePayloadV2(p, record.Request)))
	if record.State == useReady {
		assert.That(bytes.Equal(record.Response, response), ErrFirstUse)
	}
	try.To(freshFirstUseV2(p, now()))
	return record, nil
}

func commitFirstUseReadyV2(tx storage.WriteTx, root, local key.Public,
	runtime ContactRuntimeV2, response []byte, now func() time.Time,
) (err error) {
	defer err2.Handle(&err, nil)
	record := try.To1(requesterFirstUseGuardsV2(tx, root, local,
		runtime, response, now))
	if record.State == useReady {
		return errRequesterUnchanged
	}
	record.State, record.Response = useReady, response
	return tx.Put([]byte(firstUseKey), try.To1(wire.Marshal(record)))
}

// ExpireFirstUseV2 cancels or expires Await/Ready while retaining exact signed
// history. Like v1 cancellation, no current holding, Known or signer is needed;
// deletion cannot prevent it. Hold the owner mutation lock. There is no Idle
// reset, replacement session, timer or delayed-response revival.
func ExpireFirstUseV2(vault *storage.Vault, root, local key.Public,
	cancel bool,
) (bool, error) {
	return expireFirstUseV2(vault, root, local, cancel, time.Now)
}

func expireFirstUseV2(vault *storage.Vault, root, local key.Public,
	cancel bool, now func() time.Time,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrFirstUse })

	assert.NotNil(vault, ErrFirstUse)
	root, local = bytes.Clone(root), bytes.Clone(local)
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitFirstUseExpiredV2(tx, root, local, cancel, now)
	})
	if updateErr == errRequesterUnchanged {
		return false, nil
	}
	try.To(updateErr)
	return true, nil
}

func commitFirstUseExpiredV2(tx storage.WriteTx, root, local key.Public,
	cancel bool, now func() time.Time,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	h := try.To1(readLocalHistoryV2(tx, root, local, true))
	assert.That(h.version == 2 && h.accepted, ErrFirstUse)
	record := h.firstUse
	if record.State == "" || record.State == useExpired {
		return errRequesterUnchanged
	}
	p := try.To1(decodeFirstUseV2(record.Request,
		acceptedPayloadV2(h.binding, h.request)))
	if !cancel && try.To1(firstUseTime(now())) < p.ExpiresUnixNano {
		return errRequesterUnchanged
	}
	record.State = useExpired
	return tx.Put([]byte(firstUseKey), try.To1(wire.Marshal(record)))
}
