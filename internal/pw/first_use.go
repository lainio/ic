package pw

import (
	"bytes"
	"crypto/rand"
	"math"
	"time"

	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// SavedFirstUse is an owned, committed request. Only SaveFirstUse constructs
// it; transport callers cannot select an endpoint, binding, time or session.
type SavedFirstUse struct {
	request  []byte
	endpoint string
}

// SaveFirstUse is the durable half of SendFirstUse. The caller MUST hold the
// existing owner mutation/signer lock. Only an explicit authenticated owner
// invocation may start it. No existing session (even Await) is sent again.
// Probe/sign/verify precede Update; all durable guards are reread inside it.
func SaveFirstUse(vault *storage.Vault, root, local key.Public,
	signer key.Handle,
) (SavedFirstUse, error) {
	return saveFirstUse(vault, root, local, signer, time.Now)
}

func saveFirstUse(vault *storage.Vault, root, local key.Public,
	signer key.Handle, now func() time.Time,
) (_ SavedFirstUse, err error) {
	reason := "undetermined"
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error {
		glog.V(1).Infof("intro_pw op=first_use side=requester "+
			"stage=await result=refused reason=%s", reason)
		return ErrFirstUse
	})

	assert.NotNil(vault, ErrFirstUse)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var established Accepted
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		established = try.To1(firstUseHistory(tx, root, local, true))
		try.To(firstUseGuards(tx, established, true))
		_, exists := try.To2(tx.Get([]byte(firstUseKey)))
		if exists {
			reason = "session_already_exists"
		}
		assert.ThatNot(exists, ErrFirstUse)
		return nil
	}))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	if !state.Authorized {
		reason = "device_not_authorized"
	} else if !state.Usable {
		reason = "signer_unusable"
	}
	assert.That(state.Authorized && state.Usable, ErrFirstUse)
	glog.V(1).Info("intro_pw op=first_use side=requester " +
		"stage=signer result=usable")
	n := try.To1(firstUseTime(now()))
	assert.That(n <= math.MaxInt64-int64(FirstUseLifetime), ErrFirstUse)
	p := FirstUse{
		Version:         1,
		Established:     established,
		SessionID:       make([]byte, 32),
		IssuedUnixNano:  n,
		ExpiresUnixNano: n + int64(FirstUseLifetime),
		HeldEvidence:    true,
	}
	try.To1(rand.Read(p.SessionID))
	digest := key.HashTagged(FirstUsePurpose, try.To1(wire.Marshal(p)))
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	raw := try.To1(wire.Marshal(SignedFirstUse{Payload: p,
		Signature: bytes.Clone(signature)}))
	try.To1(decodeFirstUse(raw, established))
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitFirstUseAwait(tx, root, local, raw, now)
	}))
	glog.V(1).Info("intro_pw op=first_use side=requester " +
		"stage=await result=committed")
	saved := attemptSnapshot(nil, established.Binding.Ad, true, true)
	return SavedFirstUse{request: raw, endpoint: saved.endpoint}, nil
}

func commitFirstUseAwait(tx storage.WriteTx, root, local key.Public,
	raw []byte, now func() time.Time,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	established := try.To1(firstUseHistory(tx, root, local, true))
	try.To(firstUseGuards(tx, established, true))
	_, exists := try.To2(tx.Get([]byte(firstUseKey)))
	assert.ThatNot(exists, ErrFirstUse)
	p := try.To1(decodeFirstUse(raw, established))
	try.To(freshFirstUse(p, now()))
	return tx.Put([]byte(firstUseKey), try.To1(wire.Marshal(firstUseRecord{
		Version: 1, State: useAwait, Request: raw,
	})))
}

// BobFirstUse authenticates against Bob's saved acceptance, probes/signs under
// the owner's mutation lock outside transactions, then rechecks and commits
// exactly one receipt before returning response bytes. It reads only Bob's
// Vault. Every duplicate is refused, including a retry after a lost response.
func BobFirstUse(vault *storage.Vault, root, local key.Public,
	signer key.Handle, raw []byte,
) ([]byte, error) {
	return bobFirstUse(vault, root, local, signer, raw, time.Now)
}

func bobFirstUse(vault *storage.Vault, root, local key.Public,
	signer key.Handle, raw []byte, now func() time.Time,
) (_ []byte, err error) {
	reason := "undetermined"
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error {
		glog.V(1).Infof("intro_pw op=first_use side=acceptor "+
			"stage=receipt result=refused reason=%s", reason)
		return ErrFirstUse
	})

	assert.NotNil(vault, ErrFirstUse)
	root, local, raw = bytes.Clone(root), bytes.Clone(local), bytes.Clone(raw)
	var p FirstUse
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		p = try.To1(bobFirstUseGuards(tx, root, local, raw, now))
		return nil
	}))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	if !state.Authorized {
		reason = "device_not_authorized"
	} else if !state.Usable {
		reason = "signer_unusable"
	}
	assert.That(state.Authorized && state.Usable, ErrFirstUse)
	glog.V(1).Info("intro_pw op=first_use side=acceptor " +
		"stage=signer result=usable")
	payload := firstUseResponsePayload(p, raw)
	digest := key.HashTagged(
		FirstUseResponsePurpose,
		try.To1(wire.Marshal(payload)),
	)
	signature := try.To1((localSigner{signer}).Sign(bytes.Clone(digest[:])))
	response := try.To1(wire.Marshal(SignedFirstUseResponse{Payload: payload,
		Signature: bytes.Clone(signature)}))
	try.To(verifyFirstUseResponse(response, payload))
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitFirstUseReceipt(tx, root, local, raw, response, now)
	}))
	glog.V(1).Info("intro_pw op=first_use side=acceptor " +
		"stage=receipt result=committed")
	return response, nil
}

func bobFirstUseGuards(tx storage.ReadTx, root, local key.Public,
	raw []byte, now func() time.Time,
) (_ FirstUse, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	established := try.To1(firstUseHistory(tx, root, local, false))
	try.To(firstUseGuards(tx, established, false))
	_, seen := try.To2(tx.Get([]byte(useSeenKey)))
	assert.ThatNot(seen, ErrFirstUse)
	p := try.To1(decodeFirstUse(raw, established))
	try.To(freshFirstUse(p, now()))
	return p, nil
}

func commitFirstUseReceipt(tx storage.WriteTx, root, local key.Public,
	raw, response []byte, now func() time.Time,
) (err error) {
	defer err2.Handle(&err, nil)
	p := try.To1(bobFirstUseGuards(tx, root, local, raw, now))
	try.To(verifyFirstUseResponse(response, firstUseResponsePayload(p, raw)))
	return tx.Put([]byte(useSeenKey), try.To1(wire.Marshal(firstUseReceipt{
		Version: 1, Request: raw, Response: response,
	})))
}

// ReceiveFirstUse records only historical LOCAL Ready after authenticating
// Bob's exact response and checking Alice's current guards. Hold the owner lock
// throughout. No third message or read of Bob's current policy is performed.
// An exact Ready duplicate is a no-write observation under the same guards;
// neither an expired session nor a deleted holding can be revived.
func ReceiveFirstUse(vault *storage.Vault, root, local key.Public,
	signer key.Handle, response []byte,
) (bool, error) {
	return receiveFirstUse(vault, root, local, signer, response, time.Now)
}

func receiveFirstUse(vault *storage.Vault, root, local key.Public,
	signer key.Handle, response []byte, now func() time.Time,
) (_ bool, err error) {
	reason := "undetermined"
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error {
		glog.V(1).Infof("intro_pw op=first_use side=requester "+
			"stage=ready result=refused reason=%s", reason)
		return ErrFirstUse
	})

	assert.NotNil(vault, ErrFirstUse)
	root, local = bytes.Clone(root), bytes.Clone(local)
	response = bytes.Clone(response)
	var record firstUseRecord
	read := func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		record = try.To1(
			requesterFirstUseGuards(tx, root, local, response, now),
		)
		return nil
	}
	try.To(vault.View(read))
	state := try.To1(
		device.InspectLocal(vault, root, local, localSigner{signer}),
	)
	if !state.Authorized {
		reason = "device_not_authorized"
	} else if !state.Usable {
		reason = "signer_unusable"
	}
	assert.That(state.Authorized && state.Usable, ErrFirstUse)
	glog.V(1).Info("intro_pw op=first_use side=requester " +
		"stage=signer result=usable")
	if record.State == useReady {
		try.To(vault.View(read))
		glog.V(1).Info("intro_pw op=first_use side=requester " +
			"stage=ready result=retained")
		return true, nil
	}
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		return commitFirstUseReady(tx, root, local, response, now)
	})
	if updateErr != errRequesterUnchanged {
		try.To(updateErr)
		glog.V(1).Info("intro_pw op=first_use side=requester " +
			"stage=ready result=committed")
	} else {
		glog.V(1).Info("intro_pw op=first_use side=requester " +
			"stage=ready result=retained")
	}
	return true, nil
}

func requesterFirstUseGuards(tx storage.ReadTx, root, local key.Public,
	response []byte, now func() time.Time,
) (_ firstUseRecord, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	established := try.To1(firstUseHistory(tx, root, local, true))
	try.To(firstUseGuards(tx, established, true))
	record := try.To1(readFirstUse(tx, established))
	assert.That(
		record.State == useAwait || record.State == useReady,
		ErrFirstUse,
	)
	p := try.To1(decodeFirstUse(record.Request, established))
	expected := firstUseResponsePayload(p, record.Request)
	try.To(verifyFirstUseResponse(response, expected))
	if record.State == useReady {
		assert.That(bytes.Equal(record.Response, response), ErrFirstUse)
	}
	try.To(freshFirstUse(p, now()))
	return record, nil
}

func commitFirstUseReady(tx storage.WriteTx, root, local key.Public,
	response []byte, now func() time.Time,
) (err error) {
	defer err2.Handle(&err, nil)
	record := try.To1(requesterFirstUseGuards(tx, root, local, response, now))
	if record.State == useReady {
		return errRequesterUnchanged
	}
	record.State, record.Response = useReady, response
	return tx.Put([]byte(firstUseKey), try.To1(wire.Marshal(record)))
}

// ExpireFirstUse projects Await/Ready to Expired on local deadline evaluation
// or explicit cancellation. It needs no live holding, Known or signer, so local
// deletion cannot prevent cancellation. Hold the owner mutation lock. No timer,
// remote request or replacement session is created; exact evidence is retained.
func ExpireFirstUse(vault *storage.Vault, root, local key.Public,
	cancel bool,
) (bool, error) {
	return expireFirstUse(vault, root, local, cancel, time.Now)
}

func expireFirstUse(vault *storage.Vault, root, local key.Public,
	cancel bool, now func() time.Time,
) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrFirstUse })

	assert.NotNil(vault, ErrFirstUse)
	root, local = bytes.Clone(root), bytes.Clone(local)
	updateErr := vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		established := try.To1(firstUseHistory(tx, root, local, true))
		record := try.To1(readFirstUse(tx, established))
		if record.State == "" || record.State == useExpired {
			return errRequesterUnchanged
		}
		p := try.To1(decodeFirstUse(record.Request, established))
		if !cancel && try.To1(firstUseTime(now())) < p.ExpiresUnixNano {
			return errRequesterUnchanged
		}
		record.State = useExpired
		return tx.Put([]byte(firstUseKey), try.To1(wire.Marshal(record)))
	})
	if updateErr == errRequesterUnchanged {
		return false, nil
	}
	try.To(updateErr)
	return true, nil
}
