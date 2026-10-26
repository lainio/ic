// Package device projects V19 BootstrapDevice onto one existing local software
// signer. It provides neither general device delegation nor a consent protocol.
package device

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"reflect"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const (
	authNamespace = "local-device-auth-v1"
	localDevice   = "local-software-signer"
	probePurpose  = "local-device-usability/v1"
)

var (
	ErrInvalidBinding       = errors.New("invalid local device binding")
	ErrNotKnown             = errors.New("local node is not Known-introduced")
	ErrAlreadyAuthorized    = errors.New("local device already authorized")
	ErrInvalidAuthorization = errors.New("invalid local device authorization")
	ErrUnusableSigner       = errors.New("local software signer is not usable")
)

// Local separates durable authorization from a point-in-time signer check.
// Usable is never stored and grants no ad, PW, or other modeled transition.
type Local struct {
	Authorized bool
	Usable     bool
}

// BootstrapLocal explicitly authorizes the saved, independently restored node
// signer (for example from nodeidentity.OpenDirectory). The caller supplies the
// same independently configured Root and local identity used to bind/open this
// dedicated Vault. Vault itself exposes no node/root binding. Inputs must never
// be inferred from peer data. No identity, handle, or Vault is created here.
//
// The private localDevice slot denotes this node signer, not a second key or a
// caller-chosen device ID. Its single encrypted record binds the exact Root and
// owner/device public key. No signer secrets or live flag are persisted.
//
// Non-Root nodes require their own full public key in the validated Known view.
// Exact equality to the configured Root supplies V19 Init's self-Known case.
// The caller must serialize changes to evidence, configuration, and signer use
// across the read preflight and commit, including reentrant callbacks. Competing
// bootstraps remain safe: the final empty guard is inside the atomic Update.
// A valid existing authorization returns ErrAlreadyAuthorized before signing
// or sealing. Invalid state fails closed. Every error returns a zero Local.
func BootstrapLocal(vault *storage.Vault, expectedRoot, expectedLocal key.Public,
	signer key.Handle,
) (_ Local, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	binding := try.To1(authorizationBinding(vault, expectedRoot, expectedLocal))
	expectedRoot, expectedLocal = bytes.Clone(expectedRoot), bytes.Clone(expectedLocal)
	assert.ThatNot(try.To1(readAuthorization(vault, binding)), ErrAlreadyAuthorized)
	if !bytes.Equal(expectedRoot, expectedLocal) {
		known := try.To1(onboarding.ListKnownIntroductions(vault, expectedRoot))
		found := false
		for _, subject := range known {
			found = found || bytes.Equal(subject, expectedLocal)
		}
		assert.That(found, ErrNotKnown)
	}
	try.To(checkSigner(signer, expectedLocal))
	try.To(vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)

		assert.ThatNot(try.To1(authorized(tx, binding)), ErrAlreadyAuthorized)
		records := try.To1(tx.EnsureChild([]byte(authNamespace)))
		return records.Put([]byte(localDevice), binding)
	}))
	return Local{Authorized: true, Usable: true}, nil
}

// InspectLocal reads authorization without writing or re-bootstrapping. Its
// Vault/binding contract is the same as BootstrapLocal. An absent authorization
// returns zero without signing. A valid record remains Authorized even when the
// supplied signer is absent, wrong, or fails its local probe; these cases return
// Usable=false with no error. Storage/binding errors return zero and an error.
// Supplying a signer explicitly opts into a fresh local diagnostic signature;
// it is never stored, transmitted, or treated as peer authentication. Merely
// opening the Vault or inspecting with nil does not sign.
func InspectLocal(vault *storage.Vault, expectedRoot, expectedLocal key.Public,
	signer key.Handle,
) (_ Local, err error) {
	defer err2.Handle(&err, nil)

	binding := try.To1(authorizationBinding(vault, expectedRoot, expectedLocal))
	expectedLocal = bytes.Clone(expectedLocal)
	if !try.To1(readAuthorization(vault, binding)) {
		return Local{}, nil
	}
	return Local{Authorized: true, Usable: checkSigner(signer, expectedLocal) == nil}, nil
}

func authorizationBinding(vault *storage.Vault, root, local key.Public) ([]byte, error) {
	if vault == nil || len(root) == 0 || len(local) == 0 {
		return nil, ErrInvalidBinding
	}
	// Private version, root length, exact root, then exact owner/device key.
	// Canonical comparison below rejects other versions, extra bytes, and any
	// mismatched owner/root without interpreting them as fresh authorization.
	record := binary.AppendUvarint([]byte{1}, uint64(len(root)))
	record = append(record, root...)
	return append(record, local...), nil
}

func readAuthorization(vault *storage.Vault, binding []byte) (_ bool, err error) {
	defer err2.Handle(&err, nil)

	var found bool
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		found = try.To1(authorized(tx, binding))
		return nil
	}))
	return found, nil
}

func authorized(tx storage.ReadTx, binding []byte) (_ bool, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	if !try.To1(tx.HasChild([]byte(authNamespace))) {
		return false, nil
	}
	records := try.To1(tx.Child([]byte(authNamespace)))
	record, found := try.To2(records.Get([]byte(localDevice)))
	// This package creates the namespace and record together. An existing
	// empty/partial namespace is invalid, not an invitation to repair it.
	assert.That(found && bytes.Equal(record, binding), ErrInvalidAuthorization)
	return true, records.Each(func(name, value []byte) error {
		if string(name) != localDevice || !bytes.Equal(value, binding) {
			return ErrInvalidAuthorization
		}
		return nil
	})
}

func checkSigner(signer key.Handle, expected key.Public) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(cause error) error {
		return errors.Join(ErrUnusableSigner, cause)
	})

	assert.INotNil(signer, ErrUnusableSigner)
	// key.Handle is an interface; reject a typed nil before invoking methods.
	value := reflect.ValueOf(signer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		assert.ThatNot(value.IsNil(), ErrUnusableSigner)
	}
	public := try.To1(signer.CBORPublicKey())
	assert.That(bytes.Equal(public, expected), ErrUnusableSigner)
	var nonce [32]byte
	try.To1(rand.Read(nonce[:]))
	digest := key.HashTagged(probePurpose, nonce[:])
	signature := key.Signature(try.To1(signer.Sign(bytes.Clone(digest[:]))))
	// Verify independently with the expected public key, never signer.Verify.
	assert.That(signature.Verify(expected, digest[:]), ErrUnusableSigner)
	return nil
}
