package record

import (
	"bytes"
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

// ErrCleared indicates that a Scope has been permanently cleared.
var ErrCleared = errors.New("record: scope cleared")

// Scope owns derived keys for one immutable vault/key generation. Use the
// pointer returned by Derive; a Scope must not be copied or used as a zero value.
// It provides neither authorization nor global key-usage accounting.
//
// Live Token, Seal, and Open calls may run concurrently if the supplied spend
// gate is safe for concurrent calls. The owner must drain all work before Clear;
// concurrent Clear/use and reentrancy are outside this bridge's contract.
type Scope struct {
	ke, ki  []byte
	vault   [16]byte
	id      [16]byte
	spend   func() error
	cleared bool
}

// Derive binds caller-provisioned identity and a nonnil spend gate to owned
// derived keys. The secret must contain exactly 32 bytes; its entropy and the
// caller's authorization are external responsibilities. Derive copies the
// borrowed secret for derivation, clears that copy on exit, and never spends.
// The gate must consume an allowance for the actual derived encryption key on
// each successful call, without provider I/O. Derive does not reset allowances.
func Derive(secret []byte, vault, id [16]byte, spend func() error) (scope *Scope, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.SLen(secret, 32, errFormat)
	assert.That(spend != nil, errBudget)
	owned := bytes.Clone(secret)
	defer clear(owned)
	ke, ki := try.To2(derive(owned, vault, id))
	return &Scope{ke: ke, ki: ki, vault: vault, id: id, spend: spend}, nil
}

// Token computes the deterministic lookup token without spending. Path segments
// are literal bytes; the future Vault layer supplies any reserved prefixes.
func (s *Scope) Token(path [][]byte, key []byte) (token [32]byte, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.That(!s.cleared, ErrCleared)
	context := try.To1(encodeContext(s.vault, path))
	return lookupToken(s.ki, context, s.id, key)
}

// ValidatePath checks the existing context bounds without spending, deriving
// keys, computing a lookup token, or retaining any input bytes.
func (s *Scope) ValidatePath(path [][]byte) (err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.That(!s.cleared, ErrCleared)
	try.To1(encodeContext(s.vault, path))
	return nil
}

// Seal validates inputs and spends once before sealing with the existing codec.
// A completed seal consumes its allowance even when discarded. Use Token to
// obtain its lookup token; missing or exhausted allowances never enable sealing.
func (s *Scope) Seal(path [][]byte, key, value []byte) (envelope []byte, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.That(!s.cleared, ErrCleared)
	context := try.To1(encodeContext(s.vault, path))
	_, sealed := try.To2(sealRecord(s.ke, s.ki, s.id, context, key, value, s.spend))
	return sealed, nil
}

// Open authenticates, decodes, verifies the token, and checks any requested key
// before returning owned bytes. Nil wantKey selects iteration; a nonnil key must
// be nonempty. Expected identity comes from Scope, never the envelope. Open does
// not spend and remains available when the allowance is exhausted.
func (s *Scope) Open(path [][]byte, token [32]byte, wantKey, envelope []byte) (key, value []byte, err error) {
	defer err2.Handle(&err, nil)
	defer assert.PushAsserter(assert.Plain)()

	assert.That(!s.cleared, ErrCleared)
	context := try.To1(encodeContext(s.vault, path))
	return openRecord(s.ke, s.ki, s.id, context, token, wantKey, envelope)
}

// Clear terminally invalidates Scope and overwrites its owned key buffers,
// dropping their references and the spend gate. It is idempotent and never
// spends, refunds, or calls a provider. The owner must first drain all work.
// Erasure is best effort: runtime/crypto copies may remain. Caller-owned secrets
// and previously returned bytes are unaffected.
func (s *Scope) Clear() {
	clear(s.ke)
	clear(s.ki)
	s.ke, s.ki, s.spend = nil, nil, nil
	s.cleared = true
}
