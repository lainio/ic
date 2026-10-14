package record

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

var errScopeAllowance = errors.New("test scope allowance exhausted")

// scopeProvider supplies a fresh test secret and a synchronized finite allowance
// shared by every scope using that generation in a test. Fixed-vector tests use
// their existing secret with the same gate. This ephemeral fixture proves only
// local consumption, not lifetime caps, non-replayable reservations, ledger
// freshness, authorization, or safe production deployment.
type scopeProvider struct {
	secret    []byte
	mu        sync.Mutex
	remaining int
	calls     int
}

func newScopeProvider(remaining int) (provider *scopeProvider, err error) {
	defer err2.Handle(&err, nil)
	secret := make([]byte, 32)
	try.To1(rand.Read(secret))
	return &scopeProvider{secret: secret, remaining: remaining}, nil
}

func (p *scopeProvider) spend() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.remaining == 0 {
		return errScopeAllowance
	}
	p.remaining--
	return nil
}

func TestScopeConstruction(t *testing.T) {
	defer assert.PushTester(t)()
	p := try.To1(newScopeProvider(1))
	t.Cleanup(func() { clear(p.secret) })
	for _, tc := range []struct {
		name   string
		secret []byte
		spend  func() error
		want   error
	}{
		{"nil_secret", nil, p.spend, errFormat},
		{"short_secret", p.secret[:31], p.spend, errFormat},
		{"long_secret", make([]byte, 33), p.spend, errFormat},
		{"nil_gate", p.secret, nil, errBudget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			s, err := Derive(tc.secret, [16]byte{}, [16]byte{}, tc.spend)
			if s != nil {
				t.Cleanup(s.Clear)
			}
			assert.Equal(err, tc.want)
			assert.Nil(s)
		})
	}
	s := try.To1(Derive(p.secret, [16]byte{}, [16]byte{}, p.spend))
	t.Cleanup(s.Clear)
	assert.Equal(p.calls, 0)
	assert.Equal(p.remaining, 1)
}

func TestScopeValidatePath(t *testing.T) {
	defer assert.PushTester(t)()
	p := try.To1(newScopeProvider(1))
	t.Cleanup(func() { clear(p.secret) })
	s := try.To1(Derive(p.secret, [16]byte{1}, [16]byte{2}, p.spend))
	t.Cleanup(s.Clear)
	path := [][]byte{{1}, []byte("a/b")}
	try.To(s.ValidatePath(nil))
	try.To(s.ValidatePath(path))
	assert.Equal(string(path[1]), "a/b")
	for _, invalid := range [][][]byte{{nil}, {make([]byte, maxSegmentSize+1)}, make([][]byte, maxSegments+1)} {
		assert.Equal(s.ValidatePath(invalid), errFormat)
	}
	assert.Equal(p.calls, 0)
	assert.Equal(p.remaining, 1)
	s.Clear()
	assert.Equal(s.ValidatePath(path), ErrCleared)
	assert.Equal(s.ValidatePath([][]byte{nil}), ErrCleared)
	assert.Equal(p.calls, 0)
}

func TestScopeComposition(t *testing.T) {
	defer assert.PushTester(t)()
	secret := try.To1(hex.DecodeString(fixtureSecret))
	t.Cleanup(func() { clear(secret) })
	vault := [16]byte(try.To1(hex.DecodeString(fixtureVault)))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	p := &scopeProvider{secret: secret, remaining: 2}
	s := try.To1(Derive(secret, vault, id, p.spend))
	t.Cleanup(s.Clear)
	assert.Equal(p.calls, 0)
	for _, tc := range []struct {
		name  string
		path  [][]byte
		token string
		value []byte
	}{
		{"root", nil, fixtureRootToken, []byte("7")},
		{"nested_empty", [][]byte{[]byte("a/b"), []byte("c")}, fixtureNestedToken, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			token := try.To1(s.Token(tc.path, []byte("count")))
			assert.Equal(token, [32]byte(try.To1(hex.DecodeString(tc.token))))
			envelope := try.To1(s.Seal(tc.path, []byte("count"), tc.value))
			for _, wantKey := range [][]byte{[]byte("count"), nil} {
				key, value := try.To2(s.Open(tc.path, token, wantKey, envelope))
				assert.Equal(bytes.Equal(key, []byte("count")), true)
				assert.Equal(bytes.Equal(value, tc.value), true)
			}
		})
	}
	path := [][]byte{[]byte("a/b"), []byte("c")}
	token := [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
	envelope := try.To1(hex.DecodeString(fixtureEnvelope))
	key, value := try.To2(s.Open(path, token, nil, envelope))
	assert.Equal(bytes.Equal(key, []byte("count")), true)
	assert.Equal(bytes.Equal(value, []byte("7")), true)
	assert.Equal(p.calls, 2)
	assert.Equal(p.remaining, 0)
}

func TestScopeValidation(t *testing.T) {
	defer assert.PushTester(t)()
	p := try.To1(newScopeProvider(2))
	t.Cleanup(func() { clear(p.secret) })
	s := try.To1(Derive(p.secret, [16]byte{1}, [16]byte{2}, p.spend))
	t.Cleanup(s.Clear)
	path := [][]byte{[]byte("a/b"), []byte("c")}
	context := try.To1(encodeContext(s.vault, path))
	token := try.To1(s.Token(path, []byte("count")))
	otherToken := try.To1(s.Token(path, []byte("other")))
	payload := try.To1(encodePlaintext([]byte("count"), []byte("7")))
	for _, tc := range []struct {
		name    string
		token   [32]byte
		payload []byte
		want    error
	}{
		{"inconsistent_token", otherToken, payload, errAuthentication},
		{"malformed_payload", token, payload[:len(payload)-1], errFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			envelope := try.To1(sealEnvelope(s.ke, s.id, context, tc.token, tc.payload, p.spend))
			// Establish AEAD success; Scope must still perform full validation.
			authenticated := try.To1(openEnvelope(s.ke, s.id, context, tc.token, envelope))
			assert.Equal(bytes.Equal(authenticated, tc.payload), true)
			key, value, err := s.Open(path, tc.token, nil, envelope)
			assert.Equal(err, tc.want)
			assert.SNil(key)
			assert.SNil(value)
		})
	}
	// Use the unchanged fixed record for requested-key checks, with no new seals.
	secret := try.To1(hex.DecodeString(fixtureSecret))
	t.Cleanup(func() { clear(secret) })
	vault := [16]byte(try.To1(hex.DecodeString(fixtureVault)))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	fixedGate := &scopeProvider{}
	fixed := try.To1(Derive(secret, vault, id, fixedGate.spend))
	t.Cleanup(fixed.Clear)
	token = [32]byte(try.To1(hex.DecodeString(fixtureNestedToken)))
	envelope := try.To1(hex.DecodeString(fixtureEnvelope))
	for _, tc := range []struct {
		name string
		key  []byte
		want error
	}{
		{"requested_key_mismatch", []byte("Count"), errCollision},
		{"empty_requested_key", []byte{}, errFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			key, value, err := fixed.Open(path, token, tc.key, envelope)
			assert.Equal(err, tc.want)
			assert.SNil(key)
			assert.SNil(value)
		})
	}
	assert.Equal(p.calls, 2)
	assert.Equal(fixedGate.calls, 0)
}

func TestScopeOwnershipAndClear(t *testing.T) {
	defer assert.PushTester(t)()
	p := try.To1(newScopeProvider(1))
	t.Cleanup(func() { clear(p.secret) })
	beforeSecret := bytes.Clone(p.secret)
	t.Cleanup(func() { clear(beforeSecret) })
	vault, id := [16]byte{1}, [16]byte{2}
	s := try.To1(Derive(p.secret, vault, id, p.spend))
	t.Cleanup(s.Clear)
	peer := try.To1(Derive(p.secret, vault, id, p.spend))
	t.Cleanup(peer.Clear)
	assert.Equal(bytes.Equal(p.secret, beforeSecret), true)
	path := [][]byte{[]byte("a/b"), []byte("c")}
	inputKey, inputValue := []byte("count"), []byte("7")
	token := try.To1(s.Token(path, inputKey))
	p.secret[0] ^= 1
	vault[0], id[0] = 9, 9
	assert.Equal(try.To1(s.Token(path, inputKey)), token)
	assert.Equal(try.To1(peer.Token(path, inputKey)), token)
	envelope := try.To1(s.Seal(path, inputKey, inputValue))
	beforeEnvelope := bytes.Clone(envelope)
	inputKey[0], inputValue[0] = 'x', 'x'
	key, value := try.To2(s.Open(path, token, nil, envelope))
	assert.Equal(bytes.Equal(key, []byte("count")), true)
	assert.Equal(bytes.Equal(value, []byte("7")), true)
	key[0], value[0] = 'y', 'y'
	retainedKey, retainedValue := try.To2(s.Open(path, token, nil, envelope))
	assert.Equal(bytes.Equal(envelope, beforeEnvelope), true)
	// Retain aliases only to inspect owned buffers, not to claim GC erasure.
	ke, ki := s.ke, s.ki
	assert.SLen(ke, 32)
	assert.SLen(ki, 32)
	s.Clear()
	s.Clear()
	assert.Equal(bytes.Equal(ke, make([]byte, 32)), true)
	assert.Equal(bytes.Equal(ki, make([]byte, 32)), true)
	assert.SNil(s.ke)
	assert.SNil(s.ki)
	assert.Equal(s.spend == nil, true)
	assert.Equal(s.cleared, true)
	beforeSecret[0] ^= 1
	assert.Equal(bytes.Equal(p.secret, beforeSecret), true)
	for _, tc := range []struct {
		name     string
		path     [][]byte
		key      []byte
		envelope []byte
	}{
		{"valid", path, []byte("count"), envelope},
		{"invalid", [][]byte{nil}, nil, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			gotToken, err := s.Token(tc.path, tc.key)
			assert.Equal(err, ErrCleared)
			assert.Equal(gotToken, [32]byte{})
			sealed, err := s.Seal(tc.path, tc.key, nil)
			assert.Equal(err, ErrCleared)
			assert.SNil(sealed)
			key, value, err := s.Open(tc.path, token, tc.key, tc.envelope)
			assert.Equal(err, ErrCleared)
			assert.SNil(key)
			assert.SNil(value)
		})
	}
	assert.Equal(bytes.Equal(retainedKey, []byte("count")), true)
	assert.Equal(bytes.Equal(retainedValue, []byte("7")), true)
	assert.Equal(bytes.Equal(envelope, beforeEnvelope), true)
	key, value = try.To2(peer.Open(path, token, nil, envelope))
	assert.Equal(bytes.Equal(key, retainedKey), true)
	assert.Equal(bytes.Equal(value, retainedValue), true)
	clear(envelope)
	assert.Equal(bytes.Equal(key, retainedKey), true)
	assert.Equal(bytes.Equal(value, retainedValue), true)
	assert.Equal(p.calls, 1)
	assert.Equal(p.remaining, 0)
}

func TestScopeSpending(t *testing.T) {
	defer assert.PushTester(t)()
	p := try.To1(newScopeProvider(2))
	t.Cleanup(func() { clear(p.secret) })
	vault, id := [16]byte{1}, [16]byte{2}
	s := try.To1(Derive(p.secret, vault, id, p.spend))
	t.Cleanup(s.Clear)
	other := try.To1(Derive(p.secret, vault, id, p.spend))
	t.Cleanup(other.Clear)
	key, value := []byte("count"), []byte("7")
	token := try.To1(s.Token(nil, key))
	assert.Equal(try.To1(other.Token(nil, key)), token)
	for _, tc := range []struct {
		name       string
		path       [][]byte
		key, value []byte
	}{
		{"path", [][]byte{nil}, key, value},
		{"key", nil, nil, value},
		{"value", nil, key, make([]byte, maxPlaintextSize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			envelope, err := s.Seal(tc.path, tc.key, tc.value)
			assert.Equal(err, errFormat)
			assert.SNil(envelope)
		})
	}
	badToken, err := s.Token([][]byte{nil}, key)
	assert.Equal(err, errFormat)
	assert.Equal(badToken, [32]byte{})
	badKey, badValue, err := s.Open([][]byte{nil}, token, nil, nil)
	assert.Equal(err, errFormat)
	assert.SNil(badKey)
	assert.SNil(badValue)
	assert.Equal(p.calls, 0)
	assert.Equal(p.remaining, 2)
	envelope := try.To1(s.Seal(nil, key, value))
	// A successful seal discarded by the other scope is still spent.
	_ = try.To1(other.Seal(nil, key, value))
	assert.Equal(p.calls, 2)
	assert.Equal(p.remaining, 0)
	for _, scope := range []*Scope{s, other} {
		denied, err := scope.Seal(nil, key, value)
		assert.ErrorIs(err, errBudget)
		assert.ErrorIs(err, errScopeAllowance)
		assert.SNil(denied)
		assert.Equal(try.To1(scope.Token(nil, key)), token)
		gotKey, gotValue := try.To2(scope.Open(nil, token, key, envelope))
		assert.Equal(bytes.Equal(gotKey, key), true)
		assert.Equal(bytes.Equal(gotValue, value), true)
	}
	assert.Equal(p.calls, 4)
	s.Clear()
	// Recreate the same generation with the exhausted gate: no reset or refund.
	recreated := try.To1(Derive(p.secret, vault, id, p.spend))
	t.Cleanup(recreated.Clear)
	assert.Equal(p.calls, 4)
	assert.Equal(p.remaining, 0)
	assert.Equal(try.To1(recreated.Token(nil, key)), token)
	gotKey, gotValue := try.To2(recreated.Open(nil, token, nil, envelope))
	assert.Equal(bytes.Equal(gotKey, key), true)
	assert.Equal(bytes.Equal(gotValue, value), true)
	denied, err := recreated.Seal(nil, key, value)
	assert.ErrorIs(err, errBudget)
	assert.ErrorIs(err, errScopeAllowance)
	assert.SNil(denied)
	assert.Equal(p.calls, 5)
	assert.Equal(p.remaining, 0)
}

func TestScopeConcurrentAllowance(t *testing.T) {
	defer assert.PushTester(t)()
	const allowance, attempts = 3, 8
	p := try.To1(newScopeProvider(allowance))
	t.Cleanup(func() { clear(p.secret) })
	var scopes [2]*Scope
	for i := range scopes {
		scopes[i] = try.To1(Derive(p.secret, [16]byte{1}, [16]byte{2}, p.spend))
		t.Cleanup(scopes[i].Clear)
	}
	key, value := []byte("count"), []byte("7")
	wantToken := try.To1(scopes[0].Token(nil, key))
	type result struct {
		token                [32]byte
		envelope, key, value []byte
		err                  error
	}
	results := make(chan result, attempts)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := range attempts {
		workers.Add(1)
		go func(s *Scope) {
			defer workers.Done()
			<-start
			r := result{}
			r.token, r.err = s.Token(nil, key)
			if r.err == nil {
				r.envelope, r.err = s.Seal(nil, key, value)
			}
			if r.err == nil {
				r.key, r.value, r.err = s.Open(nil, r.token, nil, r.envelope)
			}
			results <- r
		}(scopes[i%len(scopes)])
	}
	close(start)
	workers.Wait() // Drain before assertions can trigger cleanup/Clear.
	close(results)
	successes := 0
	for r := range results {
		assert.Equal(r.token, wantToken)
		if r.err != nil {
			assert.ErrorIs(r.err, errBudget)
			assert.ErrorIs(r.err, errScopeAllowance)
			assert.SNil(r.envelope)
			assert.SNil(r.key)
			assert.SNil(r.value)
			continue
		}
		successes++
		assert.Equal(bytes.Equal(r.key, key), true)
		assert.Equal(bytes.Equal(r.value, value), true)
	}
	assert.Equal(successes, allowance)
	assert.Equal(p.calls, attempts)
	assert.Equal(p.remaining, 0)
}
