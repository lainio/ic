package record

import (
	"bytes"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

const (
	fixtureSecret      = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	fixtureKE          = "763036fd88581b2dfba48006541b74090bdfe1cd64476d935c094245b0b48e98"
	fixtureKI          = "39bc32865d38eb114f07e4a2a8b2a902e6868917a935053876e554f7d8ad9300"
	fixtureRootToken   = "3509c2edeb88bef6a881bf694ca7721eb185ae209551f0e6b35ae3616ede35e0"
	fixtureNestedToken = "66139daaf95cf23e867958a5498c6556240b32ac42295abf2b1760eb805a7de7"
)

func TestDeriveFixed(t *testing.T) {
	defer assert.PushTester(t)()
	secret := try.To1(hex.DecodeString(fixtureSecret))
	vault := [16]byte(try.To1(hex.DecodeString(fixtureVault)))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	ke, ki := try.To2(derive(secret, vault, id))
	assert.Equal(hex.EncodeToString(ke), fixtureKE)
	assert.Equal(hex.EncodeToString(ki), fixtureKI)
	assert.SLen(ke, 32)
	assert.SLen(ki, 32)
	assert.Equal(bytes.Equal(ke, ki), false)
	assert.Equal(hex.EncodeToString(secret), fixtureSecret)
}

func TestTokenFixed(t *testing.T) {
	defer assert.PushTester(t)()
	ki := try.To1(hex.DecodeString(fixtureKI))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	for _, tc := range []struct{ name, context, want string }{
		{"root", fixtureRootContext, fixtureRootToken},
		{"nested", fixtureNestedContext, fixtureNestedToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			context := try.To1(hex.DecodeString(tc.context))
			token := try.To1(lookupToken(ki, context, id, []byte("count")))
			assert.Equal(hex.EncodeToString(token[:]), tc.want)
			assert.Equal(len(token), 32)
			assert.Equal(try.To1(lookupToken(ki, context, id, []byte("count"))), token)
		})
	}
}

func TestTokenSeparation(t *testing.T) {
	defer assert.PushTester(t)()
	ki := try.To1(hex.DecodeString(fixtureKI))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	context := try.To1(hex.DecodeString(fixtureNestedContext))
	want := try.To1(lookupToken(ki, context, id, []byte("count")))
	for _, name := range []string{"index_key", "id", "logical_key", "binary_key", "vault", "path", "root"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			indexKey, i, c, key := bytes.Clone(ki), id, bytes.Clone(context), []byte("count")
			switch name {
			case "index_key":
				indexKey[0] ^= 1
			case "id":
				i[0] ^= 1
			case "logical_key":
				key = []byte("counts")
			case "binary_key":
				key = []byte{0, 0xff, '/', 0x80}
			case "vault":
				c[4] ^= 1
			case "path":
				vault := [16]byte(try.To1(hex.DecodeString(fixtureVault)))
				c = try.To1(encodeContext(vault, [][]byte{[]byte("a"), []byte("b/c")}))
			case "root":
				c = try.To1(hex.DecodeString(fixtureRootContext))
			}
			assert.NotEqual(try.To1(lookupToken(indexKey, c, i, key)), want)
		})
	}
}

func TestTokenBounds(t *testing.T) {
	defer assert.PushTester(t)()
	context := try.To1(hex.DecodeString(fixtureRootContext))
	for _, tc := range []struct {
		name            string
		kiSize, keySize int
		want            error
	}{
		{"minimum", 32, 1, nil}, {"maximum_key", 32, 4096, nil},
		{"empty_key", 32, 0, errFormat}, {"overlong_key", 32, 4097, errFormat},
		{"empty_index_key", 0, 1, errFormat}, {"short_index_key", 31, 1, errFormat},
		{"long_index_key", 33, 1, errFormat},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			token, err := lookupToken(make([]byte, tc.kiSize), context, [16]byte{}, make([]byte, tc.keySize))
			assert.Equal(err, tc.want)
			if tc.want != nil {
				assert.Equal(token, [32]byte{})
			}
		})
	}
}

func TestTokenOwnership(t *testing.T) {
	defer assert.PushTester(t)()
	ki := try.To1(hex.DecodeString(fixtureKI))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	context := try.To1(hex.DecodeString(fixtureNestedContext))
	key := []byte("count")
	token1 := try.To1(lookupToken(ki, context, id, key))
	token2 := try.To1(lookupToken(ki, context, id, key))
	token1[0] ^= 1
	assert.Equal(hex.EncodeToString(token2[:]), fixtureNestedToken)
	assert.Equal(hex.EncodeToString(ki), fixtureKI)
	assert.Equal(hex.EncodeToString(context), fixtureNestedContext)
	assert.Equal(hex.EncodeToString(id[:]), fixtureID)
	assert.Equal(string(key), "count")
	token3 := try.To1(lookupToken(ki, context, id, key))
	clear(ki)
	clear(context)
	clear(key)
	id[0] ^= 1
	assert.Equal(hex.EncodeToString(token3[:]), fixtureNestedToken)
}

func TestDeriveInvalidSecret(t *testing.T) {
	defer assert.PushTester(t)()
	for _, size := range []int{0, 1, 31, 33, 64} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			defer assert.PushTester(t)()
			ke, ki, err := derive(make([]byte, size), [16]byte{}, [16]byte{})
			assert.Equal(err, errFormat)
			assert.SNil(ke)
			assert.SNil(ki)
		})
	}
	ke, ki, err := derive(nil, [16]byte{}, [16]byte{})
	assert.Equal(err, errFormat)
	assert.SNil(ke)
	assert.SNil(ki)
	// Provisioning quality is outside this helper; zero bytes are not forbidden.
	ke, ki = try.To2(derive(make([]byte, 32), [16]byte{}, [16]byte{}))
	assert.SLen(ke, 32)
	assert.SLen(ki, 32)
}

func TestDeriveSeparation(t *testing.T) {
	defer assert.PushTester(t)()
	secret := try.To1(hex.DecodeString(fixtureSecret))
	vault := [16]byte(try.To1(hex.DecodeString(fixtureVault)))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	ke, ki := try.To2(derive(secret, vault, id))
	for _, name := range []string{"secret", "vault", "id"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			s, v, i := bytes.Clone(secret), vault, id
			switch name {
			case "secret":
				s[0] ^= 1
			case "vault":
				v[0] ^= 1
			case "id":
				i[0] ^= 1
			}
			otherKE, otherKI := try.To2(derive(s, v, i))
			assert.Equal(bytes.Equal(ke, otherKE), false)
			assert.Equal(bytes.Equal(ki, otherKI), false)
			assert.Equal(bytes.Equal(otherKE, otherKI), false)
		})
	}
}

func TestDeriveOwnership(t *testing.T) {
	defer assert.PushTester(t)()
	secret := try.To1(hex.DecodeString(fixtureSecret))
	vault := [16]byte(try.To1(hex.DecodeString(fixtureVault)))
	id := [16]byte(try.To1(hex.DecodeString(fixtureID)))
	ke1, ki1 := try.To2(derive(secret, vault, id))
	ke2, ki2 := try.To2(derive(secret, vault, id))
	clear(ke1)
	assert.Equal(hex.EncodeToString(ki1), fixtureKI)
	clear(ki1)
	assert.Equal(hex.EncodeToString(secret), fixtureSecret)
	assert.Equal(hex.EncodeToString(ke2), fixtureKE)
	assert.Equal(hex.EncodeToString(ki2), fixtureKI)
	ke3, ki3 := try.To2(derive(secret, vault, id))
	clear(secret)
	vault[0], id[0] = 0, 0
	assert.Equal(hex.EncodeToString(ke3), fixtureKE)
	assert.Equal(hex.EncodeToString(ki3), fixtureKI)
}
