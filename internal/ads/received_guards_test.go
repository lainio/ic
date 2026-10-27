package ads

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestReceiveClaimMalformedInputNeverWrites(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer, other := newSigner(t), newSigner(t), newSigner(t)
	good := claimBytes(t, root.public, peer.public)
	cases := malformedClaims(t, good, other.public)
	for _, existing := range []bool{false, true} {
		f := newVault(t)
		if existing {
			assert.That(try.To1(ReceiveClaim(f.vault, root.public, peer.public, good)))
		}
		f.lease.remaining = 0 // All failures must precede any encryption attempt.
		for name, ad := range cases {
			t.Run(name+map[bool]string{false: "/absent", true: "/present"}[existing], func(t *testing.T) {
				defer assert.PushTester(t)()
				f.unchanged(t, func() {
					changed, err := ReceiveClaim(f.vault, root.public, peer.public, ad)
					assert.ThatNot(changed)
					assert.ErrorIs(err, ErrInvalidClaim)
					var want []byte
					if existing {
						want = good
					}
					readClaim(t, f.vault, root.public, peer.public, want)
				})
			})
		}
	}
}

func malformedClaims(t *testing.T, good []byte, other key.Public) map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	cases := map[string][]byte{
		"empty": nil, "truncated": good[:len(good)-1],
		"trailing":     append(bytes.Clone(good), 0),
		"noncanonical": append([]byte{0x98, 0x02}, good[1:]...),
		"tagged":       append([]byte{0xc0}, good...), "oversize": make([]byte, maxRecordBytes+1),
		"map": {0xa0}, "null": {0xf6}, "wrong field type": {0x82, 0x01, 0x01},
		"indefinite": append(append([]byte{0x9f}, good[1:]...), 0xff),
	}
	for name, change := range map[string]func(*Current){
		"version":            func(c *Current) { c.Payload.Version = 2 },
		"slot":               func(c *Current) { c.Payload.Slot = 2 },
		"zero slot":          func(c *Current) { c.Payload.Slot = 0 },
		"epoch":              func(c *Current) { c.Payload.Epoch = 1 },
		"Root":               func(c *Current) { c.Payload.Root = other },
		"subject":            func(c *Current) { c.Payload.Node = other },
		"device":             func(c *Current) { c.Payload.Device = other },
		"empty token":        func(c *Current) { c.Payload.Token = nil },
		"short token":        func(c *Current) { c.Payload.Token = c.Payload.Token[:31] },
		"long token":         func(c *Current) { c.Payload.Token = append(c.Payload.Token, 0) },
		"negative expiry":    func(c *Current) { c.Payload.ExpiresUnixNano = -1 },
		"missing Root":       func(c *Current) { c.Payload.Root = nil },
		"short subject":      func(c *Current) { c.Payload.Node = c.Payload.Node[:14] },
		"malformed device":   func(c *Current) { c.Payload.Device = []byte{0xa0} },
		"empty signature":    func(c *Current) { c.Signature = nil },
		"oversize signature": func(c *Current) { c.Signature = make([]byte, 73) },
	} {
		cases[name] = changeClaim(t, good, change)
	}
	for i, endpoint := range []string{
		"", "http://localhost:8080/peer/introduction", "http://127.0.0.1:08080/peer/introduction",
		"https://127.0.0.1:80/peer/introduction", "http://127.0.0.1:0/peer/introduction",
		"http://192.0.2.1:80/peer/introduction", "http://example.com:80/peer/introduction",
		"http://127.0.0.1:80/peer/ad", "http://127.0.0.1:65536/peer/introduction",
		"http://[::1%25lo]:80/peer/introduction", "http://[::ffff:127.0.0.1]:80/peer/introduction",
		"http://127.0.0.1/peer/introduction", "http://user:secret@127.0.0.1:80/peer/introduction",
		endpoint + "?", endpoint + "#", endpoint + "/", strings.Repeat("x", maxEndpointBytes+1),
	} {
		cases["endpoint/"+string(rune('a'+i))] = changeClaim(t, good, func(c *Current) {
			c.Payload.PeerIntroductionURL = endpoint
		})
	}
	var fields []any
	try.To(wire.Unmarshal(&fields, good))
	cases["missing signature field"] = try.To1(wire.Marshal(fields[:1]))
	cases["extra field"] = try.To1(wire.Marshal(append(fields, uint64(0))))
	payload := fields[0].([]any)
	cases["missing payload field"] = try.To1(wire.Marshal([]any{payload[:len(payload)-1], fields[1]}))
	cases["extra payload field"] = try.To1(wire.Marshal([]any{append(payload, uint64(0)), fields[1]}))
	return cases
}

func TestReceiveClaimIndependentIdentityAndCompletePublicKeys(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer, other := newSigner(t), newSigner(t), newSigner(t)
	f := newVault(t)
	good := claimBytes(t, root.public, peer.public)
	for _, tc := range []struct {
		name          string
		vault         *storage.Vault
		root, subject key.Public
	}{
		{"nil Vault", nil, root.public, peer.public},
		{"nil Root", f.vault, nil, peer.public},
		{"nil subject", f.vault, root.public, nil},
		{"wrong Root", f.vault, other.public, peer.public},
		{"wrong subject", f.vault, root.public, other.public},
		{"truncated Root", f.vault, root.public[:14], peer.public},
		{"truncated subject", f.vault, root.public, peer.public[:14]},
		{"oversize key", f.vault, root.public, make([]byte, maxPublicBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f.unchanged(t, func() {
				changed, err := ReceiveClaim(tc.vault, tc.root, tc.subject, good)
				assert.ThatNot(changed)
				assert.ErrorIs(err, ErrInvalidClaim)
			})
		})
	}
	// Even a matching input/ad key must be a complete, canonical P-256 point.
	for name, invalid := range malformedClaimKeys(t, peer.public) {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f.unchanged(t, func() {
				for _, asRoot := range []bool{false, true} {
					r, subject := root.public, peer.public
					if asRoot {
						r = invalid
					} else {
						subject = invalid
					}
					changed, err := ReceiveClaim(f.vault, r, subject, claimBytes(t, r, subject))
					assert.ThatNot(changed)
					assert.ErrorIs(err, ErrInvalidClaim)
					ad, found, err := ReadReceivedClaim(f.vault, r, subject)
					assert.SNil(ad)
					assert.ThatNot(found)
					assert.ErrorIs(err, ErrInvalidClaim)
				}
			})
		})
	}
	f.unchanged(t, func() { readClaim(t, f.vault, root.public, peer.public, nil) })
}

func malformedClaimKeys(t *testing.T, good key.Public) map[string]key.Public {
	t.Helper()
	defer assert.PushTester(t)()
	cases := map[string]key.Public{
		"nil": nil, "empty map": {0xa0}, "noncanonical key": append([]byte{0xb8, 0x05}, good[1:]...),
		"trailing key": append(bytes.Clone(good), 0), "oversize key": make([]byte, maxPublicBytes+1),
	}
	for _, field := range []int{1, 3, -1, -2, -3} {
		var fields map[int]any
		try.To(wire.Unmarshal(&fields, good))
		delete(fields, field)
		name := map[int]string{1: "type", 3: "algorithm", -1: "curve", -2: "x", -3: "y"}[field]
		cases["missing "+name] = try.To1(wire.Marshal(fields))
		fields[field] = int64(0)
		if field < -1 {
			fields[field] = make([]byte, 32)
		}
		cases["invalid "+name] = try.To1(wire.Marshal(fields))
	}
	return cases
}

func TestReceivedClaimErrorsDoNotDiscloseInput(t *testing.T) {
	defer assert.PushTester(t)()
	root, peer := newSigner(t), newSigner(t)
	f := newVault(t)
	var trace bytes.Buffer
	previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&trace)
	err2.SetErrRetTracer(&trace)
	defer func() { err2.SetErrorTracer(previousError); err2.SetErrRetTracer(previousReturn) }()
	const secret = "UNTRUSTED_PRIVATE_VALUE"
	for _, address := range []string{secret, "127.0.0.1:" + secret, "127.0.0.1:999999999999"} {
		ad := changeClaim(t, claimBytes(t, root.public, peer.public), func(c *Current) {
			c.Payload.PeerIntroductionURL = "http://" + address + "/peer/introduction"
		})
		_, err := ReceiveClaim(f.vault, root.public, peer.public, ad)
		assert.ErrorIs(err, ErrInvalidClaim)
		assert.ThatNot(strings.Contains(err.Error(), address))
		assert.ThatNot(strings.Contains(trace.String(), address))
	}
}
