package ads

import (
	"errors"
	"math"
	"strings"
	"testing"
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

func TestKnownAndAuthorizationGuards(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, other := newSigner(t), newSigner(t), newSigner(t)
	r, owner := root.public, local.public
	for _, stage := range []string{"absent", "choice", "received", "other Known", "known"} {
		t.Run(stage, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			if stage == "other Known" {
				try.To(ownEvidence(f.vault, root, other, "known"))
			} else if stage != "absent" {
				try.To(ownEvidence(f.vault, root, local, stage))
			}
			probe := &observedSigner{Handle: local.handle}
			f.unchanged(t, func() {
				got, err := PublishLocal(
					f.vault,
					r,
					owner,
					probe,
					endpoint,
					fixedNow,
				)
				if stage == "known" {
					assert.ErrorIs(
						err,
						ErrUnusable,
					) // Known alone cannot authorize.
				} else {
					assert.ErrorIs(err, ErrNotKnown)
				}
				assert.DeepEqual(got, Current{})
				got, found := try.To2(
					ReadCurrentLocal(f.vault, r, owner, fixedNow),
				)
				assert.ThatNot(found)
				assert.DeepEqual(got, Current{})
				assert.Equal(
					try.To1(device.InspectLocal(f.vault, r, owner, nil)),
					device.Local{},
				)
			})
			assert.Equal(probe.calls, 0)
		})
	}
	// Publication must recheck Known even after authorization, without repairing
	// a deleted marker or promoting the retained Received evidence again.
	f := newVault(t)
	try.To(ownEvidence(f.vault, root, local, "known"))
	try.To1(device.BootstrapLocal(f.vault, r, owner, local.handle))
	try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		ns := try.To1(tx.ChildForUpdate([]byte("known-introductions-v1")))
		return ns.Delete(owner)
	}))
	probe := &observedSigner{Handle: local.handle}
	f.unchanged(t, func() {
		_, err := PublishLocal(f.vault, r, owner, probe, endpoint, fixedNow)
		assert.ErrorIs(err, ErrNotKnown)
		assert.SLen(try.To1(onboarding.ListKnownIntroductions(f.vault, r)), 0)
	})
	assert.Equal(probe.calls, 0)
}

func TestInputGuardsPrecedeSigning(t *testing.T) {
	defer assert.PushTester(t)()
	local, other := newSigner(t), newSigner(t)
	f := newVault(t)
	r := local.public
	try.To1(device.BootstrapLocal(f.vault, r, r, local.handle))
	for _, value := range []string{
		"", "https://127.0.0.1:80/peer/introduction",
		"HTTP://127.0.0.1:80/peer/introduction", "http:127.0.0.1:80/peer/introduction",
		"http://example.com:80/peer/introduction", "http://192.0.2.1:80/peer/introduction",
		"http://localhost.localdomain:80/peer/introduction",
		"http://LOCALHOST:80/peer/introduction", "http://localhost.:80/peer/introduction",
		"http://127.0.0.1/peer/introduction", "http://127.0.0.1:0/peer/introduction",
		"http://127.0.0.1:+80/peer/introduction", "http://127.0.0.1:http/peer/introduction",
		"http://127.0.0.1:65536/peer/introduction", "http://127.0.0.1:/peer/introduction",
		"http://user:secret@127.0.0.1:80/peer/introduction",
		"http://127.0.0.1:80/peer%2fintroduction",
		"http://%31%32%37.0.0.1:80/peer/introduction",
		"http://[::1%25lo]:80/peer/introduction", "http://[::]:80/peer/introduction",
		"http://127.0.0.1:80//peer/introduction", "http://127.0.0.1:80/x/../peer/introduction",
		endpoint + "/", endpoint + "?", endpoint + "#", endpoint + "?x=y", endpoint + "#x",
		"http://127.0.0.1:80/?/peer/introduction", "http://127.0.0.1:80/#/peer/introduction",
		" " + endpoint, endpoint + "\n", strings.Repeat("x", maxEndpointBytes+1),
	} {
		t.Run(value, func(t *testing.T) {
			defer assert.PushTester(t)()
			probe := &observedSigner{Handle: local.handle}
			f.unchanged(t, func() {
				got, err := PublishLocal(f.vault, r, r, probe, value, fixedNow)
				assert.ErrorIs(err, ErrInvalidInput)
				assert.DeepEqual(got, Current{})
			})
			assert.Equal(probe.calls, 0)
		})
	}
	for _, tc := range []struct {
		name        string
		vault       *storage.Vault
		root, local key.Public
		now         time.Time
	}{
		{"nil Vault", nil, r, r, fixedNow},
		{"nil Root", f.vault, nil, r, fixedNow},
		{"nil local", f.vault, r, nil, fixedNow},
		{"malformed Root", f.vault, []byte{0xa0}, r, fixedNow},
		{"malformed local", f.vault, r, []byte{0xff}, fixedNow},
		{"oversize key", f.vault, make([]byte, 129), r, fixedNow},
		{"wrong Root", f.vault, other.public, r, fixedNow},
		{"wrong local", f.vault, r, other.public, fixedNow},
		{"foreign Root and local", f.vault, other.public, other.public, fixedNow},
		{"zero time", f.vault, r, r, time.Time{}},
		{"negative time", f.vault, r, r, time.Unix(-1, 0)},
		{"time overflow", f.vault, r, r, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"expiry overflow", f.vault, r, r, time.Unix(0, math.MaxInt64).Add(-TTL + 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			probe := &observedSigner{Handle: local.handle}
			f.unchanged(t, func() {
				got, err := PublishLocal(
					tc.vault,
					tc.root,
					tc.local,
					probe,
					endpoint,
					tc.now,
				)
				assert.Error(err)
				assert.DeepEqual(got, Current{})
			})
			assert.Equal(probe.calls, 0)
		})
	}
}

func TestSignerFailuresPreserveCurrent(t *testing.T) {
	defer assert.PushTester(t)()
	local, other := newSigner(t), newSigner(t)
	r := local.public
	cause := errors.New("injected signer failure")
	for _, existing := range []bool{false, true} {
		for _, name := range []string{"nil", "typed nil", "wrong signer", "unusable",
			"final failure", "final forgery", "final malformed", "signer mutates digest"} {
			t.Run(
				name+map[bool]string{false: "/absent", true: "/present"}[existing],
				func(t *testing.T) {
					defer assert.PushTester(t)()
					f := newVault(t)
					try.To1(device.BootstrapLocal(f.vault, r, r, local.handle))
					if existing {
						try.To1(
							PublishLocal(
								f.vault,
								r,
								r,
								local.handle,
								endpoint,
								fixedNow,
							),
						)
					}
					before := try.To1(
						records(
							f.vault,
							currentNamespace,
							"local-device-auth-v1",
						),
					)
					signer := key.Handle(&observedSigner{Handle: local.handle,
						sign: func(call int, data []byte) ([]byte, error) {
							if name == "unusable" ||
								call == 2 && name == "final failure" {
								return []byte("partial signature"), cause
							}
							if call == 2 {
								switch name {
								case "final forgery":
									return other.handle.Sign(data)
								case "final malformed":
									return []byte("invalid"), nil
								case "signer mutates digest":
									data[0] ^= 1
								}
							}
							return local.handle.Sign(data)
						}})
					switch name {
					case "nil":
						signer = nil
					case "typed nil":
						signer = (*observedSigner)(nil)
					case "wrong signer":
						signer = other.handle
					}
					f.unchanged(t, func() {
						got, err := PublishLocal(
							f.vault,
							r,
							r,
							signer,
							endpoint,
							fixedNow,
						)
						assert.Error(err)
						if name == "final failure" {
							assert.ErrorIs(err, cause)
						}
						assert.DeepEqual(got, Current{})
						_, found := try.To2(
							ReadCurrentLocal(f.vault, r, r, fixedNow),
						)
						assert.Equal(found, existing)
					})
					assert.DeepEqual(try.To1(records(f.vault, currentNamespace,
						"local-device-auth-v1")), before)
				},
			)
		}
	}
}

func TestPublicKeyValidation(t *testing.T) {
	defer assert.PushTester(t)()
	local := newSigner(t)
	f := newVault(t)
	var public map[int]any
	try.To(wire.Unmarshal(&public, local.public))
	for _, field := range []int{1, 3, -1, -2, -3} {
		t.Run(
			map[int]string{1: "type", 3: "algorithm", -1: "curve", -2: "x", -3: "y"}[field],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				var changed map[int]any
				try.To(wire.Unmarshal(&changed, local.public))
				changed[field] = int64(0)
				if field < -1 {
					changed[field] = make([]byte, 32)
				}
				invalid := key.Public(try.To1(wire.Marshal(changed)))
				probe := &observedSigner{Handle: local.handle}
				f.unchanged(t, func() {
					_, err := PublishLocal(
						f.vault,
						invalid,
						local.public,
						probe,
						endpoint,
						fixedNow,
					)
					assert.ErrorIs(err, ErrInvalidInput)
					_, _, err = ReadCurrentLocal(
						f.vault,
						invalid,
						local.public,
						fixedNow,
					)
					assert.ErrorIs(err, ErrInvalidInput)
				})
				assert.Equal(probe.calls, 0)
			},
		)
	}
}
