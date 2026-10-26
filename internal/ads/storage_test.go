package ads

import (
	"bytes"
	"errors"
	"math"
	"os"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestTamperingNeverReadsOrOverwritesInvalidCurrent(t *testing.T) {
	defer assert.PushTester(t)()
	local, other := newSigner(t), newSigner(t)
	r := local.public
	for _, tc := range []struct {
		name   string
		change func(*Current)
	}{
		{"endpoint", func(c *Current) { c.Payload.PeerIntroductionURL = "http://127.0.0.1:9/peer/introduction" }},
		{"epoch", func(c *Current) { c.Payload.Epoch = 1 }},
		{"slot", func(c *Current) { c.Payload.Slot = 2 }},
		{"device", func(c *Current) { c.Payload.Device = other.public }},
		{"Root", func(c *Current) { c.Payload.Root = other.public }},
		{"node", func(c *Current) { c.Payload.Node = other.public }},
		{"expiry", func(c *Current) { c.Payload.ExpiresUnixNano++ }},
		{"token", func(c *Current) { c.Payload.Token[0] ^= 1 }},
		{"signature", func(c *Current) { c.Signature[0] ^= 1 }},
		{"version", func(c *Current) { c.Payload.Version = 2 }},
		{"short token", func(c *Current) { c.Payload.Token = c.Payload.Token[:31] }},
		{"long token", func(c *Current) { c.Payload.Token = append(c.Payload.Token, 0) }},
		{"negative expiry", func(c *Current) { c.Payload.ExpiresUnixNano = -1 }},
		{"impossible expiry", func(c *Current) { c.Payload.ExpiresUnixNano = 1 }},
		{"empty signature", func(c *Current) { c.Signature = nil }},
		{"oversize signature", func(c *Current) { c.Signature = make([]byte, 73) }},
		{"unnormalized endpoint", func(c *Current) { c.Payload.PeerIntroductionURL = "http://localhost:8080/peer/introduction" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			try.To1(device.BootstrapLocal(f.vault, r, r, local.handle))
			current := try.To1(
				PublishLocal(f.vault, r, r, local.handle, endpoint, fixedNow),
			)
			tc.change(&current)
			try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(tx.ChildForUpdate([]byte(currentNamespace)))
				return ns.Put(
					[]byte(currentSlot),
					try.To1(wire.Marshal(current)),
				)
			}))
			assertInvalidStorage(t, f, local)
		})
	}
}

func TestMalformedEncodingAndNamespaceShape(t *testing.T) {
	defer assert.PushTester(t)()
	local := newSigner(t)
	r := local.public
	for _, name := range []string{"empty", "truncated", "trailing", "noncanonical",
		"tagged", "oversize", "missing private record", "namespace is record",
		"slot is namespace", "extra slot"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			try.To1(device.BootstrapLocal(f.vault, r, r, local.handle))
			try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				if name == "namespace is record" {
					return tx.Put(
						[]byte(currentNamespace),
						[]byte("wrong shape"),
					)
				}
				ns := try.To1(tx.EnsureChild([]byte(currentNamespace)))
				if name == "slot is namespace" {
					try.To1(ns.EnsureChild([]byte(currentSlot)))
				}
				return nil
			}))
			if name != "missing private record" &&
				name != "namespace is record" &&
				name != "slot is namespace" {
				// Get a valid signed record from a separate temporary Vault.
				other := newVault(t)
				try.To1(device.BootstrapLocal(other.vault, r, r, local.handle))
				current := try.To1(
					PublishLocal(
						other.vault,
						r,
						r,
						local.handle,
						endpoint,
						fixedNow,
					),
				)
				record := try.To1(wire.Marshal(current))
				switch name {
				case "empty":
					record = nil
				case "truncated":
					record = record[:len(record)-1]
				case "trailing":
					record = append(record, 0)
				case "noncanonical":
					// Top-level two-item array encoded with a redundant length byte.
					record = append([]byte{0x98, 0x02}, record[1:]...)
				case "tagged":
					record = append([]byte{0xc0}, record...)
				case "oversize":
					record = make([]byte, maxRecordBytes+1)
				}
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					ns := try.To1(tx.ChildForUpdate([]byte(currentNamespace)))
					try.To(ns.Put([]byte(currentSlot), record))
					if name == "extra slot" {
						try.To(ns.Put([]byte("slot-2"), record))
					}
					return nil
				}))
			}
			assertInvalidStorage(t, f, local)
		})
	}
}

func assertInvalidStorage(t *testing.T, f vaultFixture, local savedSigner) {
	t.Helper()
	defer assert.PushTester(t)()
	f.lease.remaining = 0 // Invalid storage must fail before trying to seal.
	f.unchanged(t, func() {
		for _, now := range []time.Time{fixedNow, fixedNow.Add(2 * TTL)} {
			got, found, err := ReadCurrentLocal(
				f.vault,
				local.public,
				local.public,
				now,
			)
			assert.Error(err) // Expiry never masks corruption.
			assert.DeepEqual(got, Current{})
			assert.ThatNot(found)
		}
		got, err := PublishLocal(f.vault, local.public, local.public,
			local.handle, endpoint, fixedNow)
		assert.Error(err)
		assert.ErrorIsNot(err, storage.ErrKeyUsageExhausted)
		assert.DeepEqual(got, Current{})
	})
}

func TestValidSignatureCannotBypassBindingOrVersion(t *testing.T) {
	defer assert.PushTester(t)()
	local, other := newSigner(t), newSigner(t)
	r := local.public
	f := newVault(t)
	try.To1(device.BootstrapLocal(f.vault, r, r, local.handle))
	current := try.To1(
		PublishLocal(f.vault, r, r, local.handle, endpoint, fixedNow),
	)
	for _, name := range []string{"epoch", "slot", "version", "Root", "node", "device"} {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			changed := current
			switch name {
			case "epoch":
				changed.Payload.Epoch = 1
			case "slot":
				changed.Payload.Slot = 2
			case "version":
				changed.Payload.Version = 2
			case "Root":
				changed.Payload.Root = other.public
			case "node":
				changed.Payload.Node = other.public
			case "device":
				changed.Payload.Device = other.public
			}
			digest := key.HashTagged(
				SignaturePurpose,
				try.To1(wire.Marshal(changed.Payload)),
			)
			changed.Signature = try.To1(local.handle.Sign(digest[:]))
			assert.That(changed.Signature.Verify(r, digest[:]))
			_, err := decodeCurrent(try.To1(wire.Marshal(changed)), r, r)
			assert.ErrorIs(err, ErrInvalidRecord)
		})
	}
	// An authentic record must also fail under a different caller's binding.
	f.unchanged(t, func() {
		for _, binding := range [][2]key.Public{{other.public, r}, {r, other.public}} {
			got, found, err := ReadCurrentLocal(
				f.vault,
				binding[0],
				binding[1],
				fixedNow,
			)
			assert.ErrorIs(err, ErrInvalidRecord)
			assert.ThatNot(found)
			assert.DeepEqual(got, Current{})
		}
	})
}

func TestEncryptionFailureAndRollbackPreserveCurrent(t *testing.T) {
	defer assert.PushTester(t)()
	local := newSigner(t)
	r := local.public
	cause := errors.New("injected transaction failure")
	for _, existing := range []bool{false, true} {
		for _, failure := range []string{"exhaustion", "seal failure", "rollback"} {
			t.Run(
				failure+map[bool]string{false: "/absent", true: "/present"}[existing],
				func(t *testing.T) {
					defer assert.PushTester(t)()
					f := newVault(t)
					try.To1(device.BootstrapLocal(f.vault, r, r, local.handle))
					var previous Current
					if existing {
						previous = try.To1(
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
					if failure == "rollback" {
						// Exercise the exact replacement callback, then abort after Put.
						other := newVault(t)
						try.To1(
							device.BootstrapLocal(
								other.vault,
								r,
								r,
								local.handle,
							),
						)
						candidate := try.To1(
							PublishLocal(
								other.vault,
								r,
								r,
								local.handle,
								endpoint,
								fixedNow,
							),
						)
						before := try.To1(os.ReadFile(f.path))
						remaining := f.lease.remaining
						err := f.vault.Update(
							func(tx storage.WriteTx) (err error) {
								defer err2.Handle(&err, nil)
								try.To(
									replaceCurrent(
										tx,
										r,
										r,
										candidate,
										try.To1(wire.Marshal(candidate)),
									),
								)
								return cause
							},
						)
						assert.ErrorIs(err, cause)
						assert.Equal(
							f.lease.remaining,
							remaining-1,
						) // No usage refund.
						assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
					} else {
						expected := cause
						if failure == "exhaustion" {
							f.lease.remaining = 0
							expected = storage.ErrKeyUsageExhausted
						} else {
							f.lease.sealErr = cause
						}
						f.unchanged(t, func() {
							got, err := PublishLocal(f.vault, r, r, local.handle, endpoint, fixedNow)
							assert.ErrorIs(err, expected)
							assert.DeepEqual(got, Current{})
						})
					}
					f.unchanged(t, func() {
						got, found := try.To2(
							ReadCurrentLocal(f.vault, r, r, fixedNow),
						)
						assert.Equal(found, existing)
						assert.DeepEqual(got, previous)
					})
				},
			)
		}
	}
}

func TestClockBoundsAndLocation(t *testing.T) {
	defer assert.PushTester(t)()
	local := newSigner(t)
	f := newVault(t)
	r := local.public
	try.To1(device.BootstrapLocal(f.vault, r, r, local.handle))
	for _, now := range []time.Time{
		time.Unix(0, 0), fixedNow.In(time.FixedZone("local", 2*60*60)),
		time.Unix(0, math.MaxInt64).Add(-TTL),
	} {
		published := try.To1(
			PublishLocal(f.vault, r, r, local.handle, endpoint, now),
		)
		assert.Equal(
			published.Payload.ExpiresUnixNano,
			now.UTC().Add(TTL).UnixNano(),
		)
		got, found := try.To2(ReadCurrentLocal(f.vault, r, r, now.UTC()))
		assert.That(found)
		assert.DeepEqual(got, published)
	}
	for _, now := range []time.Time{time.Time{}, time.Unix(-1, 0),
		time.Unix(0, math.MaxInt64).Add(time.Nanosecond)} {
		f.unchanged(t, func() {
			got, found, err := ReadCurrentLocal(f.vault, r, r, now)
			assert.ErrorIs(err, ErrInvalidInput)
			assert.ThatNot(found)
			assert.DeepEqual(got, Current{})
		})
	}
	_, _, err := ReadCurrentLocal(nil, r, r, fixedNow)
	assert.ErrorIs(err, ErrInvalidInput)
}

func TestReturnedPublicationOwnsItsBytes(t *testing.T) {
	defer assert.PushTester(t)()
	local := newSigner(t)
	f := newVault(t)
	r := bytes.Clone(local.public)
	try.To1(device.BootstrapLocal(f.vault, r, r, local.handle))
	current := try.To1(
		PublishLocal(f.vault, r, r, local.handle, endpoint, fixedNow),
	)
	stored := try.To1(wire.Marshal(current))
	r[0] ^= 1
	assert.DeepEqual(try.To1(wire.Marshal(current)), stored)
	current.Payload.Root[0] ^= 1
	current.Payload.Node[0] ^= 1
	current.Payload.Device[0] ^= 1
	current.Payload.Token[0] ^= 1
	current.Signature[0] ^= 1
	got, found := try.To2(
		ReadCurrentLocal(f.vault, local.public, local.public, fixedNow),
	)
	assert.That(found)
	assert.DeepEqual(try.To1(wire.Marshal(got)), stored)
}
