package policy

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestMalformedPolicyNeverReadsPartiallyOrRepairs(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, peer, other := newPublic(
		t,
	), newPublic(
		t,
	), newPublic(
		t,
	), newPublic(
		t,
	)
	good := deniedPeers{
		Version: 1,
		Root:    root,
		Local:   local,
		Peers:   []key.Public{peer},
	}
	raw := try.To1(wire.Marshal(good))
	cases := map[string][]byte{
		"empty": nil, "truncated": raw[:len(raw)-1],
		"trailing":     append(bytes.Clone(raw), 0),
		"noncanonical": append([]byte{0x98, 4}, raw[1:]...),
		"oversized":    make([]byte, maxDeniedBytes+1), "map": {0xa0},
		"missing field": try.To1(wire.Marshal([]any{1, root, local})),
		"extra field": try.To1(
			wire.Marshal([]any{1, root, local, good.Peers, true}),
		),
		"boolean entry": try.To1(
			wire.Marshal([]any{1, root, local, []any{true}}),
		),
		"string entry": try.To1(
			wire.Marshal([]any{1, root, local, []any{string(peer)}}),
		),
	}
	for name, change := range map[string]func(*deniedPeers){
		"version":          func(p *deniedPeers) { p.Version = 2 },
		"foreign root":     func(p *deniedPeers) { p.Root = other },
		"foreign local":    func(p *deniedPeers) { p.Local = other },
		"invalid root":     func(p *deniedPeers) { p.Root = nil },
		"null peers":       func(p *deniedPeers) { p.Peers = nil },
		"duplicate":        func(p *deniedPeers) { p.Peers = append(p.Peers, peer) },
		"over capacity":    func(p *deniedPeers) { p.Peers = slices.Repeat(p.Peers, 33) },
		"invalid key":      func(p *deniedPeers) { p.Peers = append(p.Peers, []byte{0xff}) },
		"noncanonical key": func(p *deniedPeers) { p.Peers[0] = append([]byte{0xb8, 5}, peer[1:]...) },
		"self denial":      func(p *deniedPeers) { p.Peers = []key.Public{local} },
		"unsorted": func(p *deniedPeers) {
			p.Peers = append(p.Peers, other)
			slices.SortFunc(p.Peers, func(a, b key.Public) int { return -bytes.Compare(a, b) })
		},
	} {
		var damaged deniedPeers
		try.To(wire.UnmarshalCanonical(&damaged, raw))
		change(&damaged)
		cases[name] = try.To1(wire.Marshal(damaged))
	}
	for name, damaged := range cases {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			try.To(f.vault.Update(func(tx storage.WriteTx) error {
				return tx.Put([]byte(deniedKey), damaged)
			}))
			assertRejectedPolicy(
				t,
				f,
				root,
				local,
				[]key.Public{peer, other},
				ErrInvalidRecord,
			)
			assert.That(bytes.Equal(rawPolicy(t, f.vault), damaged))
		})
	}
}

func assertRejectedPolicy(t *testing.T, f vaultFixture, root, local key.Public,
	peers []key.Public, want error,
) {
	t.Helper()
	defer assert.PushTester(t)()
	f.unchanged(t, func() {
		for _, peer := range peers {
			denied, err := IsDenied(f.vault, root, local, peer)
			assert.ThatNot(denied)
			assert.ErrorIs(err, want)
			for _, deny := range []bool{true, false} {
				changed, err := changeLocal(f.vault, root, local, peer, deny)
				assert.ThatNot(changed)
				assert.ErrorIs(err, want)
			}
			err = f.vault.View(func(tx storage.ReadTx) (err error) {
				defer err2.Handle(&err, nil)
				denied, err = IsDeniedInTx(tx, root, local, peer)
				assert.ThatNot(denied)
				return err
			})
			assert.ErrorIs(err, want)
		}
	})
}

func TestWrongNamespaceShapeFailsClosed(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, peer := newPublic(t), newPublic(t), newPublic(t)
	for _, shape := range []string{"empty", "child", "peer record"} {
		t.Run(shape, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(tx.EnsureChild([]byte(deniedKey)))
				switch shape {
				case "child":
					try.To1(ns.EnsureChild([]byte("unexpected")))
				case "peer record":
					try.To(ns.Put(peer, []byte{1}))
				}
				return nil
			}))
			assertRejectedPolicy(
				t,
				f,
				root,
				local,
				[]key.Public{peer},
				storage.ErrConflict,
			)
		})
	}
}

func TestInvalidInputsAndForeignBindings(t *testing.T) {
	defer assert.PushTester(t)()
	f := newVault(t)
	root, local, peer := newPublic(t), newPublic(t), newPublic(t)
	bad := []key.Public{nil, {}, {0xff}, {0xa0}, make([]byte, 129),
		append(bytes.Clone(peer), 0), append([]byte{0xb8, 5}, peer[1:]...)}
	for _, field := range []int{1, 3, -1, -2, -3} {
		var fields map[int]any
		try.To(wire.Unmarshal(&fields, peer))
		fields[field] = int64(0)
		if field < -1 {
			fields[field] = make([]byte, 32)
		}
		bad = append(bad, try.To1(wire.Marshal(fields)))
	}
	f.unchanged(t, func() {
		for _, operation := range []func(*storage.Vault, key.Public, key.Public, key.Public) (bool, error){
			DenyLocal, AllowLocal, IsDenied,
		} {
			ok, err := operation(nil, root, local, peer)
			assert.ThatNot(ok)
			assert.ErrorIs(err, ErrInvalidInput)
			for _, inputs := range [][3]key.Public{{root, local, local}, {root, peer, peer}} {
				ok, err := operation(f.vault, inputs[0], inputs[1], inputs[2])
				assert.ThatNot(ok)
				assert.ErrorIs(err, ErrInvalidInput)
			}
			for _, invalid := range bad {
				for _, inputs := range [][3]key.Public{{invalid, local, peer}, {root, invalid, peer}, {root, local, invalid}} {
					ok, err := operation(
						f.vault,
						inputs[0],
						inputs[1],
						inputs[2],
					)
					assert.ThatNot(ok)
					assert.ErrorIs(err, ErrInvalidInput)
				}
			}
		}
	})
	assert.That(try.To1(DenyLocal(f.vault, root, local, peer)))
	assertRejectedPolicy(
		t,
		f,
		newPublic(t),
		local,
		[]key.Public{peer},
		ErrInvalidRecord,
	)
	assertRejectedPolicy(
		t,
		f,
		root,
		newPublic(t),
		[]key.Public{peer},
		ErrInvalidRecord,
	)
}

func TestFailuresDoNotCommitOrReportSuccess(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, peer, extra := newPublic(
		t,
	), newPublic(
		t,
	), newPublic(
		t,
	), newPublic(
		t,
	)
	for _, failure := range []string{"exhaustion", "seal", "abort after Put"} {
		for _, deny := range []bool{true, false} {
			t.Run(
				failure+map[bool]string{true: "/deny", false: "/allow"}[deny],
				func(t *testing.T) {
					defer assert.PushTester(t)()
					f := newVault(t)
					assert.That(try.To1(DenyLocal(f.vault, root, local, peer)))
					want := rawPolicy(t, f.vault)
					subject := peer
					if deny {
						subject = extra
					}
					cause := errors.New("injected write failure")
					if failure == "abort after Put" {
						before, remaining := try.To1(
							os.ReadFile(f.path),
						), f.lease.remaining.Load()
						err := f.vault.Update(
							func(tx storage.WriteTx) (err error) {
								defer err2.Handle(&err, nil)
								try.To(
									changeDenied(
										tx,
										root,
										local,
										subject,
										deny,
									),
								)
								return cause
							},
						)
						assert.ErrorIs(err, cause)
						assert.Equal(f.lease.remaining.Load(), remaining-1)
						assert.DeepEqual(try.To1(os.ReadFile(f.path)), before)
					} else {
						if failure == "exhaustion" {
							f.lease.remaining.Store(0)
							cause = storage.ErrKeyUsageExhausted
						} else {
							f.lease.sealErr = cause
						}
						f.unchanged(t, func() {
							changed, err := changeLocal(f.vault, root, local, subject, deny)
							assert.ThatNot(changed)
							assert.ErrorIs(err, cause)
						})
					}
					assert.DeepEqual(rawPolicy(t, f.vault), want)
					f.reopen(t)
					assert.DeepEqual(rawPolicy(t, f.vault), want)
				},
			)
		}
	}
}

func TestClosedVaultAndInvalidLeaseFailClosed(t *testing.T) {
	defer assert.PushTester(t)()
	root, local, peer := newPublic(t), newPublic(t), newPublic(t)
	for _, closeVault := range []bool{true, false} {
		f := newVault(t)
		assert.That(try.To1(DenyLocal(f.vault, root, local, peer)))
		want := storage.ErrVaultClosed
		if closeVault {
			try.To(f.vault.Close())
		} else {
			want = storage.ErrProvider
			f.lease.checkErr = want
		}
		assertRejectedPolicy(t, f, root, local, []key.Public{peer}, want)
	}
}

func TestPolicyDiagnosticsDoNotTraceInput(t *testing.T) {
	defer assert.PushTester(t)()
	f := newVault(t)
	root, local, peer := newPublic(t), newPublic(t), newPublic(t)
	const secret = "PRIVATE_POLICY_INPUT"
	bad := try.To1(wire.Marshal(map[string]string{secret: secret}))
	try.To(f.vault.Update(func(tx storage.WriteTx) error {
		return tx.Put([]byte(deniedKey), bad)
	}))
	var trace bytes.Buffer
	previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&trace)
	err2.SetErrRetTracer(&trace)
	defer func() { err2.SetErrorTracer(previousError); err2.SetErrRetTracer(previousReturn) }()
	assertRejectedPolicy(
		t,
		f,
		root,
		local,
		[]key.Public{peer},
		ErrInvalidRecord,
	)
	_, err := DenyLocal(f.vault, root, local, bad)
	assert.ErrorIs(err, ErrInvalidInput)
	assert.ThatNot(strings.Contains(trace.String(), secret))
}
