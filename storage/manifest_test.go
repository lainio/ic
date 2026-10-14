package storage

import (
	"bytes"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage/internal/engine"
	"github.com/lainio/ic/storage/internal/record"
)

var errManifestAllowance = errors.New("test manifest allowance exhausted")

// Test-only preallocated allowance: no provider, persistence, or lifetime claim.
type manifestGate struct {
	mu               sync.Mutex
	remaining, calls int
}

func (g *manifestGate) spend() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls++
	if g.remaining == 0 {
		return errManifestAllowance
	}
	g.remaining--
	return nil
}

func manifestSecret(t *testing.T) []byte {
	t.Helper()
	secret := make([]byte, 32)
	try.To1(rand.Read(secret))
	t.Cleanup(func() { clear(secret) })
	return secret
}

func manifestScope(t *testing.T, secret []byte, vault, id [16]byte, gate *manifestGate) *record.Scope {
	t.Helper()
	scope := try.To1(record.Derive(secret, vault, id, gate.spend))
	t.Cleanup(scope.Clear) // All work in this suite is synchronous and drained.
	return scope
}

func openManifestBolt(t *testing.T, path string) engine.Engine {
	t.Helper()
	db := try.To1(engine.OpenBolt(path))
	t.Cleanup(func() {
		defer assert.PushTester(t)()
		assert.NoError(db.Close())
	})
	return db
}

func TestVaultManifest(t *testing.T) {
	for _, backend := range []struct {
		name string
		open func(*testing.T) engine.Engine
	}{
		{"memory", func(t *testing.T) engine.Engine {
			db := engine.NewMemory()
			t.Cleanup(func() {
				defer assert.PushTester(t)()
				assert.NoError(db.Close())
			})
			return db
		}},
		{"bbolt", func(t *testing.T) engine.Engine {
			return openManifestBolt(t, filepath.Join(t.TempDir(), "manifest.db"))
		}},
	} {
		t.Run(backend.name, func(t *testing.T) {
			runManifestTests(t, backend.open)
		})
	}
}

func runManifestTests(t *testing.T, open func(*testing.T) engine.Engine) {
	t.Helper()
	t.Run("create_verify_and_duplicate", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		id := [16]byte{3}
		vaults := [][16]byte{{1}, {2}}
		var scopes []*record.Scope
		var gates []*manifestGate
		var envelopes [][]byte
		try.To(db.Update(func(root engine.WriteTx) error {
			return root.Put([]byte("root"), []byte("original"))
		}))
		for _, vault := range vaults {
			gate := &manifestGate{remaining: 1}
			scope := manifestScope(t, manifestSecret(t), vault, id, gate)
			scopes, gates = append(scopes, scope), append(gates, gate)
			// Returning the helper's error is required to abort the Update.
			try.To(db.Update(func(root engine.WriteTx) error {
				return createVaultState(root, scope, vault, id)
			}))
			envelopes = append(envelopes, readManifest(t, db, scope, vault))
			assert.Equal(gate.calls, 1)
			assert.Equal(gate.remaining, 0)
		}
		for i, vault := range vaults {
			scope, gate := scopes[i], gates[i]
			try.To(db.View(func(root engine.ReadTx) error {
				return verifyVaultState(root, scope, vault, id)
			}))
			assert.Equal(db.Update(func(root engine.WriteTx) error {
				return createVaultState(root, scope, vault, id)
			}), errVaultExists)
			assert.Equal(bytes.Equal(readManifest(t, db, scope, vault), envelopes[i]), true)
			assert.Equal(gate.calls, 1, "verification and duplicate creation never spend")
		}
		checkManifestRoot(t, db)
	})
	t.Run("rollback_and_allowance", func(t *testing.T) {
		defer assert.PushTester(t)()
		db := open(t)
		vault, id := [16]byte{1}, [16]byte{2}
		deniedGate := &manifestGate{}
		denied := manifestScope(t, manifestSecret(t), vault, id, deniedGate)
		err := db.Update(func(root engine.WriteTx) error {
			return createVaultState(root, denied, vault, id)
		})
		assert.ErrorIs(err, errManifestAllowance)
		assert.ThatNot(errors.Is(err, errVaultManifest))
		try.To(db.View(func(root engine.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			assert.ThatNot(try.To1(root.HasChild([]byte("vaults"))))
			return nil
		}))

		gate := &manifestGate{remaining: 1}
		scope := manifestScope(t, manifestSecret(t), vault, id, gate)
		try.To(db.Update(func(root engine.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			try.To(root.Put([]byte("root"), []byte("original")))
			return createVaultState(root, scope, vault, id)
		}))
		original := readManifest(t, db, scope, vault)
		other := [16]byte{3}
		otherGate := &manifestGate{remaining: 1}
		otherScope := manifestScope(t, manifestSecret(t), other, id, otherGate)
		stop := errors.New("callback fails after successful creation")
		assert.Equal(db.Update(func(root engine.WriteTx) (err error) {
			defer err2.Handle(&err, nil)
			try.To(createVaultState(root, otherScope, other, id))
			try.To(root.Put([]byte("root"), []byte("pending")))
			return stop
		}), stop)
		assert.Equal(otherGate.calls, 1)
		assert.Equal(otherGate.remaining, 0, "rollback must not refund a seal")
		// Retry with the same exhausted allowance: no newly created Vault remains.
		assert.ErrorIs(db.Update(func(root engine.WriteTx) error {
			return createVaultState(root, otherScope, other, id)
		}), errManifestAllowance)
		assert.Equal(otherGate.calls, 2)
		otherScope.Clear()
		assert.Equal(db.Update(func(root engine.WriteTx) error {
			return createVaultState(root, otherScope, other, id)
		}), record.ErrCleared, "creation preserves operational codec failures")
		assert.Equal(otherGate.calls, 2)
		try.To(db.View(func(root engine.ReadTx) (err error) {
			defer err2.Handle(&err, nil)
			collection := try.To1(root.Child([]byte("vaults")))
			assert.ThatNot(try.To1(collection.HasChild(other[:])))
			return verifyVaultState(root, scope, vault, id)
		}))
		assert.Equal(bytes.Equal(readManifest(t, db, scope, vault), original), true)
		checkManifestRoot(t, db)
		scope.Clear()
		var expired engine.ReadTx
		assert.Equal(db.View(func(root engine.ReadTx) error {
			expired = root
			return verifyVaultState(root, scope, vault, id)
		}), record.ErrCleared, "verification preserves operational codec failures")
		assert.Equal(verifyVaultState(expired, scope, vault, id), engine.ErrTxClosed)
	})
	t.Run("missing_and_wrong_kind", func(t *testing.T) {
		vault, id := [16]byte{1}, [16]byte{2}
		for _, tc := range []struct {
			name        string
			depth       int // Existing children in vaults / VaultID / metadata.
			record      bool
			want        error
			vaultExists bool
		}{
			{"absent_collection", 0, false, errVaultNotFound, false},
			{"absent_vault", 1, false, errVaultNotFound, false},
			{"empty_vault", 2, false, errVaultManifest, true},
			{"missing_manifest", 3, false, errVaultManifest, true},
			{"empty_manifest", 3, true, errVaultManifest, true},
			{"collection_record", 0, true, engine.ErrConflict, false},
			{"vault_record", 1, true, engine.ErrConflict, false},
			{"metadata_record", 2, true, engine.ErrConflict, true},
			{"token_child", 4, false, engine.ErrConflict, true},
		} {
			t.Run(tc.name, func(t *testing.T) {
				defer assert.PushTester(t)()
				db := open(t)
				gate := &manifestGate{}
				scope := manifestScope(t, manifestSecret(t), vault, id, gate)
				token := try.To1(scope.Token([][]byte{{3}}, []byte("manifest")))
				path := [][]byte{[]byte("vaults"), vault[:], {3}, token[:]}
				try.To(db.Update(func(root engine.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					try.To(root.Put([]byte("root"), []byte("original")))
					var ns engine.WriteNS = root
					for _, name := range path[:tc.depth] {
						ns = try.To1(ns.EnsureChild(name))
					}
					if tc.record {
						return ns.Put(path[tc.depth], nil)
					}
					return nil
				}))
				err := db.View(func(root engine.ReadTx) error {
					return verifyVaultState(root, scope, vault, id)
				})
				assert.ErrorIs(err, tc.want)
				if tc.want == engine.ErrConflict {
					assert.Equal(err, tc.want, "wrong-kind errors remain engine errors")
				}
				if tc.vaultExists || tc.want == engine.ErrConflict {
					want := engine.ErrConflict
					if tc.vaultExists {
						want = errVaultExists
					}
					assert.Equal(db.Update(func(root engine.WriteTx) error {
						return createVaultState(root, scope, vault, id)
					}), want, "existing state is never repaired, even if malformed")
				}
				try.To(db.View(func(root engine.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					var ns engine.ReadNS = root
					for _, name := range path[:tc.depth] {
						ns = try.To1(ns.Child(name))
					}
					if tc.record {
						value, found := try.To2(ns.Get(path[tc.depth]))
						assert.That(found)
						assert.SLen(value, 0)
					} else if tc.depth < 3 {
						assert.ThatNot(try.To1(ns.HasChild(path[tc.depth])))
					} else if tc.depth == 3 {
						_, found := try.To2(ns.Get(token[:]))
						assert.ThatNot(found)
					}
					return nil
				}))
				assert.Equal(gate.calls, 0)
				checkManifestRoot(t, db)
			})
		}
	})
	t.Run("authentication", func(t *testing.T) {
		for _, name := range []string{"tampered", "wrong_secret", "wrong_generation", "relocated"} {
			t.Run(name, func(t *testing.T) {
				defer assert.PushTester(t)()
				db := open(t)
				vault, id := [16]byte{1}, [16]byte{2}
				secret := manifestSecret(t)
				gate := &manifestGate{remaining: 1}
				scope := manifestScope(t, secret, vault, id, gate)
				try.To(db.Update(func(root engine.WriteTx) error {
					return createVaultState(root, scope, vault, id)
				}))
				envelope := readManifest(t, db, scope, vault)
				targetVault, targetID, targetSecret := vault, id, secret
				switch name {
				case "tampered":
					envelope[len(envelope)-1] ^= 1
				case "wrong_secret":
					targetSecret = manifestSecret(t)
				case "wrong_generation":
					targetID[0]++
				case "relocated":
					targetVault[0]++
				}
				readGate := &manifestGate{}
				target := manifestScope(t, targetSecret, targetVault, targetID, readGate)
				if name == "wrong_secret" || name == "wrong_generation" {
					assert.Equal(db.View(func(root engine.ReadTx) error {
						return verifyVaultState(root, target, targetVault, targetID)
					}), errVaultManifest, "only the externally expected token is looked up")
				}
				token := try.To1(target.Token([][]byte{{3}}, []byte("manifest")))
				// Place hostile bytes at the expected token to exercise full Open,
				// including relocation across Vaults with the same secret/generation.
				try.To(db.Update(func(root engine.WriteTx) error {
					return putManifestFixture(root, targetVault, token, envelope)
				}))
				_, _, cause := target.Open([][]byte{{3}}, token, []byte("manifest"), envelope)
				assert.Error(cause)
				err := db.View(func(root engine.ReadTx) error {
					return verifyVaultState(root, target, targetVault, targetID)
				})
				assert.ErrorIs(err, errVaultManifest)
				assert.ErrorIs(err, cause, "codec verification cause must survive composition")
				try.To(db.View(func(root engine.ReadTx) (err error) {
					defer err2.Handle(&err, nil)
					collection := try.To1(root.Child([]byte("vaults")))
					state := try.To1(collection.Child(targetVault[:]))
					metadata := try.To1(state.Child([]byte{3}))
					stored, found := try.To2(metadata.Get(token[:]))
					assert.That(found)
					assert.Equal(bytes.Equal(stored, envelope), true, "verification never repairs bytes")
					return nil
				}))
				if name != "tampered" {
					try.To(db.View(func(root engine.ReadTx) error {
						return verifyVaultState(root, scope, vault, id)
					}))
				}
				assert.Equal(gate.calls, 1)
				assert.Equal(readGate.calls, 0)
			})
		}
	})
	t.Run("authenticated_invalid_payload", func(t *testing.T) {
		for _, name := range []string{"version", "vault", "key_id", "short", "long"} {
			t.Run(name, func(t *testing.T) {
				defer assert.PushTester(t)()
				db := open(t)
				vault, id := [16]byte{1}, [16]byte{2}
				gate := &manifestGate{remaining: 1}
				scope := manifestScope(t, manifestSecret(t), vault, id, gate)
				value := make([]byte, 33)
				value[0] = 1
				copy(value[1:17], vault[:])
				copy(value[17:], id[:])
				switch name {
				case "version":
					value[0]++
				case "vault":
					value[1]++
				case "key_id":
					value[17]++
				case "short":
					value = value[:32]
				case "long":
					value = append(value, 0)
				}
				path, key := [][]byte{{3}}, []byte("manifest")
				token := try.To1(scope.Token(path, key))
				envelope := try.To1(scope.Seal(path, key, value))
				openedKey, openedValue := try.To2(scope.Open(path, token, key, envelope))
				assert.Equal(string(openedKey), "manifest")
				assert.Equal(bytes.Equal(openedValue, value), true, "full record opening succeeds")
				try.To(db.Update(func(root engine.WriteTx) error {
					return putManifestFixture(root, vault, token, envelope)
				}))
				assert.Equal(db.View(func(root engine.ReadTx) error {
					return verifyVaultState(root, scope, vault, id)
				}), errVaultManifest)
				assert.Equal(gate.calls, 1)
				assert.Equal(gate.remaining, 0)
			})
		}
	})
}

func putManifestFixture(root engine.WriteTx, vault [16]byte, token [32]byte, envelope []byte) (err error) {
	defer err2.Handle(&err, nil)
	collection := try.To1(root.EnsureChild([]byte("vaults")))
	state := try.To1(collection.EnsureChild(vault[:]))
	metadata := try.To1(state.EnsureChild([]byte{3}))
	return metadata.Put(token[:], envelope)
}

func TestVaultManifestReopen(t *testing.T) {
	defer assert.PushTester(t)()
	path := filepath.Join(t.TempDir(), "manifest.db")
	db := openManifestBolt(t, path)
	vault, rolledBack, id := [16]byte{1}, [16]byte{2}, [16]byte{3}
	secret, otherSecret := manifestSecret(t), manifestSecret(t)
	gate, otherGate := &manifestGate{remaining: 1}, &manifestGate{remaining: 1}
	scope := manifestScope(t, secret, vault, id, gate)
	other := manifestScope(t, otherSecret, rolledBack, id, otherGate)
	try.To(db.Update(func(root engine.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(root.Put([]byte("root"), []byte("original")))
		return createVaultState(root, scope, vault, id)
	}))
	original := readManifest(t, db, scope, vault)
	stop := errors.New("rollback before reopen")
	assert.Equal(db.Update(func(root engine.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To(createVaultState(root, other, rolledBack, id))
		return stop
	}), stop)
	try.To(db.Close())
	scope.Clear()
	other.Clear()

	reopened := openManifestBolt(t, path)
	fresh := manifestScope(t, secret, vault, id, gate)
	freshOther := manifestScope(t, otherSecret, rolledBack, id, otherGate)
	assert.Equal(gate.remaining, 0)
	assert.Equal(otherGate.remaining, 0)
	try.To(reopened.View(func(root engine.ReadTx) error {
		return verifyVaultState(root, fresh, vault, id)
	}))
	assert.Equal(reopened.View(func(root engine.ReadTx) error {
		return verifyVaultState(root, freshOther, rolledBack, id)
	}), errVaultNotFound)
	try.To(reopened.View(func(root engine.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		collection := try.To1(root.Child([]byte("vaults")))
		assert.ThatNot(try.To1(collection.HasChild(rolledBack[:])))
		return nil
	}))
	assert.Equal(bytes.Equal(readManifest(t, reopened, fresh, vault), original), true)
	assert.Equal(gate.calls, 1)
	assert.Equal(otherGate.calls, 1, "reopen and verification need no new allowance")
	checkManifestRoot(t, reopened)
}

// Inspect the explicit layout independently of production constants. Full Open
// also establishes that the stored envelope contains the expected manifest.
func readManifest(t *testing.T, db engine.Engine, scope *record.Scope, vault [16]byte) []byte {
	t.Helper()
	var envelope []byte
	try.To(db.View(func(root engine.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		collection := try.To1(root.Child([]byte("vaults")))
		state := try.To1(collection.Child(vault[:]))
		assert.ThatNot(try.To1(state.HasChild([]byte{1})))
		assert.ThatNot(try.To1(state.HasChild([]byte{2})))
		metadata := try.To1(state.Child([]byte{3}))
		token := try.To1(scope.Token([][]byte{{3}}, []byte("manifest")))
		var found bool
		envelope, found = try.To2(metadata.Get(token[:]))
		assert.That(found)
		key, value := try.To2(scope.Open([][]byte{{3}}, token, []byte("manifest"), envelope))
		assert.Equal(string(key), "manifest")
		assert.SLen(value, 33)
		assert.Equal(value[0], byte(1))
		assert.Equal([16]byte(value[1:17]), vault)
		assert.ThatNot(bytes.Equal(envelope, value))
		assert.ThatNot(bytes.Contains(envelope, value))
		count := 0
		try.To(metadata.Each(func(key, value []byte) error {
			count++
			assert.SLen(key, 32)
			assert.Equal([32]byte(key), token)
			assert.Equal(bytes.Equal(value, envelope), true)
			return nil
		}))
		assert.Equal(count, 1)
		return nil
	}))
	return envelope
}

func checkManifestRoot(t *testing.T, db engine.Engine) {
	t.Helper()
	try.To(db.View(func(root engine.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		value, found := try.To2(root.Get([]byte("root")))
		assert.That(found)
		assert.Equal(string(value), "original")
		return nil
	}))
}
