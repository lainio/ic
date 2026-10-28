package ads

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// Share the existing encrypted Bolt/finite-lease fixture with external tests
// that import peerapi. These symbols exist only in the ads test build.
type TestVault = vaultFixture

func NewTestVault(t *testing.T) TestVault                { return newVault(t) }
func (f vaultFixture) Vault() *storage.Vault             { return f.vault }
func (f vaultFixture) Remaining() int                    { return f.lease.remaining }
func (f vaultFixture) SetRemaining(n int)                { f.lease.remaining = n }
func (f vaultFixture) SetSealError(err error)            { f.lease.sealErr = err }
func (f vaultFixture) Unchanged(t *testing.T, fn func()) { f.unchanged(t, fn) }

func ProofDigestForTest(root, subject key.Public, ad, nonce []byte) (key.Hash, error) {
	return currentProofDigest(root, subject, ad, nonce)
}

func (f *vaultFixture) Reopen(t *testing.T) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(f.db.Close())
	f.db = try.To1(storage.OpenBolt(f.path))
	db := f.db
	t.Cleanup(func() { assert.NoError(db.Close()) })
	f.vault = try.To1(f.db.OpenVault(t.Context(), storage.VaultID{1}, storage.KeyID{7}, f.lease))
}
