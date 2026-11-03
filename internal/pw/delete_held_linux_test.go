package pw

import (
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/key"
)

func TestDeleteHeldBackendCommitFailure(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUse(t)
	for _, node := range []struct {
		fixture *vaultFixture
		local   key.Public
	}{{&f.f, f.local.public}, {&f.alice, f.peer.public}} {
		before := heldTestState(t, node.fixture.vault)
		node.fixture.unchanged(t, func() {
			restore := readOnlyVaultDescriptor(t, node.fixture.path)
			deleted, err := DeleteHeldLocal(
				node.fixture.vault,
				f.root.public,
				node.local,
			)
			restore()
			assert.Equal(err, ErrDeleteHeld)
			assert.ThatNot(deleted)
		})
		node.fixture.reopen(t)
		assert.DeepEqual(heldTestState(t, node.fixture.vault), before)
		assert.That(
			try.To1(
				DeleteHeldLocal(node.fixture.vault, f.root.public, node.local),
			),
		)
	}
}
