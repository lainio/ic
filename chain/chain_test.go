package chain

import (
	"os"
	"testing"

	"github.com/findy-network/ic/crypto"
	"github.com/stretchr/testify/assert"
)

var (
	c                   Chain
	rootKey, inviteeKey *crypto.Key
)

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
}

func setup() {
	rootKey = crypto.NewKey()
	c = NewChain(rootKey.PubKey)
	inviteeKey = crypto.NewKey()
	level := 1
	c.AddBlock(rootKey, inviteeKey.PubKey, level)
}

func TestNewChain(t *testing.T) {
	assert.Len(t, c.Blocks, 2)
}

func TestRead(t *testing.T) {
	c2 := NewChainFromData(c.Bytes())
	assert.Len(t, c2.Blocks, 2)
	assert.True(t, c2.Verify())
}

func TestVerifyChain(t *testing.T) {
	assert.Len(t, c.Blocks, 2)
	assert.True(t, c.Verify())

	newInvitee := crypto.NewKey()
	level := 3
	c.AddBlock(inviteeKey, newInvitee.PubKey, level)

	assert.Len(t, c.Blocks, 3)
	assert.True(t, c.Verify())
}
