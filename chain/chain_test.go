package chain

import (
	"os"
	"testing"

	"github.com/findy-network/ic/crypto"
	"github.com/stretchr/testify/assert"
)

var (
	c Chain
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
	rootKey := crypto.NewKey()
	c = NewChain(rootKey.PubKey)
	inviteeKey := crypto.NewKey()
	level := 1
	c.AddBlock(rootKey, inviteeKey.PubKey, level)
}

func TestNewChain(t *testing.T) {
	assert.Len(t, c.blocks, 2)
}

func TestVerifyChain(t *testing.T) {
	assert.Len(t, c.blocks, 2)
	assert.True(t, c.Verify())
}
