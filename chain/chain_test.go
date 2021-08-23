package chain

import (
	"testing"

	"github.com/findy-network/ic/crypto"
	"github.com/stretchr/testify/assert"
)

func TestNewChain(t *testing.T) {
	rootKey := crypto.NewKey()
	c := NewChain(rootKey.PubKey)
	inviteeKey := crypto.NewKey()
	level := 1
	c.AddBlock(rootKey, inviteeKey.PubKey, level)
	assert.Len(t, c.blocks, 2)
}
