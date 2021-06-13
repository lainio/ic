package chain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewChain(t *testing.T) {
	rootKey := Key{}
	c := NewChain(rootKey.PubKey)
	inviteeKey := Key{}
	level := 1
	c.AddBlock(rootKey, inviteeKey.PubKey, level)
	assert.Len(t, c.blocks, 2)
}
