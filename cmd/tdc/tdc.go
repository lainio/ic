package main

import (
	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/cmds"
	_ "github.com/lainio/ic/cmds/domain"
	_ "github.com/lainio/ic/cmds/id"
)

func main() {
	assert.SetDefault(assert.Plain)

	cmds.Execute()
}
