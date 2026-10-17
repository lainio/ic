package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/storage"
)

func TestRunPersistence(t *testing.T) {
	defer assert.PushTester(t)()
	parent := t.TempDir()
	var output bytes.Buffer
	input := "get\nput hello\nget\nput replacement\nreopen\nget\n"
	try.To(run(strings.NewReader(input), &output, parent))
	assert.Equal(output.String(), sessionNotice+"\n"+
		"> not found\n> ok\n> hello\n> ok\n> reopened\n> replacement\n> ")
	assert.SLen(try.To1(os.ReadDir(parent)), 0)
}

func TestRunCommandErrorsAndQuit(t *testing.T) {
	defer assert.PushTester(t)()
	var output bytes.Buffer
	input := "put\nget extra\nreopen extra\nhelp extra\nquit extra\nunknown\n\n" +
		"put  \"hello\"\\world \nget\nput \nget\nquit\nput ignored\n"
	try.To(run(strings.NewReader(input), &output, t.TempDir()))
	assert.Equal(output.String(), sessionNotice+"\n"+
		"> error: put: use put TEXT\n"+
		"> error: get: takes no arguments\n"+
		"> error: reopen: takes no arguments\n"+
		"> error: help: takes no arguments\n"+
		"> error: quit: takes no arguments\n"+
		"> error: unknown command \"unknown\"; use help\n"+
		"> > ok\n>  \"hello\"\\world \n> ok\n> \n> ")
}

func TestRunHelp(t *testing.T) {
	defer assert.PushTester(t)()
	var output bytes.Buffer
	try.To(run(strings.NewReader("help\n"), &output, t.TempDir()))
	assert.Equal(output.String(), sessionNotice+"\n"+
		"> put TEXT  store TEXT as the greeting\n"+
		"get       read the greeting\n"+
		"reopen    close and reopen this session's database\n"+
		"help      show commands and session boundary\n"+
		"quit      exit (EOF also exits)\n"+sessionNotice+"\n> ")
}

func TestRunIndependentSessionsAndCleanup(t *testing.T) {
	defer assert.PushTester(t)()
	parent := t.TempDir()
	callerFile := filepath.Join(parent, "caller.txt")
	try.To(os.WriteFile(callerFile, []byte("keep"), 0600))
	for _, text := range []string{"first", "second"} {
		var output bytes.Buffer
		input := "get\nput " + text + "\nget\nquit\n"
		try.To(run(strings.NewReader(input), &output, parent))
		assert.Equal(output.String(), sessionNotice+"\n"+
			"> not found\n> ok\n> "+text+"\n> ")
		entries := try.To1(os.ReadDir(parent))
		assert.SLen(entries, 1)
		assert.Equal(entries[0].Name(), "caller.txt")
		assert.Equal(string(try.To1(os.ReadFile(callerFile))), "keep")
	}
}

func TestRunInputError(t *testing.T) {
	defer assert.PushTester(t)()
	parent := t.TempDir()
	inputErr := errors.New("input failed")
	input := io.MultiReader(strings.NewReader("put goodbye\n"), iotest.ErrReader(inputErr))
	var output bytes.Buffer
	err := run(input, &output, parent)
	assert.ErrorIs(err, inputErr)
	assert.That(strings.Contains(err.Error(), "reading input"))
	assert.Equal(output.String(), sessionNotice+"\n> ok\n> ")
	assert.SLen(try.To1(os.ReadDir(parent)), 0)
}

func TestDemoProviderSharedConsumption(t *testing.T) {
	defer assert.PushTester(t)()
	p := newDemoProvider()
	defer clear(p.secret)
	assert.Equal(p.remainingEncryptions, uint32(1<<24))
	p.remainingEncryptions = 2 // Tiny private test policy, set before use.
	ctx := context.Background()
	first := try.To1(p.Acquire(ctx, p.vault, p.id))
	second := try.To1(p.Acquire(ctx, p.vault, p.id))
	try.To(first.ConsumeEncryption())
	try.To(first.Release())
	reacquired := try.To1(p.Acquire(ctx, p.vault, p.id))
	assert.Equal(p.remainingEncryptions, uint32(1))
	try.To(second.ConsumeEncryption())
	assert.ErrorIs(reacquired.ConsumeEncryption(), storage.ErrKeyUsageExhausted)
	try.To(second.Release())
	try.To(reacquired.Release())
	afterExhaustion := try.To1(p.Acquire(ctx, p.vault, p.id))
	try.To(afterExhaustion.Check()) // Exhaustion does not deny reads.
	assert.SLen(afterExhaustion.Secret(), 32)
	assert.ErrorIs(afterExhaustion.ConsumeEncryption(), storage.ErrKeyUsageExhausted)
	try.To(afterExhaustion.Release())
	assert.Equal(p.remainingEncryptions, uint32(0))

	lease, err := p.Acquire(ctx, storage.VaultID{2}, p.id)
	assert.INil(lease)
	assert.ErrorIs(err, storage.ErrProvider)
	lease, err = p.Acquire(ctx, p.vault, storage.KeyID{8})
	assert.INil(lease)
	assert.ErrorIs(err, storage.ErrProvider)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	lease, err = p.Acquire(canceled, p.vault, p.id)
	assert.INil(lease)
	assert.ErrorIs(err, context.Canceled)
}
