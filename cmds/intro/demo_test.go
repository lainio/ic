package intro

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/cmds"
	coreintro "github.com/lainio/ic/internal/core/intro"
)

func TestDemoCases(t *testing.T) {
	for _, tc := range []struct {
		name       string
		path       string
		signatures bool
		root       bool
		result     string
		want       error
	}{
		{"valid", "R -> Alice -> Bob", true, true, "accepted", nil},
		{
			"bad-signature", "R -> Alice -> Bob", false, true, "rejected",
			coreintro.ErrBadSignature,
		},
		{
			"bad-link", "R -> Alice -> Bob", true, true, "rejected",
			coreintro.ErrBrokenPath,
		},
		{
			"wrong-root", "X -> Alice -> Bob", true, false, "rejected",
			coreintro.ErrWrongRoot,
		},
		{
			"root-cycle", "R -> Alice -> R", true, true, "rejected",
			coreintro.ErrCycleOrDuplicate,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			cmd := newDemoCommand()
			var output bytes.Buffer
			cmd.SetOut(&output)
			args := []string{tc.name}

			// Execute would run Cobra's process-wide legacy initializers,
			// even on a fresh command. Exercise its callbacks directly.
			assert.NoError(cmd.ValidateArgs(args))
			err := cmd.RunE(cmd, args)
			if tc.want == nil {
				assert.NoError(err)
			} else {
				assert.ErrorIs(err, tc.want)
			}

			wantOutput := fmt.Sprintf(
				"case: %s\nfixture path: %s\n"+
					"descendant signatures valid: %t\n"+
					"starts at expected root: %t\npath check: %s\n",
				tc.name, tc.path, tc.signatures, tc.root, tc.result,
			)
			assert.Equal(output.String(), wantOutput)
		})
	}
}

func TestDemoArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing", nil},
		{"additional", []string{"valid", "bad-link"}},
		{"unknown", []string{"unknown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			cmd := newDemoCommand()
			var output bytes.Buffer
			cmd.SetOut(&output)

			assert.Error(cmd.ValidateArgs(tc.args))
			assert.Empty(output.String())
		})
	}
}

func TestDemoOutputFailure(t *testing.T) {
	defer assert.PushTester(t)()

	want := errors.New("demo output unavailable")
	cmd := newDemoCommand()
	cmd.SetOut(failingWriter{err: want})
	args := []string{"valid"}

	assert.NoError(cmd.ValidateArgs(args))
	assert.ErrorIs(cmd.RunE(cmd, args), want)
}

type failingWriter struct {
	err error
}

func (w failingWriter) Write([]byte) (int, error) {
	return 0, w.err
}

func TestDemoHelp(t *testing.T) {
	defer assert.PushTester(t)()

	cmd := newDemoCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)

	assert.NoError(cmd.Help())
	for _, text := range []string{
		"valid", "bad-signature", "bad-link", "wrong-root", "root-cycle",
		"exit nonzero", "ProveFromRoot", "Received/Known",
	} {
		assert.That(strings.Contains(output.String(), text), text)
	}
}

func TestDemoRegistration(t *testing.T) {
	defer assert.PushTester(t)()

	cmd, args, err := cmds.RootCmd().Find([]string{"intro", "demo"})
	assert.NoError(err)
	assert.SEmpty(args)
	assert.Equal(cmd.Use, "demo CASE")
	assert.Equal(cmd.Parent().Name(), "intro")
	assert.That(cmd.RunE != nil)
}
