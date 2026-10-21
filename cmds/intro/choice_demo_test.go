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
	"github.com/spf13/cobra"
)

func TestChoiceDemoCases(t *testing.T) {
	for _, tc := range []struct {
		first, second         string
		firstPath, secondPath string
		result                string
		sameSignature         bool
		want                  error
	}{
		{
			"root", "root", "R -> Alice", "R -> Alice",
			"completed", true, nil,
		},
		{
			"bob", "bob", "R -> Bob -> Alice", "R -> Bob -> Alice",
			"completed", true, nil,
		},
		{
			"root", "bob", "R -> Alice", "R -> Bob -> Alice",
			"refused", false, coreintro.ErrDifferentAcceptance,
		},
		{
			"bob", "root", "R -> Bob -> Alice", "R -> Alice",
			"refused", false, coreintro.ErrDifferentAcceptance,
		},
	} {
		t.Run(tc.first+" "+tc.second, func(t *testing.T) {
			defer assert.PushTester(t)()

			cmd := newChoiceDemoCommand()
			var output, diagnostic bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&diagnostic)
			args := []string{tc.first, tc.second}

			// Callbacks avoid Cobra's process-wide legacy initializers.
			assert.NoError(cmd.ValidateArgs(args))
			err := cmd.RunE(cmd, args)
			if tc.want == nil {
				assert.NoError(err)
			} else {
				assert.ErrorIs(err, tc.want)
			}
			assert.ErrorIsNot(err, coreintro.ErrWrongParent)
			assert.ErrorIsNot(err, coreintro.ErrBadAcceptance)

			wantOutput := fmt.Sprintf(
				"first proposal: %s\nfirst acceptance verifies: true\n"+
					"second proposal: %s\nsecond path proof passes: true\n"+
					"second request: %s\nsame signature returned: %t\n",
				tc.firstPath, tc.secondPath, tc.result, tc.sameSignature,
			)
			assert.Equal(output.String(), wantOutput)
			assert.Empty(diagnostic.String())
		})
	}
}

func TestChoiceDemoArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing both", nil},
		{"missing second", []string{"root"}},
		{"additional", []string{"root", "bob", "root"}},
		{"unknown first", []string{"alice", "root"}},
		{"unknown second", []string{"root", "alice"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			cmd := newChoiceDemoCommand()
			var output, diagnostic bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&diagnostic)

			assert.Error(cmd.ValidateArgs(tc.args))
			assert.Empty(output.String())
			assert.Empty(diagnostic.String())
		})
	}
}

func TestChoiceDemoOutputFailure(t *testing.T) {
	for _, second := range []string{"root", "bob"} {
		t.Run(second, func(t *testing.T) {
			defer assert.PushTester(t)()

			want := errors.New("choice demo output unavailable")
			cmd := newChoiceDemoCommand()
			cmd.SetOut(failingWriter{err: want})
			args := []string{"root", second}

			assert.NoError(cmd.ValidateArgs(args))
			assert.ErrorIs(cmd.RunE(cmd, args), want)
		})
	}
}

func TestChoiceDemoHelp(t *testing.T) {
	defer assert.PushTester(t)()

	cmd := newChoiceDemoCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)

	assert.NoError(cmd.Help())
	for _, text := range []string{
		"choice-demo FIRST SECOND", "root  R -> Alice",
		"bob   R -> Bob -> Alice", "AcceptanceChoice",
		"ErrDifferentAcceptance", "stdout", "stderr", "exit nonzero",
		"fresh fixture keys", "once-only enrollment", "CanIntroduce",
	} {
		assert.That(strings.Contains(output.String(), text), text)
	}
}

func TestChoiceDemoRegistration(t *testing.T) {
	defer assert.PushTester(t)()

	cmd, args, err := cmds.RootCmd().Find([]string{"intro", "choice-demo"})
	assert.NoError(err)
	assert.SEmpty(args)
	assert.Equal(cmd.Use, "choice-demo FIRST SECOND")
	assert.Equal(cmd.Parent().Name(), "intro")
	assert.That(cmd.RunE != nil)
}

func TestChoiceDemoCompletion(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		toComplete string
		want       []string
	}{
		{"first", nil, "", []string{"root", "bob"}},
		{"after root", []string{"root"}, "", []string{"root", "bob"}},
		{"after bob", []string{"bob"}, "", []string{"root", "bob"}},
		{"first prefix", nil, "r", []string{"root"}},
		{"repeat prefix", []string{"root"}, "r", []string{"root"}},
		{"second prefix", []string{"root"}, "b", []string{"bob"}},
		{"unknown prefix", nil, "alice", nil},
		{"complete", []string{"root", "root"}, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			cmd := newChoiceDemoCommand()
			assert.That(cmd.ValidArgsFunction != nil)
			assert.SEmpty(cmd.ValidArgs)

			matches, directive := cmd.ValidArgsFunction(
				cmd, tc.args, tc.toComplete,
			)
			assert.DeepEqual(matches, tc.want)
			assert.Equal(directive, cobra.ShellCompDirectiveNoFileComp)
		})
	}
}
