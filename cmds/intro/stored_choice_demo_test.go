package intro

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/cmds"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/spf13/cobra"
)

func TestStoredChoiceDemoCases(t *testing.T) {
	for _, tc := range []struct {
		first, second         string
		firstPath, secondPath string
		result                string
		verified              bool
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

			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			cmd := newStoredChoiceDemoCommand()
			cmd.SetContext(t.Context())
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
					"database reopened: true\n"+
					"second proposal: %s\nsecond path proof passes: true\n"+
					"second request: %s\nsecond acceptance verifies: %t\n",
				tc.firstPath, tc.secondPath, tc.result, tc.verified,
			)
			assert.Equal(output.String(), wantOutput)
			assert.Empty(diagnostic.String())
			assert.SEmpty(try.To1(os.ReadDir(parent)))
		})
	}
}

func TestStoredChoiceDemoArguments(t *testing.T) {
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

			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			cmd := newStoredChoiceDemoCommand()
			cmd.SetContext(t.Context())
			var output, diagnostic bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&diagnostic)

			assert.Error(cmd.ValidateArgs(tc.args))
			assert.Empty(output.String())
			assert.Empty(diagnostic.String())
			assert.SEmpty(try.To1(os.ReadDir(parent)))
		})
	}
}

func TestStoredChoiceDemoOutputFailure(t *testing.T) {
	for _, second := range []string{"root", "bob"} {
		t.Run(second, func(t *testing.T) {
			defer assert.PushTester(t)()

			parent := t.TempDir()
			t.Setenv("TMPDIR", parent)
			want := errors.New("stored choice demo output unavailable")
			cmd := newStoredChoiceDemoCommand()
			cmd.SetContext(t.Context())
			cmd.SetOut(failingWriter{err: want})
			var diagnostic bytes.Buffer
			cmd.SetErr(&diagnostic)
			args := []string{"root", second}

			assert.NoError(cmd.ValidateArgs(args))
			err := cmd.RunE(cmd, args)
			assert.ErrorIs(err, want)
			if second == "bob" {
				assert.ErrorIs(err, coreintro.ErrDifferentAcceptance)
			} else {
				assert.ErrorIsNot(err, coreintro.ErrDifferentAcceptance)
			}
			assert.Empty(diagnostic.String())
			assert.SEmpty(try.To1(os.ReadDir(parent)))
		})
	}
}

func TestStoredChoiceDemoHelp(t *testing.T) {
	defer assert.PushTester(t)()

	cmd := newStoredChoiceDemoCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)

	assert.NoError(cmd.Help())
	for _, text := range []string{
		"stored-choice-demo FIRST SECOND", "root  R -> Alice",
		"bob   R -> Bob -> Alice", "SignAfterStoredChoice",
		"ErrDifferentAcceptance", "stdout", "stderr", "exit nonzero",
		"same file", "disposable", "same process", "production wallet recovery",
	} {
		assert.That(strings.Contains(output.String(), text), text)
	}
}

func TestStoredChoiceDemoRegistration(t *testing.T) {
	defer assert.PushTester(t)()

	cmd, args, err := cmds.RootCmd().Find(
		[]string{"intro", "stored-choice-demo"},
	)
	assert.NoError(err)
	assert.SEmpty(args)
	assert.Equal(cmd.Use, "stored-choice-demo FIRST SECOND")
	assert.Equal(cmd.Parent().Name(), "intro")
	assert.That(cmd.RunE != nil)
}

func TestStoredChoiceDemoCompletion(t *testing.T) {
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
		{"repeat root", []string{"root"}, "r", []string{"root"}},
		{"repeat bob", []string{"bob"}, "b", []string{"bob"}},
		{"second prefix", []string{"root"}, "b", []string{"bob"}},
		{"unknown prefix", nil, "alice", nil},
		{"complete root", []string{"root", "root"}, "", nil},
		{"complete bob", []string{"bob", "bob"}, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			cmd := newStoredChoiceDemoCommand()
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
