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

func TestAcceptanceDemoCases(t *testing.T) {
	for _, tc := range []struct {
		name       string
		path       string
		proof      bool
		acceptance bool
		result     string
		want       error
		unwanted   error
	}{
		{"valid", "R -> Alice", true, true, "passed", nil, nil},
		{
			"missing", "R -> Alice", true, false, "rejected",
			coreintro.ErrBadAcceptance, coreintro.ErrBrokenPath,
		},
		{
			"transferred", "R -> Bob -> Alice", true, false, "rejected",
			coreintro.ErrBadAcceptance, coreintro.ErrBrokenPath,
		},
		{
			"bad-link", "R -> Alice", false, true, "rejected",
			coreintro.ErrBrokenPath, coreintro.ErrBadAcceptance,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()

			cmd := newAcceptanceDemoCommand()
			var output, diagnostic bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetErr(&diagnostic)
			args := []string{tc.name}

			// Callbacks avoid Cobra's process-wide legacy initializers.
			assert.NoError(cmd.ValidateArgs(args))
			err := cmd.RunE(cmd, args)
			if tc.want == nil {
				assert.NoError(err)
			} else {
				assert.ErrorIs(err, tc.want)
				assert.ErrorIsNot(err, tc.unwanted)
			}

			wantOutput := fmt.Sprintf(
				"case: %s\nfixture path: %s\n"+
					"path proof passes: %t\n"+
					"acceptance signature verifies: %t\nchecks: %s\n",
				tc.name, tc.path, tc.proof, tc.acceptance, tc.result,
			)
			assert.Equal(output.String(), wantOutput)
			assert.Empty(diagnostic.String())
		})
	}
}

func TestAcceptanceDemoArguments(t *testing.T) {
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

			cmd := newAcceptanceDemoCommand()
			var output bytes.Buffer
			cmd.SetOut(&output)

			assert.Error(cmd.ValidateArgs(tc.args))
			assert.Empty(output.String())
		})
	}
}

func TestAcceptanceDemoOutputFailure(t *testing.T) {
	defer assert.PushTester(t)()

	want := errors.New("acceptance demo output unavailable")
	cmd := newAcceptanceDemoCommand()
	cmd.SetOut(failingWriter{err: want})
	args := []string{"valid"}

	assert.NoError(cmd.ValidateArgs(args))
	assert.ErrorIs(cmd.RunE(cmd, args), want)
}

func TestAcceptanceDemoHelp(t *testing.T) {
	defer assert.PushTester(t)()

	cmd := newAcceptanceDemoCommand()
	var output bytes.Buffer
	cmd.SetOut(&output)

	assert.DeepEqual(cmd.ValidArgs, []string{
		"valid", "missing", "transferred", "bad-link",
	})
	assert.NoError(cmd.Help())
	for _, text := range []string{
		"Cases:\n" +
			"  valid        Alice signs R -> Alice; present that path\n" +
			"  missing      Present R -> Alice without acceptance\n" +
			"  transferred  Attach Alice's direct acceptance to R -> Bob -> Alice\n" +
			"  bad-link     Change Prev, re-sign with R, then obtain fresh Alice acceptance\n\n",
		"exit nonzero", "stdout", "stderr", "not enrollment", "human consent",
		"one-time", "global parent uniqueness", "no V19 transition",
	} {
		assert.That(strings.Contains(output.String(), text), text)
	}
}

func TestAcceptanceDemoRegistration(t *testing.T) {
	defer assert.PushTester(t)()

	cmd, args, err := cmds.RootCmd().Find([]string{"intro", "acceptance-demo"})
	assert.NoError(err)
	assert.SEmpty(args)
	assert.Equal(cmd.Use, "acceptance-demo CASE")
	assert.Equal(cmd.Parent().Name(), "intro")
	assert.That(cmd.RunE != nil)
}
