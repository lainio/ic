package intro

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

func newChoiceDemoCommand() *cobra.Command {
	selectors := []string{"root", "bob"}
	return &cobra.Command{
		Use:   "choice-demo FIRST SECOND",
		Short: "Make two requests through one remembered acceptance choice",
		Long: `Make two explicit requests through one in-memory AcceptanceChoice.

Each selector names a generated proposal, not a user or live wallet:
  root  R -> Alice
  bob   R -> Bob -> Alice

The owner's first request selects either proposal. An exact retry returns the
saved acceptance; a different proposal is refused with ErrDifferentAcceptance.
Both proposals use the same R and Alice keys and pass individual path proof.
The summary goes to stdout; refusals exit nonzero with the cause on stderr.

Each invocation starts with fresh fixture keys and a fresh choice. This is
auxiliary signing state, not a persistent wallet or once-only enrollment.
It changes no Edges, Received, Known, trust, device, recovery, or pairwise state.
It implements neither V19 Introduce/VerifyReceived nor the global CanIntroduce
no-existing-parent guard. Incoming evidence is not automatically accepted.`,
		Example: "  tdc intro choice-demo root root\n" +
			"  tdc intro choice-demo root bob",
		Args: func(cmd *cobra.Command, args []string) (err error) {
			defer err2.Handle(&err)

			try.T(
				cobra.ExactArgs(2)(cmd, args),
			)(
				"checking fixture selector count",
			)
			for _, arg := range args {
				if !slices.Contains(selectors, arg) {
					return fmt.Errorf(
						"unknown fixture %q (use root or bob)",
						arg,
					)
				}
			}
			return nil
		},
		ValidArgsFunction: func(
			_ *cobra.Command, args []string, toComplete string,
		) ([]string, cobra.ShellCompDirective) {
			var matches []string
			if len(args) < 2 {
				for _, selector := range selectors {
					if strings.HasPrefix(selector, toComplete) {
						matches = append(matches, selector)
					}
				}
			}
			return matches, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: runChoiceDemo,
	}
}

func runChoiceDemo(cmd *cobra.Command, args []string) (err error) {
	defer err2.Handle(&err)

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := key.Public(try.T1(root.CBORPublicKey())(
		"reading the independently expected R public key",
	))
	bobPublic := key.Public(try.T1(bob.CBORPublicKey())(
		"reading the independently expected Bob public key",
	))

	aliceInfo := key.InfoFromHandle(alice)
	rootPath := coreintro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, aliceInfo)
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, aliceInfo)
	selectProposal := func(selector string) (coreintro.Path, key.Public, string) {
		if selector == "bob" {
			return indirect, bobPublic, "R -> Bob -> Alice"
		}
		return direct, expectedRoot, "R -> Alice"
	}

	first, firstParent, firstLabel := selectProposal(args[0])
	first = try.T1(coreintro.ParsePath(first.Bytes()))(
		"parsing the first proposal",
	)
	choice := coreintro.NewAcceptanceChoice(alice, expectedRoot)
	firstSignature := try.T1(choice.Accept(first, firstParent))(
		"accepting the first proposal",
	)
	firstVerifyErr := first.VerifyAcceptance(firstSignature)
	try.T(firstVerifyErr)("verifying the first acceptance")

	// Selecting an existing fixture preserves its exact signed proposal bytes.
	second, secondParent, secondLabel := selectProposal(args[1])
	second = try.T1(coreintro.ParsePath(second.Bytes()))(
		"parsing the second proposal",
	)
	proofErr := second.ProveFromRoot(expectedRoot)
	try.T(proofErr)("proving the second proposal independently")
	secondSignature, secondErr := choice.Accept(second, secondParent)

	result, sameSignature := "refused", false
	if secondErr == nil {
		try.T(second.VerifyAcceptance(secondSignature))(
			"verifying the second acceptance",
		)
		result = "completed"
		sameSignature = bytes.Equal(firstSignature, secondSignature)
	}

	try.T1(fmt.Fprintf(cmd.OutOrStdout(),
		"first proposal: %s\nfirst acceptance verifies: %t\n"+
			"second proposal: %s\nsecond path proof passes: %t\n"+
			"second request: %s\nsame signature returned: %t\n",
		firstLabel, firstVerifyErr == nil, secondLabel, proofErr == nil,
		result, sameSignature,
	))("writing choice demo results")
	try.T(secondErr)("accepting the second proposal")
	return nil
}
