package intro

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/cmds"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

func init() {
	introCmd := &cobra.Command{
		Use:   "intro",
		Short: "Introduction path checks",
	}
	introCmd.AddCommand(newDemoCommand())
	introCmd.AddCommand(newAcceptanceDemoCommand())
	cmds.RootCmd().AddCommand(introCmd)
}

func newDemoCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "demo CASE",
		Short: "Check a generated introduction path fixture",
		Long: `Check one generated fixture with the existing ProveFromRoot verifier.

Cases:
  valid          R -> Alice -> Bob
  bad-signature  Alter Bob's signature
  bad-link       Alter Bob's predecessor link and re-sign with Alice
  wrong-root     X -> Alice -> Bob, independently expecting R
  root-cycle     R -> Alice -> R, correctly signed and linked

Negative cases exit nonzero and the CLI reports the core proof error.
All fixtures use zero BackupKeyIndex; backup and rotation policy are not tested.

This is a generated-fixture demo, not a general evidence-import command or an
implementation of V19 Introduce, ReceiveEdge, or VerifyReceived. It creates no
Received/Known state and grants no introduction, trust, pairwise, or device
authority. Accepted means only that ProveFromRoot returned nil for this fixture.
It does not prove presenter key control, global unique parenthood, complete V19
conformance, or safe handling of arbitrary network-supplied paths.`,
		Example: "  tdc intro demo valid\n  tdc intro demo bad-link",
		Args:    cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{
			"valid", "bad-signature", "bad-link", "wrong-root", "root-cycle",
		},
		RunE: runDemo,
	}
}

func runDemo(cmd *cobra.Command, args []string) (err error) {
	defer err2.Handle(&err)

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := try.T1(root.CBORPublicKey())(
		"reading the independently expected R public key",
	)

	pathRoot, leaf := root, bob
	label := "R -> Alice -> Bob"
	switch args[0] {
	case "wrong-root":
		pathRoot = key.New()
		label = "X -> Alice -> Bob"
	case "root-cycle":
		leaf = root
		label = "R -> Alice -> R"
	}

	// Default options leave every BackupKeyIndex zero.
	path := coreintro.New(key.InfoFromHandle(pathRoot)).Introduce(
		pathRoot, key.InfoFromHandle(alice),
	)
	path = path.Introduce(alice, key.InfoFromHandle(leaf))

	switch args[0] {
	case "bad-signature":
		sig := path[2].ParentSig
		sig[len(sig)-1] ^= 1
	case "bad-link":
		path[2].Body.Prev[0] ^= 1
		path[2].ParentSig = try.T1(alice.Sign(path[2].ExcludeBytes()))(
			"re-signing Bob's edge with a wrong predecessor",
		)
	}

	decoded := try.T1(coreintro.ParsePath(path.Bytes()))(
		"parsing fixture path",
	)
	signaturesValid := true
	for i, edge := range decoded[1:] {
		if !edge.VerifySignature(decoded[i].Public()) {
			signaturesValid = false
		}
	}
	startsAtExpectedRoot := decoded.FirstEdge().Public().Equal(expectedRoot)
	proofErr := decoded.ProveFromRoot(expectedRoot)

	result := "accepted"
	if proofErr != nil {
		result = "rejected"
	}
	try.T1(fmt.Fprintf(cmd.OutOrStdout(),
		"case: %s\nfixture path: %s\n"+
			"descendant signatures valid: %t\n"+
			"starts at expected root: %t\npath check: %s\n",
		args[0], label, signaturesValid, startsAtExpectedRoot, result,
	))("writing demo results")
	try.T(proofErr)("checking fixture path")
	return nil
}
