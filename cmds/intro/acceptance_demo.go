package intro

import (
	"errors"
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

func newAcceptanceDemoCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "acceptance-demo CASE",
		Short: "Check path proof and the child's detached acceptance separately",
		Long: `Check a generated path and its final child's detached acceptance.

Cases:
  valid        Alice signs R -> Alice; present that path
  missing      Present R -> Alice without acceptance
  transferred  Attach Alice's direct acceptance to R -> Bob -> Alice
  bad-link     Change Prev, re-sign with R, then obtain fresh Alice acceptance

Both checks are reported on stdout before rejection returns an error.
Rejected checks exit nonzero; the root CLI reports the cause on stderr.
The bad-link fixture deliberately bypasses proof before signing to demonstrate
a misbehaving signer; this is not a recommended acceptance workflow.

Passing checks is not enrollment or human consent and proves neither one-time
acceptance nor global parent uniqueness. These local checks change no Received,
Known, introduction, trust, device, or PW state and implement no V19 transition.
Only the final child's acceptance is signed, not an acceptance chain for every
ancestor. The path label describes the fixture; it grants no authority.`,
		Example: "  tdc intro acceptance-demo valid\n" +
			"  tdc intro acceptance-demo transferred\n" +
			"  tdc intro acceptance-demo bad-link",
		Args: cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{
			"valid", "missing", "transferred", "bad-link",
		},
		RunE: runAcceptanceDemo,
	}
}

func runAcceptanceDemo(cmd *cobra.Command, args []string) (err error) {
	defer err2.Handle(&err)

	root, alice, bob := key.New(), key.New(), key.New()
	expectedRoot := try.T1(root.CBORPublicKey())(
		"reading the independently expected R public key",
	)
	aliceInfo := key.InfoFromHandle(alice)
	rootPath := coreintro.New(key.InfoFromHandle(root))
	direct := rootPath.Introduce(root, aliceInfo)
	bobPath := rootPath.Introduce(root, key.InfoFromHandle(bob))
	indirect := bobPath.Introduce(bob, aliceInfo)
	presented := direct
	label := "R -> Alice"

	var acceptance key.Signature
	switch args[0] {
	case "valid", "transferred":
		try.T(direct.ProveFromRoot(expectedRoot))("checking offered path")
		assert.That(direct.LastEdge().Public().Equal(aliceInfo.Public),
			"offered final child must be Alice")
		assert.That(direct.SecondLastEdge().Public().Equal(expectedRoot),
			"offered parent must be R")

		acceptance = try.T1(direct.SignAcceptance(alice))(
			"signing Alice's acceptance of the direct proposal",
		)
	case "bad-link":
		// Fault injection: a misbehaving signer bypasses proof before signing.
		// This is not a recommended acceptance workflow.
		last := &presented[len(presented)-1]
		last.Body.Prev[0] ^= 1
		last.ParentSig = try.T1(root.Sign(last.ExcludeBytes()))(
			"re-signing Alice's edge with a wrong predecessor",
		)
		acceptance = try.T1(presented.SignAcceptance(alice))(
			"signing Alice's acceptance of the changed path",
		)
	}
	if args[0] == "transferred" {
		presented = indirect
		label = "R -> Bob -> Alice"
	}

	decoded := try.T1(coreintro.ParsePath(presented.Bytes()))(
		"parsing fixture path",
	)
	proofErr := decoded.ProveFromRoot(expectedRoot)
	acceptanceErr := decoded.VerifyAcceptance(acceptance)
	checkErr := errors.Join(proofErr, acceptanceErr)

	result := "passed"
	if checkErr != nil {
		result = "rejected"
	}
	try.T1(fmt.Fprintf(cmd.OutOrStdout(),
		"case: %s\nfixture path: %s\n"+
			"path proof passes: %t\n"+
			"acceptance signature verifies: %t\nchecks: %s\n",
		args[0], label, proofErr == nil, acceptanceErr == nil, result,
	))("writing acceptance demo results")
	try.T(checkErr)("checking fixture path and acceptance")
	return nil
}
