package intro

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	coreintro "github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
	"github.com/spf13/cobra"
)

func newStoredChoiceDemoCommand() *cobra.Command {
	selectors := []string{"root", "bob"}
	return &cobra.Command{
		Use:   "stored-choice-demo FIRST SECOND",
		Short: "Request acceptance before and after reopening a temporary Vault",
		Long: `Make two explicit requests through SignAfterStoredChoice.

Each selector names a generated proposal:
  root  R -> Alice
  bob   R -> Bob -> Alice

Either proposal may be selected first. Close the Vault and database, reopen the
same file, then request the exact stored proposal again or a different one.
Exact retries verify the saved acceptance without signing again;
different proposals return ErrDifferentAcceptance.
The summary goes to stdout; refusals exit nonzero with the cause on stderr.
Completion offers both selectors at both positions, including repeated choices.

This disposable demo keeps the same process, provider, and fixture keys alive.
It removes its temporary database and clears the provider secret after use.
Auxiliary choice and its verified acceptance are stored; neither is membership.
If signing or saving fails, selection remains pending and an explicit retry may
sign again. Signing and saving are separate operations, not exactly-once signing.
This is not process restart or production wallet recovery. Other Vaults,
restored files, and direct key use can bypass this local guard.
It changes no Edges, Received, Known, trust, device, recovery, or pairwise state
and adds no V19 action. Incoming evidence is not automatically accepted.`,
		Example: "  tdc intro stored-choice-demo root root\n" +
			"  tdc intro stored-choice-demo root bob",
		Args: func(cmd *cobra.Command, args []string) (err error) {
			defer err2.Handle(&err)

			try.T(cobra.ExactArgs(2)(cmd, args))(
				"checking fixture selector count",
			)
			for _, arg := range args {
				if !slices.Contains(selectors, arg) {
					return fmt.Errorf(
						"unknown fixture %q (use root or bob)", arg,
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
		RunE: runStoredChoiceDemo,
	}
}

func runStoredChoiceDemo(cmd *cobra.Command, args []string) (err error) {
	defer err2.Handle(&err)

	fixtures := try.To1(newStoredChoiceFixtures())
	dir := try.T1(os.MkdirTemp("", "intro-stored-choice-demo-"))(
		"creating temporary directory",
	)
	defer func() { try.Out(os.RemoveAll(dir)).Logf() }()
	path := filepath.Join(dir, "vault.db")
	provider := newStoredChoiceProvider()
	// Runs after all handle cleanup, including on failure.
	defer clear(provider.secret)
	try.T1(rand.Read(provider.secret))("generating provider secret")

	ctx := cmd.Context()
	db := try.T1(storage.OpenBolt(path))("opening database")
	defer func() { try.Out(db.Close()).Logf() }()
	try.T(db.CreateVault(ctx, provider.vault, provider.id, provider))(
		"creating Alice/R vault",
	)
	vault := try.T1(db.OpenVault(ctx, provider.vault, provider.id, provider))(
		"opening Alice/R vault",
	)
	defer func() { try.Out(vault.Close()).Logf() }()

	first, firstParent, firstLabel := fixtures.selectProposal(args[0])
	first = try.T1(coreintro.ParsePath(first.Bytes()))(
		"parsing first proposal",
	)
	firstSignature := try.T1(onboarding.SignAfterStoredChoice(
		vault, fixtures.alice, fixtures.rootPublic, firstParent, first,
	))("accepting first proposal")
	firstVerifyErr := first.VerifyAcceptance(firstSignature)
	try.T(firstVerifyErr)("verifying first acceptance")

	// These required closes must succeed before the same file is reopened.
	// Deferred closes above are fallback diagnostics, not proof of success.
	try.T(vault.Close())("closing initial vault")
	try.T(db.Close())("closing initial database")
	reopenedDB := try.T1(storage.OpenBolt(path))("reopening database")
	defer func() { try.Out(reopenedDB.Close()).Logf() }()
	reopenedVault := try.T1(reopenedDB.OpenVault(
		ctx, provider.vault, provider.id, provider,
	))("reopening existing Alice/R vault")
	defer func() { try.Out(reopenedVault.Close()).Logf() }()

	// Reuse the signed fixtures; selection is consulted only by the helper.
	second, secondParent, secondLabel := fixtures.selectProposal(args[1])
	second = try.T1(coreintro.ParsePath(second.Bytes()))(
		"parsing second proposal",
	)
	proofErr := second.ProveFromRoot(fixtures.rootPublic)
	try.T(proofErr)("proving second proposal independently")
	secondSignature, secondErr := onboarding.SignAfterStoredChoice(
		reopenedVault,
		fixtures.alice,
		fixtures.rootPublic,
		secondParent,
		second,
	)

	result, secondVerified := "refused", false
	if secondErr == nil {
		verifyErr := second.VerifyAcceptance(secondSignature)
		try.T(verifyErr)("verifying second acceptance")
		result, secondVerified = "completed", verifyErr == nil
	}

	// Attempt both closes and removal before output, preserving every cause.
	closeErr := errors.Join(reopenedVault.Close(), reopenedDB.Close())
	clear(provider.secret)
	removeErr := os.RemoveAll(dir)
	_, outputErr := fmt.Fprintf(cmd.OutOrStdout(),
		"first proposal: %s\nfirst acceptance verifies: %t\n"+
			"database reopened: %t\n"+
			"second proposal: %s\nsecond path proof passes: %t\n"+
			"second request: %s\nsecond acceptance verifies: %t\n",
		firstLabel, firstVerifyErr == nil, reopenedVault != nil,
		secondLabel, proofErr == nil, result, secondVerified,
	)
	return errors.Join(secondErr, closeErr, removeErr, outputErr)
}

type storedChoiceFixtures struct {
	alice                 key.Handle
	rootPublic, bobPublic key.Public
	direct, indirect      coreintro.Path
}

func newStoredChoiceFixtures() (fixtures storedChoiceFixtures, err error) {
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
	return storedChoiceFixtures{
		alice: alice, rootPublic: expectedRoot, bobPublic: bobPublic,
		direct: direct, indirect: indirect,
	}, nil
}

func (f storedChoiceFixtures) selectProposal(
	selector string,
) (coreintro.Path, key.Public, string) {
	if selector == "bob" {
		return f.indirect, f.bobPublic, "R -> Bob -> Alice"
	}
	return f.direct, f.rootPublic, "R -> Alice"
}
