package pw

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/internal/protocol"
	"github.com/spf13/cobra"
)

var (
	pwViewDoc = `The view command opens a secure pipe to the second party of our pairwise.

We can either be the party hwo starts the protocol (addresser) or the party who
accept the protocol (addressee).

The command has several different ways to use it. The 'view' command takes two
arguments which point what Identities we connecting. The --type flag to tell
format used in arguments. Please see the examples for more information.`

	//nolint:gosec // we don't have hard-coded identities here
	pwViewExample = `  # Identities can be given as DB IDs:
    tdc pw view --type=db 12 1
  # or give IDK string:
    tdc pw view --type=idk $(pbpaste) <from_typing>
`
)

var pwViewCmd = &cobra.Command{
	Use:     "view",
	Short:   "view command shows details of the pairwise",
	Long:    pwViewDoc,
	Example: pwViewExample,
	Args:    cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		user, _ := protocol.ReadParties(args...)
		pconn := protocol.ViewPW(user.ID, user.KeyInfo.Public)
		assert.NotNil(pconn, "pairwise doesn't exist")
		fmt.Println("pairwise connection:", pconn.String())

		return nil
	},
}

func init() {
	defer err2.Catch()

	_ = pwViewCmd.PersistentFlags()

	pwCmd.AddCommand(pwViewCmd)
}
