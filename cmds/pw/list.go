package pw

import (
	"fmt"
	"math/rand/v2"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/internal/protocol"
	"github.com/spf13/cobra"
)

var (
	//nolint:gosec // we don't have hard-coded identities here
	pwListDoc = `TODO: The list command lists all pairwises.

We can either be the party hwo starts the protocol (addresser) or the party who
accept the protocol (addressee).

The command has several different ways to use it. The 'list' command takes two
arguments which point what Identities we connecting. The --type flag to tell
format used in arguments. Please see the examples for more information.`

	//nolint:gosec // we don't have hard-coded identities here
	pwListExample = `  # Identities can be given as DB IDs:
    tdc pw list --type=db 12 1
  # or give IDK string:
    tdc pw list --type=idk $(pbpaste) <from_typing>
`
)

var pwListCmd = &cobra.Command{
	Use:     "list",
	Short:   "list command lists pairwises",
	Long:    pwListDoc,
	Example: pwListExample,
	// Args:    cobra.ExactArgs(1),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		pconn := protocol.ListPW(isAddresser)

		fmt.Println("pairwise connection count:", len(pconn))
		for i, pw := range pconn {
			fmt.Println(i, ":", pw)
		}

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := pwListCmd.PersistentFlags()
	flags.BoolVarP(&isAddresser, "addresser", "a", false,
		"handshake starts as addresser other side is addressee")

	flags.IntVar(
		&protocol.IdInviteCmdData.PinCode,
		"pin-code",
		rand.Int(), //nolint:gosec // UI simulation only!
		"secret PIN code for handshakes, etc.",
	)

	pwCmd.AddCommand(pwListCmd)
}
