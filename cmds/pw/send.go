package pw

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/internal/protocol"
	"github.com/spf13/cobra"
)

var (
	pwSendDoc = `The send command opens a secure pipe to the second party of our pairwise.

We can either be the party hwo starts the protocol (addresser) or the party who
accept the protocol (addressee).

The command has several different ways to use it. The 'send' command takes two
arguments which point what Identities we connecting. The --type flag to tell
format used in arguments. Please see the examples for more information.`

	//nolint:gosec // we don't have hard-coded identities here
	pwSendExample = `  # Identities can be given as DB IDs:
    tdc pw send --type=db 12 1
  # or give IDK string:
    tdc pw send --type=idk $(pbpaste) <from_typing>
`
)

var pwSendCmd = &cobra.Command{
	Use:     "send",
	Short:   "todo: sends pw messages if pw exists",
	Long:    pwSendDoc,
	Example: pwSendExample,
	Args:    cobra.ExactArgs(2),
	RunE: func(c *cobra.Command, args []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		senderPW, rcvrPW := protocol.SendPW(!addressee, args...)

		fmt.Fprintln(c.OutOrStdout(),
			"senderPW:", senderPW,
			"\nrcvrPW:", rcvrPW,
		)

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := pwSendCmd.PersistentFlags()
	flags.BoolVarP(&addressee, "addressee", "a", false,
		"we are the addressee, receiver of the pairwise")

	pwCmd.AddCommand(pwSendCmd)
}

var (
	addressee bool
)
