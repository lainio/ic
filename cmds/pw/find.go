package pw

import (
	"fmt"
	"math/rand/v2"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/lainio/ic/internal/protocol"
	"github.com/spf13/cobra"
)

var (
	pwFindDoc = `The find command run the new pairwise build protocol.

We can either be the party hwo starts the protocol (addresser) or the party who
accept the protocol (addressee).

The command has several different ways to use it. The 'find' command takes two
arguments which point what Identities we finding. The --type flag to tell
format used in arguments. Please see the examples for more information.`

	//nolint:gosec // we don't have hard-coded identities here
	pwFindExample = `  # Identities can be given as DB IDs:
    tdc pw find 12 Xf
  # or give IDK string:
    tdc pw find --type=idk $(pbpaste) <from_typing>
`
)

var pwFindCmd = &cobra.Command{
	Use:     "find",
	Aliases: []string{"fd", "f"},
	Short:   "find command find pw for a owner",
	Long:    pwFindDoc,
	Example: pwFindExample,
	Args:    cobra.ExactArgs(1),
	RunE: func(c *cobra.Command, args []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		cmd.Flags().Type2 = protocol.IdInviteCmdData.Type2 // override!
		if cmd.DryRun() {
			fmt.Println("type2:", protocol.IdInviteCmdData.Type2)
			return cmd.PrintDefaultDryRun()
		}
		var userID uint32
		if cmd.Flags().Type == cmd.DBType {
			user, _ := protocol.ReadParties(args...)
			userID = user.ID
		}

		conns := try.To1(enclave.GetAllPW(userID, isAddresser))
		for _, v := range conns {
			fmt.Println(v)
		}

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := pwFindCmd.PersistentFlags()
	flags.BoolVarP(&isAddresser, "addresser", "a", false,
		"TODO")

	try.To(protocol.IdInviteCmdData.Type2.Set(string(cmd.DigestV2Type)))
	flags.VarP(&protocol.IdInviteCmdData.Type2, "type2", "T",
		"TODO")

	flags.BoolVar(&plain, "plain", false,
		"plain print, i.e., only IDK, good for piping")

	flags.IntVar(
		&protocol.IdInviteCmdData.PinCode,
		"pin-code",
		rand.Int(), //nolint:gosec // UI simulation only!
		"secret PIN code for finds, etc.",
	)

	pwCmd.AddCommand(pwFindCmd)
}
