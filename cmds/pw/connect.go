package pw

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/internal/protocol"
	"github.com/spf13/cobra"
)

var (
	pwConnectDoc = `The connect command run the new pairwise build protocol.

We can either be the party hwo starts the protocol (addresser) or the party who
accept the protocol (addressee).

The command has several different ways to use it. The 'connect' command takes two
arguments which point what Identities we connecting. The --type flag to tell
format used in arguments. Please see the examples for more information.`

	//nolint:gosec // we don't have hard-coded identities here
	pwConnectExample = `  # Identities can be given as DB IDs:
    tdc pw connect --type=db 12 1
  # or give IDK string:
    tdc pw connect --type=idk $(pbpaste) <from_typing>
`
)

var pwConnectCmd = &cobra.Command{
	Use:     "connect",
	Short:   "list all trust domains we connect",
	Long:    pwConnectDoc,
	Example: pwConnectExample,
	Args:    cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)

		senderUser := enclave.TryGetExistingUserByType(
			cmd.Flags().Type.String(),
			args[0],
		)
		rcvrUser := enclave.TryGetExistingUserByType(
			cmd.Flags().Type.String(),
			args[1],
		)
		enclave.TryClose()

		pwFromDig := senderUser.Identity()
		wot := rcvrUser.Identity().WebOfTrust(*pwFromDig)
		if wot == nil || wot.Hops == hop.NotConnected {
			return fmt.Errorf("identities don't share trust domains")
		}
		fmt.Println(wot)

		// TODO: start the pw protocol
		try.To(protocol.PairwiseHandshake())

		return nil
	},
}

var (
	addresser bool
)

func init() {
	defer err2.Catch()

	flags := pwConnectCmd.PersistentFlags()
	flags.BoolVarP(&addresser, "addresser", "a", false,
		"handshake starts as addresser other side is addressee")

	pwCmd.AddCommand(pwConnectCmd)
}
