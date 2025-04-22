package id

import (
	"fmt"

	"github.com/lainio/ic/internal/protocol"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/lainio/ic/hop"
	"github.com/spf13/cobra"
)

var (
	idBelongDoc = `The belong command counts web of trust of two identities.

The command has several different ways to use it. The 'belong' command takes two
arguments which point what Identities we querieng. The --type flag to tell
format used in arguments. Please see the examples for more information.`

	idBelongExample = `  # Identities can be given as user IDs:
    tdc id belong --type=db 12 1
  # or give identities by their IDK string:
    tdc id belong --type=idk asbaasbaasba $(pbpaste) # second from clipboard
`
)

var idBelongCmd = &cobra.Command{
	Use:     "belong",
	Short:   "list all trust domains we belong",
	Long:    idBelongDoc,
	Example: idBelongExample,
	Args:    cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		cmd.Flags().Type2 = protocol.IdInviteCmdData.Type2 // override!
		if cmd.DryRun() {
			fmt.Println("type2:", protocol.IdInviteCmdData.Type2)
			return cmd.PrintDefaultDryRun()
		}
		senderUser, rcvrUser := protocol.ReadParties(args...)

		idFromDig := senderUser.Identity()
		wot := rcvrUser.Identity().WebOfTrust(*idFromDig)
		assert.That(wot != nil && wot.Hops != hop.NotConnected,
			"identities don't share trust domains")
		enclave.TryInitSealedBox(protocol.CmdData.WalletFilename, "",
			protocol.CmdData.MasterKey)
		inviter := enclave.TryGetExistingUserByIDK(wot.CommonInviterPubKey)
		fmt.Println(wot)
		printInfoln(inviter, false)

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := idBelongCmd.PersistentFlags()
	try.To(protocol.IdInviteCmdData.Type2.Set(string(cmd.DigestV2Type)))
	flags.VarP(&protocol.IdInviteCmdData.Type2, "type2", "T",
		"Can be overridden at the belong cmd level")

	idCmd.AddCommand(idBelongCmd)
}
