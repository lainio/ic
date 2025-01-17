package id

import (
	"fmt"

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

		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)

		senderUser := enclave.TryGetExistingUserByType(string(CmdData.Type), args[0])
		rcvrUser := enclave.TryGetExistingUserByType(string(CmdData.Type), args[1])
		enclave.TryClose()

		// TODO: using Digest with WoT doesn't give symmetric results if we
		// don't add RootIDKs to it
		//wot := rcvrUser.Identity().WoT(senderDigest)

		idFromDig := senderUser.Identity()
		wot := rcvrUser.Identity().WebOfTrust(*idFromDig)
		if wot == nil || wot.Hops == hop.NotConnected {
			return fmt.Errorf("identities don't share trust domains")
		}
		fmt.Println(wot)

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := idBelongCmd.PersistentFlags()
	flags.Uint32Var(&idInviteCmdData.RcvrUserID, "rcvr-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["rcvr-user-id"]))
	try.To(idBelongCmd.MarkPersistentFlagRequired("rcvr-user-id"))

	flags.Uint32Var(&idInviteCmdData.SenderUserID, "sender-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["sender-user-id"]))
	try.To(idBelongCmd.MarkPersistentFlagRequired("sender-user-id"))

	idCmd.AddCommand(idBelongCmd)
}
