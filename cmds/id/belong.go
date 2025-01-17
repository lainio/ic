package id

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/digest"
	"github.com/lainio/ic/enclave"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/identity"
	"github.com/spf13/cobra"
)

var (
	idBelongDoc = `The belong command counts web of trust of two identities.

The command has two different ways to use it. Please see the examples for more
information.`

	idBelongExample = `  # Both identities can be given as user ID (flags):
    tdc id belong --id-type=db 12 1
  # or give identities by their IDK:
    tdc id belong --id-type=idk 12 $(pbpaste) # second from clipboard
`
)

var idBelongCmd = &cobra.Command{
	Use:     "belong",
	Short:   "list all trust domains we belong",
	Long:    idBelongDoc,
	Example: idBelongExample,
	Args:    cobra.MinimumNArgs(0),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)

		var senderDigest *digest.Digest
		if idInviteCmdData.SenderUserID == 0 {
			assert.SNotEmpty(args, "user ID: argument missing")
			dig := digest.NewFromString(args[0])
			senderDigest = &dig
		} else {
			senderUser = enclave.TryGetExistingUser(idInviteCmdData.SenderUserID)
			dig := senderUser.Identity().Digest()
			senderDigest = &dig
		}
		rcvrUser = enclave.TryGetExistingUser(idInviteCmdData.RcvrUserID)
		var idFromDig identity.Identity
		users := enclave.TryGetAllUsers()
		for _, v := range users {
			equal := v.Identity().Digest().Equal(*senderDigest)
			if equal {
				idFromDig = *v.Identity()
				break
			}
		}
		enclave.TryClose()

		//wot := rcvrUser.Identity().WoT(senderDigest)
		wot := rcvrUser.Identity().WebOfTrust(idFromDig)
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
