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
	"github.com/spf13/cobra"
)

// TODO: think about POW-lvl as and extra flag?

var idBelongDoc = `TODO`

var idBelongCmd = &cobra.Command{
	Use:   "belong",
	Short: "list all trust domains we belong",
	Long:  idBelongDoc,
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer err2.Handle(&err, nil)

		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)

		var senderDigest *digest.Digest
		if idInviteCmdData.SenderUserID == 0 {
			assert.SLonger(args, 0, "user ID: argument missing")
			dig := digest.NewFromString(args[0])
			senderDigest = &dig
		} else {
			senderUser = enclave.TryGetExistingUser(idInviteCmdData.SenderUserID)
			dig := senderUser.Identity().Digest()
			senderDigest = &dig
		}

		rcvrUser = enclave.TryGetExistingUser(idInviteCmdData.RcvrUserID)
		enclave.TryClose()

		wot := rcvrUser.Identity().WoT(senderDigest)
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
