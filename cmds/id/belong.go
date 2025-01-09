package id

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
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
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err, nil)

		try.To(enclave.InitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey))
		senderUser = try.To1(enclave.GetExistingUser(idInviteCmdData.SenderUserID))
		rcvrUser = try.To1(enclave.GetExistingUser(idInviteCmdData.RcvrUserID))
		try.To(enclave.Close())

		wot := senderUser.Identity().WebOfTrust(*rcvrUser.Identity())
		if wot.Hops == hop.NotConnected {
			return fmt.Errorf("identities don't share trust domains")
		}
		fmt.Println("WoT:", wot)

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
