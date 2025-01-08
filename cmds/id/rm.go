package id

import (
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

var idRmDoc = `Removes the current user from the DB.

    tdc id rm --user-id <user-db-#>

See the flags of the parent command.`

var idRmCmd = &cobra.Command{
	Use:   "rm",
	Short: "rm the user from our DB",
	Long:  idRmDoc,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		try.To(enclave.InitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey))
		//senderUser = try.To1(enclave.GetExistingUser(idInviteCmdData.RcvrUserID))
		//glog.V(3).Infoln("ic count:", senderUser.Identity().ICCount())
		glog.V(1).Infoln("removing user ID:", idInviteCmdData.RcvrUserID)
		try.To(enclave.RemoveUser(idInviteCmdData.RcvrUserID))
		try.To(enclave.Close())

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := idRmCmd.PersistentFlags()
	flags.Uint32Var(&idInviteCmdData.RcvrUserID, "user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["user-id"]))
	try.To(idRmCmd.MarkPersistentFlagRequired("user-id"))

	idCmd.AddCommand(idRmCmd)
}
