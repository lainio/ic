package id

import (
	"fmt"

	"github.com/findy-network/findy-common-go/x"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

// TODO: think about POW-lvl as and extra flag?

var idViewDoc = `TODO`

var idViewCmd = &cobra.Command{
	Use:   "view",
	Short: "view information about your Identity",
	Long:  idViewDoc,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err, nil)

		try.To(enclave.InitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey))
		rcvrUser = try.To1(enclave.GetExistingUser(idInviteCmdData.RcvrUserID))
		try.To(enclave.Close())

		v := rcvrUser

		fmt.Printf(
			"User ID: %d, PK: %v, IC Count: %v, Root: %v\n",
			v.ID,
			v.Identity().GetIDK().PKString(),
			v.Identity().ICCount(),
			x.Whom(v.Identity().IsRoot(), "yes", "no"),
		)

		//v.Identity().Digest()

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := idViewCmd.PersistentFlags()
	flags.Uint32Var(&idInviteCmdData.RcvrUserID, "user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["user-id"]))
	try.To(idViewCmd.MarkPersistentFlagRequired("user-id"))

	idCmd.AddCommand(idViewCmd)
}
