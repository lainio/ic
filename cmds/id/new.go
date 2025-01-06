package id

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

// TODO: think about POW-lvl as and extra flag?

var idNewDoc = `TODO`

var idNewCmd = &cobra.Command{
	Use:   "new",
	Short: "creates a new trust id",
	Long:  idNewDoc,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		try.To(enclave.InitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey))
		var user enclave.User
		if idNewCmdData.IsDomain {
			user = enclave.NewUser(
				chain.WithEndpoint("TODO", true),
			)
		} else {
			user = enclave.NewUser()
		}
		try.To(enclave.PutUser(user))
		myID := user.Identity()

		fmt.Println("The user ID of the new identity:", user.ID)

		glog.V(5).Infoln("IDK:", myID.GetIDK())
		assert.Equal(myID.IsRoot(), idNewCmdData.IsDomain)

		return nil
	},
}

// TODO: flags:
//  - see chain.WithEndpoint, etc.

var idNewCmdData = struct {
	IsDomain bool
}{}

func init() {
	defer err2.Catch()

	flags := idNewCmd.PersistentFlags()
	flags.BoolVar(&idNewCmdData.IsDomain, "trust-domain", false,
		"is this a trust domain")

	idCmd.AddCommand(idNewCmd)
}
