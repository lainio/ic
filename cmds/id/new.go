package id

import (
	"fmt"

	"github.com/findy-network/findy-common-go/x"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

// TODO: think about POW-lvl as and extra flag?

var idNewDoc = `The id new command creates either a new identity domain or a new trust domain.`

var idNewExample = `  # Create a new identity domain
    tdc id new
  # Create a new trust domain
    tdc id new --trust-domain
  # Create a new identity domain with name, i.e., alias
    tdc id new "Alias Name"
`

var idNewCmd = &cobra.Command{
	Use:     "new",
	Short:   "creates a new trust id",
	Long:    idNewDoc,
	Example: idNewExample,
	Args:    cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer err2.Handle(&err, nil)

		try.To(enclave.InitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey))
		alias := x.Whom(len(args) == 1, args[0], "")
		var user enclave.User
		var extraArgs []chain.Opts
		if idNewCmdData.IsDomain {
			extraArgs = []chain.Opts{
				chain.WithEndpoint("TODO", true),
			}
		}
		user = enclave.NewUserWithAlias(alias, extraArgs...)

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
