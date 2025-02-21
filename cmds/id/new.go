package id

import (
	"fmt"

	"github.com/lainio/ic/internal/protocol"

	"github.com/findy-network/findy-common-go/x"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

var idNewDoc = `The id new command creates either a new identity domain or a new trust domain.`

var idNewExample = `  # Create a new identity domain
    tdc id new
  # Create a new trust domain
    tdc id new --trust-domain
  # Create a new domain with the name, a.k.a alias
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

		try.To(enclave.InitSealedBox(protocol.CmdData.WalletFilename, "", protocol.CmdData.MasterKey))
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
		try.Out(enclave.Close()).Logf("closing failure")

		myID := user.Identity()
		if idNewCmdData.IDK {
			fmt.Println(myID.GetIDK().Public.PKString())
			idNewCmdData.Verbose = false
		}
		if idNewCmdData.UserID {
			fmt.Println(user.ID)
			idNewCmdData.Verbose = false
		}
		if idNewCmdData.Verbose {
			fmt.Printf("The user ID (%v) of the new identity, IDK: %v\n",
				user.ID,
				myID.GetIDK().Public.PKString(),
			)
		}

		glog.V(5).Infoln("IDK:", myID.GetIDK())
		assert.Equal(myID.IsRoot(), idNewCmdData.IsDomain)

		return nil
	},
}

var idNewCmdData = struct {
	IsDomain bool
	Verbose  bool
	IDK      bool
	UserID   bool
}{}

func init() {
	defer err2.Catch()

	flags := idNewCmd.PersistentFlags()
	flags.BoolVar(&idNewCmdData.IsDomain, "trust-domain", false,
		"is this a trust domain")
	flags.BoolVar(&idNewCmdData.Verbose, "verbose", true,
		"use verbose output, overridden by --idk or --user-id")
	flags.BoolVar(&idNewCmdData.IDK, "idk", false,
		"output IDK")
	flags.BoolVar(&idNewCmdData.UserID, "user-id", false,
		"output user ID")

	idCmd.AddCommand(idNewCmd)
}
