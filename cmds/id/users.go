package id

import (
	"fmt"

	"github.com/findy-network/findy-common-go/x"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

// TODO: think about POW-lvl as and extra flag?

var idUsersDoc = `TODO`

var idUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "lists all users in this enclave",
	Long:  idUsersDoc,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
		users := enclave.TryGetAllUsers()
		glog.V(3).Infoln("count of users:", len(users))
		for _, v := range users {
			if idUsersCmdData.Domains && !v.Identity().IsRoot() {
				continue
			}
			fmt.Printf(
				"User ID: %d, PK: %v, IC Count: %v, Root: %v\n",
				v.ID,
				v.Identity().GetIDK().PKString(),
				v.Identity().ICCount(),
				x.Whom(v.Identity().IsRoot(), "yes", "no"),
			)
		}

		return nil
	},
}

// TODO: flags:
//  - see chain.WithEndpoint, etc.

var idUsersCmdData = struct {
	Domains bool
}{}

func init() {
	defer err2.Catch()

	flags := idUsersCmd.PersistentFlags()
	flags.BoolVar(&idUsersCmdData.Domains, "only-domains", false,
		"lists only users that are trust domains")

	idCmd.AddCommand(idUsersCmd)
}
