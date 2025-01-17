package id

import (
	"fmt"

	"github.com/findy-network/findy-common-go/x"
	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

var idUsersDoc = `The users command lists all users from our enclave.`

var idUsersExample = `  # search all users:
    tdc id users
  # search trust domains only:
    tdc id users --only-domains
  # search NON trust domains only:
    tdc id users --non-domains
`

var idUsersCmd = &cobra.Command{
	Use:     "users",
	Short:   "lists all users in this enclave",
	Long:    idUsersDoc,
	Example: idUsersExample,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
		users := enclave.TryGetAllUsers()
		glog.V(3).Infoln("count of users:", len(users))
		for _, v := range users {
			if idUsersCmdData.DomainsOnly && !v.Identity().IsRoot() {
				continue
			}
			if idUsersCmdData.NonDomainsOnly && v.Identity().IsRoot() {
				continue
			}
			fmt.Printf(
				"User ID: %d, '%v', PK: %v, IC Count: %v, Root: %v\n",
				v.ID,
				v.Alias,
				v.Identity().GetIDK().PKString(),
				v.Identity().ICCount(),
				x.Whom(v.Identity().IsRoot(), "yes", "no"),
			)
		}

		return nil
	},
}

var idUsersCmdData = struct {
	DomainsOnly    bool
	NonDomainsOnly bool
}{}

func init() {
	defer err2.Catch()

	flags := idUsersCmd.PersistentFlags()
	flags.BoolVar(&idUsersCmdData.DomainsOnly, "only-domains", false,
		"lists only users that are trust domains")
	flags.BoolVar(&idUsersCmdData.NonDomainsOnly, "non-domains", false,
		"lists only users that are NOT trust domains")

	idCmd.AddCommand(idUsersCmd)
}
