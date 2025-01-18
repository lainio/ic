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
		for _, user := range users {
			if idUsersCmdData.DomainsOnly && !user.Identity().IsRoot() {
				continue
			}
			if idUsersCmdData.NonDomainsOnly && user.Identity().IsRoot() {
				continue
			}
			printInfoln(user, idUsersCmdData.Chains)
		}

		return nil
	},
}

var idUsersCmdData = struct {
	DomainsOnly    bool
	NonDomainsOnly bool
	Chains         bool
}{}

func init() {
	defer err2.Catch()

	flags := idUsersCmd.PersistentFlags()
	flags.BoolVar(&idUsersCmdData.DomainsOnly, "only-domains", false,
		"lists only users that are trust domains")
	flags.BoolVar(&idUsersCmdData.NonDomainsOnly, "non-domains", false,
		"lists only users that are NOT trust domains")
	flags.BoolVar(&idUsersCmdData.Chains, "chains", false,
		"lists invitee chains also")

	idCmd.AddCommand(idUsersCmd)
}

func printInfoln(user enclave.User, chains bool) {
	fmt.Printf(
		"UserID: %2d, PK: %v, ICs: %2v, Root: %-3v, '%v'\n",
		user.ID,
		user.Identity().GetIDK().PKString(),
		user.Identity().ICCount(),
		x.Whom(user.Identity().IsRoot(), "yes", "no"),
		user.Alias,
	)
	if chains { // TODO: all root ones print one reduntant IC
		if user.Identity().ICCount() > 0 {
			for _, ic := range user.Identity().InviteeChains {
				pkStr := ic.FirstBlock().Invitee.PKString()
				fmt.Println("- Invitee Root PK", pkStr)
			}
		}
	}
}
