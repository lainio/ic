package id

import (
	"fmt"

	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/identity"
	"github.com/lainio/ic/internal/protocol"

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
	Aliases: []string{"list", "ls"},
	Short:   "lists all users in this enclave",
	Long:    idUsersDoc,
	Example: idUsersExample,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		enclave.TryInitSealedBox(protocol.CmdData.WalletFilename, "", protocol.CmdData.MasterKey)
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
	identity := user.Identity()
	assert.NotNil(identity)

	fmt.Printf(
		"UserID: %2d, PK: %v, ICs: %2v, Root: %-3v, '%v'\n",
		user.ID,
		identity.GetIDK().PKString(),
		identity.ICCount(),
		x.Whom(identity.IsRoot(), "yes", "no"),
		user.Alias,
	)
	if chains {
		printChains(identity)
	}
}

func printChains(identity *identity.Identity) {
	for _, ic := range identity.InviteeChains {
		if identity.IsRoot() &&
			identity.GetIDK().Public.Equal(ic.FirstBlock().Invitee.Public) {
			continue
		} else {
			pkStr := ic.FirstBlock().Invitee.PKString()
			fmt.Println("- Invitee Root PK", pkStr, ic.Len()-1)
		}
	}
}
