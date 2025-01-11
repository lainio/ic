package id

import (
	"fmt"
	"strconv"

	"github.com/findy-network/findy-common-go/x"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

// TODO: think about POW-lvl as and extra flag?

var idFindDoc = `TODO`

var idFindCmd = &cobra.Command{
	Use:   "find",
	Short: "lists all trust ids for a user",
	Long:  idFindDoc,
	Args:  cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer err2.Handle(&err, nil)

		assert.SLonger(args, 0, "user ID: argument missing")

		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
		users := enclave.TryGetAllUsers()
		try.To(enclave.Close())

		for _, u := range users {
			if calcSearch(args[0], u) {
				fmt.Printf(
					"User ID: %d, PK: %v, IC Count: %v, Root: %v\n",
					u.ID,
					u.Identity().GetIDK().PKString(),
					u.Identity().ICCount(),
					x.Whom(u.Identity().IsRoot(), "yes", "no"),
				)
				if u.Identity().ICCount() > 0 {
					for _, ic := range u.Identity().InviteeChains {
						pkStr := ic.FirstBlock().Invitee.PKString()
						fmt.Println("- Invitee Root PK", pkStr)
					}
				}
			}
		}

		return nil
	},
}

var idFindCmdData = struct {
	DomainPK  bool
	UseDigest bool
}{}

func calcSearch(s string, u enclave.User) bool {
	if idFindCmdData.UseDigest {
		uDigest := u.Identity().Digest().Base58()
		return uDigest == s
	}

	var (
		pkStr  string
		id     uint32
		retval bool
	)
	if len(s) == 14 {
		pkStr = s
	} else {
		id = uint32(try.To1(strconv.Atoi(s))) //nolint
	}
	if idFindCmdData.DomainPK {
		for _, ic := range u.Identity().InviteeChains {
			if ic.FirstBlock().Invitee.PKString() == pkStr {
				retval = true
				break
			}
		}
	} else {
		retval = u.RoleInfo.KeyInfo.PKString() == pkStr || u.ID == id
	}
	return retval
}

func init() {
	defer err2.Catch()

	flags := idFindCmd.PersistentFlags()
	flags.BoolVar(&idFindCmdData.DomainPK, "domain-pk", false,
		"instead of IDK, use Domain Root PK for search")
	flags.BoolVar(&idFindCmdData.UseDigest, "use-digest", false,
		"use full digest to find all which have similar one")

	idCmd.AddCommand(idFindCmd)
}
