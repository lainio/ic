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

var idViewDoc = `TODO`

var idViewCmd = &cobra.Command{
	Use:   "view",
	Short: "view information about your Identity",
	Long:  idViewDoc,
	Args:  cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer err2.Handle(&err, nil)

		assert.SLonger(args, 0, "user ID: argument missing")

		userID := uint32(try.To1(strconv.Atoi(args[0]))) //nolintlint
		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
		rcvrUser = try.To1(enclave.GetExistingUser(userID))
		try.To(enclave.Close())

		u := rcvrUser

		if idViewCmdData.PrintDigest || idViewCmdData.DigestOnly {
			d := u.Identity().Digest()
			if idViewCmdData.PrintDigest {
				fmt.Println(d.Base58())
			}
			if idViewCmdData.DigestOnly {
				fmt.Println(d)
			}
		} else {
			// TODO: extract to method
			fmt.Printf(
				"User ID: %d, Root: %v, Digest: {%v}, IC Count: %v\n",
				u.ID,
				x.Whom(u.Identity().IsRoot(), "yes", "no"),
				//u.Identity().GetIDK().PKString(),
				u.Identity().Digest(),
				u.Identity().ICCount(),
			)
			if u.Identity().ICCount() > 0 {
				for _, ic := range u.Identity().InviteeChains {
					pkStr := ic.FirstBlock().Invitee.PKString()
					fmt.Println("- Invitee Root PK", pkStr)
				}
			}
		}

		return nil
	},
}

var idViewCmdData = struct {
	PrintDigest bool
	DigestOnly  bool
}{}

func init() {
	defer err2.Catch()

	flags := idViewCmd.PersistentFlags()
	flags.BoolVarP(&idViewCmdData.PrintDigest, "print-digest", "d", false,
		"print Digest for transportation")
	flags.BoolVarP(&idViewCmdData.DigestOnly, "digest-only", "o", false,
		"print Digest only")
	try.To(idViewCmd.MarkPersistentFlagRequired("print-digest"))
	try.To(idViewCmd.MarkPersistentFlagRequired("digest-only"))

	idCmd.AddCommand(idViewCmd)
}
