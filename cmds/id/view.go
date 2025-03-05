package id

import (
	"fmt"

	"github.com/lainio/ic/internal/protocol"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

var idViewDoc = `The view command shows identity information according User ID.`

var idViewCmd = &cobra.Command{
	Use:   "view",
	Short: "view information about your Identity",
	Long:  idViewDoc,
	Args:  cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer err2.Handle(&err, nil)

		assert.SLonger(args, 0, "user ID: argument missing")

		enclave.TryInitSealedBox(protocol.CmdData.WalletFilename, "", protocol.CmdData.MasterKey)
		protocol.RcvrUser = enclave.TryGetExistingUserByType(
			cmd.Flags().Type.String(),
			args[0],
		)
		enclave.TryClose()

		u := protocol.RcvrUser

		if digestFlag() {
			d := u.Identity().Digest()
			if idViewCmdData.DigestV2 {
				fmt.Println(d.Digest())
			}
			if idViewCmdData.PrintDigest {
				fmt.Println(d.Base58())
			}
			if idViewCmdData.DigestOnly {
				fmt.Println(d)
			}
		} else if idViewCmdData.IDK {
			idkStr := u.Identity().GetIDK().PKString()
			fmt.Println(idkStr)
		} else {
			printInfoln(u, true)
		}

		return nil
	},
}

var idViewCmdData = struct {
	IDK         bool
	PrintDigest bool
	DigestV2    bool
	DigestOnly  bool
}{}

func init() {
	defer err2.Catch()

	flags := idViewCmd.PersistentFlags()
	flags.BoolVarP(&idViewCmdData.IDK, "idk", "k", false,
		"print IDK only")
	flags.BoolVarP(&idViewCmdData.PrintDigest, "print-digest", "p", false,
		"print Digest for transportation")
	flags.BoolVarP(&idViewCmdData.DigestV2, "digest", "d", false,
		"print Digest V2 for transportation")
	flags.BoolVarP(&idViewCmdData.DigestOnly, "digest-only", "o", false,
		"print Digest only")

	try.To(idViewCmd.MarkPersistentFlagRequired("print-digest"))
	try.To(idViewCmd.MarkPersistentFlagRequired("digest-only"))

	idCmd.AddCommand(idViewCmd)
}

func digestFlag() bool {
	return idViewCmdData.PrintDigest || idViewCmdData.DigestOnly ||
		idViewCmdData.DigestV2
}
