package id

import (
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

var idSetDoc = `The 'set' command set identity information according to its arguments.`

var idSetCmd = &cobra.Command{
	Use:   "set",
	Short: "set information for your Identity",
	Long:  idSetDoc,
	Args:  cobra.ExactArgs(3),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer err2.Handle(&err, nil)

		attrib := args[1]
		value := args[2]
		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
		rcvrUser = enclave.TryGetExistingUserByType(
			CmdData.Type.String(),
			args[0],
		)

		switch attrib {
		case "alias":
			rcvrUser.Alias = value
			enclave.TryPutUser(rcvrUser)
		default:
			assert.NotImplemented()
		}

		enclave.TryClose()

		return nil
	},
}

func init() {
	defer err2.Catch()

	idCmd.AddCommand(idSetCmd)
}
