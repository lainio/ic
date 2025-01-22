package id

import (
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

var idSetDoc = `The 'set' command set identity information according to its arguments.

List of the Identity attributes that can be updated: 'alias'.`

var idSetExample = `  # Set new alias:
    tdc id set alias 'New Alias Name Here'
`

var idSetCmd = &cobra.Command{
	Use:     "set",
	Short:   "set information for your Identity",
	Long:    idSetDoc,
	Example: idSetExample,
	Args:    cobra.ExactArgs(3),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer err2.Handle(&err, nil)

		attrib := args[1]
		value := args[2]
		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
		rcvrUser = enclave.TryGetExistingUserByType(
			cmd.Flags().Type.String(),
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
