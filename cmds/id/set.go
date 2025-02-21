package id

import (
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/lainio/ic/internal/protocol"
	"github.com/spf13/cobra"
)

var idSetDoc = `The 'set' command set identity information according to its arguments.

List of the Identity attributes that can be updated: 'alias'.`

var idSetExample = `  # Set new alias for ID=12:
    tdc id set 10 alias 'New Alias Name Here'
  ## Set new alias for alias=Elvis
    tdc id set -t=alias Elvis alias 'Mr. Elvis Presley'
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
		enclave.TryInitSealedBox(protocol.CmdData.WalletFilename, "", protocol.CmdData.MasterKey)
		protocol.RcvrUser = enclave.TryGetExistingUserByType(
			cmd.Flags().Type.String(),
			args[0],
		)

		switch attrib {
		case "alias":
			protocol.RcvrUser.Alias = value
			enclave.TryPutUser(protocol.RcvrUser)
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
