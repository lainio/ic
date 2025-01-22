package id

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var idDoc = `The id command is parent command a group of commands for the identity.

Please note that all of the id command's flags are inherited to subcommands and
awailable for them.`

var idCmd = &cobra.Command{
	Use:   "id",
	Short: "Trust Domain",
	Long:  idDoc,
	PreRunE: func(*cobra.Command, []string) (err error) {
		return cmd.BindEnvs(envs, "")
	},
	Run: func(c *cobra.Command, _ []string) {
		cmd.SubCmdNeeded(c)
	},
}

var CmdData = struct {
	WalletFilename string
	MasterKey      string
}{}

func PrintCmdData() {
	cb := try.To1(yaml.Marshal(CmdData))
	fmt.Println(string(cb))
}

func init() {
	defer err2.Catch()

	flags := idCmd.PersistentFlags()
	flags.StringVar(&CmdData.MasterKey, "master-key", "",
		cmd.FlagInfo("agent JWT token", "", envs["master-key"]))
	flags.StringVar(&CmdData.WalletFilename, "wallet", "",
		cmd.FlagInfo("filename for identity wallet", "", envs["wallet"]))

	try.To(idCmd.MarkPersistentFlagRequired("master-key"))
	try.To(idCmd.MarkPersistentFlagRequired("wallet"))
	cmd.RootCmd().AddCommand(idCmd)
}

var envs = map[string]string{
	"master-key":     "MASTER_KEY",
	"wallet":         "WALLET",
	"user-id":        "USER_ID",
	"sender-user-id": "SENDER_USER_ID",
	"rcvr-user-id":   "RCVR_USER_ID",
	"codec":          "CODEC",
	"type":           "TYPE",
}
