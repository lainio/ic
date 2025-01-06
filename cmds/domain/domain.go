package domain

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// TODO

var domainDoc = `domain, aka trust domain command.

TODO.`

var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Trust Domain",
	Long:  domainDoc,
	PreRunE: func(*cobra.Command, []string) (err error) {
		return cmd.BindEnvs(envs, "")
	},
	Run: func(c *cobra.Command, _ []string) {
		cmd.SubCmdNeeded(c)
	},
}

var CmdData = struct {
	ConnID    string
	MasterKey string
}{}

func PrintCmdData() {
	cb := try.To1(yaml.Marshal(CmdData))
	fmt.Println(string(cb))
}

func init() {
	defer err2.Catch()

	flags := domainCmd.PersistentFlags()
	flags.StringVar(&CmdData.MasterKey, "master-key", "",
		cmd.FlagInfo("agent JWT token", "", envs["master-key"]))
	flags.StringVar(&CmdData.ConnID, "conn-id", "",
		cmd.FlagInfo("connection id aka pairwise id", "", envs["conn-id"]))

	try.To(domainCmd.MarkPersistentFlagRequired("master-key"))
	cmd.RootCmd().AddCommand(domainCmd)
}

var envs = map[string]string{
	"master-key": "MASTER_KEY",
	"conn-id":    "CONN_ID",
}
