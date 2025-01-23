package pw

import (
	"errors"
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/internal/protocol"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var pwDoc = `The pw command is parent command a group of commands for the identity.

Please note that all of the pw command's flags are inherited to subcommands and
awailable for them.`

var pwCmd = &cobra.Command{
	Use:   "pw",
	Short: "Trust Domain",
	Long:  pwDoc,
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
	Type           cmd.ArgType
}{}

func PrintCmdData() {
	cb := try.To1(yaml.Marshal(CmdData))
	fmt.Println(string(cb))
}

func init() {
	defer err2.Catch()

	flags := pwCmd.PersistentFlags()
	flags.StringVar(&protocol.CmdData.MasterKey, "master-key", "",
		cmd.FlagInfo("agent JWT token", "", envs["master-key"]))
	flags.StringVar(&protocol.CmdData.WalletFilename, "wallet", "",
		cmd.FlagInfo("filename for identity wallet", "", envs["wallet"]))

	try.To(pwCmd.MarkPersistentFlagRequired("master-key"))
	try.To(pwCmd.MarkPersistentFlagRequired("wallet"))
	cmd.RootCmd().AddCommand(pwCmd)
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

///////////////////////////////////////////////////////////////////////////

type ArgType string

const (
	DBType     ArgType = "db"
	DigestType ArgType = "digest"
	IDKType    ArgType = "idk"
	AliasType  ArgType = "alias"
)

// Validate the flag value
func (t *ArgType) String() string {
	return string(*t)
}

func (t *ArgType) Set(value string) error {
	switch value {
	case string(DBType), string(DigestType),
		string(IDKType), string(AliasType):
		*t = ArgType(value)
		return nil
	default:
		return errors.New("must be one of [db, digest, idk, alias]")
	}
}

func (t *ArgType) Type() string {
	return "ArgType"
}
