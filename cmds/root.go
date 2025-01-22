package cmds

import (
	goflag "flag"
	"fmt"
	"os"
	"strings"

	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const envPrefix = "TDC"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	SilenceUsage: true,
	Use:          "tdc",
	Short:        "Trust Domain CLI tool",
	Long: `
Trust Domain CLI tool (tdc) is command line UI for your TD based indentity
	`,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		// NOTE! Very important. Adds support for std flag pkg users: glog, err2
		goflag.Parse()

		try.To(goflag.Set("logtostderr", "true"))
		handleViperFlags(cmd)
		glog.CopyStandardLogTo("ERROR") // for err2

		return nil
	},
}

// Execute root
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// To fix errors printed twice removing the cobra generators next
		// see: https://github.com/spf13/cobra/issues/304
		// fmt.Println(err)

		os.Exit(1)
	}
}

// RootCmd returns a current root command which can be used for adding own
// commands in an own repo.
//
//	implCmd.AddCommand(listCmd)
//
// That's a helper function to extend this CLI with own commands and offering
// same base commands as this CLI.
func RootCmd() *cobra.Command {
	return rootCmd
}

// DryRun returns a value of a dry run flag. That's a helper function to extend
// this CLI with own commands and offering same base commands as this CLI.
func DryRun() bool {
	return rootFlags.dryRun
}

func Flags() *RootFlags {
	return &rootFlags
}

// RootFlags are the common flags
type RootFlags struct {
	cfgFile string
	dryRun  bool
	codec   string
	Type    ArgType
}

// ClientFlags agent flags
type ClientFlags struct {
	WalletName string
	WalletKey  string
	URL        string
}

var rootFlags = RootFlags{}

var rootEnvs = map[string]string{
	"config":  "CONFIG",
	"dry-run": "DRY_RUN",
	"codec":   "CODEC",
	"type":    "TYPE",
}

func init() {
	defer err2.Catch()

	cobra.OnInitialize(initConfig)

	flags := rootCmd.PersistentFlags()
	flags.StringVar(&rootFlags.cfgFile, "config", "", FlagInfo("configuration file", "", rootEnvs["config"]))
	flags.BoolVarP(&rootFlags.dryRun, "dry-run", "n", false, FlagInfo("perform a trial run with no changes made", "", rootEnvs["dry-run"]))
	flags.StringVar(&rootFlags.codec, "codec", "json",
		FlagInfo("currently used codec with nats.io", "", rootEnvs["codec"]))
	try.To(rootFlags.Type.Set("db"))
	flags.VarP(&rootFlags.Type, "type", "t",
		FlagInfo("Type of arguments (db|digest|idk|alias)", "", rootEnvs["type"]))

	try.To(viper.BindPFlag("dry-run", flags.Lookup("dry-run")))

	try.To(BindEnvs(rootEnvs, ""))

	// NOTE! Very important. Adds support for std flag pkg users: glog, err2
	pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	rootCmd.SetUsageTemplate(customUsageTemplate)

	// Override the default help function, NOTE: we got exactly what we want with
	// the changed Usage Template where we removed Global Flgs section.
	// rootCmd.SetHelpFunc(myHelp)
	_ = myHelp
}

func myHelp(cmd *cobra.Command, args []string) {
	// Check if a specific help flag was provided
	showGlobalFlags := len(args) > 0 && args[0] == "global-flags"

	fmt.Println("Usage: myapp [flags] [command]")
	fmt.Println("\nCommands:")
	for _, c := range cmd.Commands() {
		fmt.Printf("  %-10s %s\n", c.Name(), c.Short)
	}
	fmt.Println("\nUse 'myapp help [command]' for more information about a command.")

	// Optionally show global flags
	if showGlobalFlags {
		fmt.Println("\nGlobal Flags:")
		cmd.PersistentFlags().PrintDefaults()
	}
}

func initConfig() {
	viper.SetEnvPrefix(envPrefix)
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)
	readConfigFile()
	readBoundRootFlags()
}

func readBoundRootFlags() {
	rootFlags.dryRun = viper.GetBool("dry-run")
}

func readConfigFile() {
	cfgEnv := os.Getenv(getEnvName("", "config"))
	if rootFlags.cfgFile != "" || cfgEnv != "" {
		printInfo := true
		if rootFlags.cfgFile == "" {
			rootFlags.cfgFile = cfgEnv
			printInfo = false
		}
		viper.SetConfigFile(rootFlags.cfgFile)
		// If a config file is found, read it in.
		if err := viper.ReadInConfig(); err == nil && printInfo {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		}
	}
}

// BindEnvs calls viper.BindEnv with envMap and cmdName which can be empty if
// flag is general.
func BindEnvs(envMap map[string]string, cmdName string) (err error) {
	defer err2.Handle(&err)
	for flagKey, envName := range envMap {
		finalEnvName := getEnvName(cmdName, envName)
		try.To(viper.BindEnv(flagKey, finalEnvName))
	}
	return nil
}

func FlagInfo(info, cmdPrefix, envName string) string {
	return info + ", " + getEnvName(cmdPrefix, envName)
}

func getEnvName(cmdName, envName string) string {
	if cmdName == "" {
		return envPrefix + "_" + strings.ToUpper(envName)
	}
	return envPrefix + "_" + strings.ToUpper(cmdName) + "_" + envName
}

func handleViperFlags(cmd *cobra.Command) {
	setRequiredStringFlags(cmd)
	if cmd.HasParent() {
		handleViperFlags(cmd.Parent())
	}
}

func setRequiredStringFlags(cmd *cobra.Command) {
	defer err2.Catch()

	try.To(viper.BindPFlags(cmd.LocalFlags()))
	if cmd.PreRunE != nil {
		try.To(cmd.PreRunE(cmd, nil))
	}
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if viper.GetString(f.Name) != "" {
			try.To(cmd.LocalFlags().Set(f.Name, viper.GetString(f.Name)))
		}
	})
}

// SubCmdNeeded prints the help and error messages because the cmd is abstract.
func SubCmdNeeded(cmd *cobra.Command) {
	fmt.Println("Subcommand needed!")
	_ = cmd.Help()
	os.Exit(1)
}

var customUsageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

Available Commands:{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{.Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

Additional Commands:{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
