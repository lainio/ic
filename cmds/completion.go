package cmds

import (
	"os"

	"github.com/spf13/cobra"
)

// completionCmd represents the completion command
var completionCmd = &cobra.Command{
	Use:   "completion",
	Short: "Generates shell completion scripts",
	Long: `
To load completion run following:

bash:
	source <(tdc completion bash)

zsh: 
	source <(tdc completion zsh)

To configure your shell to load completions for each session add command 
above to your shell configuration script (e.g. .bash_profile/.zshrc).

`,
	ValidArgs: []string{"bash", "zsh"},
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletion(os.Stdout)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
