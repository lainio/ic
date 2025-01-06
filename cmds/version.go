package cmds

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/utils"
	"github.com/spf13/cobra"
)

var versionDoc = ``

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints the version and build information of the CLI tool",
	Long:  versionDoc,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		glog.V(3).Infoln("print version string:", utils.Version)
		try.To1(fmt.Println(utils.Version))
		return nil
	},
}

func init() {
	defer err2.Catch()

	rootCmd.AddCommand(versionCmd)
}
