package domain

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/ic/identity"
	"github.com/spf13/cobra"
)

// TODO: think about POW-lvl as and extra flag?

var domainNewDoc = `TODO`

var domainNewCmd = &cobra.Command{
	Use:   "new",
	Short: "creates a new trust domain",
	Long:  domainNewDoc,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		glog.V(3).Infoln("something...")
		identity := identity.NewRoot(nil) // TODO: check flags: Trust Domain node nees..
		_ = identity                      // to where we store this? From where we'll use it

		if identity.IsRoot() {
			fmt.Println("Root Domain Identity OK")
		}
		return nil
	},
}

func init() {
	defer err2.Catch()

	domainCmd.AddCommand(domainNewCmd)
}
