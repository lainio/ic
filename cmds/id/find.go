package id

import (
	"fmt"
	"strconv"

	"github.com/lainio/ic/internal/protocol"
	"github.com/lainio/ic/key"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/enclave"
	"github.com/spf13/cobra"
)

var idFindDoc = `The id find command finds identities according to given search parameters.

The command can be used to find identities by their direct attributes or by the
properties of their trust domains. Please see the examples for more
information.`

var idFindExample = `  # Find by user DB ID (pratically same as view command):
    tdc id find 13
  # find by digest (base58 formatted):
    tdc id find --use-digest $(pbpaste) # digest is in clipboard
  # find by a public key:
    tdc id find TJtNVsFBQBynnV
  # find by trust domain root public key (list all who belongs to that domain):
    tdc id find --domain-pk TJtNVsFBQBynnV`

var idFindCmd = &cobra.Command{
	Use:     "find",
	Short:   "lists all trust ids for a user",
	Long:    idFindDoc,
	Example: idFindExample,
	Args:    cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer err2.Handle(&err, nil)

		assert.SLonger(args, 0, "user ID: argument missing")

		enclave.TryInitSealedBox(
			protocol.CmdData.WalletFilename,
			"",
			protocol.CmdData.MasterKey,
		)

		// TODO: check if we could change this to protocol.readParties
		// OR merge with the else branch
		if len(args[0]) < key.PKLen {
			users := enclave.TryGetAllUsersByIDKPrefix(args[0])
			try.To(enclave.Close())
			for _, u := range users {
				if idFindCmdData.PrintIDOnly {
					fmt.Println(u.ID)
				} else {
					printInfoln(u, true)
				}
			}
			return nil
		}
		users := enclave.TryGetAllUsers()
		try.To(enclave.Close())

		for _, u := range users {
			if calcSearch(args[0], u) {
				printInfoln(u, true)
			}
		}

		return nil
	},
}

var idFindCmdData = struct {
	DomainPK  bool
	UseDigest bool

	PrintIDOnly bool
}{}

func calcSearch(s string, u enclave.User) bool {
	if idFindCmdData.UseDigest {
		uDigest := u.Identity().Digest().Base58()
		return uDigest == s
	}

	var (
		pkStr  string
		id     uint32
		retval bool
	)
	if len(s) == key.PKLen {
		pkStr = s
	} else {
		id = uint32(try.To1(strconv.Atoi(s))) //nolint
	}
	if idFindCmdData.DomainPK {
		for _, ic := range u.Identity().InviteeChains {
			if ic.FirstBlock().Invitee.PKString() == pkStr {
				retval = true
				break
			}
		}
	} else {
		retval = u.EqualPK(pkStr) || u.ID == id
	}
	return retval
}

func init() {
	defer err2.Catch()

	flags := idFindCmd.PersistentFlags()
	flags.BoolVar(&idFindCmdData.DomainPK, "domain-pk", false,
		"instead of IDK, use Domain Root PK for search")
	flags.BoolVar(&idFindCmdData.UseDigest, "use-digest", false,
		"use full digest to find all which have similar one")
	flags.BoolVar(&idFindCmdData.PrintIDOnly, "id", false,
		"print only db id, good for piping, TODO only prefix")

	idCmd.AddCommand(idFindCmd)
}
