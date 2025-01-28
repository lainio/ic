package pw

import (
	"fmt"
	"math/rand/v2"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/hop"
	"github.com/lainio/ic/internal/protocol"
	"github.com/spf13/cobra"
)

var (
	pwHandshakeDoc = `The handshake command run the new pairwise build protocol.

We can either be the party hwo starts the protocol (addresser) or the party who
accept the protocol (addressee).

The command has several different ways to use it. The 'handshake' command takes two
arguments which point what Identities we handshakeing. The --type flag to tell
format used in arguments. Please see the examples for more information.`

	//nolint:gosec // we don't have hard-coded identities here
	pwHandshakeExample = `  # Identities can be given as DB IDs:
    tdc pw handshake --type=db 12 1
  # or give IDK string:
    tdc pw handshake --type=idk $(pbpaste) <from_typing>
`
)

var pwHandshakeCmd = &cobra.Command{
	Use:     "handshake",
	Short:   "handshake command executes a protocol to build persistent pairwise",
	Long:    pwHandshakeDoc,
	Example: pwHandshakeExample,
	Args:    cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		senderUser, rcvrUser := protocol.ReadParties(args...)

		// use full identities to get easily full picture about WoT
		senderIdentity := senderUser.Identity()
		rcvrIdentity := rcvrUser.Identity()
		wot := rcvrIdentity.WebOfTrust(*senderIdentity)
		if wot == nil || wot.Hops == hop.NotConnected {
			return fmt.Errorf("identities don't share trust domains")
		}
		Println(wot)

		protocol.IdInviteCmdData.RcvrUserID = rcvrUser.ID
		protocol.IdInviteCmdData.SenderUserID = senderUser.ID

		try.To(protocol.PairwiseHandshake(isAddresser))

		return nil
	},
}

func Println(a ...any) (n int) {
	if !plain {
		return try.To1(fmt.Println(a...))
	}
	return 0
}

var (
	isAddresser bool
	plain       bool
)

func init() {
	defer err2.Catch()

	flags := pwHandshakeCmd.PersistentFlags()
	flags.BoolVarP(&isAddresser, "addresser", "a", false,
		"handshake starts as addresser other side is addressee")

	flags.BoolVar(&plain, "plain", false,
		"plain print, i.e., only IDK, good for piping")

	flags.IntVar(
		&protocol.IdInviteCmdData.PinCode,
		"pin-code",
		rand.Int(), //nolint:gosec // UI simulation only!
		"secret PIN code for handshakes, etc.",
	)

	pwCmd.AddCommand(pwHandshakeCmd)
}
