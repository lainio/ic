package id

import (
	"math/rand/v2"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/protocol"
	"github.com/spf13/cobra"
)

var (
	idIntroduceDoc = `The introduce command run the new pairwise build protocol.

We can either be the party hwo starts the protocol (addresser) or the party who
accept the protocol (addressee).

The command has several different ways to use it. The 'introduce' command takes two
arguments which point what Identities we introduceing. The --type flag to tell
format used in arguments. Please see the examples for more information.`

	idIntroduceExample = `  # Identities can be given as DB IDs:
    tdc id introduce --type=db 12 1
  # or give IDK string:
    tdc id introduce --type=idk $(pbpaste) <from_typing>
`
)

var idIntroduceCmd = &cobra.Command{
	Use:     "introduce",
	Short:   "introduces new party to existing trust domains",
	Long:    idIntroduceDoc,
	Example: idIntroduceExample,
	Args:    cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		senderUser, rcvrUser := protocol.ReadParties(args...)

		protocol.IdInviteCmdData.RcvrUserID = rcvrUser.ID
		protocol.IdInviteCmdData.SenderUserID = senderUser.ID

		if addresser {
			try.To(protocol.InvitationHandshake())
		} else {
			try.To(protocol.InvitationHandshakeInvitee())
		}

		return nil
	},
}

var (
	addresser bool
)

func init() {
	defer err2.Catch()

	flags := idIntroduceCmd.PersistentFlags()
	flags.BoolVarP(&addresser, "addresser", "a", false,
		"handshake starts as addresser other side is addressee")

	flags.IntVar(
		&protocol.IdInviteCmdData.PinCode,
		"pin-code",
		rand.Int(), //nolint:gosec // UI simulation only!
		"secret PIN code for handshakes, etc.",
	)

	idCmd.AddCommand(idIntroduceCmd)
}
