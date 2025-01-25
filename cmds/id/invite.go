package id

import (
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/internal/protocol"
	"github.com/spf13/cobra"
)

var (
	idInviteDoc = `The invite command start handshake protocol part where our end initiates
invitation process.

The invitation protocol is relatively complex network protocol where two
parties: inviter (= we with the invite command) and invitee, build
cryptographically temperproof relationship between the parties. See more
information from the invition documentation from our web site.`

	idInviteExample = `  # Both identities can be given as used DB ID (flags):
    tdc id invite --rcvr-user-id=12 --sender-user-id=1
  # or send to Digest as a string from clipboard:
    tdc id invite --rcvr-user-idk=$(pbpaste) --sender-user-id=1` // TODO: impl
)

var idInviteCmd = &cobra.Command{
	Use:     "invite",
	Short:   "invites other party to our trust domains",
	Long:    idInviteDoc,
	Example: idInviteExample,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		protocol.ReadUsersAndInitCodec()
		defer protocol.FlushAndCloseNats()

		try.To(protocol.InvitationHandshake())

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := idInviteCmd.PersistentFlags()
	flags.IntVar(&protocol.IdInviteCmdData.PinCode, "pin-code", 1,
		"secret PIN code for handshakes, etc.",
	)
	try.To(idInviteCmd.MarkPersistentFlagRequired("pin-code"))

	flags.Uint32Var(&protocol.IdInviteCmdData.SenderUserID, "sender-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["sender-user-id"]))
	try.To(idInviteCmd.MarkPersistentFlagRequired("sender-user-id"))

	flags.Uint32Var(&protocol.IdInviteCmdData.RcvrUserID, "rcvr-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["rcvr-user-id"]))
	try.To(idInviteCmd.MarkPersistentFlagRequired("rcvr-user-id"))

	flags.StringVar(&protocol.IdInviteCmdData.Codec, "codec", "json",
		cmd.FlagInfo("currently used codec with nats.io", "", envs["codec"]))

	idCmd.AddCommand(idInviteCmd)
}
