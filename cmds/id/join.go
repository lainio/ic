package id

import (
	"github.com/lainio/ic/internal/protocol"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/spf13/cobra"
)

var (
	idJoinDoc = `The join command start handshake protocol part where our end accepts invitation.

The invitation protocol is relatively complex network protocol where two
parties: inviter and invitee (= we with the join command) build
cryptographically temperproof relationship between the parties. See more
information from the invittion command.`

	idJoinExample = `  # Both identities can be given as used DB ID (flags):
    tdc id invite --rcvr-user-id=12 --sender-user-id=1
  # or send Digest as a string from clipboard:
    tdc id belong --rcvr-user-id=12 $(pbpaste)`
)

var idJoinCmd = &cobra.Command{
	Use:     "join",
	Short:   "accepts an invitation to join a trust domains presented to a user",
	Long:    idJoinDoc,
	Example: idJoinExample,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		protocol.ReadUsersAndInitCodec()
		defer protocol.FlushAndCloseNats()

		try.To(protocol.InvitationHandshakeInvitee())

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := idJoinCmd.PersistentFlags()
	flags.IntVar(&protocol.IdInviteCmdData.PinCode, "pin-code", 1,
		"secret PIN code for handshakes, etc.",
	)
	try.To(idInviteCmd.MarkPersistentFlagRequired("pin-code"))

	flags.Uint32Var(&protocol.IdInviteCmdData.RcvrUserID, "rcvr-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["rcvr-user-id"]))
	try.To(idJoinCmd.MarkPersistentFlagRequired("rcvr-user-id"))

	flags.Uint32Var(&protocol.IdInviteCmdData.SenderUserID, "sender-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["sender-user-id"]))
	try.To(idInviteCmd.MarkPersistentFlagRequired("sender-user-id"))

	flags.StringVar(&protocol.IdInviteCmdData.Codec, "codec", "json",
		cmd.FlagInfo("currently used codec with nats.io", "", envs["codec"]))

	idCmd.AddCommand(idJoinCmd)
}
