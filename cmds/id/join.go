package id

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/lainio/ic/key"
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
		defer err2.Handle(&err)

		readUsersAndInitCodec()

		defer flushAndCloseNats()

		try.To(invitationHandshakeInvitee())

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := idJoinCmd.PersistentFlags()
	flags.Uint32Var(&idInviteCmdData.RcvrUserID, "rcvr-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["rcvr-user-id"]))
	try.To(idJoinCmd.MarkPersistentFlagRequired("rcvr-user-id"))

	flags.Uint32Var(&idInviteCmdData.SenderUserID, "sender-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["sender-user-id"]))
	try.To(idInviteCmd.MarkPersistentFlagRequired("sender-user-id"))

	flags.StringVar(&idInviteCmdData.Codec, "codec", "json",
		cmd.FlagInfo("currently used codec with nats.io", "", envs["codec"]))

	idCmd.AddCommand(idJoinCmd)
}

func invitationHandshakeInvitee() (err error) {
	defer err2.Handle(&err)

	listenInvitationCh, subject := makeInSubject(subjectInvitationPropose, idInviteCmdData.RcvrUserID)
	sendInvitationCh, subject2 := makeOutSubject(subjectInvitationReply, idInviteCmdData.RcvrUserID)

	glog.V(3).Infoln("0. IC count:", rcvrUser.Identity().ICCount())
	glog.V(3).Infoln("-- start to wait:", subject)
	invitationPropose := <-listenInvitationCh
	glog.V(3).Infoln("<- we received invitation from:", invitationPropose.Sender.ID)

	assert.Equal(invitationPropose.Rcvr.ID, idInviteCmdData.RcvrUserID)
	assert.Equal(invitationPropose.Sender.ID, idInviteCmdData.SenderUserID)

	todoRandom := 1234 // TODO: implement in utils or...
	fmt.Println("pin CODE:", todoRandom)
	challenge := chain.NewBlockFromData(invitationPropose.Challenge.Bytes())
	challenge.Position = todoRandom

	kh := key.NewFromInfo(rcvrUser.KeyInfo)
	sig := try.To1(kh.Sign(challenge.Bytes()))
	glog.V(3).Infoln("signature ok", todoRandom)

	me := Invitation{
		Sender: senderUser.RoleInfo,
		Rcvr:   rcvrUser.RoleInfo,

		Challenge:    challenge,
		ChallengeSig: sig,

		IdentityStr: rcvrUser.IdentityStr(),
	}

	glog.V(3).Infoln("--- we'll sleep", subject2)
	time.Sleep(0 * time.Second)
	glog.V(3).Infoln("--- we'll send", subject2)
	sendInvitationCh <- me

	glog.V(3).Infoln("--> rcvr ID:", me.Rcvr.ID)

	reply := <-listenInvitationCh
	assert.NotEmpty(reply.IdentityStr)
	rcvrUser.SetIdentityFromStr(reply.IdentityStr)
	glog.V(3).Infoln("<- we received invitation_ACK from:", reply.Sender.ID)
	glog.V(3).Infoln("IC count:", rcvrUser.Identity().ICCount())
	try.To(rcvrUser.Identity().CheckIntegrity())

	putUser(rcvrUser)
	glog.V(3).Infoln("IC count:", rcvrUser.Identity().ICCount())

	glog.V(3).Infoln("--- all OK", subject2)

	return nil
}

func putUser(u enclave.User) {
	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	glog.V(3).Infoln("*** put user, IC count:", u.Identity().ICCount())
	enclave.TryPutUser(u)
	enclave.TryClose()
}
