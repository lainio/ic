package id

import (
	"fmt"

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
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		readUsersAndInitCodec()
		defer flushAndCloseNats()

		try.To(invitationHandshakeInvitee())

		return nil
	},
}

func init() {
	defer err2.Catch()

	flags := idJoinCmd.PersistentFlags()
	flags.IntVar(&idInviteCmdData.PinCode, "pin-code", 0,
		"secret PIN code for handshakes, etc.",
	)
	try.To(idInviteCmd.MarkPersistentFlagRequired("pin-code"))

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
	defer assert.PushAsserter(assert.Plain)() // asserts as errors
	defer err2.Handle(&err, nil)

	listenInvitationCh, subject := makeInSubject(subjectInvitationPropose, idInviteCmdData.RcvrUserID)
	sendInvitationCh, subject2 := makeOutSubject(subjectInvitationReply, idInviteCmdData.RcvrUserID)

	glog.V(3).Infoln("0. IC count:", rcvrUser.Identity().ICCount())
	glog.V(3).Infoln("-- start to wait:", subject)
	fmt.Println(
		"Ready to listen inviter.",
		"\nPlease execute: `tdc id invite ..`, at their end.",
	)
	invitationPropose := <-listenInvitationCh //////////////////////////////
	glog.V(3).Infoln("<- we received invitation from:", invitationPropose.Sender.ID)

	defer err2.Handle(&err, onErrorInvitationReply(sendInvitationCh))

	assert.Equal(invitationPropose.Rcvr.ID, idInviteCmdData.RcvrUserID)
	assert.Equal(invitationPropose.Sender.ID, idInviteCmdData.SenderUserID)

	glog.V(3).Infoln("-- received invitation & challenge")
	pinCode := idInviteCmdData.PinCode
	challenge := chain.NewBlockFromData(invitationPropose.Challenge.Bytes())
	challenge.Position = pinCode

	kh := key.NewFromInfo(rcvrUser.KeyInfo)
	sig := try.To1(kh.Sign(challenge.Bytes()))
	glog.V(3).Infoln("signature ok", pinCode)

	me := Invitation{
		Sender: senderUser.RoleInfo,
		Rcvr:   rcvrUser.RoleInfo,

		Challenge:    challenge,
		ChallengeSig: sig,

		IdentityStr: rcvrUser.IdentityStr(),
	}

	glog.V(3).Infoln("-- signed challenge ready, let's send it to", subject2)
	sendInvitationCh <- me //////////////////////////////////////////

	glog.V(3).Infoln("-- start to wait reply", subject)

	reply := <-listenInvitationCh //////////////////////////////////////////
	glog.V(3).Infoln("-- received reply", me.Rcvr.ID, ", let's verify it..")

	assert.Empty(reply.Status, "inviter's error: %v", reply.Status)
	assert.NotEmpty(reply.IdentityStr)

	firstCount := rcvrUser.Identity().ICCount()
	idClone := rcvrUser.MakeIdentityFromStr(reply.IdentityStr)
	try.To(idClone.CheckIntegrity())
	glog.V(3).Infoln("<- we received invitation_ACK from:", reply.Sender.ID)
	rcvrUser.SetIdentity(idClone)
	secondCount := rcvrUser.Identity().ICCount()

	putUser(rcvrUser)

	fmt.Println("All OK, and introducing", secondCount-firstCount, "new Trust Domains")

	return nil
}

func putUser(u enclave.User) {
	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	glog.V(3).Infoln("*** put user, IC count:", u.Identity().ICCount())
	enclave.TryPutUser(u)
	enclave.TryClose()
}
