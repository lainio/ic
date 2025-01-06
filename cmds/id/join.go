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
	"github.com/lainio/ic/internal/nconn"
	"github.com/lainio/ic/key"
	"github.com/spf13/cobra"
)

// TODO: think about POW-lvl as and extra flag?

var idJoinDoc = `TODO`

var idJoinCmd = &cobra.Command{
	Use:   "join",
	Short: "accepts an invitation to join a trust domains presented to a user",
	Long:  idJoinDoc,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		try.To(enclave.InitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey))
		senderUser = try.To1(enclave.GetExistingUser(idInviteCmdData.SenderUserID))
		rcvrUser = try.To1(enclave.GetExistingUser(idInviteCmdData.RcvrUserID))
		try.To(enclave.Close())

		codec := nconn.CBOR_DECODER
		ec = nconn.New(codec).EncodedConn
		defer func() {
			glog.V(3).Infoln("closing nats")
			ec.Close()
		}()

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

	idCmd.AddCommand(idJoinCmd)
}

func invitationHandshakeInvitee() (err error) {
	defer err2.Handle(&err)

	listenInvitationCh, subject := makeInSubject(subjectInvitationPropose, idInviteCmdData.RcvrUserID)
	sendInvitationCh, subject2 := makeOutSubject(subjectInvitationReply, idInviteCmdData.RcvrUserID)

	glog.V(3).Infoln("-- start to wait:", subject)
	invitationPropose := <-listenInvitationCh
	glog.V(3).Infoln("<- we received invitation from:", invitationPropose.Sender.ID)

	assert.Equal(invitationPropose.Rcvr.ID, idInviteCmdData.RcvrUserID)
	assert.Equal(invitationPropose.Sender.ID, idInviteCmdData.SenderUserID)
	//try.To(reply.Indentity.CheckIntegrity())

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
		//Indentity: identity.Identity{},
	}

	glog.V(3).Infoln("--- we'll sleep", subject2)
	time.Sleep(0 * time.Second)
	glog.V(3).Infoln("--- we'll send", subject2)
	sendInvitationCh <- me

	glog.V(3).Infoln("--> rcvr ID:", me.Rcvr.ID)
	glog.V(3).Infoln("--- we'll sleep", subject2)
	time.Sleep(4 * time.Second)
	// TODO: challenge

	return nil
}
