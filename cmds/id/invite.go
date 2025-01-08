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
	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
)

// TODO: think about POW-lvl as and extra flag?

var idInviteDoc = `TODO`

var idInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "invites other party to our trust domains",
	Long:  idInviteDoc,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		try.To(enclave.InitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey))
		senderUser = try.To1(enclave.GetExistingUser(idInviteCmdData.SenderUserID))
		rcvrUser = try.To1(enclave.GetExistingUser(idInviteCmdData.RcvrUserID))
		try.To(enclave.Close())

		//codec := nconn.CBOR_DECODER
		codec := nats.JSON_ENCODER
		ec = nconn.New(codec).EncodedConn
		defer func() {
			glog.V(3).Infoln("closing nats")
			try.Out(ec.Drain()).Logf("drain failure")
			ec.Close()
		}()

		try.To(invitationHandshake())
		// TODO: --------------------------------------
		//  - how to do it with CLI, when we don't have data channel
		//  - how about use nats-io!
		//  - generate invitation> what is this?
		//  = how to do challenge!
		//user.Identity().Invite()

		return nil
	},
}

var idInviteCmdData = struct {
	SenderUserID uint32
	RcvrUserID   uint32
}{}

var (
	senderUser enclave.User
	rcvrUser   enclave.User

	ec *nats.EncodedConn
)

func init() {
	defer err2.Catch()

	flags := idInviteCmd.PersistentFlags()
	flags.Uint32Var(&idInviteCmdData.RcvrUserID, "rcvr-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["rcvr-user-id"]))
	try.To(idInviteCmd.MarkPersistentFlagRequired("rcvr-user-id"))

	flags.Uint32Var(&idInviteCmdData.SenderUserID, "sender-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["sender-user-id"]))
	try.To(idInviteCmd.MarkPersistentFlagRequired("sender-user-id"))

	idCmd.AddCommand(idInviteCmd)
}

func invitationHandshake() (err error) {
	defer err2.Handle(&err)

	sendInvitationCh, subject := makeOutSubject(subjectInvitationPropose, idInviteCmdData.RcvrUserID)
	listenInvitationCh, subject2 := makeInSubject(subjectInvitationReply, idInviteCmdData.RcvrUserID)

	glog.V(3).Infoln("--- we'll send", subject)

	todoRandom := 1234 // TODO: implement in utils or...
	challenge, verify := chain.NewVerifyBlock(todoRandom)
	invitationProposal := Invitation{
		Sender:    senderUser.RoleInfo,
		Rcvr:      rcvrUser.RoleInfo,
		Challenge: challenge,
		//Indentity: ,
	}
	assert.Equal(verify.Position, todoRandom)

	fmt.Println("pin CODE:", todoRandom)

	glog.V(3).Infoln("=== send ===")
	sendInvitationCh <- invitationProposal

	glog.V(3).Infoln(
		"--> sender ID", invitationProposal.Sender.ID,
		"rcvr ID", invitationProposal.Rcvr.ID,
	)

	glog.V(3).Infoln("--- we'll start to listen", subject2)
	glog.V(3).Infoln("=== listen ===")
	reply := <-listenInvitationCh

	glog.V(3).Infoln("=== reply received")

	assert.Equal(reply.Rcvr.ID, idInviteCmdData.RcvrUserID)
	assert.Equal(reply.Sender.ID, idInviteCmdData.SenderUserID)
	//try.To(reply.Indentity.CheckIntegrity())

	// TODO: verify
	assert.Equal(reply.Challenge.Position, todoRandom, "wrong PIN code")

	pubKey := reply.Rcvr.KeyInfo.Public
	//pubKey := reply.Sender.KeyInfo.Public // Can be used to simulate failure

	//sigMsg := reply.Challenge.Bytes() // TODO: try with verify block
	sigMsg := verify.Bytes()
	//sigMsg := []byte{1,2,3,4,5}
	verified := reply.ChallengeSig.Verify(pubKey, sigMsg)
	assert.That(verified, "cannot verify signature")

	// TODO: send invitation Identity
	rcvrUser.SetIdentityFromStr(reply.IdentityStr)
	assert.NotNil(rcvrUser.Identity())
	glog.V(3).Infoln("1. IC count:", rcvrUser.Identity().ICCount())
	glog.V(3).Infoln("invite!!!")
	invited := senderUser.Identity().Invite(
		*rcvrUser.Identity(),
		chain.WithEndpoint("TODO", true),
	)
	_ = invited // TODO
	rcvrUser.SetIdentity(&invited)
	try.To(rcvrUser.Identity().CheckIntegrity())
	glog.V(3).Infoln("2. IC count:", rcvrUser.Identity().ICCount())
	invitedMsg := Invitation{
		Sender:      senderUser.RoleInfo,
		Rcvr:        rcvrUser.RoleInfo,
		IdentityStr: rcvrUser.IdentityStr(),
	}

	glog.V(3).Infoln("=== send new invited identity ===")
	sendInvitationCh <- invitedMsg

	glog.V(3).Infoln("--- we'll sleep, to not close too already", subject2)
	time.Sleep(100 * time.Millisecond)

	glog.V(3).Infoln("all OK")

	return nil
}

func makeInSubject(base string, target uint32) (chan Invitation, string) {
	invitationCh := make(chan Invitation)
	subject := fmt.Sprintf(
		"%s_%d", base, target,
	)
	tryBindInChannelToSubject(subject, invitationCh)
	glog.V(3).Infoln("=== In CHANNEL created: ", subject)
	return invitationCh, subject
}

func makeOutSubject(base string, target uint32) (chan Invitation, string) {
	invitationCh := make(chan Invitation)
	subject := fmt.Sprintf(
		"%s_%d", base, target,
	)
	tryBindOutChannelToSubject(subject, invitationCh)
	glog.V(3).Infoln("=== Out CHANNEL created: ", subject)
	return invitationCh, subject
}

func tryBindOutChannelToSubject(subject string, invitationCh chan Invitation) {
	try.To(ec.BindSendChan(subject, invitationCh))
}

func tryBindInChannelToSubject(subject string, invitationCh chan Invitation) {
	try.To1(ec.BindRecvChan(subject, invitationCh))
}

type Invitation struct {
	Sender enclave.RoleInfo // both parties..
	Rcvr   enclave.RoleInfo // ..  keep them same

	Challenge    chain.Block
	ChallengeSig key.Signature // only in reply

	IdentityStr string // CBOR string in base58
	//Identity *identity.Identity // not used yet
}

const (
	subjectInvitationPropose = "INVITATION_PROPOSE"
	subjectInvitationReply   = "INVITATION_REPLY"
	subjectInvitationACK     = "INVITATION_ACK"
)
