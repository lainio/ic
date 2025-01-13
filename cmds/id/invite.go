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

var (
	idInviteDoc = `The invite command start handshake protocol part where our end initiates
invitation process.

The invitation protocol is relatively complex network protocol where two
parties: inviter (we with the invite command) and invitee, build
cryptographically temperproof relationship between the parties. See more
information from the invition documentation from our web site.`

	idInviteExample = `  # Both identities can be given as used DB ID (flags):
  tdc id invite --rcvr-user-id=12 --sender-user-id=1
  # or send Digest as a string from clipboard:
  tdc id belong --rcvr-user-id=12 $(pbpaste)`
)

var idInviteCmd = &cobra.Command{
	Use:     "invite",
	Short:   "invites other party to our trust domains",
	Long:    idInviteDoc,
	Example: idInviteExample,
	RunE: func(_ *cobra.Command, _ []string) (err error) {
		defer err2.Handle(&err)

		readUsers()

		//codec := nconn.CBOR_DECODER
		codec := nats.JSON_ENCODER
		ec = nconn.New(codec).EncodedConn
		defer func() {
			glog.V(3).Infoln("closing nats")
			try.Out(ec.Drain()).Logf("drain failure")
			ec.Close()
		}()

		try.To(invitationHandshake())

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
	assert.Equal(reply.Challenge.Position, todoRandom, "wrong PIN code")

	pubKey := reply.Rcvr.KeyInfo.Public
	//pubKey := reply.Sender.KeyInfo.Public // Can be used to simulate failure

	//sigMsg := reply.Challenge.Bytes() // TODO: try with verify block
	sigMsg := verify.Bytes()
	//sigMsg := []byte{1,2,3,4,5}
	verified := reply.ChallengeSig.Verify(pubKey, sigMsg)
	assert.That(verified, "cannot verify signature")

	// Their identity comes thru msg as a string, bring up the instance
	rcvrUser.SetIdentityFromStr(reply.IdentityStr)
	assert.NotNil(rcvrUser.Identity())
	try.To(rcvrUser.Identity().CheckIntegrity())
	glog.V(3).Infoln("1. IC count:", rcvrUser.Identity().ICCount())
	invited := senderUser.Identity().Invite(
		*rcvrUser.Identity(),
		chain.WithEndpoint("TODO", true), // TODO: how to get from User?
	)
	rcvrUser.SetIdentity(&invited)               // set new invited identity
	try.To(rcvrUser.Identity().CheckIntegrity()) // double safety
	glog.V(3).Infoln("2. IC count:", rcvrUser.Identity().ICCount())
	invitedMsg := Invitation{
		Sender:      senderUser.RoleInfo,
		Rcvr:        rcvrUser.RoleInfo,
		IdentityStr: rcvrUser.IdentityStr(),
	}

	glog.V(3).Infoln("=== send new invited identity ===")
	sendInvitationCh <- invitedMsg

	// TODO: should we wait ACK from other end that the Invitation is DONE!

	glog.V(3).Infoln("--- we'll sleep, to not close too already", subject2)
	time.Sleep(10 * time.Millisecond) // TODO: do we need this? See Close ↑

	glog.V(3).Infoln("all OK")

	return nil
}

func readUsers() {
	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	senderUser = enclave.TryGetExistingUser(idInviteCmdData.SenderUserID)
	rcvrUser = enclave.TryGetExistingUser(idInviteCmdData.RcvrUserID)
	enclave.TryClose()
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
