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

		readUsersAndInitCodec()
		defer flushAndCloseNats()

		try.To(invitationHandshake())

		return nil
	},
}

var idInviteCmdData = struct {
	SenderUserID uint32
	RcvrUserID   uint32
	Codec        string
	PinCode      int
}{}

var (
	senderUser enclave.User
	rcvrUser   enclave.User

	ec *nats.EncodedConn
)

func init() {
	defer err2.Catch()

	flags := idInviteCmd.PersistentFlags()
	flags.IntVar(&idInviteCmdData.PinCode, "pin-code", 0,
		"secret PIN code for handshakes, etc.",
	)
	try.To(idInviteCmd.MarkPersistentFlagRequired("pin-code"))

	flags.Uint32Var(&idInviteCmdData.SenderUserID, "sender-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["sender-user-id"]))
	try.To(idInviteCmd.MarkPersistentFlagRequired("sender-user-id"))

	flags.Uint32Var(&idInviteCmdData.RcvrUserID, "rcvr-user-id", 0,
		cmd.FlagInfo("current user ID", "", envs["rcvr-user-id"]))
	try.To(idInviteCmd.MarkPersistentFlagRequired("rcvr-user-id"))

	flags.StringVar(&idInviteCmdData.Codec, "codec", "json",
		cmd.FlagInfo("currently used codec with nats.io", "", envs["codec"]))

	idCmd.AddCommand(idInviteCmd)
}

func invitationHandshake() (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	sendInvitationCh, subject := makeOutSubject(subjectInvitationPropose, idInviteCmdData.RcvrUserID)
	listenInvitationCh, subject2 := makeInSubject(subjectInvitationReply, idInviteCmdData.RcvrUserID)

	glog.V(3).Infoln("--- we'll build invitation & challenge", subject)

	pinCode := idInviteCmdData.PinCode
	challenge, verify := chain.NewVerifyBlock(pinCode)
	invitationProposal := Invitation{
		Sender:    senderUser.RoleInfo,
		Rcvr:      rcvrUser.RoleInfo,
		Challenge: challenge,
	}
	assert.Equal(verify.Position, pinCode, "challeng building error")

	glog.V(3).Infoln("=== send ===")
	sendInvitationCh <- invitationProposal ////////////////////////////////

	glog.V(3).Infoln(
		"--> sender ID", invitationProposal.Sender.ID,
		"rcvr ID", invitationProposal.Rcvr.ID,
		subject2,
	)

	reply := <-listenInvitationCh /////////////////////////////////////////
	glog.V(3).Infoln("=== challenge+reply received", subject2)

	defer err2.Handle(&err, onErrorInvitationReply(sendInvitationCh))

	assert.Equal(reply.Rcvr.ID, idInviteCmdData.RcvrUserID,
		"join cmd's user-rcvr-id (%v) not equal to our flag value (%v)",
		reply.Rcvr.ID, idInviteCmdData.RcvrUserID,
	)
	assert.Equal(
		reply.Sender.ID, idInviteCmdData.SenderUserID,
		"join cmd's user-sender-id (%v) not equal to our flag value (%v)",
		reply.Sender.ID, idInviteCmdData.SenderUserID,
	)
	assert.Equal(reply.Challenge.Position, pinCode,
		"wrong PIN code in the challenge")

	pubKey := reply.Rcvr.KeyInfo.Public

	// We'll use our end's msg data that the other end cannot just sign some
	// other block!!
	sigMsg := verify.Bytes()
	// We use their signature and their pubKey, but our constructed msg. If not
	// we should verify their given message separately.
	verified := reply.ChallengeSig.Verify(pubKey, sigMsg)
	assert.That(verified, "cannot verify signature")

	// Their identity comes thru msg as a string, bring up the instance
	rcvrUser.SetIdentityFromStr(reply.IdentityStr)
	assert.NotNil(rcvrUser.Identity(), "cannot read & create identity")
	try.To(rcvrUser.Identity().CheckIntegrity())

	firstCount := rcvrUser.Identity().ICCount() // user reporting
	invited := senderUser.Identity().Invite(
		*rcvrUser.Identity(),
		// TODO: how to get from the other end User? Property list in reply?
		// TODO: which side decides if there is conflict?
		chain.WithEndpoint("TODO", true),
	)
	rcvrUser.SetIdentity(&invited) // set new invited identity
	// let's check that everything is OK before sending it forward
	try.To(rcvrUser.Identity().CheckIntegrity())
	secondCount := rcvrUser.Identity().ICCount() // user reporting
	invitedMsg := Invitation{
		Sender:      senderUser.RoleInfo,
		Rcvr:        rcvrUser.RoleInfo,
		IdentityStr: rcvrUser.IdentityStr(),
	}

	fmt.Println(
		"All OK, and introducing",
		secondCount-firstCount,
		"new Trust Domains",
	)
	sendInvitationCh <- invitedMsg ////////////////////////////////////////

	// TODO: should we wait ACK from other end that the Invitation is DONE!
	//  - maybe the cannot save data or some other exception happens
	//  - if we rely on their successful, which might be the case in other
	//  protocols...

	// TODO: their ACK would be the place to save something in this end if..

	return nil
}

// TODO: refactor to root lvl ////////////////////////////////////////////

func onErrorInvitationReply(sendInvitationCh chan Invitation) err2.Handler {
	return func(err error) error {
		invitedMsg := Invitation{
			Status: err.Error(),
			Sender: senderUser.RoleInfo,
			Rcvr:   rcvrUser.RoleInfo,
		}
		glog.V(5).Infoln("--- error handler")
		sendInvitationCh <- invitedMsg
		time.Sleep(100 * time.Millisecond) // Flush isn't enough!
		ec.Flush()
		glog.V(5).Infoln("--- error handler sent")
		return err
	}
}

func readUsersAndInitCodec() {
	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	senderUser = enclave.TryGetExistingUser(idInviteCmdData.SenderUserID)
	rcvrUser = enclave.TryGetExistingUser(idInviteCmdData.RcvrUserID)
	enclave.TryClose()

	codec := idInviteCmdData.Codec
	ec = nconn.New(codec).EncodedConn
}
func flushAndCloseNats() {
	defer err2.Catch()

	glog.V(3).Infoln("closing nats")
	try.Out(ec.Flush()).Logf("flush failure")
	ec.Close()
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

// Invitation TODO: should we try to do already some meta modeling? E.g. we
// have IdentityStr field which is very specific. Maybe we should rename it at
// least before we continue with the pw.Connection?
type Invitation struct {
	Status string

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
