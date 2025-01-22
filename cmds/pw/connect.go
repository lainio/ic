package pw

import (
	"fmt"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/lainio/ic/hop"
	"github.com/nats-io/nats.go"
	"github.com/spf13/cobra"
)

var (
	pwConnectDoc = `The connect command run the new pairwise build protocol.

We can either be the party hwo starts the protocol (addresser) or the party who
accept the protocol (addressee).

The command has several different ways to use it. The 'connect' command takes two
arguments which point what Identities we connecting. The --type flag to tell
format used in arguments. Please see the examples for more information.`

	//nolint:gosec // we don't have hard-coded identities here
	pwConnectExample = `  # Identities can be given as DB IDs:
    tdc pw connect --type=db 12 1
  # or give IDK string:
    tdc pw connect --type=idk $(pbpaste) <from_typing>
`
)

var pwConnectCmd = &cobra.Command{
	Use:     "connect",
	Short:   "list all trust domains we connect",
	Long:    pwConnectDoc,
	Example: pwConnectExample,
	Args:    cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) (err error) {
		defer assert.PushAsserter(assert.Plain)()
		defer err2.Handle(&err, nil)

		enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)

		senderUser := enclave.TryGetExistingUserByType(
			cmd.Flags().Type.String(),
			args[0],
		)
		rcvrUser := enclave.TryGetExistingUserByType(
			cmd.Flags().Type.String(),
			args[1],
		)
		enclave.TryClose()

		pwFromDig := senderUser.Identity()
		wot := rcvrUser.Identity().WebOfTrust(*pwFromDig)
		if wot == nil || wot.Hops == hop.NotConnected {
			return fmt.Errorf("identities don't share trust domains")
		}
		fmt.Println(wot)

		// TODO: start the pw protocol
		try.To(invitationHandshake())

		return nil
	},
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
var (
	addresser bool

	senderUser enclave.User
	rcvrUser   enclave.User

	ec *nats.EncodedConn
)

func init() {
	defer err2.Catch()

	flags := pwConnectCmd.PersistentFlags()
	flags.BoolVarP(&addresser, "addresser", "a", false,
		"handshake starts as addresser other side is addressee")

	pwCmd.AddCommand(pwConnectCmd)
}

// TODO: refactor to root lvl ////////////////////////////////////////////
const (
	subjectInvitationPropose = "PW_PROPOSE"
	subjectInvitationReply   = "PW_REPLY"
	subjectInvitationACK     = "PW_ACK"
)
