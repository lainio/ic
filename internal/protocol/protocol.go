package protocol

import (
	"errors"
	"fmt"
	"time"

	"github.com/lainio/ic/cmds"

	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/chain"
	"github.com/lainio/ic/enclave"
	"github.com/lainio/ic/internal/nconn"
	"github.com/lainio/ic/key"
	"github.com/nats-io/nats.go"
)

var (
	SenderUser enclave.User
	RcvrUser   enclave.User

	Ec *nats.EncodedConn
)

func PairwiseHandshake() (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	assert.NotZero(IdInviteCmdData.RcvrUserID)

	pwSendCh, pwSendSubject := MakeOutSubject(
		subjectPairwisePropose,
		IdInviteCmdData.RcvrUserID,
	)
	pwListenCh, pwListenSub := MakeInSubject(
		subjectPairwiseReply,
		IdInviteCmdData.RcvrUserID,
	)

	glog.V(3).Infoln("--- we'll build PW: invitation & challenge", pwSendSubject)

	pinCode := IdInviteCmdData.PinCode
	challenge, verify := chain.NewVerifyBlock(pinCode)
	invitationProposal := Invitation{
		Sender:    SenderUser.RoleInfo,
		Rcvr:      RcvrUser.RoleInfo,
		Challenge: challenge,
	}
	assert.Equal(verify.Position, pinCode, "challenge building error")

	glog.V(3).Infoln("*** send ***")
	pwSendCh <- invitationProposal ////////////////////////////////

	glog.V(3).Infoln(
		"--> sender ID", invitationProposal.Sender.ID,
		"rcvr ID", invitationProposal.Rcvr.ID,
		pwListenSub,
	)

	reply := <-pwListenCh /////////////////////////////////////////
	glog.V(3).Infoln("=== pairwise received", pwListenSub)

	defer err2.Handle(&err, OnErrorReply(pwSendCh, PWType))

	assert.Equal(reply.Rcvr.ID, IdInviteCmdData.RcvrUserID,
		"join cmd's user-rcvr-id (%v) not equal to our flag value (%v)",
		reply.Rcvr.ID, IdInviteCmdData.RcvrUserID,
	)
	assert.Equal(
		reply.Sender.ID, IdInviteCmdData.SenderUserID,
		"join cmd's user-sender-id (%v) not equal to our flag value (%v)",
		reply.Sender.ID, IdInviteCmdData.SenderUserID,
	)
	assert.Equal(reply.Challenge.Position, pinCode,
		"wrong PIN code in the challenge")

	pubKey := reply.Rcvr.KeyInfo.Public

	// We'll use our end's msg data that the other end cannot just sign some
	// other block!!
	msgToSign := verify.Bytes()
	// We use their signature and their pubKey, but our constructed msg. If not
	// we should verify their given message separately.
	verified := reply.ChallengeSig.Verify(pubKey, msgToSign)
	assert.That(verified, "cannot verify signature")

	// Their identity comes thru msg as a string, bring up the instance
	RcvrUser.SetIdentityFromStr(reply.IdentityStr)
	assert.NotNil(RcvrUser.Identity(), "cannot read & create identity")
	try.To(RcvrUser.Identity().CheckIntegrity())

	firstCount := RcvrUser.Identity().ICCount() // user reporting
	invited := SenderUser.Identity().Invite(
		*RcvrUser.Identity(),
		// TODO: how to get from the other end User? Property list in reply?
		// TODO: which side decides if there is conflict?
		chain.WithEndpoint("TODO", true),
	)
	RcvrUser.SetIdentity(&invited) // set new invited identity
	// let's check that everything is OK before sending it forward
	try.To(RcvrUser.Identity().CheckIntegrity())
	secondCount := RcvrUser.Identity().ICCount() // user reporting
	invitedMsg := Invitation{
		Type:        PWType,
		Sender:      SenderUser.RoleInfo,
		Rcvr:        RcvrUser.RoleInfo,
		IdentityStr: RcvrUser.IdentityStr(),
	}

	fmt.Println(
		"All OK, and introducing",
		secondCount-firstCount,
		"new Trust Domains",
	)
	pwSendCh <- invitedMsg ////////////////////////////////////////

	// TODO: should we wait ACK from other end that the Invitation is DONE!
	//  - maybe the cannot save data or some other exception happens
	//  - if we rely on their successful, which might be the case in other
	//  protocols...

	// TODO: their ACK would be the place to save something in this end if..

	return nil
}

// TODO: simalar to PairwiseHandshake

func InvitationHandshake() (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)

	sendInvitationCh, subject := MakeOutSubject(SubjectInvitationPropose, IdInviteCmdData.RcvrUserID)
	listenInvitationCh, subject2 := MakeInSubject(SubjectInvitationReply, IdInviteCmdData.RcvrUserID)

	glog.V(3).Infoln("--- we'll build invitation & challenge", subject)

	pinCode := IdInviteCmdData.PinCode
	challenge, verify := chain.NewVerifyBlock(pinCode)
	invitationProposal := Invitation{
		Type:      InvitationType,
		Sender:    SenderUser.RoleInfo,
		Rcvr:      RcvrUser.RoleInfo,
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

	defer err2.Handle(&err, OnErrorReply(sendInvitationCh, InvitationType))

	assert.Equal(reply.Rcvr.ID, IdInviteCmdData.RcvrUserID,
		"join cmd's user-rcvr-id (%v) not equal to our flag value (%v)",
		reply.Rcvr.ID, IdInviteCmdData.RcvrUserID,
	)
	assert.Equal(
		reply.Sender.ID, IdInviteCmdData.SenderUserID,
		"join cmd's user-sender-id (%v) not equal to our flag value (%v)",
		reply.Sender.ID, IdInviteCmdData.SenderUserID,
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
	RcvrUser.SetIdentityFromStr(reply.IdentityStr)
	assert.NotNil(RcvrUser.Identity(), "cannot read & create identity")
	try.To(RcvrUser.Identity().CheckIntegrity())

	firstCount := RcvrUser.Identity().ICCount() // user reporting
	invited := SenderUser.Identity().Invite(
		*RcvrUser.Identity(),
		// TODO: how to get from the other end User? Property list in reply?
		// TODO: which side decides if there is conflict?
		chain.WithEndpoint("TODO", true),
	)
	RcvrUser.SetIdentity(&invited) // set new invited identity
	// let's check that everything is OK before sending it forward
	try.To(RcvrUser.Identity().CheckIntegrity())
	secondCount := RcvrUser.Identity().ICCount() // user reporting
	invitedMsg := Invitation{
		Type:        InvitationType,
		Sender:      SenderUser.RoleInfo,
		Rcvr:        RcvrUser.RoleInfo,
		IdentityStr: RcvrUser.IdentityStr(),
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

func OnErrorReply(sendInvitationCh chan Invitation, Type ProtType) err2.Handler {
	return func(err error) error {
		invitedMsg := Invitation{
			Type:   Type,
			Status: err.Error(),
			Sender: SenderUser.RoleInfo,
			Rcvr:   RcvrUser.RoleInfo,
		}
		glog.V(5).Infoln("--- error handler")
		sendInvitationCh <- invitedMsg
		time.Sleep(100 * time.Millisecond) // Flush isn't enough!
		Ec.Flush()
		glog.V(5).Infoln("--- error handler sent")
		return err
	}
}

func ReadUsersAndInitCodec() {
	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	SenderUser = enclave.TryGetExistingUser(IdInviteCmdData.SenderUserID)
	RcvrUser = enclave.TryGetExistingUser(IdInviteCmdData.RcvrUserID)
	enclave.TryClose()

	codec := IdInviteCmdData.Codec
	Ec = nconn.New(codec).EncodedConn
}

func FlushAndCloseNats() {
	defer err2.Catch()

	glog.V(3).Infoln("closing nats")
	try.Out(Ec.Flush()).Logf("flush failure")
	Ec.Close()
}

func MakeInSubject(base string, target uint32) (chan Invitation, string) {
	invitationCh := make(chan Invitation)
	subject := fmt.Sprintf(
		"%s_%d", base, target,
	)
	TryBindInChannelToSubject(subject, invitationCh)
	glog.V(3).Infoln("=== In CHANNEL created: ", subject)
	return invitationCh, subject
}

func MakeOutSubject(base string, target uint32) (chan Invitation, string) {
	invitationCh := make(chan Invitation)
	subject := fmt.Sprintf(
		"%s_%d", base, target,
	)
	TryBindOutChannelToSubject(subject, invitationCh)
	glog.V(3).Infoln("=== Out CHANNEL created: ", subject)
	return invitationCh, subject
}

func ReadParties(senderArg, rcvrArg string) (s, r enclave.User) {
	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	senderUser := enclave.TryGetExistingUserByType(
		cmds.Flags().Type.String(),
		senderArg,
	)
	rcvrUser := enclave.TryGetExistingUserByType(
		cmds.Flags().Type.String(),
		rcvrArg,
	)
	enclave.TryClose()
	codec := IdInviteCmdData.Codec
	Ec = nconn.New(codec).EncodedConn
	return senderUser, rcvrUser
}

func TryBindOutChannelToSubject(subject string, invitationCh chan Invitation) {
	assert.NotNil(Ec)
	assert.NotEmpty(subject)
	assert.CNotNil(invitationCh)
	try.To(Ec.BindSendChan(subject, invitationCh))
}

func TryBindInChannelToSubject(subject string, invitationCh chan Invitation) {
	assert.NotNil(Ec)
	assert.NotEmpty(subject)
	assert.CNotNil(invitationCh)
	try.To1(Ec.BindRecvChan(subject, invitationCh))
}

// Invitation TODO: should we try to do already some meta modeling? E.g. we
// have IdentityStr field which is very specific. Maybe we should rename it at
// least before we continue with the pw.Connection?
type Invitation struct {
	Type   ProtType
	Status string

	Sender enclave.RoleInfo // both parties..
	Rcvr   enclave.RoleInfo // ..  keep them same

	Challenge    chain.Block
	ChallengeSig key.Signature // only in reply

	IdentityStr string // CBOR string in base58
	//Identity *identity.Identity // not used yet
}

type ProtType string

const (
	PWType         ProtType = "pw"
	InvitationType ProtType = "invitation"
)

func (t *ProtType) String() string {
	return string(*t)
}

func (t *ProtType) Set(value string) error {
	switch value {
	case string(PWType), string(InvitationType):
		*t = ProtType(value)
		return nil
	default:
		return errors.New("must be one of [pw, invitation]")
	}
}

const (
	SubjectInvitationPropose = "INVITATION_PROPOSE"
	SubjectInvitationReply   = "INVITATION_REPLY"
	SubjectInvitationACK     = "INVITATION_ACK"
)

const (
	subjectPairwisePropose = "PW_PROPOSE"
	subjectPairwiseReply   = "PW_REPLY"
	subjectPairwiseACK     = "PW_ACK"
)

var IdInviteCmdData = struct {
	SenderUserID uint32
	RcvrUserID   uint32
	Codec        string
	PinCode      int
}{}

var CmdData = struct {
	WalletFilename string
	MasterKey      string
}{}
