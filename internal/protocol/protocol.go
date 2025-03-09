package protocol

import (
	"errors"
	"fmt"
	"time"

	"github.com/findy-network/findy-common-go/x"
	"github.com/lainio/ic/cmds"
	"github.com/lainio/ic/digest"
	"github.com/lainio/ic/pw"
	"github.com/spf13/cobra"

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

func PairwiseHandshake(c *cobra.Command, isAddresser bool) (token string, err error) {
	defer err2.Handle(&err)

	if isAddresser {
		token = try.To1(PairwiseHandshakeInit(c))
	} else {
		token = try.To1(PairwiseHandshakeJoin(c))
	}
	token = savePW(isAddresser)

	return
}

func savePW(isAddresser bool) (token string) {
	glog.V(3).Infoln("saving PW as addresser:", isAddresser)
	senderEndp := pw.ConnEndpoint{
		Info:     SenderUser.KeyInfo,
		Endpoint: "TODO",
	}
	rcvrEndp := pw.ConnEndpoint{
		Info:     RcvrUser.KeyInfo,
		Endpoint: "TODO",
	}
	pwConn := pw.New(isAddresser, senderEndp, rcvrEndp)
	token = pwConn.TheirIDK().PKString()

	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	glog.V(3).Infoln("saving PW as isAddresser:", isAddresser)
	try.To(enclave.PutPW(isAddresser, pwConn))
	enclave.TryClose()

	return
}

func PairwiseHandshakeInit(c *cobra.Command) (token string, err error) {
	glog.V(3).Infoln("\n=== PW HS INIT ===\n")
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	defer FlushAndCloseNats()

	isAddresser := true

	assert.NotZero(IdInviteCmdData.RcvrUserID)

	pwSendCh, pwSendSubject := MakeOutSubject(
		SubjectPairwisePropose,
		IdInviteCmdData.RcvrUserID,
	)
	pwListenCh, pwListenSub := MakeInSubject(
		SubjectPairwiseReply,
		IdInviteCmdData.RcvrUserID,
	)

	pinCode := IdInviteCmdData.PinCode
	glog.V(3).Infof(
		"--- build PW to (%v):\ninvitation & challenge: OUR PIN-code:\n %v",
		pwSendSubject, pinCode)

	challenge, verify := chain.NewVerifyBlock(pinCode)
	invitationProposal := Handshake{
		Type:      ProtocolTypePW,
		Sender:    SenderUser.RoleInfo,
		Rcvr:      RcvrUser.RoleInfo,
		Challenge: challenge,
	}
	assert.Equal(verify.Position, pinCode, "challenge building error")

	glog.V(3).Infoln("→ will send pw proposal and challenge")
	pwSendCh <- invitationProposal /////////  SEND  ///////////////
	glog.V(3).Infoln(
		"==> sender ID", invitationProposal.Sender.ID,
		"rcvr ID", invitationProposal.Rcvr.ID,
		pwListenSub,
	)

	glog.V(3).Infoln("← start to listen")
	reply := <-pwListenCh ////////////  LISTEN  ///////////////////
	glog.V(3).Infoln("<== pairwise CHALLENGE reply received", pwListenSub)

	defer err2.Handle(&err, OnErrorReply(pwSendCh, ProtocolTypePW))

	assert.Equal(reply.Type, ProtocolTypePW)
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
		"wrong PIN code (%d) in the challenge", pinCode)

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

	invitedMsg := Handshake{
		Type:   ProtocolTypePW,
		Sender: SenderUser.RoleInfo,
		Rcvr:   RcvrUser.RoleInfo,
	}

	glog.V(3).Infoln("→ start send pw ACCEPTED msg")
	pwSendCh <- invitedMsg ////////////  SEND  ////////////////////
	glog.V(3).Infoln("==> pw accepted msg")

	token = RcvrUser.KeyInfo.Public.String()
	fmt.Fprintf(
		c.ErrOrStderr(),
		"All OK, we are %s\n",
		x.Whom(isAddresser, "addresser", "addressee"),
	)

	// TODO: should we wait ACK from other end that the Invitation is DONE!
	//  - maybe the cannot save data or some other exception happens
	//  - if we rely on their successful, which might be the case in other
	//  protocols...

	// TODO: their ACK would be the place to save something in this end if..

	return
}

func PairwiseHandshakeJoin(c *cobra.Command) (token string, err error) {
	glog.V(3).Infoln("\n=== PW HS JOIN ===\n")
	defer assert.PushAsserter(assert.Plain)() // asserts as errors
	defer err2.Handle(&err, nil)
	defer FlushAndCloseNats()

	isAddresser := false

	assert.NotZero(IdInviteCmdData.RcvrUserID)
	assert.NotZero(IdInviteCmdData.SenderUserID)

	pwListenCh, pwListenSub := MakeInSubject(
		SubjectPairwisePropose,
		IdInviteCmdData.RcvrUserID,
	)
	pwSendCh, pwSendSub := MakeOutSubject(
		SubjectPairwiseReply,
		IdInviteCmdData.RcvrUserID,
	)

	glog.V(3).Infoln("0. IC count:", RcvrUser.Identity().ICCount())
	glog.V(3).Infoln("-- start to wait:", pwListenSub)
	fmt.Fprintf(
		c.OutOrStderr(),
		"Ready to listen addresser. Please execute:\n"+
			"\t'tdc pw handshake --addresser --pin-code=%v ..', at their end.\n",
		IdInviteCmdData.PinCode,
	)
	glog.V(3).Infoln("← listening pw invitation reply")
	connectPropose := <-pwListenCh //////////  LISTEN  //////////
	glog.V(3).Infoln("<== we received connnect propose from:",
		connectPropose.Sender.ID)

	defer err2.Handle(&err, OnErrorReply(
		pwSendCh,
		ProtocolTypePW),
	)

	assert.Equal(connectPropose.Type, ProtocolTypePW)
	assert.Equal(connectPropose.Rcvr.ID, IdInviteCmdData.RcvrUserID,
		"pw addresser cmd's user-rcvr-id (%v) not equal to our flag value (%v)",
		connectPropose.Rcvr.ID, IdInviteCmdData.RcvrUserID,
	)
	assert.Equal(connectPropose.Sender.ID, IdInviteCmdData.SenderUserID,
		"pw addresser cmd's user-sender-id (%v) not equal to our flag value (%v)",
		connectPropose.Sender.ID, IdInviteCmdData.SenderUserID,
	)

	glog.V(3).Infoln("-- received PW start & CHALLENGE, our PIN-code:\n",
		IdInviteCmdData.PinCode,
	)
	pinCode := IdInviteCmdData.PinCode
	challenge := chain.NewBlockFromData(connectPropose.Challenge.Bytes())
	challenge.Position = pinCode

	kh := key.NewFromInfo(RcvrUser.KeyInfo)
	sig := try.To1(kh.Sign(challenge.Bytes()))
	glog.V(3).Infoln("signature ok, OUR PIN-code:\n", pinCode)

	me := Handshake{
		Type:   ProtocolTypePW,
		Sender: SenderUser.RoleInfo,
		Rcvr:   RcvrUser.RoleInfo,

		Challenge:    challenge,
		ChallengeSig: sig,

		IdentityStr: RcvrUser.IdentityStr(),
	}

	glog.V(3).Infoln("→ sending CHALLENGE reply")
	pwSendCh <- me ////////////  SEND  //////////////////////
	glog.V(3).Infoln("==> signed CHALLENGE sent", pwSendSub)

	glog.V(3).Infoln("← start to wait a reply", pwListenSub)
	reply := <-pwListenCh ////////////  LISTEN  ////////////////////
	glog.V(3).Infoln("<== received a reply", me.Rcvr.ID, ", let's verify it..")

	assert.Empty(reply.Status, "inviter's error: %v", reply.Status)

	token = SenderUser.KeyInfo.Public.String()
	// TODO: send ACK to other end now
	// TODO: need 2 lvl printing, or start to use stderr, stdout:
	//  - tokens, etc. to stdout
	//  - information about progress etc. to stderr
	fmt.Fprintf(
		c.ErrOrStderr(),
		"All OK, we are %s\n",
		x.Whom(isAddresser, "addresser", "addressee"),
	)

	return
}

func PutUser(u enclave.User) {
	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	glog.V(3).Infoln("*** put user, IC count:", u.Identity().ICCount())
	enclave.TryPutUser(u)
	enclave.TryClose()
}

func InvitationHandshake() (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	defer FlushAndCloseNats()

	sendInvitationCh, subject := MakeOutSubject(SubjectInvitationPropose, IdInviteCmdData.RcvrUserID)
	listenInvitationCh, subject2 := MakeInSubject(SubjectInvitationReply, IdInviteCmdData.RcvrUserID)

	glog.V(3).Infoln("--- we'll build invitation & challenge", subject,
		"--pin-code:\n",
		IdInviteCmdData.PinCode,
	)

	pinCode := IdInviteCmdData.PinCode
	challenge, verify := chain.NewVerifyBlock(pinCode)
	invitationProposal := Handshake{
		Type:      ProtocolTypeInvitation,
		Sender:    SenderUser.RoleInfo,
		Rcvr:      RcvrUser.RoleInfo,
		Challenge: challenge,
	}
	assert.Equal(verify.Position, pinCode, "challeng building error")

	glog.V(3).Infoln("=== send ===")
	sendInvitationCh <- invitationProposal //////////  SEND  //////////////

	glog.V(3).Infoln(
		"--> sender ID", invitationProposal.Sender.ID,
		"rcvr ID", invitationProposal.Rcvr.ID,
		subject2,
	)

	reply := <-listenInvitationCh ////////////  LISTEN  ///////////////////
	glog.V(3).Infoln("=== challenge+reply received", subject2)

	defer err2.Handle(&err, OnErrorReply(sendInvitationCh, ProtocolTypeInvitation))

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
		"wrong PIN code (%d) in the challenge", pinCode)

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
	invitedMsg := Handshake{
		Type:        ProtocolTypeInvitation,
		Sender:      SenderUser.RoleInfo,
		Rcvr:        RcvrUser.RoleInfo,
		IdentityStr: RcvrUser.IdentityStr(),
	}

	fmt.Println(
		"All OK, and introducing",
		secondCount-firstCount,
		"new Trust Domains",
	)
	sendInvitationCh <- invitedMsg ////////////  SEND  ////////////////////

	// TODO: should we wait ACK from other end that the Invitation is DONE!
	//  - maybe the cannot save data or some other exception happens
	//  - if we rely on their successful, which might be the case in other
	//  protocols...

	// TODO: their ACK would be the place to save something in this end if..

	return nil
}

func OnErrorReply(sendInvitationCh chan Handshake, Type ProtocolType) err2.Handler {
	return func(err error) error {
		invitedMsg := Handshake{
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

	codec := cmds.Flags().Codec
	Ec = nconn.New(codec).EncodedConn
}

func FlushAndCloseNats() {
	defer err2.Catch()

	glog.V(3).Infoln("closing nats")
	try.Out(Ec.Flush()).Logf("flush failure")
	Ec.Close()
}

func MakeInSubject(base string, target uint32) (chan Handshake, string) {
	invitationCh := make(chan Handshake)
	subject := fmt.Sprintf(
		"%s_%d", base, target,
	)
	TryBindInChannelToSubject(subject, invitationCh)
	glog.V(3).Infoln("=== In CHANNEL created: ", subject)
	return invitationCh, subject
}

func MakeOutSubject(base string, target uint32) (chan Handshake, string) {
	invitationCh := make(chan Handshake)
	subject := fmt.Sprintf(
		"%s_%d", base, target,
	)
	TryBindOutChannelToSubject(subject, invitationCh)
	glog.V(3).Infoln("=== Out CHANNEL created: ", subject)
	return invitationCh, subject
}

func ReadParties(parties ...string) (s, r enclave.User) {
	assert.SNotEmpty(parties)

	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	SenderUser = enclave.TryGetExistingUserByType(
		cmds.Flags().Type.String(),
		parties[sender],
	)
	if len(parties) > 1 {
		if cmds.Flags().Type2 == cmds.DigestV2Type {
			dv2 := digest.DigestV2(parties[rcvr])
			idkPrefix := dv2.PKStringIDK()
			glog.V(3).Infoln("idkPrefix:", idkPrefix)
			rus := enclave.TryGetAllUsersByIDKPrefix(idkPrefix)
			assert.SLen(rus, 1, "finding %v", idkPrefix)
			RcvrUser = rus[0]
		} else {
			RcvrUser = enclave.TryGetExistingUserByType(
				cmds.Flags().Type2.String(),
				parties[rcvr],
			)
		}
	}
	enclave.TryClose()
	codec := cmds.Flags().Codec
	Ec = nconn.New(codec).EncodedConn
	return SenderUser, RcvrUser
}

func ListPW(role bool) (pconn []*pw.Connection) {
	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	pconn = try.To1(enclave.GetAllPW(role))
	enclave.TryClose()
	//	codec := cmds.Flags().Codec
	//	Ec = nconn.New(codec).EncodedConn
	return
}

// func SendPW(parties ...string) (s, r enclave.User) {
func SendPW(addresser bool, parties ...string) (s, r *pw.Connection) {
	assert.SNotEmpty(parties, "arguments needed")

	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)

	SenderUser = enclave.TryGetExistingUserByType(
		cmds.Flags().Type.String(),
		parties[sender],
	)
	if len(parties) > 1 {
		RcvrUser = enclave.TryGetExistingUserByType(
			cmds.Flags().Type.String(),
			parties[rcvr],
		)
	}
	// default is that we aren't addresser in role
	ourIDK := SenderUser.Identity().GetIDK().Public
	theirIDK := RcvrUser.Identity().GetIDK().Public
	if addresser { // PW are indexed from user PoW, that's why..
		ourIDK = RcvrUser.Identity().GetIDK().Public
		theirIDK = SenderUser.Identity().GetIDK().Public
	}
	sendPW, sfound := try.To2(enclave.GetSendersPW(ourIDK))
	assert.That(sfound, "not found: %s", ourIDK.PKString())
	rcvrPW, rfound := try.To2(enclave.GetReceiversPW(theirIDK))
	assert.That(rfound, "not found: %s", theirIDK.PKString())

	enclave.TryClose()
	codec := cmds.Flags().Codec
	Ec = nconn.New(codec).EncodedConn
	return sendPW, rcvrPW
}

func ViewPW(IDK key.Public) (pconn *pw.Connection) {
	enclave.TryInitSealedBox(CmdData.WalletFilename, "", CmdData.MasterKey)
	var found bool
	pconn, found = try.To2(enclave.GetSendersPW(IDK))
	if found {
		glog.V(3).Infoln("found from Sender-bucket",
			pconn.OurIDK().PKString())
		return
	}
	pconn, found = try.To2(enclave.GetReceiversPW(IDK))
	if found {
		glog.V(3).Infoln("found from Receiver-bucket",
			pconn.OurIDK().PKString())
		return
	}
	enclave.TryClose()
	codec := cmds.Flags().Codec
	Ec = nconn.New(codec).EncodedConn
	return
}

func TryBindOutChannelToSubject(subject string, invitationCh chan Handshake) {
	assert.NotNil(Ec)
	assert.NotEmpty(subject)
	assert.CNotNil(invitationCh)
	try.To(Ec.BindSendChan(subject, invitationCh))
}

func TryBindInChannelToSubject(subject string, invitationCh chan Handshake) {
	assert.NotNil(Ec)
	assert.NotEmpty(subject)
	assert.CNotNil(invitationCh)
	try.To1(Ec.BindRecvChan(subject, invitationCh))
}

// Handshake TODO: should we try to do already some meta modeling? E.g. we
// have IdentityStr field which is very specific. Maybe we should rename it at
// least before we continue with the pw.Connection?
//
// TODO: Also we shouldhave separated header, and way to bring dynamic fields
// when needed?
type Handshake struct {
	Type   ProtocolType
	Status string

	Sender enclave.RoleInfo // both parties..
	Rcvr   enclave.RoleInfo // ..  keep them same

	Challenge    chain.Block
	ChallengeSig key.Signature // only in reply

	IdentityStr string // CBOR string in base58
	//Identity *identity.Identity // not used yet

	Endpoint string
}

type ProtocolType string

const (
	ProtocolTypePW         ProtocolType = "pairwise"
	ProtocolTypeInvitation ProtocolType = "invitation"
)

func (t *ProtocolType) String() string {
	return string(*t)
}

func (t *ProtocolType) Set(value string) error {
	switch value {
	case string(ProtocolTypePW), string(ProtocolTypeInvitation):
		*t = ProtocolType(value)
		return nil
	default:
		return errors.New("must be one of [pairwise, invitation]")
	}
}

const (
	SubjectInvitationPropose = "INVITATION_PROPOSE"
	SubjectInvitationReply   = "INVITATION_REPLY"
	SubjectInvitationACK     = "INVITATION_ACK"
)

const (
	SubjectPairwisePropose = "PW_PROPOSE"
	SubjectPairwiseReply   = "PW_REPLY"
	SubjectPairwiseACK     = "PW_ACK"
)

const (
	sender = iota
	rcvr
)

var IdInviteCmdData = struct {
	SenderUserID uint32
	RcvrUserID   uint32
	PinCode      int
}{}

var CmdData = struct {
	WalletFilename string
	MasterKey      string
}{}

func InvitationHandshakeInvitee() (err error) {
	defer assert.PushAsserter(assert.Plain)() // asserts as errors
	defer err2.Handle(&err, nil)
	defer FlushAndCloseNats()

	listenInvitationCh, subject := MakeInSubject(SubjectInvitationPropose, IdInviteCmdData.RcvrUserID)
	sendInvitationCh, subject2 := MakeOutSubject(SubjectInvitationReply, IdInviteCmdData.RcvrUserID)

	pinCode := IdInviteCmdData.PinCode
	glog.V(3).Infoln("0. IC count:", RcvrUser.Identity().ICCount())
	glog.V(3).Infoln("-- start to wait:", subject)
	fmt.Printf("Ready to listen inviter.\n"+
		"Please execute: `tdc id introduce --addresser --pin-code=%v ..`, at their end.\n",
		pinCode,
	)
	invitationPropose := <-listenInvitationCh //////////////////////////////
	glog.V(3).Infoln("<- we received invitation from:", invitationPropose.Sender.ID)

	defer err2.Handle(&err, OnErrorReply(
		sendInvitationCh,
		ProtocolTypeInvitation),
	)

	assert.Equal(invitationPropose.Rcvr.ID, IdInviteCmdData.RcvrUserID,
		"invite cmd's user-rcvr-id (%v) not equal to our flag value (%v)",
		invitationPropose.Rcvr.ID, IdInviteCmdData.RcvrUserID,
	)
	assert.Equal(invitationPropose.Sender.ID, IdInviteCmdData.SenderUserID,
		"invite cmd's user-sender-id (%v) not equal to our flag value (%v)",
		invitationPropose.Sender.ID, IdInviteCmdData.SenderUserID,
	)

	glog.V(3).Infoln(
		"-- received invitation & challenge, --pin-code:\n",
		pinCode,
	)
	challenge := chain.NewBlockFromData(invitationPropose.Challenge.Bytes())
	challenge.Position = pinCode

	kh := key.NewFromInfo(RcvrUser.KeyInfo)
	sig := try.To1(kh.Sign(challenge.Bytes()))
	glog.V(3).Infoln("signature ok", pinCode)

	me := Handshake{
		Sender: SenderUser.RoleInfo,
		Rcvr:   RcvrUser.RoleInfo,

		Challenge:    challenge,
		ChallengeSig: sig,

		IdentityStr: RcvrUser.IdentityStr(),
	}

	glog.V(3).Infoln("-- signed challenge ready, let's send it to", subject2)
	sendInvitationCh <- me //////////////////////////////////////////

	glog.V(3).Infoln("-- start to wait a reply", subject)

	reply := <-listenInvitationCh //////////////////////////////////////////
	glog.V(3).Infoln("-- received a reply", me.Rcvr.ID, ", let's verify it..")

	assert.Empty(reply.Status, "inviter's error: %v", reply.Status)
	assert.NotEmpty(reply.IdentityStr, "identity data is missing")

	firstCount := RcvrUser.Identity().ICCount() // UI reporting
	idClone := RcvrUser.MakeIdentityFromStr(reply.IdentityStr)
	try.To(idClone.CheckIntegrity())
	glog.V(3).Infoln("<- we received invitation_ACK from:", reply.Sender.ID)
	RcvrUser.SetIdentity(idClone)
	secondCount := RcvrUser.Identity().ICCount() // UI reporting

	PutUser(RcvrUser) // TODO: this can fail! other end doesn't know it now!

	// TODO: send ACK to other end now
	fmt.Println("All OK, and introducing", secondCount-firstCount, "new Trust Domains")

	return nil
}
