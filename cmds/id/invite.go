package id

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/lainio/ic/identity"
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

		codec := nconn.CBOR_DECODER
		ec = nconn.New(codec).EncodedConn
		defer func() {
			glog.V(3).Infoln("closing nats")
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

	invitationCh := make(chan Invitation)
	subject := fmt.Sprintf(
		"%s_%d", subjectInvitationPropose, idInviteCmdData.RcvrUserID,
	)
	glog.V(3).Infoln("--- we'll listen", subject)
	tryBindInOutChannelToSubject(subject, invitationCh)

	me := Invitation{
		Sender: RoleInfo{
			ID:      senderUser.ID,
			KeyInfo: senderUser.KeyInfo,
		},
		Rcvr: RoleInfo{
			ID:      rcvrUser.ID,
			KeyInfo: rcvrUser.KeyInfo,
		},
		Indentity: identity.Identity{},
	}
	//		Sender.UserID: senderUser.ID,
	//		Rcvr.UserID:   rcvrUser.ID,
	//		Rcvr.IDK:      rcvrUser.KeyID,

	invitationCh <- me

	glog.V(3).Infoln(
		"done pub: sender ID", me.Sender.ID,
		"rcvr ID", me.Rcvr.ID,
	)
	glog.V(3).Infoln("-- start to wait reply")
	reply := <-invitationCh

	glog.V(3).Infoln("reply received")

	assert.Equal(reply.Rcvr.ID, idInviteCmdData.RcvrUserID)
	assert.Equal(reply.Sender.ID, idInviteCmdData.SenderUserID)
	//try.To(reply.Indentity.CheckIntegrity())

	glog.V(3).Infoln("all OK")

	// TODO: challenge

	return nil
}

func tryBindInOutChannelToSubject(subject string, invitationCh chan Invitation) {
	try.To(ec.BindSendChan(subject, invitationCh))
	try.To1(ec.BindRecvChan(subject, invitationCh))
}

type Invitation struct {
	Sender    RoleInfo
	Rcvr      RoleInfo
	Indentity identity.Identity
}

type RoleInfo struct {
	ID      uint32
	KeyInfo key.Info
}

const (
	subjectInvitationPropose = "INVITATION_PROPOSE"
	subjectInvitationACK     = "INVITATION_ACK"
)
