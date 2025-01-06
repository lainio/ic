package id

import (
	"fmt"

	"github.com/golang/glog"
	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	cmd "github.com/lainio/ic/cmds"
	"github.com/lainio/ic/enclave"
	"github.com/lainio/ic/internal/nconn"
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
			glog.V(3).Infoln("NOT closing nats")
			//ec.Close()
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

	invitationCh := make(chan Invitation)
	subject := fmt.Sprintf(
		"%s_%d", subjectInvitationPropose, idInviteCmdData.RcvrUserID,
	)
	glog.V(3).Infoln("--- we'll listen", subject)
	tryBindInOutChannelToSubject(subject, invitationCh)

	glog.V(3).Infoln("-- start to wait", subjectInvitationPropose)
	invitationPropose := <-invitationCh
	glog.V(3).Infoln("-- we received invitation", invitationPropose.Sender.ID)

	assert.Equal(invitationPropose.Rcvr.ID, idInviteCmdData.RcvrUserID)
	assert.Equal(invitationPropose.Sender.ID, idInviteCmdData.SenderUserID)
	//try.To(reply.Indentity.CheckIntegrity())

	me := Invitation{
		Sender: RoleInfo{
			ID:      senderUser.ID,
			KeyInfo: senderUser.KeyInfo,
		},
		Rcvr: RoleInfo{
			ID:      rcvrUser.ID,
			KeyInfo: rcvrUser.KeyInfo,
		},
		//Indentity: identity.Identity{},
	}

	invitationCh <- me

	glog.V(3).Infoln("sent: rcvr ID:", me.Rcvr.ID)
	// TODO: challenge

	return nil
}
