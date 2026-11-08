package ownerapi

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
)

// Each capture starts a fresh test process with glog's ordinary flags. No
// global flag mutation, stderr replacement, or production logging adapter.
// The selected tests also check HTTP results, durable state and signer counts.
func TestPWDiagnosticStages(t *testing.T) {
	defer assert.PushTester(t)()
	executable := try.To1(os.Executable())
	const redeem = "intro_pw op=redeem side=requester "
	const establish = "intro_pw op=establish side=acceptor "
	const use = "intro_pw op=first_use side=requester "
	const receipt = "intro_pw op=first_use side=acceptor stage=receipt "
	const messagePrepare = "intro_pw op=message_send version=2 " +
		"stage=prepare result=authorized"
	const messageReceipt = "intro_pw op=message_receive version=2 " +
		"stage=receipt result=prepared"
	const messageACK = "intro_pw op=message_send version=2 stage=ack result=observed"
	for _, tc := range []struct {
		name, run string
		ordered   []string
		absent    []string
	}{
		{"before_save", "TestRedemptionSaveFailureAndUnlockedIO$/^0$",
			[]string{redeem + "stage=request result=accepted",
				redeem + "stage=attempt result=refused reason=undetermined"},
			[]string{redeem + "stage=attempt result=committed", "stage=peer_exchange"}},
		{"after_save", "TestRedemptionSaveFailureAndUnlockedIO$/^1$",
			[]string{redeem + "stage=attempt result=committed",
				redeem + "stage=peer_exchange result=started",
				establish + "stage=acceptance result=committed",
				establish + "stage=response result=prepared",
				redeem + "stage=acceptance result=refused reason=undetermined"},
			[]string{redeem + "stage=acceptance result=committed"}},
		{"redemption", "TestRedemptionSaveFailureAndUnlockedIO$/^3$",
			[]string{redeem + "stage=attempt result=committed",
				establish + "stage=acceptance result=committed",
				establish + "stage=reply result=retained",
				redeem + "stage=acceptance result=committed",
				redeem + "stage=attempt result=retained",
				redeem + "stage=acceptance result=retained"}, nil},
		{"await_refusal", "TestFirstUseHTTPOnlyAfterCommits$/^{0_1}$",
			[]string{use + "stage=request result=accepted",
				use + "stage=await result=refused reason=undetermined"},
			[]string{use + "stage=await result=committed",
				use + "stage=peer_exchange", receipt + "result=committed"}},
		{"unknown_reply", "TestFirstUseHTTPOnlyAfterCommits$/^{2_0}$",
			[]string{use + "stage=await result=committed",
				use + "stage=peer_exchange result=started",
				receipt + "result=refused reason=undetermined",
				use + "stage=peer_exchange result=unknown reason=undetermined"},
			[]string{receipt + "result=committed", use + "stage=ready result=committed"}},
		{"ready_refusal", "TestFirstUseHTTPOnlyAfterCommits$/^{1_1}$",
			[]string{use + "stage=await result=committed", receipt + "result=committed",
				use + "stage=ready result=refused reason=undetermined"},
			[]string{use + "stage=ready result=committed"}},
		{"first_use", "TestFirstUseHTTPOnlyAfterCommits$/^{2_1}$",
			[]string{use + "stage=await result=committed",
				use + "stage=peer_exchange result=started", receipt + "result=committed",
				"intro_pw op=first_use side=acceptor stage=response result=prepared",
				use + "stage=peer_exchange result=response_received",
				use + "stage=ready result=committed"}, nil},
		{"invitation", "TestPWDiagnosticInvitationInput$",
			[]string{"stage=issue result=refused reason=input_invalid",
				"stage=issue result=committed",
				"stage=issue result=refused reason=invitation_already_exists"},
			[]string{diagnosticPrivateInput}},
		{"signer", "TestDeviceFailuresAreGenericAndReadOnly$/^failed_signer$",
			[]string{"stage=authorization result=refused reason=signer_unusable"},
			[]string{"secret wrapped handle diagnostic", "result=committed",
				"stage=signer result=usable"}},
		{"bob_commit_failure", "TestEstablishmentCommitFailureNeverRepliesSuccess$",
			[]string{establish + "stage=acceptance result=refused reason=undetermined"},
			[]string{establish + "stage=acceptance result=committed",
				establish + "stage=response result=prepared"}},
		{"message_prepare", "TestOwnerMessageV2OperationFailures$/^prepare$",
			[]string{"intro_pw op=message_send stage=prepare result=refused"},
			[]string{messagePrepare, messageReceipt, messageACK}},
		{"message_inbox", "TestOwnerMessageV2OperationFailures$/^inbox$",
			[]string{messagePrepare,
				"intro_pw op=message_send stage=exchange result=unknown"},
			[]string{messageReceipt, messageACK}},
		{"message_receipt", "TestOwnerMessageV2OperationFailures$/^receipt$",
			[]string{messagePrepare,
				"intro_pw op=message_send stage=exchange result=unknown"},
			[]string{messageReceipt, messageACK}},
		{"message_ack", "TestOwnerMessageV2OperationFailures$/^ack$",
			[]string{messagePrepare, messageReceipt,
				"intro_pw op=message_send stage=ack result=unknown"},
			[]string{messageACK}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer assert.PushTester(t)()
			for _, verbosity := range []string{"0", "1"} {
				cmd := exec.CommandContext(t.Context(), executable,
					"-test.run=^"+tc.run, "-test.count=1", "-test.timeout=30s",
					"-v="+verbosity, "-logtostderr=true")
				output, err := cmd.CombinedOutput()
				assert.NoError(err, "diagnostic subprocess failed")
				logs := string(output)
				assert.ThatNot(strings.Contains(logs, "private message diagnostic"))
				assert.ThatNot(strings.Contains(logs, "private receipt signer diagnostic"))
				if verbosity == "0" {
					assert.ThatNot(strings.Contains(logs, "intro_pw "))
					continue
				}
				rest := logs
				for _, event := range tc.ordered {
					index := strings.Index(rest, event)
					assert.That(index >= 0, "missing ordered event: "+event)
					rest = rest[index+len(event):]
				}
				for _, forbidden := range tc.absent {
					assert.ThatNot(strings.Contains(logs, forbidden),
						"unexpected diagnostic field or transition")
				}
			}
		})
	}
}

const diagnosticPrivateInput = "private-owner-input-must-never-be-logged"

func TestPWDiagnosticInvitationInput(t *testing.T) {
	defer assert.PushTester(t)()
	f := newInvitationOwner(t)
	w := deviceRequest(f.owner, f.auth, "POST", invitationIssuePath,
		`{"recipient_public_key_hex":"`+diagnosticPrivateInput+`"}`)
	assert.Equal(w.Code, 400)
	assert.Equal(w.Body.String(), "Bad Request\n")
	for _, status := range []int{200, 409} {
		assert.Equal(deviceRequest(f.owner, f.auth, "POST",
			invitationIssuePath, issueAnyBody).Code, status)
	}
}
