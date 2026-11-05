package pw

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
)

func TestRequesterDiagnosticCodes(t *testing.T) {
	defer assert.PushTester(t)()
	executable := try.To1(os.Executable())
	for _, tc := range []struct{ run, reason string }{
		{"TestRequesterMissingAuthorizationDiagnostic$", "device_not_authorized"},
		{"TestRequesterCurrentGuards$/^save$/^known_self$/^false$", "own_introduction_not_known"},
		{"TestRequesterCurrentGuards$/^save$/^known_peer$/^false$", "peer_not_known"},
		{"TestRequesterCurrentGuards$/^save$/^deny$/^false$", "policy_deny"},
		{"TestRequesterCurrentGuards$/^save$/^received$/^false$", "ad_evidence_missing"},
		{"TestRequesterCurrentGuards$/^save$/^expiry$/^false$", "ad_invalid_or_expired"},
		{"TestRequesterCurrentGuards$/^save$/^unusable$/^false$", "signer_unusable"},
		{"TestRequesterSigningAndFinalSaveGuard$/^deny_during_signing$", "policy_deny"},
	} {
		t.Run(tc.reason+tc.run, func(t *testing.T) {
			defer assert.PushTester(t)()
			cmd := exec.CommandContext(t.Context(), executable,
				"-test.run=^"+tc.run, "-test.count=1", "-test.timeout=30s",
				"-v=1", "-logtostderr=true")
			output, err := cmd.CombinedOutput()
			assert.NoError(err, "diagnostic subprocess failed")
			logs := string(output)
			assert.That(strings.Contains(logs,
				"intro_pw op=redeem side=requester stage=attempt result=refused reason="+tc.reason))
			assert.ThatNot(strings.Contains(logs, "result=committed"))
			assert.ThatNot(strings.Contains(logs, "unusable signer"))
		})
	}
	for _, run := range []string{
		"TestRequesterIndependentAcceptanceAndDeletion",
		"TestFirstUseLostResponseRetainsAwaitAndOneTimeReceipt",
	} {
		t.Run(run, func(t *testing.T) {
			defer assert.PushTester(t)()
			cmd := exec.CommandContext(t.Context(), executable,
				"-test.run=^"+run+"$", "-test.count=1", "-test.timeout=30s",
				"-v=1", "-logtostderr=true")
			output, err := cmd.CombinedOutput()
			assert.NoError(err, "diagnostic subprocess failed")
			logs := string(output)
			assert.That(strings.Contains(logs,
				"intro_pw op=redeem side=requester stage=acceptance result=committed"))
			if strings.Contains(run, "LostResponse") {
				assert.That(strings.Contains(logs,
					"intro_pw op=first_use side=acceptor stage=receipt result=committed"))
				assert.That(strings.Contains(logs,
					"intro_pw op=first_use side=requester stage=peer_exchange result=unknown"))
				assert.ThatNot(strings.Contains(logs, "stage=ready result=committed"))
				assert.That(strings.Contains(logs,
					"stage=await result=refused reason=session_already_exists"))
			}
		})
	}
}

func TestFirstUseSignerDiagnostic(t *testing.T) {
	defer assert.PushTester(t)()
	executable := try.To1(os.Executable())
	for _, tc := range []struct{ phase, side, stage string }{
		{"Await", "requester", "await"},
		{"useSeen", "acceptor", "receipt"},
		{"Ready", "requester", "ready"},
	} {
		t.Run(tc.phase, func(t *testing.T) {
			defer assert.PushTester(t)()
			cmd := exec.CommandContext(t.Context(), executable,
				"-test.run=^TestFirstUseCurrentLocalGuards$/^"+tc.phase+"$/^unusable$/^false$",
				"-test.count=1", "-test.timeout=30s", "-v=1", "-logtostderr=true")
			output, err := cmd.CombinedOutput()
			assert.NoError(err, "diagnostic subprocess failed")
			logs := string(output)
			prefix := "intro_pw op=first_use side=" + tc.side + " stage=" + tc.stage
			assert.That(strings.Contains(logs,
				prefix+" result=refused reason=signer_unusable"))
			assert.ThatNot(strings.Contains(logs, prefix+" result=committed"))
			assert.ThatNot(strings.Contains(logs, "private provider diagnostic"))
		})
	}
}

func TestRequesterMissingAuthorizationDiagnostic(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishment(t, false)
	alice := newVault(t)
	base := intro.New(key.Info{Public: f.root.public})
	savePath(t, alice.vault, f.root.public,
		base.Introduce(f.root.handle, key.Info{Public: f.peer.public}), f.peer)
	try.To1(onboarding.VerifyReceived(alice.vault, f.root.public))
	signer := &probeSigner{Handle: f.peer.handle}
	alice.unchanged(t, func() {
		_, err := saveAttempt(alice.vault, f.root.public, f.peer.public,
			f.root.public, signer, f.invitation.ID, InvitationAny,
			func() time.Time { return f.now })
		assert.Equal(err, ErrEstablishment)
	})
	assert.Equal(signer.signCalls.Load(), 0)
	assert.DeepEqual(requesterRecords(t, alice.vault), [3][]byte{})
}
