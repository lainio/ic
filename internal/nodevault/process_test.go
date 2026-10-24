package nodevault

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/key"
)

// These expected public identities come from the parent's configuration,
// separately from the proposal and from both databases. No handle IDs appear.
type processConfig struct {
	Binding     Binding
	OtherParent key.Public
}

func TestStoreAcrossProcesses(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	try.To(writeProcessFixture(f))
	clear(f.secret)
	identityPath := filepath.Join(f.dir, "alice", "identity.json")
	identity := try.To1(os.ReadFile(identityPath))
	unlock := try.To1(os.ReadFile(filepath.Join(f.dir, "unlock")))
	defer clear(unlock)
	executable := try.To1(os.Executable())
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	// Each CombinedOutput starts and joins a fresh test-executable process.
	// B cannot use A's provider, counters, signature slice or restored handle.
	for i, phase := range []string{"accept", "retry"} {
		child := exec.CommandContext(ctx, executable,
			"-test.run=^TestStoreProcess$", "--", phase, f.dir)
		output, err := child.CombinedOutput()
		assert.NoError(err, "child %s: %s", phase, output)
		assert.Equal(try.To1(diskCharge(f)), uint64(i+1)*reservationSize)
		assert.DeepEqual(try.To1(os.ReadFile(identityPath)), identity)
		assert.DeepEqual(
			try.To1(os.ReadFile(filepath.Join(f.dir, "unlock"))),
			unlock,
		)
	}
	accepted := try.To1(
		os.ReadFile(filepath.Join(f.dir, "observed-acceptance")),
	)
	reread := try.To1(os.ReadFile(filepath.Join(f.dir, "reopened-acceptance")))
	assert.SNotEmpty(accepted)
	assert.DeepEqual(reread, accepted)
	assert.NoError(f.proposal.VerifyAcceptance(accepted))
}

func TestReservationSurvivesProcessExit(t *testing.T) {
	defer assert.PushTester(t)()

	f := try.To1(prepareFixture(t.TempDir()))
	defer clear(f.secret)
	try.To(writeProcessFixture(f))
	s := try.To1(Create(t.Context(), f.state(), f.secret, f.binding))
	try.To(s.Close())
	executable := try.To1(os.Executable())
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable,
		"-test.run=^TestStoreProcess$", "--", "abandon", f.dir)
	output, err := child.CombinedOutput()
	assert.NoError(err, "child abandoned an open Store: %s", output)
	assert.Equal(try.To1(diskCharge(f)), 2*reservationSize)

	reopened := try.To1(Open(t.Context(), f.state(), f.secret, f.binding))
	defer func() { try.Out(reopened.Close()).Logf() }()
	assert.Equal(
		try.To1(readUsage(reopened.usage, f.binding)),
		3*reservationSize,
	)
	assert.Equal(reopened.provider.remaining, reservationSize)
	try.To(reopened.Close())
}

func writeProcessFixture(f fixture) (err error) {
	defer err2.Handle(&err, nil)

	config := try.To1(json.Marshal(processConfig{f.binding, f.otherParent}))
	for name, data := range map[string][]byte{
		"expected.json": config, "proposal": f.proposal.Bytes(),
		"different-proposal": f.different.Bytes(),
	} {
		try.To(os.WriteFile(filepath.Join(f.dir, name), data, 0600))
	}
	return nil
}

func TestStoreProcess(t *testing.T) {
	defer assert.PushTester(t)()

	if len(flag.Args()) != 2 {
		t.Skip("invoked only by bounded subprocess tests")
	}
	phase, dir := flag.Args()[0], flag.Args()[1]
	var config processConfig
	try.To(
		json.Unmarshal(
			try.To1(os.ReadFile(filepath.Join(dir, "expected.json"))),
			&config,
		),
	)
	b := config.Binding
	secret := try.To1(os.ReadFile(filepath.Join(dir, "storage-secret")))
	defer clear(secret)
	alice := try.To1(nodeidentity.OpenDirectory(
		filepath.Join(dir, "alice"), filepath.Join(dir, "unlock"),
	))
	assert.DeepEqual(try.To1(alice.CBORPublicKey()), []byte(b.Child))
	proposal := try.To1(
		intro.ParsePath(try.To1(os.ReadFile(filepath.Join(dir, "proposal")))),
	)
	different := try.To1(
		intro.ParsePath(
			try.To1(os.ReadFile(filepath.Join(dir, "different-proposal"))),
		),
	)
	try.To(proposal.ProveFromRoot(b.Root))
	try.To(different.ProveFromRoot(b.Root))
	state := filepath.Join(dir, "state")

	if phase == "accept" {
		store := try.To1(Create(t.Context(), state, secret, b))
		defer func() { try.Out(store.Close()).Logf() }()
		signer := &countingSigner{Handle: alice}
		signed := try.To1(onboarding.SignAfterStoredChoice(
			store.Vault(), signer, b.Root, b.Root, proposal,
		))
		assert.Equal(signer.calls, 1)
		try.To(proposal.VerifyAcceptance(signed))
		try.To(
			os.WriteFile(
				filepath.Join(dir, "observed-acceptance"),
				signed,
				0600,
			),
		)
		try.To(store.Close())
		return
	}

	store := try.To1(Open(t.Context(), state, secret, b))
	if phase == "abandon" {
		assert.Equal(store.provider.remaining, reservationSize)
		// Intentionally no Store.Close or deferred cleanup. The bounded child
		// exits via the test runner with both databases and the lease still open.
		return
	}
	defer func() { try.Out(store.Close()).Logf() }()
	assert.Equal(phase, "retry")
	saved, found := try.To2(
		onboarding.ReadStoredChoice(store.Vault(), b.Root, b.Child),
	)
	assert.That(found)
	assert.DeepEqual(saved.Proposal.Bytes(), proposal.Bytes())
	observed := try.To1(os.ReadFile(filepath.Join(dir, "observed-acceptance")))
	assert.DeepEqual([]byte(saved.Acceptance), observed)
	try.To(saved.Proposal.VerifyAcceptance(saved.Acceptance))
	remaining := store.provider.remaining
	signer := &countingSigner{
		Handle: alice,
		fail:   errors.New("retry must not sign"),
	}
	retry := try.To1(onboarding.SignAfterStoredChoice(
		store.Vault(), signer, b.Root, b.Root, proposal,
	))
	assert.Equal(signer.calls, 0)
	assert.DeepEqual([]byte(retry), observed)
	refused, err := onboarding.SignAfterStoredChoice(
		store.Vault(), signer, b.Root, config.OtherParent, different,
	)
	assert.ErrorIs(err, intro.ErrDifferentAcceptance)
	assert.SNil(refused)
	assert.Equal(signer.calls, 0)
	assert.Equal(store.provider.remaining, remaining)
	try.To(
		os.WriteFile(
			filepath.Join(dir, "reopened-acceptance"),
			saved.Acceptance,
			0600,
		),
	)
	try.To(store.Close())
}
