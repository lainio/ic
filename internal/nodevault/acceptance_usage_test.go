package nodevault

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/ownerapi"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
)

// Keep the accounting assertion here, where both the in-memory lease budget
// and durable charge are visible without adding a production inspection API.
func TestRequesterAcceptanceSpendsNoEncryption(t *testing.T) {
	defer assert.PushTester(t)()
	a := try.To1(prepareFixture(t.TempDir()))
	defer clear(a.secret)
	unlock := randomSecret()
	defer clear(unlock)
	identity := filepath.Join(t.TempDir(), "identity.json")
	try.To1(nodeidentity.Create(identity, unlock))
	peerSigner := try.To1(nodeidentity.Open(identity, unlock))
	b := fixture{dir: t.TempDir(), secret: randomSecret(), binding: a.binding}
	defer clear(b.secret)
	b.binding.Child = try.To1(peerSigner.CBORPublicKey())
	b.proposal = a.proposal.Introduce(
		a.alice,
		key.Info{Public: b.binding.Child},
	)
	x := try.To1(Create(t.Context(), a.state(), a.secret, a.binding))
	y := try.To1(Create(t.Context(), b.state(), b.secret, b.binding))
	defer func() { assert.NoError(x.Close()); assert.NoError(y.Close()) }()
	for _, subject := range []struct {
		f      fixture
		signer key.Handle
	}{
		{a, a.alice}, {b, peerSigner},
	} {
		signature := try.To1(subject.f.proposal.SignAcceptance(subject.signer))
		for _, store := range []*Store{x, y} {
			try.To2(onboarding.SaveIntroduction(store.Vault(), a.binding.Root,
				subject.f.proposal.Bytes(), signature))
		}
	}
	for _, store := range []*Store{x, y} {
		try.To1(onboarding.VerifyReceived(store.Vault(), a.binding.Root))
	}
	try.To1(
		device.BootstrapLocal(
			x.Vault(),
			a.binding.Root,
			a.binding.Child,
			a.alice,
		),
	)
	try.To1(
		device.BootstrapLocal(
			y.Vault(),
			b.binding.Root,
			b.binding.Child,
			peerSigner,
		),
	)
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	endpoint := "http://" + server.Listener.Addr().
		String() +
		"/peer/introduction"
	ad := try.To1(
		wire.Marshal(try.To1(ads.PublishLocal(y.Vault(), b.binding.Root,
			b.binding.Child, peerSigner, endpoint, time.Now()))),
	)
	_, _, bind := try.To3(
		ownerapi.NewAcceptanceCredentials(t.Context(), y.Vault(),
			b.binding.Root, b.binding.Child, peerSigner, t.TempDir()),
	)
	prove, accept := bind(server.Listener)
	server.Config.Handler = peerapi.NewAcceptanceHandler(
		y.Vault(),
		b.binding.Root,
		b.binding.Child,
		endpoint,
		accept,
		peerapi.NewProofHandler(y.Vault(),
			b.binding.Root, b.binding.Child, endpoint, prove),
	)
	server.Start()
	try.To1(ads.ReceiveClaim(x.Vault(), a.binding.Root, b.binding.Child, ad))
	try.To1(ads.VerifyReceivedRemote(t.Context(), x.Vault(), a.binding.Root,
		a.binding.Child, b.binding.Child))
	for _, exhausted := range []bool{false, true} {
		if exhausted {
			x.provider.remaining, y.provider.remaining = 0, 0
		}
		beforeX, beforeY := try.To1(stateFiles(a)), try.To1(stateFiles(b))
		remainingX, remainingY := x.provider.remaining, y.provider.remaining
		try.To(
			pw.RequestRemoteAcceptance(t.Context(), x.Vault(), a.binding.Root,
				a.binding.Child, b.binding.Child, a.alice),
		)
		assert.Equal(x.provider.remaining, remainingX)
		assert.Equal(y.provider.remaining, remainingY)
		assert.DeepEqual(try.To1(stateFiles(a)), beforeX)
		assert.DeepEqual(try.To1(stateFiles(b)), beforeY)
	}
}
