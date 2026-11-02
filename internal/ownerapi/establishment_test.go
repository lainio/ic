package ownerapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const establishmentPath = "/peer/pw/establish"

type establishmentOwnerFixture struct {
	acceptanceFixture
	request pw.SignedEstablishment
	raw     []byte
	body    string
}

func newEstablishmentOwner(t *testing.T) establishmentOwnerFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := establishmentOwnerFixture{acceptanceFixture: newAcceptanceFixture(t)}
	owner, file, bind := try.To3(
		NewEstablishmentCredentials(t.Context(), f.vault,
			f.root, f.child, f.signer, t.TempDir()),
	)
	f.owner = owner
	f.publisher = owner.(*authenticatedStatusHandler).
		next.(*acceptanceExchangeHandler).publicationHandler
	f.auth = strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization: "))
	prove, accept, establish := bind(f.listener)
	f.peer = peerapi.NewEstablishmentHandler(establish,
		peerapi.NewAcceptanceHandler(f.vault, f.root, f.child, f.endpoint,
			accept, peerapi.NewProofHandler(f.vault, f.root, f.child,
				f.endpoint, prove)))
	assert.Equal(deviceRequest(f.owner, f.auth, "POST", invitationIssuePath,
		issueAnyBody).Code, 200)
	row, _ := try.To2(pw.ReadInvitation(f.vault, f.root, f.child))
	f.request = pw.SignedEstablishment{Payload: pw.Establishment{
		Version: 1, Root: f.root, Requester: f.requester, Target: f.child,
		InvitationID: row.ID, Audience: row.Audience,
		AttemptID: bytes.Repeat([]byte{53}, 32), Device: f.requester, Ad: f.ad,
	}}
	f.raw = signOwnerEstablishment(t, f.request, f.requesterKey)
	f.body = establishmentBody(t, f.raw)
	return f
}

func signOwnerEstablishment(t *testing.T, request pw.SignedEstablishment,
	signer key.Handle,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(pw.EstablishPurpose,
		try.To1(wire.Marshal(request.Payload)))
	request.Signature = try.To1(signer.Sign(digest[:]))
	return try.To1(wire.Marshal(request))
}

func establishmentBody(t *testing.T, raw []byte) string {
	t.Helper()
	defer assert.PushTester(t)()
	return string(try.To1(json.Marshal(struct {
		Version int    `json:"version"`
		Request []byte `json:"request"`
	}{1, raw})))
}

func (f establishmentOwnerFixture) records(t *testing.T) (records [3][]byte) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(f.vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		for i, name := range []string{
			"local-pw-invitation-v1", "local-pw-accepted-v1", "local-pw-held-v1",
		} {
			records[i], _ = try.To2(tx.Get([]byte(name)))
		}
		return nil
	}))
	return records
}

func (f establishmentOwnerFixture) savedResponse(t *testing.T) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	records := f.records(t)
	var row pw.Invitation
	try.To(wire.UnmarshalCanonical(&row, records[0]))
	assert.Equal(row.State, pw.InvitationConsumed)
	assert.DeepEqual(row.ID, f.request.Payload.InvitationID)
	var history struct {
		_                 struct{} `cbor:",toarray"`
		Version           uint8
		Request, Response []byte
	}
	try.To(wire.UnmarshalCanonical(&history, records[1]))
	assert.Equal(history.Version, 1)
	assert.DeepEqual(history.Request, f.raw)
	var response pw.SignedAccepted
	try.To(wire.UnmarshalCanonical(&response, history.Response))
	assert.Equal(response.Payload.Version, 1)
	assert.DeepEqual(response.Payload.Binding, f.request.Payload)
	digest := key.HashTagged("pw-invitation-request-digest/v1", f.raw)
	assert.DeepEqual(response.Payload.RequestDigest, digest[:])
	digest = key.HashTagged(pw.AcceptedPurpose,
		try.To1(wire.Marshal(response.Payload)))
	assert.That(response.Signature.Verify(f.child, digest[:]))
	var holding struct {
		_             struct{} `cbor:",toarray"`
		Version       uint8
		RequestDigest []byte
	}
	try.To(wire.UnmarshalCanonical(&holding, records[2]))
	assert.Equal(holding.Version, 1)
	assert.DeepEqual(holding.RequestDigest, response.Payload.RequestDigest)
	return history.Response
}

type establishmentWriter struct {
	*httptest.ResponseRecorder
	onHeader func()
	fail     bool
}

func (w *establishmentWriter) WriteHeader(code int) {
	w.onHeader()
	w.ResponseRecorder.WriteHeader(code)
}

func (w *establishmentWriter) Write(data []byte) (int, error) {
	if w.fail {
		_, _ = w.ResponseRecorder.Write(
			data,
		) // Observe bytes dropped by transport.
		return 0, errors.New("response lost after commit")
	}
	return w.ResponseRecorder.Write(data)
}

func TestEstablishmentInitialDeliveryAndFailedWrite(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "delivered", true: "lost"}[fail],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newEstablishmentOwner(t)
				defer f.requesterVault.unchanged(
					t,
				)() // No Alice state is written.
				remaining := f.lease.remaining.Load()
				var saved []byte
				w := &establishmentWriter{
					ResponseRecorder: httptest.NewRecorder(),
					fail:             fail,
					onHeader: func() {
						// This first response I/O sees all three committed records,
						// and the owner service mutation lock is already released.
						saved = f.savedResponse(t)
						locked := f.publisher.mutations.TryLock()
						assert.That(locked)
						f.publisher.mutations.Unlock()
					},
				}
				r := httptest.NewRequest("POST", establishmentPath,
					strings.NewReader(f.body))
				r.Header.Set("Content-Type", "application/json")
				f.peer.ServeHTTP(w, r)
				assert.Equal(w.Code, 200)
				assert.Equal(w.Header().Get("Cache-Control"), "no-store")
				assert.Equal(w.Header().Get("Content-Type"), "application/json")
				assert.Equal(remaining-f.lease.remaining.Load(), 3)
				assert.Equal(f.signer.signs.Load(), int32(3))
				want := string(try.To1(json.Marshal(struct {
					Version    int    `json:"version"`
					Acceptance []byte `json:"acceptance"`
				}{1, saved})))
				assert.Equal(w.Body.String(), want)
				assert.That(len(want) <= 3*1024)
				defer f.unchanged(t)()
				retry := deviceRequest(
					f.peer,
					"",
					"POST",
					establishmentPath,
					f.body,
				)
				assert.Equal(retry.Code, 200)
				assert.Equal(retry.Body.String(), want)
				assert.Equal(
					f.signer.signs.Load(),
					int32(4),
				) // Fresh probe only.
			},
		)
	}
}

func TestEstablishmentInitialReplyRechecksAfterCommit(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	defer f.requesterVault.unchanged(t)()
	f.signer.sign = func(data []byte) ([]byte, error) {
		if f.signer.signs.Load() == 3 { // BobReply's fresh usability probe.
			// Models an independent durable invalidation after TX-B. This real
			// Update also fails by deadlock if the probe is inside a Vault View.
			if _, err := policy.DenyLocal(f.vault, f.root, f.child,
				f.requester); err != nil {
				return nil, err
			}
		}
		return f.signer.Handle.Sign(data)
	}
	w := deviceRequest(f.peer, "", "POST", establishmentPath, f.body)
	assert.Equal(w.Code, 409)
	assert.Equal(w.Body.String(), "Conflict\n")
	f.savedResponse(t)
	defer f.unchanged(t)()
	assert.Equal(deviceRequest(f.peer, "", "POST", establishmentPath,
		f.body).Code, 409)
}

func TestEstablishmentLaterDenyCannotRecallAuthorizedBytes(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	w := &establishmentWriter{ResponseRecorder: httptest.NewRecorder(),
		onHeader: func() {
			f.publisher.mutations.Lock()
			defer f.publisher.mutations.Unlock()
			try.To1(policy.DenyLocal(f.vault, f.root, f.child, f.requester))
		}}
	r := httptest.NewRequest(
		"POST",
		establishmentPath,
		strings.NewReader(f.body),
	)
	r.Header.Set("Content-Type", "application/json")
	f.peer.ServeHTTP(w, r)
	assert.Equal(w.Code, 200)
	f.savedResponse(t)
	defer f.unchanged(t)()
	assert.Equal(
		deviceRequest(f.peer, "", "POST", establishmentPath, f.body).Code,
		409,
	)
}

func TestEstablishmentPreservesProofAndOwnerRoutes(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	defer f.unchanged(t)()
	nonce := f.challenge(t)
	w := deviceRequest(f.peer, "", "POST", acceptancePath,
		f.acceptanceFixture.body(t, nonce, f.requesterProof(t, nonce)))
	checkAcceptanceResponse(t, w, f.root, f.child, f.requester, nonce)
	for _, path := range []string{invitationIssuePath, invitationRevokePath} {
		assert.Equal(
			deviceRequest(f.peer, f.auth, "POST", path, "{}").Code,
			404,
		)
		assert.Equal(deviceRequest(f.owner, "", "POST", path, "{}").Code, 401)
	}
	assert.Equal(deviceRequest(f.owner, f.auth, "POST", establishmentPath,
		f.body).Code, 404)
	_, _, bind := try.To3(NewEstablishmentCredentials(t.Context(), f.vault,
		f.root, f.child, f.signer, t.TempDir()))
	prove, accept, establish := bind(nil)
	assert.That(prove == nil && accept == nil && establish == nil)
	prove, accept, establish = bind(f.listener)
	assert.That(prove == nil && accept == nil && establish == nil)
	disabled := peerapi.NewEstablishmentHandler(establish,
		peerapi.NewHandler(f.vault, f.root, f.child))
	assert.Equal(deviceRequest(disabled, f.auth, "POST", establishmentPath,
		f.body).Code, 404)
}
