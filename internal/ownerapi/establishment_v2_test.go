package ownerapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func ownerRequestV2(t *testing.T, f establishmentOwnerFixture,
) pw.EstablishmentV2 {
	t.Helper()
	p := f.request.Payload
	return pw.EstablishmentV2{Version: 2, Root: p.Root, Requester: p.Requester,
		Target: p.Target, InvitationID: p.InvitationID, Audience: p.Audience,
		Recipient: p.Recipient, AttemptID: p.AttemptID, Device: p.Device,
		Epoch: p.Epoch, Ad: p.Ad,
		RequesterContact: "http://" + publicationListener(t).Addr().String(),
		TargetContact: strings.TrimSuffix(
			f.endpoint,
			"/peer/introduction",
		)}
}

func signOwnerV2(t *testing.T, f establishmentOwnerFixture,
	p pw.EstablishmentV2,
) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	digest := key.HashTagged(pw.EstablishPurposeV2, try.To1(wire.Marshal(p)))
	return try.To1(wire.Marshal(pw.SignedEstablishmentV2{Payload: p,
		Signature: try.To1(f.requesterKey.Sign(digest[:]))}))
}

func versionedEstablishmentBody(t *testing.T, version int, raw []byte) string {
	t.Helper()
	defer assert.PushTester(t)()
	return string(try.To1(json.Marshal(struct {
		Version int    `json:"version"`
		Request []byte `json:"request"`
	}{version, raw})))
}

func TestEstablishmentV2RejectsBytesBeforeSigning(t *testing.T) {
	for _, consumed := range []bool{false, true} {
		t.Run(fmt.Sprint(consumed), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishmentOwner(t)
			p := ownerRequestV2(t, f)
			raw := signOwnerV2(t, f, p)
			if consumed {
				assert.Equal(
					deviceRequest(f.peer, "", "POST", establishmentPath,
						versionedEstablishmentBody(t, 2, raw)).Code,
					200,
				)
			}
			defer f.unchanged(t)()
			defer f.requesterVault.unchanged(t)()
			signs := f.signer.signs.Load()
			wrongTarget := p
			wrongTarget.TargetContact = p.RequesterContact
			tampered := bytes.Clone(raw)
			tampered[len(tampered)-1] ^= 1
			for _, body := range []string{
				versionedEstablishmentBody(t, 1, raw),
				versionedEstablishmentBody(t, 2, f.raw),
				versionedEstablishmentBody(t, 2, signOwnerV2(t, f, wrongTarget)),
				versionedEstablishmentBody(t, 2, tampered),
				versionedEstablishmentBody(t, 2, []byte{0xff}),
				versionedEstablishmentBody(t, 2, append(bytes.Clone(raw), 0)),
				versionedEstablishmentBody(t, 2, append([]byte{0x98, 2}, raw[1:]...)),
			} {
				w := deviceRequest(
					f.peer,
					"",
					"POST",
					establishmentPath,
					body,
				)
				assert.Equal(w.Code, 409)
				assert.Equal(w.Body.String(), "Conflict\n")
				assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			}
			assert.Equal(f.signer.signs.Load(), signs)
		})
	}
}

func TestEstablishmentV2CommitFailureNeverDeliversSuccess(t *testing.T) {
	for allowance := range int64(3) {
		t.Run(fmt.Sprint(allowance), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishmentOwner(t)
			body := versionedEstablishmentBody(t, 2,
				signOwnerV2(t, f, ownerRequestV2(t, f)))
			before := f.records(t)
			f.lease.remaining.Store(allowance)
			w := deviceRequest(f.peer, "", "POST", establishmentPath, body)
			assert.Equal(w.Code, 409)
			assert.DeepEqual(f.records(t), before)
			assert.Equal(
				try.To1(pw.BobContactV2(f.vault, f.root, f.child)),
				"",
			)
			assert.Equal(f.signer.signs.Load(), int32(2))
		})
	}
}

func TestRedemptionV2StrictSelectorBeforeSigning(t *testing.T) {
	defer assert.PushTester(t)()
	f := newAdFetchFixture(t)
	h, auth := redemptionCredential(t, f.vault, f.root, f.local, f.signer)
	defer f.unchanged(t)()
	v1 := redemptionBody(t, f.subject, make([]byte, 32))
	v2 := v1[:len(v1)-1] + `,"version":2}`
	for _, selector := range []string{`1`, `0`, `3`, `-2`, `2.0`, `2e0`,
		`"2"`, `null`, `true`, `[]`, `{}`} {
		body := v1[:len(v1)-1] + `,"version":` + selector + `}`
		assert.Equal(deviceRequest(h, auth, "POST", invitationRedeemPath,
			body).Code, 400)
	}
	for _, body := range []string{
		v2[:len(v2)-1] + `,"version":2}`,
		strings.Replace(v2, `"version"`, `"Version"`, 1),
		strings.Replace(v2, `"version"`, `"ver\u0073ion"`, 1),
		strings.Replace(v2, `"audience"`, `"Audience"`, 1),
		`{"version":2,"audience":"Any"}`,
		v2[:len(v2)-1] + `,"audience":"Any"}`, v2 + `{}`,
	} {
		assert.Equal(deviceRequest(h, auth, "POST", invitationRedeemPath,
			body).Code, 400)
	}
	for _, field := range []string{"requester_contact", "target_contact",
		"endpoint", "target_url", "peer_url", "signer", "request", "transport"} {
		body := v2[:len(v2)-1] + `,"` + field + `":"http://127.0.0.1:1"}`
		assert.Equal(deviceRequest(h, auth, "POST", invitationRedeemPath,
			body).Code, 400)
	}
	assert.Equal(f.signer.signs.Load(), int32(0))
}

func TestEstablishmentV2AndV1ConsumedSlotIsolation(t *testing.T) {
	for _, first := range []int{1, 2} {
		t.Run(fmt.Sprint(first), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishmentOwner(t)
			bodies := map[int]string{1: f.body,
				2: versionedEstablishmentBody(t, 2,
					signOwnerV2(t, f, ownerRequestV2(t, f)))}
			assert.Equal(deviceRequest(f.peer, "", "POST", establishmentPath,
				bodies[first]).Code, 200)
			defer f.unchanged(t)()
			assert.Equal(deviceRequest(f.peer, "", "POST", establishmentPath,
				bodies[3-first]).Code, 409)
		})
	}
}

func TestEstablishmentV2ReplyAfterCommitAndUnlock(t *testing.T) {
	defer assert.PushTester(t)()
	f := newEstablishmentOwner(t)
	body := versionedEstablishmentBody(t, 2,
		signOwnerV2(t, f, ownerRequestV2(t, f)))
	var saved []byte
	w := &establishmentWriter{ResponseRecorder: httptest.NewRecorder(),
		fail: true, onHeader: func() {
			assert.That(f.publisher.mutations.TryLock())
			f.publisher.mutations.Unlock()
			records := f.records(t) // View while response I/O is pending.
			var row pw.Invitation
			try.To(wire.UnmarshalCanonical(&row, records[0]))
			assert.Equal(row.State, pw.InvitationConsumed)
			assert.SNotEmpty(records[2])
			var history struct {
				_                 struct{} `cbor:",toarray"`
				Version           uint8
				Request, Response []byte
			}
			try.To(wire.UnmarshalCanonical(&history, records[1]))
			assert.Equal(history.Version, 2)
			saved = history.Response
		}}
	r := httptest.NewRequest(
		"POST",
		establishmentPath,
		strings.NewReader(body),
	)
	r.Header.Set("Content-Type", "application/json")
	f.peer.ServeHTTP(w, r)
	assert.Equal(w.Code, 200)
	var response struct {
		Version    int
		Acceptance []byte
	}
	try.To(json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(response.Version, 2)
	assert.DeepEqual(response.Acceptance, saved)
	defer f.unchanged(t)()
	retry := deviceRequest(f.peer, "", "POST", establishmentPath, body)
	assert.Equal(retry.Code, 200)
	assert.Equal(retry.Body.String(), w.Body.String())
	assert.Equal(
		f.signer.signs.Load(),
		int32(4),
	) // Only a fresh probe on retry.
}

func TestEstablishmentV2SerializesSignerOutsideVault(t *testing.T) {
	for _, blockAt := range []int32{1, 2, 3} {
		t.Run(fmt.Sprint(blockAt), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishmentOwner(t)
			body := versionedEstablishmentBody(t, 2,
				signOwnerV2(t, f, ownerRequestV2(t, f)))
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			f.signer.sign = func(data []byte) ([]byte, error) {
				if f.signer.signs.Load() == blockAt {
					close(entered)
					<-release
				}
				return f.signer.Handle.Sign(data)
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				done <- deviceRequest(f.peer, "", "POST", establishmentPath, body)
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("v2 establishment did not reach signer")
			}
			locked := f.publisher.mutations.TryLock()
			if locked {
				f.publisher.mutations.Unlock()
			}
			assert.ThatNot(locked)
			txDone := make(chan error, 1)
			go func() {
				txDone <- f.vault.Update(func(storage.WriteTx) error { return nil })
			}()
			select {
			case err := <-txDone:
				assert.NoError(err)
			case <-time.After(5 * time.Second):
				t.Fatal("v2 signing held a Vault transaction")
			}
			unblock()
			assert.Equal(waitAcceptance(t, done).Code, 200)
		})
	}
}
