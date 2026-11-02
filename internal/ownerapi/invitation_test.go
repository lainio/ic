package ownerapi

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const issueAnyBody = `{"recipient_public_key_hex":null}`

type invitationOwnerFixture struct {
	deviceFixture
	root, target key.Public
	signer       *deviceProbe
	owner        http.Handler
	auth         string
	handler      *acceptanceExchangeHandler
}

func newInvitationOwner(t *testing.T) invitationOwnerFixture {
	t.Helper()
	defer assert.PushTester(t)()
	f := invitationOwnerFixture{deviceFixture: newDeviceFixture(t),
		signer: &deviceProbe{Handle: key.New()}}
	f.root = try.To1(key.New().CBORPublicKey())
	f.target = try.To1(f.signer.Handle.CBORPublicKey())
	file := ""
	f.owner, file, _ = try.To3(NewAcceptanceCredentials(t.Context(), f.vault,
		f.root, f.target, f.signer, t.TempDir()))
	f.auth = strings.TrimSpace(strings.TrimPrefix(
		string(try.To1(os.ReadFile(file))), "Authorization: "))
	f.handler = f.owner.(*authenticatedStatusHandler).next.(*acceptanceExchangeHandler)
	_, found := try.To2(pw.ReadInvitation(f.vault, f.root, f.target))
	assert.ThatNot(found) // Construction cannot issue, even with a signer.
	return f
}

func revokeInvitationBody(id []byte) string {
	return `{"invitation_id_hex":"` + hex.EncodeToString(id) + `"}`
}

func TestInvitationOwnerIssueAndRevoke(t *testing.T) {
	for _, directed := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "Any", true: "Directed"}[directed],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newInvitationOwner(t)
				body, audience := issueAnyBody, pw.InvitationAny
				var recipient key.Public
				if directed {
					recipient = try.To1(key.New().CBORPublicKey())
					body = `{"recipient_public_key_hex":"` + hex.EncodeToString(
						recipient,
					) + `"}`
					audience = pw.InvitationDirected
				}
				start := time.Now()
				w := deviceRequest(
					f.owner,
					f.auth,
					"POST",
					invitationIssuePath,
					body,
				)
				assert.Equal(w.Code, 200)
				assert.Equal(w.Header().Get("Cache-Control"), "no-store")
				assert.Equal(w.Header().Get("Content-Type"), "application/json")
				assert.Empty(w.Header().Get("WWW-Authenticate"))
				var fields map[string]json.RawMessage
				try.To(json.Unmarshal(w.Body.Bytes(), &fields))
				assert.Equal(len(fields), 4)
				var reply struct {
					ID        string  `json:"invitation_id_hex"`
					Expiry    int64   `json:"expires_unix_nano"`
					Audience  string  `json:"audience"`
					Recipient *string `json:"recipient_public_key_hex"`
				}
				try.To(json.Unmarshal(w.Body.Bytes(), &reply))
				id := try.To1(hex.DecodeString(reply.ID))
				assert.SLen(id, 32)
				assert.Equal(hex.EncodeToString(id), reply.ID)
				assert.Equal(reply.Audience, audience)
				assert.That(
					reply.Expiry >= start.Add(pw.InvitationTTL).UnixNano(),
				)
				assert.That(
					reply.Expiry <= time.Now().Add(pw.InvitationTTL).UnixNano(),
				)
				if directed {
					assert.Equal(
						*reply.Recipient,
						hex.EncodeToString(recipient),
					)
				} else {
					assert.Nil(reply.Recipient)
				}
				row, found := try.To2(
					pw.ReadInvitation(f.vault, f.root, f.target),
				)
				assert.That(found)
				assert.DeepEqual(row.ID, id)
				assert.DeepEqual(row.Root, f.root)
				assert.DeepEqual(row.Target, f.target)
				assert.DeepEqual(row.Recipient, recipient)
				assert.Equal(row.ExpiresUnixNano, reply.Expiry)
				assert.Equal(
					deviceRequest(
						f.owner,
						f.auth,
						"POST",
						invitationIssuePath,
						body,
					).Code,
					409,
				)
				w = deviceRequest(
					f.owner,
					f.auth,
					"POST",
					invitationRevokePath,
					revokeInvitationBody(id),
				)
				assert.Equal(w.Code, 200)
				assert.Equal(w.Body.String(), `{"revoked":true}`)
				row.State = pw.InvitationRevoked
				got, _ := try.To2(pw.ReadInvitation(f.vault, f.root, f.target))
				assert.DeepEqual(got, row)
				defer f.unchanged(t)()
				w = deviceRequest(
					f.owner,
					f.auth,
					"POST",
					invitationRevokePath,
					revokeInvitationBody(id),
				)
				assert.Equal(w.Code, 200)
				assert.Equal(w.Body.String(), `{"revoked":false}`)
				assert.Equal(f.signer.publics.Load(), int32(0))
				assert.Equal(f.signer.signs.Load(), int32(0))
			},
		)
	}
}

func TestInvitationOwnerAuthenticationBeforeBody(t *testing.T) {
	defer assert.PushTester(t)()
	f := newInvitationOwner(t)
	defer f.unchanged(t)()
	for _, path := range []string{invitationIssuePath, invitationRevokePath} {
		for _, auth := range []string{"", "Bearer " + strings.Repeat("0", 64), "Basic " + f.auth} {
			body := strings.NewReader(issueAnyBody)
			r := httptest.NewRequest("POST", path, body)
			r.Header.Set("Authorization", auth)
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			f.owner.ServeHTTP(w, r)
			assert.Equal(w.Code, 401)
			assert.Equal(w.Body.String(), "Unauthorized\n")
			assert.Equal(
				w.Header().Get("WWW-Authenticate"),
				`Bearer realm="owner-status"`,
			)
			assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			assert.Equal(body.Len(), len(issueAnyBody))
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(issueAnyBody))
		r.Header.Add("Authorization", f.auth)
		r.Header.Add("Authorization", f.auth)
		w := httptest.NewRecorder()
		f.owner.ServeHTTP(w, r)
		assert.Equal(w.Code, 401)
	}
}

func TestInvitationOlderCredentialsAndPeerExcluded(t *testing.T) {
	defer assert.PushTester(t)()
	f := newInvitationOwner(t)
	defer f.unchanged(t)()
	for _, version := range []string{"status", "read", "evidence", "device", "publication", "proof", "verification", "bare", "peer"} {
		var h http.Handler
		var file string
		dir := t.TempDir()
		switch version {
		case "status":
			h, file = try.To2(
				NewStatusCredentials(
					t.Context(),
					f.vault,
					f.root,
					f.target,
					dir,
				),
			)
		case "read":
			h, file = try.To2(
				NewReadCredentials(t.Context(), f.vault, f.root, f.target, dir),
			)
		case "evidence":
			h, file = try.To2(
				NewEvidenceCredentials(
					t.Context(),
					f.vault,
					f.root,
					f.target,
					dir,
				),
			)
		case "device":
			h, file = try.To2(
				NewDeviceCredentials(
					t.Context(),
					f.vault,
					f.root,
					f.target,
					f.signer,
					dir,
				),
			)
		case "publication":
			h, file, _ = try.To3(
				NewPublicationCredentials(
					t.Context(),
					f.vault,
					f.root,
					f.target,
					f.signer,
					dir,
				),
			)
		case "proof":
			h, file, _ = try.To3(
				NewPublicationProofCredentials(
					t.Context(),
					f.vault,
					f.root,
					f.target,
					f.signer,
					dir,
				),
			)
		case "verification":
			h, file, _ = try.To3(
				NewVerificationCredentials(
					t.Context(),
					f.vault,
					f.root,
					f.target,
					f.signer,
					dir,
				),
			)
		case "bare":
			h = NewStatusHandler(f.vault, f.root, f.target)
		case "peer":
			h = peerapi.NewAcceptanceHandler(f.vault, f.root, f.target, "", nil,
				peerapi.NewProofHandler(f.vault, f.root, f.target, "", nil))
		}
		auth := f.auth
		if file != "" {
			auth = strings.TrimSpace(
				strings.TrimPrefix(
					string(try.To1(os.ReadFile(file))),
					"Authorization: ",
				),
			)
		}
		for _, path := range []string{invitationIssuePath, invitationRevokePath,
			"/peer/pw/invitations/issue", "/peer/pw/invitations/revoke"} {
			for _, method := range []string{"POST", "GET"} {
				w := deviceRequest(h, auth, method, path, issueAnyBody)
				assert.Equal(w.Code, 404, version)
			}
		}
	}
	assert.Equal(f.signer.publics.Load(), int32(0))
	assert.Equal(f.signer.signs.Load(), int32(0))
}

func TestInvitationLostResponseKeepsCommitAndReleasesLock(t *testing.T) {
	defer assert.PushTester(t)()
	f := newInvitationOwner(t)
	var row pw.Invitation
	for _, path := range []string{invitationIssuePath, invitationRevokePath} {
		body, want := issueAnyBody, pw.InvitationActive
		if path == invitationRevokePath {
			body, want = revokeInvitationBody(row.ID), pw.InvitationRevoked
		}
		writes := 0
		w := acceptanceWriteCheck{httptest.NewRecorder(), func() {
			writes++
			assert.That(f.handler.mutations.TryLock())
			f.handler.mutations.Unlock()
			var found bool
			row, found = try.To2(pw.ReadInvitation(f.vault, f.root, f.target))
			assert.That(found)
			assert.Equal(row.State, want)
		}}
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Authorization", f.auth)
		r.Header.Set("Content-Type", "application/json")
		remaining := f.lease.remaining.Load()
		f.owner.ServeHTTP(w, r)
		assert.Equal(w.Code, 200)
		assert.Equal(writes, 1)
		assert.Equal(f.lease.remaining.Load(), remaining-1)
		unchanged := f.unchanged(t)
		assert.Equal(
			deviceRequest(
				f.owner,
				f.auth,
				"POST",
				invitationIssuePath,
				issueAnyBody,
			).Code,
			409,
		)
		got, _ := try.To2(pw.ReadInvitation(f.vault, f.root, f.target))
		assert.DeepEqual(got, row)
		unchanged()
	}
}

func TestInvitationOwnerStorageErrorsSanitized(t *testing.T) {
	for _, damage := range []string{"corrupt", "encryption", "closed", "binding"} {
		t.Run(damage, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newInvitationOwner(t)
			id := make([]byte, 32)
			switch damage {
			case "corrupt":
				try.To(f.vault.Update(func(tx storage.WriteTx) error {
					return tx.Put(
						[]byte("local-pw-invitation-v1"),
						[]byte("PRIVATE_INVITATION_MARKER"),
					)
				}))
			case "encryption":
				row := try.To1(
					pw.IssueInvitation(f.vault, f.root, f.target, nil),
				)
				id = row.ID
				f.lease.remaining.Store(0)
			case "closed":
				try.To(f.vault.Close())
			case "binding":
				row := try.To1(pw.IssueInvitation(f.vault, f.root, f.root, nil))
				id = row.ID
			}
			defer f.unchanged(t)()
			for _, path := range []string{invitationIssuePath, invitationRevokePath} {
				body, want := issueAnyBody, 500
				if path == invitationRevokePath {
					body = revokeInvitationBody(id)
				} else if damage == "encryption" {
					want = 409
				}
				w := deviceRequest(f.owner, f.auth, "POST", path, body)
				assert.Equal(w.Code, want)
				assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
				assert.Equal(w.Header().Get("Cache-Control"), "no-store")
			}
		})
	}
}
