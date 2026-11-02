package ownerapi

import (
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/storage"
)

func TestEstablishmentRefusesBeforeAcceptanceSigning(t *testing.T) {
	for _, state := range []string{
		"revoked", "expired", "missing", "history with Active", "held with Active",
	} {
		t.Run(state, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishmentOwner(t)
			if state == "revoked" {
				w := deviceRequest(
					f.owner,
					f.auth,
					"POST",
					invitationRevokePath,
					revokeInvitationBody(f.request.Payload.InvitationID),
				)
				assert.Equal(w.Code, 200)
				assert.Equal(w.Body.String(), `{"revoked":true}`)
			} else {
				try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					switch state {
					case "missing":
						return tx.Delete([]byte("local-pw-invitation-v1"))
					case "history with Active":
						return tx.Put([]byte("local-pw-accepted-v1"), []byte{0xff})
					case "held with Active":
						return tx.Put([]byte("local-pw-held-v1"), []byte{0xff})
					default:
						raw, _ := try.To2(tx.Get([]byte("local-pw-invitation-v1")))
						var row pw.Invitation
						try.To(wire.UnmarshalCanonical(&row, raw))
						row.ExpiresUnixNano = time.Unix(1_000_000, 0).UnixNano()
						return tx.Put([]byte("local-pw-invitation-v1"),
							try.To1(wire.Marshal(row)))
					}
				}))
			}
			defer f.unchanged(t)()
			w := deviceRequest(f.peer, "", "POST", establishmentPath, f.body)
			assert.Equal(w.Code, 409)
			assert.Equal(w.Body.String(), "Conflict\n")
			assert.Equal(f.signer.signs.Load(), int32(0))
		})
	}
}

func TestEstablishmentConsumedHistoryCannotRecreateDeletedState(t *testing.T) {
	for _, fault := range []string{"held", "history", "signer"} {
		t.Run(fault, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishmentOwner(t)
			assert.Equal(deviceRequest(f.peer, "", "POST", establishmentPath,
				f.body).Code, 200)
			before := f.records(t)
			if fault == "signer" {
				f.publisher.mutations.Lock()
				f.publisher.signer = nil
				f.publisher.mutations.Unlock()
			} else {
				name := "local-pw-held-v1"
				if fault == "history" {
					name = "local-pw-accepted-v1"
				}
				try.To(f.vault.Update(func(tx storage.WriteTx) error {
					return tx.Delete([]byte(name))
				}))
			}
			defer f.unchanged(t)()
			for range 2 {
				w := deviceRequest(
					f.peer,
					"",
					"POST",
					establishmentPath,
					f.body,
				)
				assert.Equal(w.Code, 409)
				assert.Equal(w.Body.String(), "Conflict\n")
			}
			after := f.records(t)
			assert.DeepEqual(after[0], before[0])
			if fault != "history" {
				assert.DeepEqual(after[1], before[1])
			}
			if fault != "held" {
				assert.DeepEqual(after[2], before[2])
			}
			want := int32(
				5,
			) // Initial probe + acceptance + reply, two retry probes.
			if fault == "signer" {
				want = 3
			}
			assert.Equal(f.signer.signs.Load(), want)
		})
	}
}

func TestEstablishmentCommitFailureNeverRepliesSuccess(t *testing.T) {
	for allowance := range int64(3) {
		t.Run(time.Duration(allowance).String(), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newEstablishmentOwner(t)
			before := f.records(t)
			f.lease.remaining.Store(allowance)
			w := deviceRequest(f.peer, "", "POST", establishmentPath, f.body)
			assert.Equal(w.Code, 409)
			assert.Equal(w.Body.String(), "Conflict\n")
			assert.DeepEqual(f.records(t), before)
			assert.Equal(
				f.signer.signs.Load(),
				int32(2),
			) // No automatic second attempt.
		})
	}
}
