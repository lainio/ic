package pw

import (
	"bytes"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/policy"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

var invitationNow = time.Date(2026, 11, 2, 12, 0, 0, 123, time.UTC)

func TestInvitationIssuanceAndTimeBoundary(t *testing.T) {
	defer assert.PushTester(t)()
	ids := make(map[string]bool)
	for _, audience := range []string{InvitationAny, InvitationDirected} {
		t.Run(audience, func(t *testing.T) {
			defer assert.PushTester(t)()
			s := ready(t)
			unknown := newSigner(t).public
			var recipient key.Public
			if audience == InvitationDirected {
				recipient = unknown // No Known eligibility for this public key.
			}
			try.To1(
				policy.DenyLocal(
					s.f.vault,
					s.root.public,
					s.local.public,
					unknown,
				),
			)
			try.To1(ads.PublishLocal(
				s.f.vault,
				s.root.public,
				s.local.public,
				s.local.handle,
				"http://127.0.0.1:1/peer/introduction",
				invitationNow,
			))
			_, found := try.To2(
				ReadInvitation(s.f.vault, s.root.public, s.local.public),
			)
			assert.ThatNot(found) // Existing publication never issues consent.
			seedInvitationSurroundings(t, s.f.vault)
			before := invitationSurroundings(t, s.f.vault)
			remaining := s.f.lease.remaining.Load()
			now := invitationNow.In(time.FixedZone("test", 2*60*60))
			row := try.To1(issueInvitation(s.f.vault, s.root.public,
				s.local.public, recipient, now))
			assert.Equal(s.f.lease.remaining.Load(), remaining-1)
			assert.Equal(row.Version, uint8(1))
			assert.Equal(row.State, InvitationActive)
			assert.Equal(row.Audience, audience)
			assert.DeepEqual(row.Root, s.root.public)
			assert.DeepEqual(row.Target, s.local.public)
			assert.DeepEqual(row.Recipient, recipient)
			assert.SLen(row.ID, 32)
			assert.ThatNot(ids[string(row.ID)])
			ids[string(row.ID)] = true
			assert.Equal(
				row.ExpiresUnixNano,
				now.Add(15*time.Minute).UnixNano(),
			)
			assert.DeepEqual(invitationSurroundings(t, s.f.vault), before)
			assert.Equal(len(try.To1(onboarding.ListKnownIntroductions(
				s.f.vault, s.root.public))), 2)

			s.f.unchanged(t, func() {
				expiry := time.Unix(0, row.ExpiresUnixNano).UTC()
				for _, tc := range []struct {
					now  time.Time
					want bool
				}{
					{expiry.Add(-time.Nanosecond), true},
					{expiry, false}, {expiry.Add(time.Nanosecond), false},
					{time.Time{}, false}, {time.Unix(-1, 0), false},
				} {
					stored, found := try.To2(ReadInvitation(s.f.vault,
						s.root.public, s.local.public))
					assert.That(found)
					assert.DeepEqual(stored, row)
					assert.Equal(
						invitationBeforeExpiry(stored, tc.now),
						tc.want,
					)
				}
				for _, next := range []key.Public{recipient, nil, s.peer.public} {
					got, err := issueInvitation(s.f.vault, s.root.public,
						s.local.public, next, expiry.Add(time.Hour))
					assert.Equal(err, ErrInvitationIssued)
					assert.DeepEqual(got, Invitation{})
				}
			})
			// Returned values are detached from persistence and caller inputs.
			row.Root[0] ^= 1
			row.ID[0] ^= 1
			stored, _ := try.To2(
				ReadInvitation(s.f.vault, s.root.public, s.local.public),
			)
			assert.ThatNot(bytes.Equal(row.ID, stored.ID))
			assert.DeepEqual(stored.Root, s.root.public)
		})
	}
}

// Opaque sentinels test preservation, not implemented PW/history/trust formats.
func seedInvitationSurroundings(t *testing.T, v *storage.Vault) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(v.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		for _, name := range []string{"test-acceptance-history", "test-PWHeld", "test-Trust"} {
			try.To(tx.Put([]byte(name), []byte("immutable unrelated sentinel")))
		}
		return nil
	}))
}

func invitationSurroundings(
	t *testing.T,
	v *storage.Vault,
) map[string]map[string][]byte {
	t.Helper()
	defer assert.PushTester(t)()
	result := preservedPolicyState(t, v)
	delete(result[""], invitationKey)
	try.To(v.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		raw, found := try.To2(tx.Get([]byte(policyKey)))
		if found {
			result[""][policyKey] = raw
		}
		return nil
	}))
	return result
}

func TestInvitationRevocationBoundaries(t *testing.T) {
	for _, initial := range []string{"absent", InvitationActive, "expired", InvitationRevoked, InvitationConsumed} {
		t.Run(initial, func(t *testing.T) {
			defer assert.PushTester(t)()
			s := ready(t)
			seedInvitationSurroundings(t, s.f.vault)
			try.To1(
				policy.DenyLocal(
					s.f.vault,
					s.root.public,
					s.local.public,
					s.peer.public,
				),
			)
			before := invitationSurroundings(t, s.f.vault)
			row := Invitation{ID: bytes.Repeat([]byte{1}, 32)}
			if initial != "absent" {
				now := time.Now()
				if initial == "expired" {
					now = now.Add(-2 * InvitationTTL)
				}
				row = try.To1(
					issueInvitation(
						s.f.vault,
						s.root.public,
						s.local.public,
						nil,
						now,
					),
				)
				if initial == InvitationRevoked ||
					initial == InvitationConsumed {
					// Consumed exists only as a fixture; no fake acceptance API.
					row.State = initial
					raw := try.To1(wire.Marshal(row))
					try.To(s.f.vault.Update(func(tx storage.WriteTx) error {
						return tx.Put([]byte(invitationKey), raw)
					}))
				}
			}
			s.f.unchanged(t, func() {
				wrong := bytes.Clone(row.ID)
				wrong[0] ^= 1
				assert.ThatNot(try.To1(RevokeInvitation(s.f.vault,
					s.root.public, s.local.public, wrong)))
			})
			remaining := s.f.lease.remaining.Load()
			want := initial == InvitationActive || initial == "expired"
			if !want {
				s.f.unchanged(t, func() {
					assert.ThatNot(try.To1(RevokeInvitation(s.f.vault,
						s.root.public, s.local.public, row.ID)))
				})
			} else {
				assert.That(try.To1(RevokeInvitation(s.f.vault,
					s.root.public, s.local.public, row.ID)))
				assert.Equal(s.f.lease.remaining.Load(), remaining-1)
				row.State = InvitationRevoked
			}
			s.f.unchanged(t, func() {
				assert.ThatNot(try.To1(RevokeInvitation(s.f.vault,
					s.root.public, s.local.public, row.ID)))
				got, found := try.To2(
					ReadInvitation(s.f.vault, s.root.public, s.local.public),
				)
				assert.Equal(found, initial != "absent")
				if found {
					assert.DeepEqual(got, row)
					_, err := IssueInvitation(
						s.f.vault,
						s.root.public,
						s.local.public,
						s.peer.public,
					)
					assert.Equal(err, ErrInvitationIssued)
				}
			})
			assert.DeepEqual(invitationSurroundings(t, s.f.vault), before)
		})
	}
}

func TestInvitationConcurrentIssueAndRevoke(t *testing.T) {
	defer assert.PushTester(t)()
	f := newVault(t)
	root, target, peer := newSigner(
		t,
	).public, newSigner(
		t,
	).public, newSigner(
		t,
	).public
	type result struct {
		row Invitation
		err error
	}
	results := make(chan result, 16)
	var workers sync.WaitGroup
	f.lease.remaining.Store(1) // Losing attempts must not ask for another seal.
	for i := range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			var recipient key.Public
			if i%2 == 0 {
				recipient = peer
			}
			row, err := issueInvitation(
				f.vault,
				root,
				target,
				recipient,
				invitationNow,
			)
			results <- result{row, err}
		}()
	}
	workers.Wait()
	close(results)
	successes := 0
	var winner Invitation
	for result := range results {
		if result.err == nil {
			successes++
			winner = result.row
		} else {
			assert.Equal(result.err, ErrInvitationIssued)
			assert.DeepEqual(result.row, Invitation{})
		}
	}
	assert.Equal(successes, 1)
	stored, found := try.To2(ReadInvitation(f.vault, root, target))
	assert.That(found)
	assert.DeepEqual(stored, winner)
	f.lease.remaining.Store(1)
	type revocation struct {
		changed bool
		err     error
	}
	revocations := make(chan revocation, 16)
	for range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			changed, err := RevokeInvitation(f.vault, root, target, winner.ID)
			revocations <- revocation{changed, err}
		}()
	}
	workers.Wait()
	close(revocations)
	successes = 0
	for result := range revocations {
		assert.NoError(result.err)
		if result.changed {
			successes++
		}
	}
	assert.Equal(successes, 1)
}

func TestInvitationInvalidInputHasNoDurableEffect(t *testing.T) {
	defer assert.PushTester(t)()
	f := newVault(t)
	root, target, peer := newSigner(
		t,
	).public, newSigner(
		t,
	).public, newSigner(
		t,
	).public
	bad := []key.Public{{}, {0xff}, {0xa0}, make([]byte, 129),
		append(bytes.Clone(peer), 0), append([]byte{0xb8, 5}, peer[1:]...)}
	for _, field := range []int{1, 3, -1, -2, -3} {
		var fields map[int]any
		try.To(wire.Unmarshal(&fields, peer))
		fields[field] = int64(0)
		if field < -1 {
			fields[field] = make([]byte, 32)
		}
		bad = append(bad, try.To1(wire.Marshal(fields)))
	}
	f.unchanged(t, func() {
		for _, invalid := range bad {
			for _, inputs := range [][3]key.Public{
				{invalid, target, nil}, {root, invalid, nil}, {root, target, invalid},
				{nil, target, nil}, {root, nil, nil}, {root, target, target},
			} {
				got, err := issueInvitation(
					f.vault,
					inputs[0],
					inputs[1],
					inputs[2],
					invitationNow,
				)
				assert.Equal(err, ErrInvitationInput)
				assert.DeepEqual(got, Invitation{})
			}
		}
		for _, now := range []time.Time{{}, time.Unix(-1, 0),
			time.Unix(0, math.MaxInt64), time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)} {
			_, err := issueInvitation(f.vault, root, target, nil, now)
			assert.Equal(err, ErrInvitationInput)
		}
		for _, id := range [][]byte{nil, {}, make([]byte, 31), make([]byte, 33)} {
			changed, err := RevokeInvitation(f.vault, root, target, id)
			assert.ThatNot(changed)
			assert.Equal(err, ErrInvitationInput)
		}
		_, err := IssueInvitation(nil, root, target, nil)
		assert.Equal(err, ErrInvitationInput)
		_, _, err = ReadInvitation(nil, root, target)
		assert.Equal(err, ErrInvitationInput)
		_, err = RevokeInvitation(nil, root, target, make([]byte, 32))
		assert.Equal(err, ErrInvitationInput)
	})
}

func TestInvitationFailedEncryptionDoesNotCommit(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "issue", true: "revoke"}[existing],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := newVault(t)
				root, target := newSigner(t).public, newSigner(t).public
				var row Invitation
				if existing {
					row = try.To1(IssueInvitation(f.vault, root, target, nil))
				}
				f.lease.remaining.Store(0)
				f.unchanged(t, func() {
					if existing {
						changed, err := RevokeInvitation(
							f.vault,
							root,
							target,
							row.ID,
						)
						assert.ThatNot(changed)
						assert.Equal(err, ErrInvitationState)
					} else {
						got, err := IssueInvitation(f.vault, root, target, nil)
						assert.DeepEqual(got, Invitation{})
						assert.Equal(err, ErrInvitationState)
					}
				})
				f.reopen(t)
				got, found := try.To2(ReadInvitation(f.vault, root, target))
				assert.Equal(found, existing)
				assert.DeepEqual(got, row)
			},
		)
	}
}
