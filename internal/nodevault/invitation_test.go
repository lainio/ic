package nodevault

import (
	"bytes"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestInvitationStoreReopen(t *testing.T) {
	for _, directed := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "Any", true: "Directed"}[directed],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := try.To1(prepareFixture(t.TempDir()))
				defer clear(f.secret)
				s := try.To1(
					Create(t.Context(), f.state(), f.secret, f.binding),
				)
				defer func() { assert.NoError(s.Close()) }()
				var recipient key.Public
				if directed {
					recipient = f.binding.Root
				}
				start := time.Now()
				row := try.To1(
					pw.IssueInvitation(
						s.Vault(),
						f.binding.Root,
						f.binding.Child,
						recipient,
					),
				)
				assert.That(
					row.ExpiresUnixNano >= start.Add(pw.InvitationTTL).
						UnixNano(),
				)
				assert.That(
					row.ExpiresUnixNano <= time.Now().
						Add(pw.InvitationTTL).
						UnixNano(),
				)
				for _, revoked := range []bool{false, true} {
					if revoked {
						assert.That(try.To1(pw.RevokeInvitation(s.Vault(),
							f.binding.Root, f.binding.Child, row.ID)))
						row.State = pw.InvitationRevoked
					}
					before := storedInvitationBytes(t, s.Vault())
					assert.DeepEqual(before, try.To1(wire.Marshal(row)))
					for _, data := range try.To1(stateFiles(f)) {
						assert.ThatNot(bytes.Contains(data, row.ID))
						assert.ThatNot(bytes.Contains(data, before))
					}
					try.To(s.Close())
					s = try.To1(
						Open(t.Context(), f.state(), f.secret, f.binding),
					)
					got, found := try.To2(
						pw.ReadInvitation(
							s.Vault(),
							f.binding.Root,
							f.binding.Child,
						),
					)
					assert.That(found)
					assert.DeepEqual(got, row)
					assert.DeepEqual(
						storedInvitationBytes(t, s.Vault()),
						before,
					)
					files := try.To1(stateFiles(f))
					remaining := s.provider.remaining
					_, err := pw.IssueInvitation(
						s.Vault(),
						f.binding.Root,
						f.binding.Child,
						nil,
					)
					assert.Equal(err, pw.ErrInvitationIssued)
					assert.Equal(s.provider.remaining, remaining)
					assert.DeepEqual(try.To1(stateFiles(f)), files)
				}
			},
		)
	}
}

func storedInvitationBytes(t *testing.T, vault *storage.Vault) []byte {
	t.Helper()
	defer assert.PushTester(t)()
	var raw []byte
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		var found bool
		raw, found = try.To2(tx.Get([]byte("local-pw-invitation-v1")))
		assert.That(found)
		return nil
	}))
	return raw
}

func TestInvitationStoreProviderFailureSurvivesReopen(t *testing.T) {
	for _, issued := range []bool{false, true} {
		t.Run(
			map[bool]string{false: "issue", true: "revoke"}[issued],
			func(t *testing.T) {
				defer assert.PushTester(t)()
				f := try.To1(prepareFixture(t.TempDir()))
				defer clear(f.secret)
				s := try.To1(
					Create(t.Context(), f.state(), f.secret, f.binding),
				)
				defer func() { assert.NoError(s.Close()) }()
				var row pw.Invitation
				if issued {
					row = try.To1(
						pw.IssueInvitation(
							s.Vault(),
							f.binding.Root,
							f.binding.Child,
							nil,
						),
					)
				}
				s.provider.remaining = 0
				before := try.To1(stateFiles(f))
				if issued {
					changed, err := pw.RevokeInvitation(
						s.Vault(),
						f.binding.Root,
						f.binding.Child,
						row.ID,
					)
					assert.ThatNot(changed)
					assert.Equal(err, pw.ErrInvitationState)
				} else {
					got, err := pw.IssueInvitation(s.Vault(), f.binding.Root, f.binding.Child, nil)
					assert.DeepEqual(got, pw.Invitation{})
					assert.Equal(err, pw.ErrInvitationState)
				}
				assert.DeepEqual(try.To1(stateFiles(f)), before)
				try.To(s.Close())
				s = try.To1(Open(t.Context(), f.state(), f.secret, f.binding))
				got, found := try.To2(
					pw.ReadInvitation(
						s.Vault(),
						f.binding.Root,
						f.binding.Child,
					),
				)
				assert.Equal(found, issued)
				assert.DeepEqual(got, row)
			},
		)
	}
}
