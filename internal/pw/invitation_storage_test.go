package pw

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestInvitationCorruptRecordsFailClosed(t *testing.T) {
	defer assert.PushTester(t)()
	root, target, peer := newSigner(
		t,
	).public, newSigner(
		t,
	).public, newSigner(
		t,
	).public
	good := Invitation{Version: 1, ID: bytes.Repeat([]byte{1}, 32),
		Root: root, Target: target, Audience: InvitationAny,
		ExpiresUnixNano: invitationNow.Add(InvitationTTL).UnixNano(),
		State:           InvitationActive}
	raw := try.To1(wire.Marshal(good))
	cases := map[string][]byte{
		"empty": nil, "truncated": raw[:len(raw)-1],
		"trailing":     append(bytes.Clone(raw), 0),
		"noncanonical": append([]byte{0x98, 8}, raw[1:]...),
		"tagged":       append([]byte{0xc0}, raw...),
		"oversize":     make([]byte, maxInvitationBytes+1),
		"map": {
			0xa0,
		}, "missing field": try.To1(wire.Marshal([]any{1})),
		"extra field": try.To1(wire.Marshal([]any{1, good.ID, root,
			target, InvitationAny, nil, good.ExpiresUnixNano, good.State, true})),
		"private diagnostic": try.To1(wire.Marshal(map[string]string{
			"PRIVATE_INVITATION_MARKER": "PRIVATE_INVITATION_MARKER"})),
	}
	for name, damage := range map[string]func(*Invitation){
		"version":             func(r *Invitation) { r.Version = 2 },
		"foreign Root":        func(r *Invitation) { r.Root = peer },
		"foreign target":      func(r *Invitation) { r.Target = peer },
		"invalid Root":        func(r *Invitation) { r.Root = nil },
		"short ID":            func(r *Invitation) { r.ID = r.ID[:31] },
		"long ID":             func(r *Invitation) { r.ID = append(r.ID, 0) },
		"null ID":             func(r *Invitation) { r.ID = nil },
		"empty state":         func(r *Invitation) { r.State = "" },
		"expired state":       func(r *Invitation) { r.State = "Expired" },
		"negative expiry":     func(r *Invitation) { r.ExpiresUnixNano = -1 },
		"impossible expiry":   func(r *Invitation) { r.ExpiresUnixNano = 1 },
		"unknown audience":    func(r *Invitation) { r.Audience = "any" },
		"Any bound recipient": func(r *Invitation) { r.Recipient = peer },
		"Any empty recipient": func(r *Invitation) { r.Recipient = key.Public{} },
		"Directed nil":        func(r *Invitation) { r.Audience = InvitationDirected },
		"Directed malformed": func(r *Invitation) {
			r.Audience, r.Recipient = InvitationDirected, key.Public{0xff}
		},
		"Directed self": func(r *Invitation) {
			r.Audience, r.Recipient = InvitationDirected, target
		},
	} {
		var row Invitation
		try.To(wire.UnmarshalCanonical(&row, raw))
		damage(&row)
		cases[name] = try.To1(wire.Marshal(row))
	}
	for name, damaged := range cases {
		t.Run(name, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newVault(t)
			try.To(f.vault.Update(func(tx storage.WriteTx) error {
				return tx.Put([]byte(invitationKey), damaged)
			}))
			assertRejectedInvitation(t, f, root, target, good.ID)
			f.reopen(t)
			assertRejectedInvitation(t, f, root, target, good.ID)
		})
	}
}

func assertRejectedInvitation(t *testing.T, f vaultFixture,
	root, target key.Public, id []byte,
) {
	t.Helper()
	defer assert.PushTester(t)()
	f.unchanged(t, func() {
		row, found, err := ReadInvitation(f.vault, root, target)
		assert.Equal(err, ErrInvitationState)
		assert.ThatNot(found)
		assert.DeepEqual(row, Invitation{})
		row, err = IssueInvitation(f.vault, root, target, nil)
		assert.Equal(err, ErrInvitationState)
		assert.DeepEqual(row, Invitation{})
		for _, candidate := range [][]byte{id, bytes.Repeat([]byte{9}, 32)} {
			changed, err := RevokeInvitation(f.vault, root, target, candidate)
			assert.ThatNot(changed)
			assert.Equal(err, ErrInvitationState)
		}
	})
}

func TestInvitationBindingAndNamespaceConflict(t *testing.T) {
	defer assert.PushTester(t)()
	root, target, other := newSigner(
		t,
	).public, newSigner(
		t,
	).public, newSigner(
		t,
	).public
	f := newVault(t)
	row := try.To1(IssueInvitation(f.vault, root, target, nil))
	assertRejectedInvitation(t, f, other, target, row.ID)
	assertRejectedInvitation(t, f, root, other, row.ID)
	try.To(f.vault.Close())
	assertRejectedInvitation(t, f, root, target, row.ID)
	f = newVault(t)
	try.To(f.vault.Update(func(tx storage.WriteTx) (err error) {
		defer err2.Handle(&err, nil)
		try.To1(tx.EnsureChild([]byte(invitationKey)))
		return nil
	}))
	assertRejectedInvitation(t, f, root, target, row.ID)
}

func TestInvitationDiagnosticsExcludeStoredSecret(t *testing.T) {
	defer assert.PushTester(t)()
	f := newVault(t)
	root, target := newSigner(t).public, newSigner(t).public
	const secret = "PRIVATE_INVITATION_MARKER"
	raw := try.To1(wire.Marshal(map[string]string{secret: secret}))
	try.To(f.vault.Update(func(tx storage.WriteTx) error {
		return tx.Put([]byte(invitationKey), raw)
	}))
	var trace bytes.Buffer
	previousError, previousReturn := err2.ErrorTracer(), err2.ErrRetTracer()
	err2.SetErrorTracer(&trace)
	err2.SetErrRetTracer(&trace)
	defer func() {
		err2.SetErrorTracer(previousError)
		err2.SetErrRetTracer(previousReturn)
	}()
	assertRejectedInvitation(t, f, root, target, bytes.Repeat([]byte{1}, 32))
	assert.ThatNot(strings.Contains(trace.String(), secret))
}
