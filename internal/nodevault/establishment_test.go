package nodevault

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/pw"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// One real nodevault fixture covers all three encryption boundaries and restart.
// Here the fixture's saved signer is Bob; the requester has a separate Vault
// which Bob never receives. No Alice acceptance or attempt is persisted.
func TestBobEstablishmentStoreRestart(t *testing.T) {
	for allowance := range uint64(4) {
		t.Run(fmt.Sprint(allowance), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := try.To1(prepareFixture(t.TempDir()))
			defer clear(f.secret)
			store := try.To1(
				Create(t.Context(), f.state(), f.secret, f.binding),
			)
			defer func() { assert.NoError(store.Close()) }()
			requester := key.New()
			public := key.Public(try.To1(requester.CBORPublicKey()))
			other := fixture{
				dir:     t.TempDir(),
				secret:  randomSecret(),
				binding: f.binding,
			}
			defer clear(other.secret)
			other.binding.Child = public
			alice := try.To1(
				Create(t.Context(), other.state(), other.secret, other.binding),
			)
			defer func() { assert.NoError(alice.Close()) }()
			aliceBefore := try.To1(stateFiles(other))
			try.To2(onboarding.SaveIntroduction(
				store.Vault(),
				f.binding.Root,
				f.proposal.Bytes(),
				try.To1(f.proposal.SignAcceptance(f.alice)),
			))
			path := f.proposal.Introduce(f.alice, key.Info{Public: public})
			try.To2(onboarding.SaveIntroduction(store.Vault(), f.binding.Root,
				path.Bytes(), try.To1(path.SignAcceptance(requester))))
			try.To1(onboarding.VerifyReceived(store.Vault(), f.binding.Root))
			try.To1(device.BootstrapLocal(store.Vault(), f.binding.Root,
				f.binding.Child, f.alice))
			const endpoint = "http://127.0.0.1:12345/peer/introduction"
			ad := try.To1(ads.PublishLocal(store.Vault(), f.binding.Root,
				f.binding.Child, f.alice, endpoint, time.Now()))
			invitation := try.To1(pw.IssueInvitation(store.Vault(),
				f.binding.Root, f.binding.Child, public))
			request := pw.SignedEstablishment{Payload: pw.Establishment{
				Version: 1, Root: f.binding.Root, Requester: public,
				Target: f.binding.Child, InvitationID: invitation.ID,
				Audience: invitation.Audience, Recipient: public,
				AttemptID: bytes.Repeat([]byte{41}, 32), Device: public,
				Ad: try.To1(wire.Marshal(ad)),
			}}
			digest := key.HashTagged(pw.EstablishPurpose,
				try.To1(wire.Marshal(request.Payload)))
			request.Signature = try.To1(requester.Sign(digest[:]))
			raw := try.To1(wire.Marshal(request))
			store.provider.remaining = allowance
			err := pw.BobAccept(store.Vault(), f.binding.Root, f.binding.Child,
				f.alice, endpoint, raw)
			if allowance < 3 {
				assert.Equal(err, pw.ErrEstablishment)
			} else {
				assert.NoError(err)
			}
			before := readBobEstablishment(t, store.Vault())
			try.To(store.Close())
			store = try.To1(Open(t.Context(), f.state(), f.secret, f.binding))
			assert.DeepEqual(readBobEstablishment(t, store.Vault()), before)
			row, found := try.To2(
				pw.ReadInvitation(
					store.Vault(),
					f.binding.Root,
					f.binding.Child,
				),
			)
			assert.That(found)
			if allowance < 3 {
				assert.DeepEqual(row, invitation)
				assert.SNil(before[1])
				assert.SNil(before[2])
			} else {
				assert.Equal(row.State, pw.InvitationConsumed)
				var record struct {
					_                 struct{} `cbor:",toarray"`
					Version           uint8
					Request, Response []byte
				}
				try.To(wire.UnmarshalCanonical(&record, before[1]))
				assert.Equal(record.Version, 1)
				assert.DeepEqual(record.Request, raw)
				var result pw.SignedAccepted
				try.To(wire.UnmarshalCanonical(&result, record.Response))
				assert.DeepEqual(result.Payload.Binding, request.Payload)
				digest := key.HashTagged(pw.AcceptedPurpose, try.To1(wire.Marshal(result.Payload)))
				assert.That(result.Signature.Verify(f.binding.Child, digest[:]))
				assert.SNotEmpty(before[2])
			}
			assert.DeepEqual(try.To1(stateFiles(other)), aliceBefore)
			assert.DeepEqual(
				readBobEstablishment(t, alice.Vault()),
				[3][]byte{},
			)
		})
	}
}

func readBobEstablishment(
	t *testing.T,
	vault *storage.Vault,
) (records [3][]byte) {
	t.Helper()
	defer assert.PushTester(t)()
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
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
