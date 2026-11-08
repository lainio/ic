package pw

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestMessageSendV2SeparateCommitsAndReadOnlyRetry(t *testing.T) {
	for seals := range int64(4) {
		t.Run(fmt.Sprint(seals), func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			n := outgoingTestNodes(f.requesterFixture)[1]
			n.own.lease.remaining.Store(seals)
			prepared, err := PrepareMessageSendV2(n.own.vault, f.root.public,
				n.local, n.signer, f.aliceRuntime, "retained")
			if seals < 3 {
				assert.Error(err)
				assert.Equal(prepared, PreparedMessageSendV2{})
			} else {
				assert.NoError(err)
			}
			before := outgoingTestState(t, n.own.vault)
			for i, name := range []string{outgoingKey, messageEnvelopeKey,
				messageSentKey, messageACKKey} {
				assert.Equal(len(before["root"][name]) > 0, int64(i) < seals)
			}
			n.own.lease.remaining.Store(3 - seals)
			prepared = try.To1(PrepareMessageSendV2(n.own.vault, f.root.public,
				n.local, n.signer, f.aliceRuntime, "retained"))
			assert.Equal(
				prepared.saved.destination,
				f.bobRuntime.BoundOrigin+messagePath,
			)
			assert.Equal(n.own.lease.remaining.Load(), 0)
			for name, row := range before["root"] {
				assert.DeepEqual(
					outgoingTestState(t, n.own.vault)["root"][name],
					row,
				)
			}
			n.own.unchanged(t, func() {
				again := try.To1(
					PrepareMessageSendV2(n.own.vault, f.root.public,
						n.local, n.signer, f.aliceRuntime, "retained"),
				)
				assert.Equal(again, prepared)
				_, err := PrepareMessageSendV2(n.own.vault, f.root.public,
					n.local, n.signer, f.aliceRuntime, "changed")
				assert.Error(err)
			})
		})
	}
}

func TestMessageTransmitV2FinalBoundary(t *testing.T) {
	for _, mode := range []string{"deny", "retry deny", "contact",
		"envelope", "corrupt history", "v1 sent", "v1 digest"} {
		t.Run(mode, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := newOutgoingV2(t)
			n := outgoingTestNodes(f.requesterFixture)[1]
			try.To1(CreateOutgoingV2(n.own.vault, f.root.public, n.local,
				n.signer, f.aliceRuntime, "saved"))
			raw := try.To1(PrepareOutgoingEnvelopeV2(n.own.vault, f.root.public,
				n.local, n.signer, f.aliceRuntime))
			if mode == "retry deny" || mode == "v1 sent" ||
				mode == "v1 digest" {
				try.To1(saveMessageTransmitV2(n.own.vault, f.root.public,
					n.local, n.signer, f.aliceRuntime))
			}
			signer := &probeSigner{Handle: n.signer}
			var after map[string]map[string][]byte
			signer.sign = func(data []byte) (_ []byte, err error) {
				defer err2.Handle(&err, nil)
				// Any write here would deadlock if probing held a transaction.
				switch mode {
				case "deny", "retry deny":
					try.To(mutateEnvelopeGuard(n, f.root.public, "deny"))
				case "contact":
					replaceMessageHistoryV2(t, f, n, "target contact")
				case "corrupt history":
					try.To(mutateEnvelopeGuard(n, f.root.public, "history"))
				case "envelope":
					var envelope messageEnvelopeV2
					try.To(wire.UnmarshalCanonical(&envelope, raw))
					digest := key.HashTagged(
						messageAuthPurposeV2,
						envelope.Message,
					)
					envelope.Signature = try.To1(n.signer.Sign(digest[:]))
					changed := try.To1(wire.Marshal(envelope))
					assert.ThatNot(bytes.Equal(changed, raw))
					try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
						return tx.Put([]byte(messageEnvelopeKey), changed)
					}))
				default:
					digest := key.HashTagged(messageSentEnvelopePurposeV2, raw)
					version := uint8(1)
					if mode == "v1 digest" {
						version = 2
						digest = key.HashTagged(messageSentEnvelopePurpose, raw)
					}
					bad := try.To1(wire.Marshal(messageSent{
						Version: version, EnvelopeDigest: digest[:],
					}))
					try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
						return tx.Put([]byte(messageSentKey), bad)
					}))
				}
				after = outgoingTestState(t, n.own.vault)
				return n.signer.Sign(data)
			}
			n.other.unchanged(t, func() {
				saved, err := saveMessageTransmitV2(n.own.vault, f.root.public,
					n.local, signer, f.aliceRuntime)
				assert.Equal(err, errMessageTransmit)
				assert.Equal(saved, savedMessageTransmitV2{})
			})
			assert.Equal(signer.signCalls.Load(), 1)
			assert.DeepEqual(outgoingTestState(t, n.own.vault), after)
		})
	}
}

func TestMessageSendV2ExpiredBootstrapAndSnapshotPolicy(t *testing.T) {
	defer assert.PushTester(t)()
	f := newFirstUseV2(t)
	f.now = f.now.Add(24 * time.Hour)
	use := try.To1(f.startUseV2())
	response := try.To1(f.bobUseV2(use.request, f.local.handle))
	assert.That(try.To1(f.receiveUseV2(response)))
	for _, n := range outgoingTestNodes(f.requesterFixture) {
		runtime := f.messageRuntime(n)
		prepared := try.To1(PrepareMessageSendV2(n.own.vault, f.root.public,
			n.local, n.signer, runtime, "historical eligibility"))
		before := prepared
		guard := "deny"
		if n.name == "Bob" {
			guard = "delete"
		}
		try.To(mutateEnvelopeGuard(n, f.root.public, guard))
		n.own.unchanged(t, func() {
			_, err := PrepareMessageSendV2(n.own.vault, f.root.public,
				n.local, n.signer, runtime, "historical eligibility")
			assert.Error(err)
			assert.Equal(prepared, before) // Already authorized bytes survive.
		})
	}
	receipt, err := SendMessageOnceV2(t.Context(), PreparedMessageSendV2{})
	assert.ErrorIs(err, ErrMessageNotDispatched)
	assert.SNil(receipt)
}
