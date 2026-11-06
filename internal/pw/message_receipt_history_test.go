package pw

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestMessageReceiptRetainedHistoryAndFinalInbox(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, mode := range []string{"corrupt acceptance", "foreign acceptance",
			"noncanonical acceptance", "resigned acceptance", "role",
			"missing holding", "corrupt holding", "mismatched holding",
			"first use version", "first use request", "first use response",
			"no historical response", "Await", "missing inbox", "corrupt inbox",
			"resigned inbox"} {
			for _, during := range []bool{false, true} {
				t.Run(
					fmt.Sprint(receiver, "/", mode, "/", during),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f, n, raw, expected := receiptTest(t, receiver)
						prior := try.To1(issueMessageReceipt(n.own.vault,
							f.root.public, n.local, n.signer, raw))
						rows := outgoingTestState(t, n.own.vault)["root"]
						var history acceptedRecord
						try.To(
							wire.UnmarshalCanonical(
								&history,
								rows[acceptedKey],
							),
						)
						name, bad := acceptedKey, []byte{0xff}
						switch mode {
						case "corrupt acceptance":
						case "foreign acceptance":
							foreign := newOutgoing(t)
							bad = requesterRecords(t, foreign.alice.vault)[1]
						case "noncanonical acceptance":
							old := rows[acceptedKey]
							bad = append(
								[]byte{0x98, old[0] & 0x1f},
								old[1:]...)
						case "resigned acceptance":
							var accepted SignedAccepted
							try.To(
								wire.UnmarshalCanonical(
									&accepted,
									history.Response,
								),
							)
							digest := key.HashTagged(AcceptedPurpose,
								try.To1(wire.Marshal(accepted.Payload)))
							accepted.Signature = try.To1(
								f.local.handle.Sign(digest[:]),
							)
							history.Response = try.To1(wire.Marshal(accepted))
							bad = try.To1(wire.Marshal(history))
							assert.ThatNot(bytes.Equal(bad, rows[acceptedKey]))
						case "role":
							name, bad = attemptKey, history.Request
							if n.name == "Alice" {
								bad = nil
							}
						case "missing holding":
							name, bad = heldKey, nil
						case "corrupt holding":
							name = heldKey
						case "mismatched holding":
							name, bad = heldKey, bytes.Clone(rows[heldKey])
							bad[len(bad)-1] ^= 1
						case "missing inbox":
							name, bad = inboxKey, nil
						case "corrupt inbox":
							name = inboxKey
						case "resigned inbox":
							var envelope messageEnvelope
							try.To(wire.UnmarshalCanonical(&envelope, raw))
							sender := outgoingTestNodes(f)[1-receiver]
							name = inboxKey
							bad = try.To1(wire.Marshal(inboxMessage{Version: 1,
								Envelope: signMessageEnvelope(
									t,
									envelope.Message,
									sender.signer,
								)}))
						default:
							name, bad = changedIncomingFirstUse(
								t,
								n,
								rows,
								mode,
							)
						}
						mutate := func() error {
							return n.own.vault.Update(
								func(tx storage.WriteTx) error {
									if bad == nil {
										return tx.Delete([]byte(name))
									}
									return tx.Put([]byte(name), bad)
								},
							)
						}
						if during {
							signer := &probeSigner{Handle: n.signer}
							var before map[string]map[string][]byte
							var disk []byte
							signer.sign = func(d []byte) (_ []byte, err error) {
								defer err2.Handle(&err, nil)
								if signer.signCalls.Load() == 2 {
									try.To(mutate())
									before = outgoingTestState(t, n.own.vault)
									disk = try.To1(os.ReadFile(n.own.path))
									n.own.lease.remaining.Store(0)
								}
								return n.signer.Sign(d)
							}
							n.other.unchanged(t, func() {
								got, err := issueMessageReceipt(n.own.vault,
									f.root.public, n.local, signer, raw)
								assert.Equal(err, errMessageReceipt)
								assert.SNil(got)
							})
							assert.DeepEqual(
								outgoingTestState(t, n.own.vault),
								before,
							)
							assert.DeepEqual(
								try.To1(os.ReadFile(n.own.path)),
								disk,
							)
							assert.Equal(n.own.lease.remaining.Load(), 0)
						} else {
							try.To(mutate())
						}
						refuseMessageReceipt(t, f, n, n.signer, raw)
						try.To1(decodeMessageReceipt(prior, raw, expected))
					},
				)
			}
		}
	}
}
