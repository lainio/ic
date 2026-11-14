package pw

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/storage"
)

func corruptMessageProjectionHistoryV2(tx storage.WriteTx,
	n outgoingTestNode, mode string,
) (err error) {
	defer err2.Handle(&err, nil)
	if mode, ok := strings.CutPrefix(mode, "accepted/"); ok {
		return corruptContactHistoryV2(tx, n.local, n.name == "Alice", mode)
	}
	if mode, ok := strings.CutPrefix(mode, "use/"); ok {
		return corruptFirstUseV2(tx, n.name == "Alice", mode)
	}
	name := useSeenKey
	if n.name == "Alice" {
		name = firstUseKey
	}
	switch mode {
	case "no relationship":
		for _, name := range []string{attemptKey, acceptedKey, heldKey,
			firstUseKey, useSeenKey, invitationKey} {
			try.To(tx.Delete([]byte(name)))
		}
		return nil
	case "no first use":
		return tx.Delete([]byte(name))
	case "Await", "Expired without success":
		if n.name == "Bob" {
			return tx.Delete([]byte(name))
		}
		raw, _ := try.To2(tx.Get([]byte(name)))
		var record firstUseRecord
		try.To(wire.UnmarshalCanonical(&record, raw))
		record.State, record.Response = useAwait, nil
		if mode == "Expired without success" {
			record.State = useExpired
		}
		return tx.Put([]byte(name), try.To1(wire.Marshal(record)))
	}
	return fmt.Errorf("unknown test mutation %q", mode)
}

func TestMessageProjectionRequiredHistoryV2(t *testing.T) {
	t.Parallel()

	var testerInit sync.Once

	for local := range 2 {
		for _, mode := range []string{
			"no relationship", "no first use", "Await", "Expired without success",
			"accepted/history absent", "accepted/history malformed",
			"accepted/history noncanonical", "accepted/history version",
			"accepted/request signature", "accepted/response signature",
			"accepted/request contact", "accepted/request target",
			"accepted/request ad", "accepted/request canonical",
			"accepted/held digest", "accepted/held version",
			"accepted/held canonical", "accepted/role", "accepted/attempt",
			"accepted/invitation", "use/malformed", "use/noncanonical",
			"use/oversize", "use/foreign version", "use/wrong slot",
			"use/request", "use/response", "use/missing response",
		} {
			for _, present := range []bool{false, true} {
				t.Run(fmt.Sprint(local, "/", mode, "/", present),
					func(t *testing.T) {
						t.Parallel()

						// Initialize err2's shared default before concurrent pushes.
						testerInit.Do(func() {
							defer assert.PushTester(t)()
						})
						defer assert.PushTester(t)()
						f, n, _, receipt := ackTestV2(t, local)
						if present {
							peer := outgoingTestNodes(f.requesterFixture)[1-local]
							try.To1(
								CreateOutgoingV2(
									peer.own.vault,
									f.root.public,
									peer.local,
									peer.signer,
									f.messageRuntime(peer),
									"inbox",
								),
							)
							raw := try.To1(
								PrepareOutgoingEnvelopeV2(
									peer.own.vault,
									f.root.public,
									peer.local,
									peer.signer,
									f.messageRuntime(peer),
								),
							)
							try.To1(
								AdmitIncomingEnvelopeV2(
									n.own.vault,
									f.root.public,
									n.local,
									n.signer,
									f.messageRuntime(n),
									raw,
								),
							)
						}
						assert.Equal(try.To1(ReadMessageInboxV2(n.own.vault,
							f.root.public, n.local)).Present, present)
						// Preflight succeeds before a deliberately interleaved edit.
						try.To(
							n.own.vault.View(
								func(tx storage.ReadTx) (err error) {
									defer err2.Handle(&err, nil)
									assert.ThatNot(
										try.To1(
											checkMessageACKV2(tx, f.root.public,
												n.local, receipt),
										),
									)
									return nil
								},
							),
						)
						try.To(
							n.own.vault.Update(func(tx storage.WriteTx) error {
								return corruptMessageProjectionHistoryV2(
									tx,
									n,
									mode,
								)
							}),
						)
						n.own.reopen(t)
						refuseMessageACKV2(t, f, n, receipt)
						refuseMessageInboxV2(t, f, n)
						n.own.unchanged(t, func() {
							err := n.own.vault.Update(
								func(tx storage.WriteTx) error {
									return commitMessageACKV2(
										tx,
										f.root.public,
										n.local,
										receipt,
									)
								},
							)
							assert.Error(err)
							assert.That(err != errACKUnchanged)
						})
					})
			}
		}
	}
}

func TestMessageProjectionExactContactsAndSignaturesV2(t *testing.T) {
	for local := range 2 {
		for _, mode := range []string{"acceptance signature", "request signature",
			"requester contact", "target contact"} {
			t.Run(fmt.Sprint(local, "/", mode), func(t *testing.T) {
				defer assert.PushTester(t)()
				// The same authentic alternate transcript must not rebind an ACK
				// or expose an inbox signed for the original exact acceptance.
				f, n, _, receipt := ackTestV2(t, local)
				old := messageBindingV2(t, n.own.vault, f.root.public, n.local)
				replaceMessageHistoryV2(t, f, n, mode)
				current := messageBindingV2(
					t,
					n.own.vault,
					f.root.public,
					n.local,
				)
				assert.ThatNot(
					bytes.Equal(old.AcceptedDigest, current.AcceptedDigest),
				)
				refuseMessageACKV2(t, f, n, receipt)

				f, n, _, _ = receiptTestV2(t, local)
				replaceMessageHistoryV2(t, f, n, mode)
				refuseMessageInboxV2(t, f, n)
			})
		}
	}
}

func TestMessageProjectionVersionIsolationV2(t *testing.T) {
	defer assert.PushTester(t)()
	for local := range 2 {
		legacy, old, _, v1Receipt := ackTest(t, local)
		f, n, _, receipt := ackTestV2(t, local)
		old.own.unchanged(t, func() {
			// Valid v1 history, even with no inbox, is not v2 absence.
			got, err := ReadMessageInboxV2(old.own.vault, legacy.root.public,
				old.local)
			assert.Equal(err, errMessageInbox)
			assert.DeepEqual(got, MessageInbox{})
			_, err = ObserveMessageReceiptV2(old.own.vault, legacy.root.public,
				old.local, receipt)
			assert.Equal(err, errMessageACK)
		})
		n.own.unchanged(t, func() {
			got, err := ReadMessageInbox(n.own.vault, f.root.public, n.local)
			assert.Equal(err, errMessageInbox)
			assert.DeepEqual(got, MessageInbox{})
			_, err = observeMessageReceipt(n.own.vault, f.root.public,
				n.local, v1Receipt)
			assert.Equal(err, errMessageACK)
		})
		// A genuine v1 inbox cannot leak through the v2 reader, or vice versa.
		got, err := ReadMessageInboxV2(old.other.vault, legacy.root.public,
			old.peer)
		assert.Equal(err, errMessageInbox)
		assert.DeepEqual(got, MessageInbox{})
		got, err = ReadMessageInbox(n.other.vault, f.root.public, n.peer)
		assert.Equal(err, errMessageInbox)
		assert.DeepEqual(got, MessageInbox{})
		oldRows := outgoingTestState(t, old.own.vault)["root"]
		rows := outgoingTestState(t, n.own.vault)["root"]
		oldRows[messageACKKey] = try.To1(wire.Marshal(messageACK{
			Version: 1, Receipt: v1Receipt,
		}))
		for _, name := range []string{acceptedKey, firstUseKey, useSeenKey,
			outgoingKey, messageEnvelopeKey, messageACKKey} {
			if oldRows[name] == nil {
				continue
			}
			try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
				return tx.Put([]byte(name), oldRows[name])
			}))
			refuseMessageACKV2(t, f, n, receipt)
			try.To(n.own.vault.Update(func(tx storage.WriteTx) error {
				if rows[name] == nil {
					return tx.Delete([]byte(name))
				}
				return tx.Put([]byte(name), rows[name])
			}))
		}
		// Same v2 history with a foreign version in the shared inbox slot.
		legacyInbox := outgoingTestState(t, old.other.vault)["root"][inboxKey]
		try.To(n.other.vault.Update(func(tx storage.WriteTx) error {
			return tx.Put([]byte(inboxKey), legacyInbox)
		}))
		receiver := outgoingTestNodes(f.requesterFixture)[1-local]
		refuseMessageInboxV2(t, f, receiver)
	}
}
