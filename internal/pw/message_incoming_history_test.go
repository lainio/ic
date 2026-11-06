package pw

import (
	"fmt"
	"testing"

	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

func TestIncomingCorruptLocalHistory(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, repeat := range []bool{false, true} {
			for _, name := range []string{acceptedKey, heldKey, firstUseKey,
				useSeenKey, attemptKey, invitationKey} {
				for _, mode := range []string{"malformed", "noncanonical", "mutation"} {
					t.Run(
						fmt.Sprint(receiver, "/", repeat, "/", name, "/", mode),
						func(t *testing.T) {
							defer assert.PushTester(t)()
							f, n, raw := incomingTest(
								t,
								receiver,
								"history required",
							)
							if repeat {
								assert.That(
									try.To1(admitIncomingEnvelope(n.own.vault,
										f.root.public, n.local, n.signer, raw)),
								)
							}
							old := outgoingTestState(t, n.own.vault)["root"][name]
							bad := []byte{0xff}
							if len(old) > 0 {
								switch mode {
								case "noncanonical":
									bad = append(
										[]byte{0x98, old[0] & 0x1f},
										old[1:]...)
								case "mutation":
									bad = old
									bad[len(bad)-1] ^= 1
								}
							}
							try.To(
								n.own.vault.Update(
									func(tx storage.WriteTx) error {
										return tx.Put([]byte(name), bad)
									},
								),
							)
							refuseIncoming(t, f, n, n.signer, raw)
						},
					)
				}
			}
		}
	}
}

func TestIncomingExactHistoryAndHistoricalSuccess(t *testing.T) {
	for _, receiver := range []int{0, 1} {
		for _, repeat := range []bool{false, true} {
			for _, mode := range []string{"foreign", "role", "resigned acceptance",
				"accepted version", "first use version", "first use request",
				"first use response", "no historical response", "Await"} {
				t.Run(
					fmt.Sprint(receiver, "/", repeat, "/", mode),
					func(t *testing.T) {
						defer assert.PushTester(t)()
						f, n, raw := incomingTest(t, receiver, "exact history")
						if repeat {
							assert.That(
								try.To1(admitIncomingEnvelope(n.own.vault,
									f.root.public, n.local, n.signer, raw)),
							)
						}
						rows := outgoingTestState(t, n.own.vault)["root"]
						var history acceptedRecord
						try.To(
							wire.UnmarshalCanonical(
								&history,
								rows[acceptedKey],
							),
						)
						name, bad := acceptedKey, rows[acceptedKey]
						switch mode {
						case "foreign":
							foreign := newOutgoing(t)
							bad = requesterRecords(t, foreign.alice.vault)[1]
						case "role":
							name, bad = attemptKey, history.Request
							if n.name == "Alice" {
								bad = nil
							}
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
						case "accepted version":
							history.Version++
							bad = try.To1(wire.Marshal(history))
						default:
							name, bad = changedIncomingFirstUse(
								t,
								n,
								rows,
								mode,
							)
						}
						try.To(
							n.own.vault.Update(func(tx storage.WriteTx) error {
								if bad == nil {
									return tx.Delete([]byte(name))
								}
								return tx.Put([]byte(name), bad)
							}),
						)
						refuseIncoming(t, f, n, n.signer, raw)
					},
				)
			}
		}
	}
}

func changedIncomingFirstUse(t *testing.T, n outgoingTestNode,
	rows map[string][]byte, mode string,
) (string, []byte) {
	t.Helper()
	defer assert.PushTester(t)()
	if n.name == "Bob" {
		var record firstUseReceipt
		try.To(wire.UnmarshalCanonical(&record, rows[useSeenKey]))
		switch mode {
		case "first use version":
			record.Version++
		case "first use request":
			record.Request[len(record.Request)-1] ^= 1
		case "first use response":
			record.Response[len(record.Response)-1] ^= 1
		default:
			record.Response = nil
		}
		return useSeenKey, try.To1(wire.Marshal(record))
	}
	var record firstUseRecord
	try.To(wire.UnmarshalCanonical(&record, rows[firstUseKey]))
	switch mode {
	case "first use version":
		record.Version++
	case "first use request":
		record.Request[len(record.Request)-1] ^= 1
	case "first use response":
		record.State = useExpired
		record.Response[len(record.Response)-1] ^= 1
	case "no historical response":
		record.State, record.Response = useExpired, nil
	case "Await":
		record.State, record.Response = useAwait, nil
	}
	return firstUseKey, try.To1(wire.Marshal(record))
}
