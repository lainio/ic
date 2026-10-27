package node

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/intro"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/nodeidentity"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const peerAdEndpoint = "http://127.0.0.1:8080/peer/introduction"

// Explicit fixture publication; the public handler receives no signer.
func publishPeerAd(t *testing.T, s *nodeServe, f serveFixture, now time.Time) ads.Current {
	t.Helper()
	defer assert.PushTester(t)()
	signer := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
	acceptance := try.To1(f.proposal.SignAcceptance(signer))
	try.To2(onboarding.SaveIntroduction(s.store.Vault(), f.root, f.proposal.Bytes(), acceptance))
	try.To1(onboarding.VerifyReceived(s.store.Vault(), f.root))
	try.To1(device.BootstrapLocal(s.store.Vault(), f.root, f.child, signer))
	return try.To1(ads.PublishLocal(s.store.Vault(), f.root, f.child, signer, peerAdEndpoint, now))
}

func TestPeerAdMinimalEvidenceAndBound(t *testing.T) {
	for _, padding := range []int{0, 95 * 1024} {
		t.Run(map[bool]string{false: "minimal", true: "near introduction limit"}[padding > 0], func(t *testing.T) {
			defer assert.PushTester(t)()
			f := prepareServeFixtureWithPath(t, func(root key.Handle, child key.Public) intro.Path {
				return intro.New(key.Info{Public: try.To1(root.CBORPublicKey())}).Introduce(
					root, key.Info{Public: child}, intro.WithEndpoint(strings.Repeat("x", padding), false))
			})
			choice := saveServeChoice(t, f, "completed")
			s := setupPeerServe(t, f)
			current := publishPeerAd(t, s, f, time.Now())
			parent := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
			if padding == 0 {
				for i := range 2 {
					other := key.New()
					path := f.proposal.Introduce(parent, key.Info{Public: try.To1(other.CBORPublicKey())})
					try.To2(onboarding.SaveIntroduction(s.store.Vault(), f.root, path.Bytes(), try.To1(path.SignAcceptance(other))))
					if i == 0 {
						try.To1(onboarding.VerifyReceived(s.store.Vault(), f.root))
					}
				}
				assert.SLen(try.To1(onboarding.ListKnownIntroductions(s.store.Vault(), f.root)), 2)
				assert.SLen(try.To1(onboarding.ListIntroductions(s.store.Vault(), f.root)), 3)
			}
			before := try.To1(deviceUnrelatedRecords(s.store.Vault()))
			assertPeerFilesUnchanged(t, f)
			root, child := bytes.Clone(f.root), bytes.Clone(f.child)
			h := peerapi.NewAdHandler(s.store.Vault(), root, child, peerAdEndpoint)
			clear(root)
			clear(child)
			for range 3 {
				w := serveDeviceRequest(h, "", "GET", "/peer/ad", nil)
				assert.Equal(w.Code, 200)
				assert.Equal(w.Header().Get("Content-Type"), "application/json")
				assert.Equal(w.Header().Get("Cache-Control"), "no-store")
				assert.Empty(w.Header().Get("Access-Control-Allow-Origin"))
				assertPeerAd(t, w.Body.Bytes(), choice, current)
				if padding > 0 {
					assert.That(w.Body.Len() > onboarding.MaxIntroductionBytes-2048)
				}
			}
			assert.DeepEqual(try.To1(deviceUnrelatedRecords(s.store.Vault())), before)
		})
	}
}

func TestPeerAdSavedRecordRefusals(t *testing.T) {
	for _, scenario := range []string{"absent", "expired", "corrupt", "noncanonical", "forged signature",
		"Root", "node", "device", "slot", "epoch", "wrong pinned Root", "wrong saved child", "closed"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := prepareServeFixture(t)
			saveServeChoice(t, f, "completed")
			s := setupPeerServe(t, f)
			root, child := f.root, f.child
			want := 500
			if scenario != "absent" {
				now := time.Now()
				if scenario == "expired" {
					now = now.Add(-2 * ads.TTL)
				}
				current := publishPeerAd(t, s, f, now)
				other := try.To1(key.New().CBORPublicKey())
				switch scenario {
				case "Root":
					current.Payload.Root = other
				case "node":
					current.Payload.Node = other
				case "device":
					current.Payload.Device = other
				case "slot":
					current.Payload.Slot = 2
				case "epoch":
					current.Payload.Epoch = 1
				case "wrong pinned Root":
					root = other
				case "wrong saved child":
					child = other
				}
				// Correct signatures still cannot bypass identity/slot/epoch binding.
				signer := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
				digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(current.Payload)))
				if scenario == "forged signature" {
					signer = key.New()
				}
				current.Signature = try.To1(signer.Sign(digest[:]))
				record := try.To1(wire.Marshal(current))
				switch scenario {
				case "corrupt":
					record = []byte("private corrupt record")
				case "noncanonical":
					record = append([]byte{0x98, 0x02}, record[1:]...)
				}
				try.To(s.store.Vault().Update(func(tx storage.WriteTx) (err error) {
					defer err2.Handle(&err, nil)
					return try.To1(tx.ChildForUpdate([]byte("local-current-ad-v1"))).Put([]byte("slot-1"), record)
				}))
			}
			if scenario == "absent" || scenario == "expired" {
				want = 409
			}
			assertPeerFilesUnchanged(t, f)
			if scenario == "closed" {
				try.To(s.store.Close())
			}
			h := peerapi.NewAdHandler(s.store.Vault(), root, child, peerAdEndpoint)
			w := serveDeviceRequest(h, "", "GET", "/peer/ad", nil)
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
		})
	}
}

func TestPeerAdRequiresOwnCompletedPublicEvidence(t *testing.T) {
	for _, scenario := range []string{"unselected", "pending", "orphaned", "bad acceptance", "bad proof", "noncanonical", "wrong evidence Root", "wrong evidence child", "oversize",
		"root ID", "parent ID", "child ID", "root backup", "parent backup", "child backup",
		"root rotation", "parent rotation", "child rotation"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			var changed intro.Path
			f := prepareServeFixtureWithPath(t, func(root key.Handle, child key.Public) intro.Path {
				parent := key.New()
				infos := []key.Info{{Public: try.To1(root.CBORPublicKey())}, {Public: try.To1(parent.CBORPublicKey())}, {Public: child}}
				good := intro.New(infos[0]).Introduce(root, infos[1]).Introduce(parent, infos[2])
				opts := make([][]intro.Opts, 3)
				for i, name := range []string{"root", "parent", "child"} {
					switch scenario {
					case name + " ID":
						infos[i].ID = []byte("private handle")
					case name + " backup":
						opts[i] = []intro.Opts{intro.WithBackupKeyIndex(1)}
					case name + " rotation":
						opts[i] = []intro.Opts{intro.WithRotation()}
					}
				}
				if scenario == "oversize" {
					opts[2] = []intro.Opts{intro.WithEndpoint(strings.Repeat("x", 100*1024), false)}
				}
				if scenario == "wrong evidence Root" {
					root = key.New()
					infos[0].Public = try.To1(root.CBORPublicKey())
				}
				if scenario == "wrong evidence child" {
					infos[2].Public = try.To1(key.New().CBORPublicKey())
				}
				changed = intro.New(infos[0], opts[0]...).Introduce(root, infos[1], opts[1]...).Introduce(parent, infos[2], opts[2]...)
				return good
			})
			s := setupPeerServe(t, f)
			current := publishPeerAd(t, s, f, time.Now())
			signer := try.To1(nodeidentity.OpenDirectory(f.dir, f.unlock))
			// Wrong-child evidence is rejected by binding before acceptance.
			acceptance := key.Signature("invalid child acceptance")
			if scenario != "wrong evidence child" {
				acceptance = try.To1(changed.SignAcceptance(signer))
			}
			proposal := changed.Bytes()
			switch scenario {
			case "unselected":
				proposal, acceptance = nil, nil
			case "pending":
				acceptance = nil
			case "orphaned":
				proposal = nil
			case "bad acceptance":
				acceptance = []byte("private bad acceptance")
			case "bad proof":
				changed[1].Body.Options.Position++
				proposal = changed.Bytes()
			case "noncanonical":
				proposal = append([]byte{0x98, 0x03}, proposal[1:]...)
			}
			try.To(s.store.Vault().Update(func(tx storage.WriteTx) (err error) {
				defer err2.Handle(&err, nil)
				ns := try.To1(tx.EnsureChild([]byte("introduction-choice-demo")))
				if proposal != nil {
					try.To(ns.Put([]byte("selected-proposal"), proposal))
				}
				if acceptance != nil {
					try.To(ns.Put([]byte("acceptance"), acceptance))
				}
				return nil
			}))
			assertPeerFilesUnchanged(t, f)
			h := peerapi.NewAdHandler(s.store.Vault(), f.root, f.child, peerAdEndpoint)
			w := serveDeviceRequest(h, "", "GET", "/peer/ad", nil)
			want := 500
			if scenario == "unselected" || scenario == "pending" {
				want = 409
			}
			assert.Equal(w.Code, want)
			assert.Equal(w.Body.String(), http.StatusText(want)+"\n")
			after, found := try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
			assert.That(found)
			assert.DeepEqual(after, current)
		})
	}
}
