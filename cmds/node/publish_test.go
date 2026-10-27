package node

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/core/wire"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/internal/onboarding"
	"github.com/lainio/ic/internal/peerapi"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

const ownerPublishPath = "/owner/ads/publish"

func TestServePublicationBoundEndpointAndRestart(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := prepareServeFixture(t)
			choice := saveServeChoice(t, f, "completed")
			cmd := serveCommand(t, f)
			try.To(cmd.Flags().Set("peer-listen", address))
			s, _ := try.To2(setupNodeServe(t.Context(), cmd))
			defer func() { try.Out(s.close()).Logf() }()
			auth := serveAuthorization(t, s)
			owner, peer := try.To2(bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress))
			peerURL := "http://" + peer.Addr().String() + "/peer/introduction"
			preServePeer := peerapi.NewAdHandler(s.store.Vault(), f.root, f.child, peerURL)
			assert.Equal(serveDeviceRequest(preServePeer, "", "GET", "/peer/ad", nil).Code, 409)
			request := func(path string, body []byte) {
				t.Helper()
				assert.Equal(serveDeviceRequest(s.handler, auth, "POST", path, body).Code, 200)
			}
			request("/owner/introductions", try.To1(onboarding.EncodeIntroduction(choice)))
			request("/owner/introductions/verify", []byte("{}"))
			request(ownerBootstrapPath, []byte("{}"))
			assert.Equal(serveDeviceRequest(preServePeer, "", "GET", "/peer/ad", nil).Code, 409)
			before := try.To1(publicationUnrelatedRecords(s.store.Vault()))
			assert.ThatNot(strings.Contains(peerURL, ":0/"))
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			var output bytes.Buffer
			var result error
			go func() { result = runNodeServe(ctx, owner, peer, s, &output); close(done) }()
			defer func() { cancel(); waitNodeServe(t, done) }()
			ownerURL := "http://" + owner.Addr().String()
			status := waitPeerHTTP(t, peerHTTPRequest(t.Context(), ownerURL+"/owner/status", auth))
			assert.NoError(status.err)
			assert.Equal(status.status, 200)
			_, found := try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
			assert.ThatNot(found) // Starting both servers never publishes.
			started := time.Now()
			response := postDeviceHTTP(t.Context(), ownerURL+ownerPublishPath, auth)
			assert.NoError(response.err)
			assert.Equal(response.status, 200)
			current, found := try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
			assert.That(found)
			assertPublishedSummary(t, response.body, current, peerURL)
			assert.DeepEqual(current.Payload.Root, f.root)
			assert.DeepEqual(current.Payload.Node, f.child)
			assert.DeepEqual(current.Payload.Device, f.child)
			assert.That(current.Payload.ExpiresUnixNano >= started.Add(ads.TTL).UnixNano())
			assert.That(current.Payload.ExpiresUnixNano <= time.Now().Add(ads.TTL).UnixNano())
			digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(current.Payload)))
			assert.That(current.Signature.Verify(f.child, digest[:]))
			assert.DeepEqual(try.To1(publicationUnrelatedRecords(s.store.Vault())), before)
			peerResponse := waitPeerHTTP(t, peerHTTPRequest(t.Context(), peerURL, ""))
			assert.NoError(peerResponse.err)
			assert.DeepEqual(peerResponse.body, try.To1(onboarding.EncodeIntroduction(choice)))
			refused := postDeviceHTTP(t.Context(), "http://"+peer.Addr().String()+ownerPublishPath, auth)
			assert.NoError(refused.err)
			assert.Equal(refused.status, 404)
			t.Run("public read only", func(t *testing.T) {
				defer assert.PushTester(t)()
				assertPeerFilesUnchanged(t, f)
				for _, token := range []string{"", auth, "Bearer wrong"} {
					got := waitPeerHTTP(t, peerHTTPRequest(t.Context(), "http://"+peer.Addr().String()+"/peer/ad", token))
					assert.NoError(got.err)
					assert.Equal(got.status, 200)
					assertPeerAd(t, got.body, choice, current)
				}
			})
			previous := current
			response = postDeviceHTTP(t.Context(), ownerURL+ownerPublishPath, auth)
			assert.NoError(response.err)
			assert.Equal(response.status, 200)
			current, found = try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
			assert.That(found)
			assertPublishedSummary(t, response.body, current, peerURL)
			assert.ThatNot(bytes.Equal(current.Payload.Token, previous.Payload.Token))
			assert.ThatNot(bytes.Equal(current.Signature, previous.Signature))
			assert.That(current.Payload.ExpiresUnixNano > previous.Payload.ExpiresUnixNano)
			assert.DeepEqual(try.To1(publicationUnrelatedRecords(s.store.Vault())), before)
			// Bind the next invocation while this port is occupied, guaranteeing
			// a different actual port without timing assumptions about reuse.
			nextOwner, nextPeer := try.To2(bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress))
			defer func() {
				try.Out(nextOwner.Close()).Logf()
				try.Out(nextPeer.Close()).Logf()
			}()
			cancel()
			waitNodeServe(t, done)
			assert.NoError(result)
			assert.That(strings.Contains(output.String(), "peer introduction URL: "+peerURL))
			assert.ThatNot(strings.Contains(output.String(), auth))
			// Reopen restores the current signed record unchanged; opening the
			// Store retains its existing usage-reservation behavior.
			s = setupPeerServe(t, f)
			after, found := try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
			assert.That(found)
			assert.DeepEqual(after, current)
			assert.DeepEqual(try.To1(publicationUnrelatedRecords(s.store.Vault())), before)
			s.configurePublication(nextPeer)
			t.Run("restart endpoint gate", func(t *testing.T) {
				defer assert.PushTester(t)()
				assertPeerFilesUnchanged(t, f)
				w := serveDeviceRequest(s.peerHandler, "", "GET", "/peer/ad", nil)
				assert.Equal(w.Code, 409)
				assert.Equal(w.Body.String(), "Conflict\n")
				// An exact fixed endpoint match remains only a signed hint.
				h := peerapi.NewAdHandler(s.store.Vault(), f.root, f.child, peerURL)
				w = serveDeviceRequest(h, "", "GET", "/peer/ad", nil)
				assert.Equal(w.Code, 200)
				assertPeerAd(t, w.Body.Bytes(), choice, current)
			})
			auth = serveAuthorization(t, s)
			assert.Equal(serveDeviceRequest(s.handler, auth, "POST", ownerPublishPath, []byte("{}")).Code, 200)
			after, found = try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
			assert.That(found)
			assert.Equal(after.Payload.PeerIntroductionURL, "http://"+nextPeer.Addr().String()+"/peer/introduction")
			assert.ThatNot(bytes.Equal(after.Payload.Token, current.Payload.Token))
			w := serveDeviceRequest(s.peerHandler, "", "GET", "/peer/ad", nil)
			assert.Equal(w.Code, 200)
			assertPeerAd(t, w.Body.Bytes(), choice, after)
			assertPeerFilesUnchanged(t, f)
			assert.Equal(serveDeviceRequest(s.handler, serveAuthorization(t, s), "GET", "/owner/status", nil).Code, 200)
		})
	}
}

func assertPeerAd(t *testing.T, body []byte, choice onboarding.StoredChoice, current ads.Current) {
	t.Helper()
	defer assert.PushTester(t)()
	assert.That(len(body) <= onboarding.MaxIntroductionBytes+4096)
	var fields map[string]json.RawMessage
	try.To(json.Unmarshal(body, &fields))
	assert.Equal(len(fields), 3)
	assert.Equal(string(fields["version"]), "1")
	assert.DeepEqual([]byte(fields["introduction"]), try.To1(onboarding.EncodeIntroduction(choice)))
	var evidence struct {
		Version              int
		Proposal, Acceptance []byte
	}
	try.To(json.Unmarshal(fields["introduction"], &evidence))
	assert.Equal(evidence.Version, 1)
	assert.DeepEqual(evidence.Proposal, choice.Proposal.Bytes())
	assert.DeepEqual(evidence.Acceptance, []byte(choice.Acceptance))
	assert.DeepEqual(try.To1(onboarding.CheckIntroduction(evidence.Proposal, evidence.Acceptance, current.Payload.Root)), current.Payload.Node)
	var ad []byte
	try.To(json.Unmarshal(fields["ad"], &ad))
	assert.DeepEqual(ad, try.To1(wire.Marshal(current)))
	assert.DeepEqual(fields["ad"], json.RawMessage(try.To1(json.Marshal(ad))))
	var decoded ads.Current
	try.To(wire.UnmarshalCanonical(&decoded, ad))
	assert.DeepEqual(decoded, current)
	digest := key.HashTagged(ads.SignaturePurpose, try.To1(wire.Marshal(decoded.Payload)))
	assert.That(decoded.Signature.Verify(current.Payload.Node, digest[:]))
}

func assertPublishedSummary(t *testing.T, body []byte, current ads.Current, endpoint string) {
	t.Helper()
	defer assert.PushTester(t)()
	var got map[string]json.RawMessage
	try.To(json.Unmarshal(body, &got))
	assert.Equal(len(got), 5)
	assert.Equal(string(got["published"]), "true")
	assert.Equal(string(got["slot"]), "1")
	assert.Equal(string(got["epoch"]), "0")
	assert.Equal(current.Payload.Slot, uint64(1))
	assert.Equal(current.Payload.Epoch, uint64(0))
	assert.Equal(current.Payload.PeerIntroductionURL, endpoint)
	assert.DeepEqual(got["peer_introduction_url"], json.RawMessage(try.To1(json.Marshal(endpoint))))
	assert.DeepEqual(got["expires_unix_nano"], json.RawMessage(try.To1(json.Marshal(current.Payload.ExpiresUnixNano))))
}

func publicationUnrelatedRecords(vault *storage.Vault) (_ map[string]map[string][]byte, err error) {
	defer err2.Handle(&err, nil)
	records := try.To1(deviceUnrelatedRecords(vault))
	delete(records, "local-current-ad-v1")
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		const name = "local-device-auth-v1"
		if try.To1(tx.HasChild([]byte(name))) {
			ns := try.To1(tx.Child([]byte(name)))
			records[name] = make(map[string][]byte)
			return ns.Each(func(k, v []byte) error { records[name][string(k)] = v; return nil })
		}
		return nil
	}))
	return records, nil
}

func TestServePublicationRequiresExplicitPrerequisites(t *testing.T) {
	for _, scenario := range []string{"unselected", "pending", "completed", "Received only", "Known without bootstrap", "no peer listener"} {
		t.Run(scenario, func(t *testing.T) {
			defer assert.PushTester(t)()
			f := prepareServeFixture(t)
			state := scenario
			if scenario != "unselected" && scenario != "pending" {
				state = "completed"
			}
			choice := saveServeChoice(t, f, state)
			cmd := serveCommand(t, f)
			if scenario != "no peer listener" {
				try.To(cmd.Flags().Set("peer-listen", "127.0.0.1:0"))
			}
			s, _ := try.To2(setupNodeServe(t.Context(), cmd))
			defer func() { try.Out(s.close()).Logf() }()
			auth := serveAuthorization(t, s)
			if scenario == "Received only" || scenario == "Known without bootstrap" || scenario == "no peer listener" {
				assert.Equal(serveDeviceRequest(s.handler, auth, "POST", "/owner/introductions", try.To1(onboarding.EncodeIntroduction(choice))).Code, 200)
			}
			if scenario == "Known without bootstrap" || scenario == "no peer listener" {
				assert.Equal(serveDeviceRequest(s.handler, auth, "POST", "/owner/introductions/verify", []byte("{}")).Code, 200)
			}
			if scenario == "no peer listener" {
				assert.Equal(serveDeviceRequest(s.handler, auth, "POST", ownerBootstrapPath, []byte("{}")).Code, 200)
			}
			owner, peer := try.To2(bindNodeListeners(t.Context(), "127.0.0.1:0", s.peerAddress))
			defer func() { try.Out(owner.Close()).Logf() }()
			if peer != nil {
				defer func() { try.Out(peer.Close()).Logf() }()
			}
			s.configurePublication(peer)
			assertPeerFilesUnchanged(t, f)
			w := serveDeviceRequest(s.handler, auth, "POST", ownerPublishPath, []byte("{}"))
			assert.Equal(w.Code, 409)
			assert.Equal(w.Body.String(), "Conflict\n")
			stateDevice := try.To1(device.InspectLocal(s.store.Vault(), f.root, f.child, nil))
			assert.Equal(stateDevice.Authorized, scenario == "no peer listener")
			_, found := try.To2(ads.ReadCurrentLocal(s.store.Vault(), f.root, f.child, time.Now()))
			assert.ThatNot(found)
		})
	}
}
