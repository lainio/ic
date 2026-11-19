package pw

import (
	"bytes"
	"errors"

	"github.com/lainio/err2"
	"github.com/lainio/err2/assert"
	"github.com/lainio/err2/try"
	"github.com/lainio/ic/internal/ads"
	"github.com/lainio/ic/internal/device"
	"github.com/lainio/ic/key"
	"github.com/lainio/ic/storage"
)

// ContactRuntimeV2 is trusted owner/service configuration, not peer or UI input.
// Running describes this process and BoundOrigin its own canonical listener
// origin. The caller holds its owner mutation/signer/configuration lock while
// supplying this snapshot. No persistent running registry or reachability claim
// is inferred from saved signatures. A changed port never rebinds history.
type ContactRuntimeV2 struct {
	Running     bool
	BoundOrigin string
}

// BobContactV2 projects Alice's declaration from Bob's authenticated committed
// history in his independently Root/local-bound Vault. Empty with nil error
// means no v2 contact (including valid v1 history); corruption or wrong role is
// ErrEstablishment. No current guards, signing, writes or network I/O occur.
// History remains readable after Deny/Delete, ad expiry and process restart.
func BobContactV2(vault *storage.Vault, root, local key.Public) (string, error) {
	return historicalContactV2(vault, root, local, false)
}

// RequesterContactV2 projects Bob's target origin only after Alice's own TX-A.
// The read-only, pinned-identity and absence/error contract is BobContactV2's.
// An ad or unaccepted saved request alone never supplies a historical contact.
func RequesterContactV2(vault *storage.Vault, root, local key.Public,
) (string, error) {
	return historicalContactV2(vault, root, local, true)
}

func historicalContactV2(vault *storage.Vault, root, local key.Public,
	alice bool,
) (_ string, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrEstablishment })
	assert.NotNil(vault, ErrEstablishment)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var contact string
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		history := try.To1(readLocalHistoryV2(tx, root, local, alice))
		contact = history.peerContact(alice)
		return nil
	}))
	return contact, nil
}

func (h localHistoryV2) peerContact(alice bool) string {
	if !h.accepted {
		return ""
	}
	if alice {
		return h.binding.TargetContact
	}
	return h.binding.RequesterContact
}

// BobUsableContactV2 adds Bob's own running, holding, Known, device, binding,
// policy and signer eligibility to BobContactV2. Hold the same owner lock as
// BobAcceptV2, including runtime changes. Probe outside View; authenticate
// history and recheck durable prerequisites against one final local snapshot.
// Ad expiry alone is irrelevant; retained evidence must authenticate and match
// the signed establishment exactly. Fresh bootstrap still requires a fresh ad.
// Empty with nil error means absent/ineligible; corrupt evidence returns error.
// This grants no remote permission, first use, PWOpen, Trust or reachability.
func BobUsableContactV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2,
) (string, error) {
	return usableContactV2(vault, root, local, signer, runtime, false)
}

// RequesterUsableContactV2 has BobUsableContactV2's local-only contract, using
// Alice's independently committed history, current prerequisites and listener.
// Neither usable projection derives an application URL from the service origin.
func RequesterUsableContactV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2,
) (string, error) {
	return usableContactV2(vault, root, local, signer, runtime, true)
}

func usableContactV2(vault *storage.Vault, root, local key.Public,
	signer key.Handle, runtime ContactRuntimeV2, alice bool,
) (_ string, err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, func(error) error { return ErrEstablishment })
	assert.That(validInvitationBinding(vault, root, local), ErrEstablishment)
	root, local = bytes.Clone(root), bytes.Clone(local)
	var state device.Local
	if runtime.Running {
		state = try.To1(device.InspectLocal(vault, root, local, localSigner{signer}))
	}
	var contact string
	try.To(vault.View(func(tx storage.ReadTx) (err error) {
		defer err2.Handle(&err, nil)
		history := try.To1(readLocalHistoryV2(tx, root, local, alice))
		ownOrigin := history.binding.TargetContact
		if alice {
			ownOrigin = history.binding.RequesterContact
		}
		if !history.accepted || !history.held || !runtime.Running ||
			!state.Authorized || !state.Usable ||
			!canonicalServiceContact(runtime.BoundOrigin) ||
			runtime.BoundOrigin != ownOrigin {
			return nil
		}
		guardErr := contactGuardsV2(tx, history.binding, alice)
		if contactIneligibleV2(guardErr, alice) {
			return nil
		}
		try.To(guardErr)
		contact = history.peerContact(alice)
		return nil
	}))
	return contact, nil
}

func contactGuardsV2(tx storage.ReadTx, p EstablishmentV2, alice bool,
) (err error) {
	defer assert.PushAsserter(assert.Plain)()
	defer err2.Handle(&err, nil)
	if alice {
		try.To(requesterPermissions(tx, p.guardBinding()))
		ad := try.To1(ads.ReadRetainedEstablishmentAdInTx(tx, p.Root, p.Target))
		assert.That(bytes.Equal(p.Ad, ad),
			establishmentRefusal("ad_evidence_changed"))
	} else {
		try.To(establishmentPermissions(tx, p.guardBinding()))
		ad, found := try.To2(ads.ReadRetainedLocalInTx(tx, p.Root, p.Target))
		try.To(checkEstablishmentAd(p.guardBinding(),
			p.TargetContact+"/peer/introduction", ad, found))
	}
	return nil
}

func contactIneligibleV2(err error, alice bool) bool {
	var refusal establishmentRefusal
	if errors.As(err, &refusal) {
		return true // Explicit missing eligibility or changed binding.
	}
	// The retained reader ignores expiry. Only missing or changed claims mean
	// ineligibility; malformed or unauthentic evidence must remain an error.
	return alice && (errors.Is(err, ads.ErrNoReceivedClaim) ||
		errors.Is(err, ads.ErrReceivedClaimChanged))
}
