# Current Go Implementation Reality

Status: implementation inventory context  
Purpose: explain current implementation shortcuts and historical naming before comparing to the IntroTree V19 TLA+ semantics.

## Current implementation scope

The current Go implementation is not a complete V19 implementation.

It contains useful implementation material, but some parts reflect earlier design
ideas and should not be treated as final semantics.

## Current known implementation facts

- The current code still uses terms such as invitation tree / trust domain in places.
- Earlier implementation work supported multi-root / multi-trust-domain ideas.
- The current TLA+ baseline is stricter: core IntroTree semantics are single-root.
- FIDO2 authenticator concepts exist in the implementation.
- There is currently no full helper-service client/server protocol.
- There is currently CLI UI, not a final end-user UI.
- Some network behavior may be simulated, and where it is the NATS.io is used.
- Some components may exist as experiments, demos, or scaffolding.
- Do not assume every existing feature is intended to survive.
- most important parts of the core logic in the implementation is
  comprehensively unit tested
- unit testing and error handling uses `err2` package that allows developers use
  same assert statements for both runtime and for testing harness.
- `err2` also allows automatic error propagation and annotation. It brings
  automatic and runtime configurable (CLI flags) errors traces

## How to classify code

Use these labels:

| Label | Meaning |
|---|---|
| Keep | Matches V19 semantics closely |
| Adapt | Useful but needs semantic changes |
| Split | Combines concepts V19 keeps separate |
| Remove | Implements obsolete or unsafe semantics |
| Defer | Useful later but outside current baseline |
| Unknown | Needs human review |

## Important semantic baseline

Use the TLA+ V19 state semantics as the source of truth.

The implementation must preserve these boundaries:

- introduction evidence is not trust;
- received evidence is not verified evidence;
- received ads are not verified ads;
- helper availability is not helper authority;
- recovery delivery is not recovery authorization;
- stale helper data cannot bootstrap;
- device authorization is not device usability;
- delete is not deny;
- bootstrap is not pairwise reuse;
- safe restore must not restore consumed authority.

### Misleading semantic facts in the Go implementation

**The implementation has these semantic errors:** 

- implementation spokes lots about web-of-trust (WoT), which must be check case by case;
- the current implementation allows creation of new roots, and it speaks about
  trust domains, all of that must be checked case by case;
- current implementation's trust model isn't correct any more, TLA introduction
  is more accurate and as correct as it can be in this time and knowledge;
- current CLI implementation lacks the concept of wallet and you can play with
  the CLI over NATS.io so that you work as two different parties. There is no
  limit. E.g. command `tdc id list` includes all the current identities in the
  virtual secure enclave. That cannot be the case in final implementation.

## Cloud/helper note

Do not assume that a helper service already exists in the Go implementation.

A helper service is allowed by the architecture, but only as availability
infrastructure. It must not create authority, verified evidence, verified ads,
or recovery grants.

We have tried different concepts in the Go package `internal/protocol`. The
package is for the current CLI playground. The idea of the playground was that
before we bring full C/S protocol (like gRPC) for helper service we are prepared
ourselves with proper understanding how the underlying layers work. The same
idea might be good when continue.

## FIDO2/authenticator note

FIDO2/passkey/authenticator-related code may be useful for implementing device
authority or recovery ceremonies.

Do not equate FIDO2 presence with completed V19 device/recovery semantics.
Map it carefully.



## Concept Mappings

We have recognized following concept mappings. They might not be 100% accurate,
but we have harshly hand checked all of them -- you shouldn't fully trust them.

Use these mappings:

| TLA Concept | Go Concept | Info |
|---|---|---|
| `Ad` | `Digest.DigestV2` | `Digest` pkg is like a public DID. Packed minimal information |
| `Introduce` | `identity.Invite` | implementation was WoT where trust was part of the implementation, it's not any more! |
| `CreatePW` | `protocol.PairwiseHandshake` | This is in CLI implementation where we have tried that underlying structures work and WoT calculations can filter untrusted PW creations |
| `Pipe` | `pw.Connection` | this is more a preparation for upcoming Onion service endpoint implementation, but it should present the idea |
