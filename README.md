## Invitation Chain

This is the Invitation Chain. It is a Go package and a CLI tool for building
invitation and reputation chains. Later we might offer gRPC API as well.

### Design

1. use case driven approach.
1. test driven approach
1. algorithm first (PoC)
1. then input and output 
  - network transport
1. last the persistence 

## Use Cases

1. Install App and generate key pairs and secure enclaves
1. Meet a friend
    - check who has *trust-level* TL status TODO:
    - greater TL

```plantuml
@startuml
left to right direction
skinparam packageStyle rectangle

actor holder
actor admin
actor node_admin

rectangle "CI System" {
  (show qr) -- holder
  (read qr) <|- (decide introduction/connection)
  (read qr) -- holder
  admin -- (make mutual introduction)
  admin -- (introduction: invite)
  admin -- (create keys)
  admin -- (app installation)

  node_admin -- (create tor proxy)
  node_admin -- (create TLS cert)
  node_admin -- (create dynDNS)
  node_admin -- (create client connection)
}

admin <|- node_admin
@enduml
```

### Use Case Explanations

#### Decide introduction/connection

If we have common invitations we could just connect and start chat. We can build
pairwise connection. However, if we already know each others well we can bind
our invitation chains together to make extra trust for our selves and our future
invitation-connections.

If we are reading QR code from ad aka sales pages and we know nothing about
other end, we must check our invitation chains. How we get invitation chain form
the QR code? The Tor address we are reading it from must be signed. This is very
important!

We don't want to contact QR-codes endpoint without knowing that it's valid! What
it means? We need QR-code resolving. And before we resolve the QR/code we need
to check if we can trust it. That happens thru our chains. If we don't have any
chains, we cannot connect to any ad, for example. That is incentive. 

DIDDoc resolving is cheap way to solve that issue, we don't want that, or do we?
Why DIDDoc resolving is so bad? For the most methods it requires that we contact
somewhere in the net to load DIDDoc!! It's bad. We want a methdot that allows us
make all the decisions before contacting anything. 

In our case it's easy, the endpoint is in our chains or it's not, that's for
that. Or we could have Nodes that work as resolvers, but let's go to that way
just until we really have to, shall we?

Okay, we don't need to have the same keys as Tor but maybe it would make things
easier? Or interesting if we would have?

Business idea, those resolvers could make business, they could sell large
invitation chains to join with. And actually those parties who have many
connections are the most valuable if they give us high score. 

##### Handshake

What happens if the QR-code is the chain block that no one knows, i.e., we use
sub keys before we print the ad. Why we would do that if it makes our life more
difficult? NOTE! we use sub key only when we bind persistent pairwises between
parties. But maybe it's not enough? It might still be because adds can be
'general' and ads are just one block (pubkey), the rest of the chain comes after
we connect to the endpoint associated to the pub key. Use next diagram to draw a
form handshake for ad sales.

(pub key : onion service address) -> connection, and start of the handshake.
We'll give our chain which is the chain that includes the (pub key). NOTE that
the position doesn't matter!! The handshake verification happens always towards
both parties leaf. This allows both parties to be pseudonym.

```mermaid
sequenceDiagram
    autonumber

    participant Seller

    %% -- box won't work on hugo, or when this machine is running it --
    %% box Issuing Service
    participant IssuerFSM
    participant BackendFSM
    participant RcvrFSM
    %% end

    participant Buyer

    Seller -) IssuerFSM: 'session_id' (GUID)
    Seller -) IssuerFSM: issuer = role
    loop Schemas attributes
    Seller -) IssuerFSM: 'attribute_value'
    end

```

# References to PUML Works! Will use this in final.

![connection-protocol-save-state.puml](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/findy-network/findy-agent/master/docs/puml/protocols/connection-protocol-save-state.puml)
