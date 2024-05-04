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
