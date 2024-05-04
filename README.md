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

actor admin
actor node_admin

rectangle "CI System" {
  admin -- (make mutual introduction)
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
