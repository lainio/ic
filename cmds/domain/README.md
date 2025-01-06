# TODO

- new 'id' commands: list, invite, accept, ...
- important `id` cmds: WoT stuff, etc.

# Specification For `Invitation` and `accept`

### Inviter

1. <TODO> how we get IDK of the invitee?
    - should the UID below be IDK?
    - here we have the *resolving* stuff, we need to calc WoTs
1. Sends a `payload` to the subject: `invitation_<UID>`. UID: invitee's
    - `payload` is challenge.
1. Starts to wait: `invitation_ACK_<UID>`

### Invitee

1. Waits a payload from the subject: `invitation_<UID>`, UID is ours.
1. When correct PL is received, sends back: `invitation_ACK_<UID>`
