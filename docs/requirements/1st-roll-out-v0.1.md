## First Functional Requirements

I'll present **everything** here because I think it's necessary to be able
understand what we want to achieve, i.e., first step of the continuous delivery.

> Life goes on after the first demo -- or life starts from that.

> See the attached PDF document that includes then UML use case diagram.

### Ubuntu Linux

- The inner loop that produces the software
  1. There will be backend app that's installable on to Linux (maybe even Mac if
    Tor is available; this is not important)
       - you can run it as CLI, but maybe we should out-scope chat UIs and
         everything that's not convenient to be run with the one time command
       - the main purpose of the backend binary is to work as a service that
       communicates outside world through Tor and what we select to *the UI app*
       - you should change hosting of the backend (this is not drawn to UC
         diagram)
  2. *The UI App* we should select the most convenient tech to start. Or we can
     start with one and bring others later. The app's philosophy should be
     WeChat: it can do everything at the end, but we start with the messaging
     app that's totally safe[Q2] (e2e encrypted) and you can run it yourself.
     Every single part of the system.
       - We have used the term *evidence* that's excellent. Let's decide that we
       start with the simple messaging app, chatting app, but v0.2 would have a
       PW evidence included
       - The PW evidence is a free formatted (if we don't invent anything
         better.) It could be a short JSON doc, but the important part is that
       both parties of PW have signed it.
       - Let's have an example, these evidences could be used to proof to some
       third party trustworthiness of these PW holders, for example.
       - we decide (if any) of this later. Let's try to remember keep it simple.
       No ZKP, etc.

### CI Server

Can be out-scoped from the first version, but we should really consider this!

### Rentable Helper

I can run this e.g. in AWS EC2 instance. We should make decision if one process
can serve small group of people without spanning more processes. Naturally, I
can test how you can install the whole system into the home server without
static IP address.

Our helper service runs here. We aren't decided what protocol is used to serve
the UI app. I have good experience of gRPC but maybe it is not best for web UI?

### The UI App

Let's select something beautiful because then we might get the wow effect from
the audience. I have always been keen on to learn how well Flutter works as a
web app. But I'm open for everything.

## Q&A

Q1: should the “Rentable Helper” be able to sign and decrypt on a node holder’s
behalf, or must those capabilities remain on the holder’s own device?

A1: Yes, the "Rental Helper" should be able to sign and decrypt on a node
holder's behalf. So, yes, the rental helper is a hosted personal node living
inside owner's trust boundary.

Q2: Is it totally safe and what e2e encryption means.

A2: We understand that this is *the question*. We (and others) have studied it a
lot. The benefits we got with this model are so big that we think it should be
that way. In this peculiar architecture decision we see that the future will
bring new inventions and tech to help us. And now we think that our solution is
some kind of hybrid model where the master key (or parts of it) are in the UI
device and the Rental Helper is not totally autonomous. It needs UI app's help.
However, we haven't decided how it is done precisely, i.e., are we going to use
some kind of session model, expiration times, or what. Let's say that until the
version 1.0 we should decide how exactly we have solved the delegation between
UI app and the helper app -- distributed key management.
