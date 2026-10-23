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
     app that's totally safe (e2e encrypted) and you can run it yourself.
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
