import 'package:flutter/foundation.dart';
import 'package:flutter/painting.dart';

// UI read models only. No protocol DTOs, credentials or inferred remote state.
enum DemoPersonKind { localIdentity, verifiedPathSubject, receivedClaimSubject }

enum DemoLinkKind { verifiedIntroduction, retainedPW }

@immutable
class DemoPerson {
  const DemoPerson(this.id, this.name, this.position, this.kind);

  final String id;
  final String name;
  final Offset position;
  final DemoPersonKind kind;
}

@immutable
class DemoLink {
  const DemoLink(this.from, this.to, this.kind, this.provenance);

  final String from;
  final String to;
  final DemoLinkKind kind;
  final String provenance;

  String get id => '${kind.name}-$from-$to';
}

@immutable
class DemoTrust {
  const DemoTrust(this.peer, this.provenance);

  final String peer;
  final String provenance;
}

@immutable
class DemoReadiness {
  const DemoReadiness(this.peer, this.provenance);

  final String peer;
  final String provenance;
}

@immutable
class DemoInvitation {
  const DemoInvitation(this.peer, this.provenance);

  final String peer;
  final String provenance;
}

@immutable
class DemoMessage {
  const DemoMessage(this.peer, this.fromOwner, this.text, this.time);

  final String peer;
  final bool fromOwner;
  final String text;
  final String time;
  String get provenance => 'Scripted conversation · no live transport';
}

@immutable
class WalletDemoFixture {
  WalletDemoFixture({
    required this.owner,
    required List<DemoPerson> people,
    required List<DemoLink> links,
    List<DemoTrust> trust = const [],
    List<DemoReadiness> readiness = const [],
    List<DemoInvitation> invitations = const [],
    List<DemoMessage> messages = const [],
  }) : people = List.unmodifiable(people),
       links = List.unmodifiable(links),
       trust = List.unmodifiable(trust),
       readiness = List.unmodifiable(readiness),
       invitations = List.unmodifiable(invitations),
       messages = List.unmodifiable(messages);

  final String owner;
  final List<DemoPerson> people;
  final List<DemoLink> links;
  final List<DemoTrust> trust;
  final List<DemoReadiness> readiness;
  final List<DemoInvitation> invitations;
  final List<DemoMessage> messages;

  DemoPerson person(String id) => people.firstWhere((p) => p.id == id);
  String get ownerName => person(owner).name;
  bool holds(String peer) => links.any(
    (link) =>
        link.kind == DemoLinkKind.retainedPW &&
        link.from == owner &&
        link.to == peer,
  );
  bool trusts(String peer) => trust.any((item) => item.peer == peer);
}

final aliceDemoWallet = WalletDemoFixture(
  owner: 'alice',
  people: const [
    DemoPerson(
      'root',
      'Root',
      Offset(.50, .10),
      DemoPersonKind.verifiedPathSubject,
    ),
    DemoPerson(
      'maya',
      'Maya',
      Offset(.25, .34),
      DemoPersonKind.verifiedPathSubject,
    ),
    DemoPerson(
      'noah',
      'Noah',
      Offset(.80, .34),
      DemoPersonKind.verifiedPathSubject,
    ),
    DemoPerson(
      'alice',
      'Alice',
      Offset(.20, .70),
      DemoPersonKind.localIdentity,
    ),
    DemoPerson(
      'carol',
      'Carol',
      Offset(.50, .88),
      DemoPersonKind.verifiedPathSubject,
    ),
    DemoPerson(
      'bob',
      'Bob',
      Offset(.83, .70),
      DemoPersonKind.verifiedPathSubject,
    ),
  ],
  links: const [
    DemoLink(
      'root',
      'maya',
      DemoLinkKind.verifiedIntroduction,
      'Alice fixture · locally verified Root → Maya path evidence',
    ),
    DemoLink(
      'maya',
      'alice',
      DemoLinkKind.verifiedIntroduction,
      'Alice fixture · locally verified Root → Maya → Alice path evidence',
    ),
    DemoLink(
      'maya',
      'carol',
      DemoLinkKind.verifiedIntroduction,
      'Alice fixture · locally verified Root → Maya → Carol path evidence',
    ),
    DemoLink(
      'root',
      'noah',
      DemoLinkKind.verifiedIntroduction,
      'Alice fixture · locally verified Root → Noah path evidence',
    ),
    DemoLink(
      'noah',
      'bob',
      DemoLinkKind.verifiedIntroduction,
      'Alice fixture · locally verified Root → Noah → Bob path evidence',
    ),
    DemoLink(
      'alice',
      'bob',
      DemoLinkKind.retainedPW,
      'Alice fixture · Alice’s retained local PW half for Bob',
    ),
    DemoLink(
      'alice',
      'carol',
      DemoLinkKind.retainedPW,
      'Alice fixture · Alice’s retained local PW half for Carol',
    ),
  ],
  trust: const [
    DemoTrust('carol', 'Alice fixture · trust explicitly assigned by Alice'),
  ],
  readiness: const [
    DemoReadiness('bob', 'Alice fixture · sample authenticated response'),
  ],
  messages: const [
    DemoMessage('bob', false, 'Hi Alice! Good to see you here.', '10:42'),
    DemoMessage(
      'bob',
      true,
      'Hi Bob. A little closer, even from here.',
      '10:43',
    ),
    DemoMessage('bob', false, 'Coffee on Friday?', '10:44'),
    DemoMessage('bob', true, 'Sounds like a plan.', '10:44'),
  ],
);

// Independently authored Bob-local knowledge. Carol is intentionally absent;
// Alice's trust and response observation say nothing about Bob's local state.
final bobDemoWallet = WalletDemoFixture(
  owner: 'bob',
  people: const [
    DemoPerson(
      'root',
      'Root',
      Offset(.50, .10),
      DemoPersonKind.verifiedPathSubject,
    ),
    DemoPerson(
      'noah',
      'Noah',
      Offset(.25, .34),
      DemoPersonKind.verifiedPathSubject,
    ),
    DemoPerson(
      'maya',
      'Maya',
      Offset(.80, .34),
      DemoPersonKind.verifiedPathSubject,
    ),
    DemoPerson('bob', 'Bob', Offset(.20, .70), DemoPersonKind.localIdentity),
    DemoPerson(
      'alice',
      'Alice',
      Offset(.83, .70),
      DemoPersonKind.verifiedPathSubject,
    ),
  ],
  links: const [
    DemoLink(
      'root',
      'noah',
      DemoLinkKind.verifiedIntroduction,
      'Bob fixture · locally verified Root → Noah path evidence',
    ),
    DemoLink(
      'noah',
      'bob',
      DemoLinkKind.verifiedIntroduction,
      'Bob fixture · locally verified Root → Noah → Bob path evidence',
    ),
    DemoLink(
      'root',
      'maya',
      DemoLinkKind.verifiedIntroduction,
      'Bob fixture · locally verified Root → Maya path evidence',
    ),
    DemoLink(
      'maya',
      'alice',
      DemoLinkKind.verifiedIntroduction,
      'Bob fixture · locally verified Root → Maya → Alice path evidence',
    ),
    DemoLink(
      'bob',
      'alice',
      DemoLinkKind.retainedPW,
      'Bob fixture · Bob’s retained local PW half for Alice',
    ),
  ],
);
