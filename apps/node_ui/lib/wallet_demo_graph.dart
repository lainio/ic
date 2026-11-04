import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'wallet_demo_fixtures.dart';

const demoBackground = Color(0xff09111f);
const demoSurface = Color(0xff101c2d);
const demoBorder = Color(0xff26354a);
const demoMuted = Color(0xffa0afc3);
const demoCyan = Color(0xff6ad7df);
const demoViolet = Color(0xffaa98e7);
const demoAmber = Color(0xffe8ba70);

class WalletDemoGraph extends StatelessWidget {
  const WalletDemoGraph({
    super.key,
    required this.fixture,
    required this.selected,
    required this.showIntroductions,
    required this.showPW,
    required this.showTrust,
    required this.onSelect,
  });

  final WalletDemoFixture fixture;
  final String? selected;
  final bool showIntroductions;
  final bool showPW;
  final bool showTrust;
  final ValueChanged<String> onSelect;

  @override
  Widget build(BuildContext context) => LayoutBuilder(
    builder: (context, constraints) {
      Offset position(String id) {
        final point = fixture.person(id).position;
        return Offset(
          50 + point.dx * (constraints.maxWidth - 100),
          54 + point.dy * (constraints.maxHeight - 108),
        );
      }

      return Stack(
        key: const ValueKey('relationship-graph'),
        children: [
          const Positioned.fill(child: CustomPaint(painter: _GridPainter())),
          for (final link in fixture.links)
            if (link.kind == DemoLinkKind.verifiedIntroduction
                ? showIntroductions
                : showPW)
              Positioned.fill(
                child: IgnorePointer(
                  child: Semantics(
                    label: link.provenance,
                    child: CustomPaint(
                      key: ValueKey('edge-${link.id}'),
                      painter: _LinkPainter(
                        from: position(link.from),
                        to: position(link.to),
                        kind: link.kind,
                        highlighted:
                            link.kind == DemoLinkKind.retainedPW &&
                            link.to == selected,
                      ),
                    ),
                  ),
                ),
              ),
          for (final person in fixture.people)
            Positioned(
              left: position(person.id).dx - 46,
              top: position(person.id).dy - 35,
              width: 92,
              height: 108,
              child: _PersonButton(
                person: person,
                isOwner: person.id == fixture.owner,
                selected: selected == person.id,
                trusted: showTrust && fixture.trusts(person.id),
                onSelect: () => onSelect(person.id),
              ),
            ),
        ],
      );
    },
  );
}

class _PersonButton extends StatelessWidget {
  const _PersonButton({
    required this.person,
    required this.isOwner,
    required this.selected,
    required this.trusted,
    required this.onSelect,
  });

  final DemoPerson person;
  final bool isOwner;
  final bool selected;
  final bool trusted;
  final VoidCallback onSelect;

  @override
  Widget build(BuildContext context) {
    final color = isOwner || selected
        ? demoCyan
        : person.kind == DemoPersonKind.receivedClaimSubject
        ? demoMuted
        : demoViolet;
    final provenance = switch (person.kind) {
      DemoPersonKind.localIdentity => 'local fixture identity',
      DemoPersonKind.verifiedPathSubject => 'locally verified path subject',
      DemoPersonKind.receivedClaimSubject => 'received claim only',
    };
    return Semantics(
      key: ValueKey('node-${person.id}'),
      selected: selected,
      label: '${person.name}, $provenance',
      child: Tooltip(
        message: 'Inspect ${person.name} · $provenance',
        child: TextButton(
          onPressed: onSelect,
          style: TextButton.styleFrom(
            padding: EdgeInsets.zero,
            foregroundColor: Colors.white,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(16),
            ),
          ),
          child: Column(
            children: [
              Container(
                width: 62,
                height: 62,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: isOwner ? const Color(0xff183e4c) : demoSurface,
                  border: Border.all(
                    color: selected || isOwner ? color : demoBorder,
                    width: selected ? 3 : 1.5,
                  ),
                  boxShadow: [
                    if (selected || isOwner)
                      BoxShadow(
                        color: color.withValues(alpha: .13),
                        blurRadius: 26,
                        spreadRadius: 5,
                      ),
                  ],
                ),
                child: person.id == 'root'
                    ? Icon(Icons.account_tree_outlined, color: color, size: 24)
                    : Center(
                        child: Text(
                          person.name[0],
                          style: TextStyle(fontSize: 23, color: color),
                        ),
                      ),
              ),
              const SizedBox(height: 5),
              Container(
                color: demoSurface,
                padding: const EdgeInsets.symmetric(horizontal: 4),
                child: Text(person.name, style: const TextStyle(fontSize: 14)),
              ),
              if (isOwner)
                const Text(
                  'YOU',
                  style: TextStyle(fontSize: 10, color: demoCyan),
                )
              else if (trusted)
                Icon(
                  Icons.diamond_outlined,
                  key: ValueKey('trust-${person.id}'),
                  size: 13,
                  color: demoAmber,
                  semanticLabel: 'Local trust assigned in this wallet',
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _GridPainter extends CustomPainter {
  const _GridPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..color = const Color(0xff253144);
    for (double x = 20; x < size.width; x += 28) {
      for (double y = 20; y < size.height; y += 28) {
        canvas.drawCircle(Offset(x, y), .7, paint);
      }
    }
  }

  @override
  bool shouldRepaint(_GridPainter oldDelegate) => false;
}

class _LinkPainter extends CustomPainter {
  const _LinkPainter({
    required this.from,
    required this.to,
    required this.kind,
    required this.highlighted,
  });

  final Offset from;
  final Offset to;
  final DemoLinkKind kind;
  final bool highlighted;

  @override
  void paint(Canvas canvas, Size size) {
    final introduction = kind == DemoLinkKind.verifiedIntroduction;
    final paint = Paint()
      ..color = introduction ? demoViolet.withValues(alpha: .65) : demoCyan
      ..strokeWidth = introduction ? 1.5 : (highlighted ? 2.8 : 1.8)
      ..style = PaintingStyle.stroke;
    final path = Path()..moveTo(from.dx, from.dy);
    if (introduction) {
      path.lineTo(to.dx, to.dy);
      for (final metric in path.computeMetrics()) {
        for (double start = 0; start < metric.length; start += 12) {
          canvas.drawPath(
            metric.extractPath(start, math.min(start + 5, metric.length)),
            paint,
          );
        }
      }
      // Direction is historical introducer → subject, never a trust arrow.
      final direction = (to - from) / (to - from).distance;
      final tip = to - direction * 39;
      final normal = Offset(-direction.dy, direction.dx);
      canvas.drawPath(
        Path()
          ..moveTo(
            (tip - direction * 7 + normal * 4).dx,
            (tip - direction * 7 + normal * 4).dy,
          )
          ..lineTo(tip.dx, tip.dy)
          ..lineTo(
            (tip - direction * 7 - normal * 4).dx,
            (tip - direction * 7 - normal * 4).dy,
          ),
        paint,
      );
    } else {
      final middle = (from + to) / 2;
      path.quadraticBezierTo(middle.dx, middle.dy - 60, to.dx, to.dy);
      canvas.drawPath(
        path,
        Paint()
          ..color = demoCyan.withValues(alpha: .06)
          ..strokeWidth = 9
          ..style = PaintingStyle.stroke,
      );
      canvas.drawPath(path, paint);
    }
  }

  @override
  bool shouldRepaint(_LinkPainter oldDelegate) =>
      from != oldDelegate.from ||
      to != oldDelegate.to ||
      kind != oldDelegate.kind ||
      highlighted != oldDelegate.highlighted;
}
