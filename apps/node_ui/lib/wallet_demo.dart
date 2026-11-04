import 'package:flutter/material.dart';

import 'live_pairing.dart';
import 'status_client.dart';
import 'wallet_demo_fixtures.dart';
import 'wallet_demo_graph.dart';

/// Fixture presentation with a separate explicit local-owner action route.
class WalletDemoScreen extends StatefulWidget {
  const WalletDemoScreen({
    super.key,
    this.fixtures,
    this.ownerStatusUrl = '',
    this.headerPath = '',
    this.createPairingClient,
  });

  final List<WalletDemoFixture>? fixtures;
  final String ownerStatusUrl;
  final String headerPath;
  final StatusClient Function()? createPairingClient;

  @override
  State<WalletDemoScreen> createState() => _WalletDemoScreenState();
}

class _WalletDemoScreenState extends State<WalletDemoScreen> {
  late final List<WalletDemoFixture> _wallets = List.unmodifiable(
    widget.fixtures ?? [aliceDemoWallet, bobDemoWallet],
  );
  int _walletIndex = 0;
  String? _selected;
  bool _showIntroductions = true;
  bool _showPW = true;
  bool _showTrust = true;

  WalletDemoFixture get _wallet => _wallets[_walletIndex];

  @override
  Widget build(BuildContext context) {
    final theme = ThemeData(
      useMaterial3: true,
      brightness: Brightness.dark,
      scaffoldBackgroundColor: demoBackground,
      colorScheme: const ColorScheme.dark(
        primary: demoCyan,
        secondary: demoViolet,
        surface: demoSurface,
        onSurface: Color(0xffe5ecf5),
        outline: demoBorder,
      ),
      dividerColor: demoBorder,
      dividerTheme: const DividerThemeData(color: demoBorder, thickness: 1),
      textTheme: ThemeData.dark().textTheme.apply(
        bodyColor: const Color(0xffe5ecf5),
        displayColor: const Color(0xffe5ecf5),
      ),
    );
    return Theme(
      data: theme,
      child: Scaffold(
        key: const ValueKey('wallet-demo'),
        body: SafeArea(
          child: Column(
            children: [
              _header(theme),
              const _DemoNotice(),
              Expanded(
                child: LayoutBuilder(
                  builder: (context, constraints) {
                    final wide = constraints.maxWidth >= 1050;
                    final peer = _selected;
                    final details = peer == null
                        ? _Overview(wallet: _wallet, onSelect: _select)
                        : _PeerPanel(
                            key: ValueKey('${_wallet.owner}-$peer-details'),
                            wallet: _wallet,
                            peer: peer,
                            narrow: !wide,
                            onClose: () => setState(() => _selected = null),
                          );
                    return Row(
                      children: [
                        if (constraints.maxWidth >= 1280)
                          _Sidebar(wallet: _wallet),
                        Expanded(
                          child: Padding(
                            padding: EdgeInsets.all(wide ? 24 : 16),
                            child: wide
                                ? Row(
                                    crossAxisAlignment:
                                        CrossAxisAlignment.stretch,
                                    children: [
                                      Expanded(child: _graphWorkspace()),
                                      const SizedBox(width: 20),
                                      SizedBox(width: 360, child: details),
                                    ],
                                  )
                                : peer == null
                                ? _graphWorkspace(scroll: true)
                                : details,
                          ),
                        ),
                      ],
                    );
                  },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _select(String peer) => setState(() => _selected = peer);

  Widget _header(ThemeData theme) => Container(
    width: double.infinity,
    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
    child: Wrap(
      alignment: WrapAlignment.spaceBetween,
      crossAxisAlignment: WrapCrossAlignment.center,
      spacing: 20,
      runSpacing: 8,
      children: [
        Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
              key: const ValueKey('close-wallet-demo'),
              tooltip: 'Return to owner screen',
              onPressed: () => Navigator.of(context).maybePop(),
              icon: const Icon(Icons.arrow_back, size: 20),
            ),
            if (MediaQuery.sizeOf(context).width >= 600) ...[
              const Icon(
                Icons.account_tree_outlined,
                color: demoCyan,
                size: 26,
              ),
              const SizedBox(width: 10),
            ],
            const Text(
              'IntroTree',
              style: TextStyle(fontSize: 22, fontWeight: FontWeight.w600),
            ),
          ],
        ),
        FilledButton.icon(
          key: const ValueKey('open-live-pairing'),
          onPressed: () => Navigator.of(context).push(
            MaterialPageRoute<void>(
              builder: (_) => LivePairingScreen(
                ownerStatusUrl: widget.ownerStatusUrl,
                headerPath: widget.headerPath,
                createClient: widget.createPairingClient,
              ),
            ),
          ),
          icon: const Icon(Icons.link),
          label: const Text('Live pairing'),
        ),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 12),
          decoration: BoxDecoration(
            color: demoSurface,
            border: Border.all(color: demoBorder),
            borderRadius: BorderRadius.circular(12),
          ),
          child: DropdownButtonHideUnderline(
            child: DropdownButton<int>(
              key: const ValueKey('wallet-switcher'),
              value: _walletIndex,
              dropdownColor: demoSurface,
              icon: const Icon(Icons.expand_more, size: 18, color: demoMuted),
              style: theme.textTheme.bodyMedium?.copyWith(
                color: Colors.white,
                fontSize: 13,
              ),
              onChanged: (index) {
                if (index == null) return;
                setState(() {
                  _walletIndex = index;
                  _selected = null;
                });
              },
              items: [
                for (var index = 0; index < _wallets.length; index++)
                  DropdownMenuItem(
                    value: index,
                    child: Text("${_wallets[index].ownerName}'s wallet"),
                  ),
              ],
            ),
          ),
        ),
      ],
    ),
  );

  Widget _graphWorkspace({bool scroll = false}) {
    final heading = Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const _Eyebrow('RELATIONSHIPS'),
        const SizedBox(height: 8),
        const Text(
          'Your corner of IntroTree',
          style: TextStyle(fontSize: 28, fontWeight: FontWeight.w500),
        ),
        const SizedBox(height: 8),
        Text(
          "${_wallet.ownerName}'s wallet / local perspective",
          key: const ValueKey('local-perspective'),
          style: const TextStyle(color: demoMuted, fontSize: 14),
        ),
        const SizedBox(height: 24),
      ],
    );
    final graph = _Panel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 18, 20, 4),
            child: Wrap(
              alignment: WrapAlignment.spaceBetween,
              spacing: 12,
              runSpacing: 8,
              children: [
                const Text(
                  'Relationship graph',
                  style: TextStyle(fontWeight: FontWeight.w600),
                ),
                Text(
                  '${_wallet.people.length} identities in this local fixture',
                  style: const TextStyle(color: demoMuted, fontSize: 12),
                ),
              ],
            ),
          ),
          Expanded(
            child: WalletDemoGraph(
              fixture: _wallet,
              selected: _selected,
              showIntroductions: _showIntroductions,
              showPW: _showPW,
              showTrust: _showTrust,
              onSelect: _select,
            ),
          ),
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 20),
            child: Text(
              'Select an identity to explore · Tab, then Enter works too',
              style: TextStyle(color: demoMuted, fontSize: 12),
            ),
          ),
          const SizedBox(height: 16),
          const Divider(height: 1),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const _Eyebrow('THREE INDEPENDENT LAYERS'),
                const SizedBox(height: 10),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    _LayerToggle(
                      id: 'introductions',
                      label: 'Verified paths',
                      tooltip:
                          'Dashed violet · introduction evidence verified '
                          'locally; no trust implied',
                      color: demoViolet,
                      icon: Icons.more_horiz,
                      selected: _showIntroductions,
                      onChanged: (value) =>
                          setState(() => _showIntroductions = value),
                    ),
                    _LayerToggle(
                      id: 'pw',
                      label: 'Held PW',
                      tooltip:
                          'Solid cyan · retained local pairwise halves; '
                          'no claim about the other wallet',
                      color: demoCyan,
                      icon: Icons.horizontal_rule,
                      selected: _showPW,
                      onChanged: (value) => setState(() => _showPW = value),
                    ),
                    _LayerToggle(
                      id: 'trust',
                      label: 'Local trust',
                      tooltip:
                          'Amber diamond · explicitly assigned by this '
                          'wallet only',
                      color: demoAmber,
                      icon: Icons.diamond_outlined,
                      selected: _showTrust,
                      onChanged: (value) => setState(() => _showTrust = value),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                const Text(
                  'Layer controls change visibility only.',
                  style: TextStyle(color: demoMuted, fontSize: 11),
                ),
              ],
            ),
          ),
        ],
      ),
    );
    const footer = Padding(
      padding: EdgeInsets.only(top: 14),
      child: Text(
        'A local view of retained evidence. No global network map.',
        style: TextStyle(color: demoMuted, fontSize: 12),
      ),
    );
    if (scroll) {
      return SingleChildScrollView(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            heading,
            SizedBox(height: 650, child: graph),
            footer,
          ],
        ),
      );
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        heading,
        Expanded(child: graph),
        footer,
      ],
    );
  }
}

class _DemoNotice extends StatelessWidget {
  const _DemoNotice();

  @override
  Widget build(BuildContext context) => Container(
    width: double.infinity,
    padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 10),
    decoration: const BoxDecoration(
      color: Color(0xff141f2e),
      border: Border.symmetric(horizontal: BorderSide(color: demoBorder)),
    ),
    child: const Wrap(
      spacing: 16,
      runSpacing: 6,
      children: [
        Text(
          'DEMO DATA · UI CONCEPT',
          style: TextStyle(
            color: demoAmber,
            fontSize: 11,
            letterSpacing: 1.3,
            fontWeight: FontWeight.w700,
          ),
        ),
        Text(
          'SCRIPTED GRAPH AND CHAT · fixtures, no messages sent. '
          'Live pairing uses explicit owner submissions.',
          style: TextStyle(color: demoMuted, fontSize: 12),
        ),
      ],
    ),
  );
}

class _Sidebar extends StatelessWidget {
  const _Sidebar({required this.wallet});

  final WalletDemoFixture wallet;

  @override
  Widget build(BuildContext context) => Container(
    width: 184,
    decoration: const BoxDecoration(
      border: Border(right: BorderSide(color: demoBorder)),
    ),
    padding: const EdgeInsets.all(20),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const SizedBox(height: 12),
        const _Eyebrow('WORKSPACE'),
        const SizedBox(height: 24),
        const Row(
          children: [
            Icon(Icons.account_tree_outlined, size: 18, color: demoCyan),
            SizedBox(width: 10),
            Expanded(
              child: Text(
                'Relationships',
                style: TextStyle(color: demoCyan, fontSize: 13),
              ),
            ),
          ],
        ),
        const SizedBox(height: 40),
        const Divider(),
        const SizedBox(height: 24),
        const _Eyebrow('LOCAL SNAPSHOT'),
        const SizedBox(height: 20),
        Text(
          '${wallet.links.where((l) => l.kind == DemoLinkKind.retainedPW).length}'
          '  retained PWs',
          style: const TextStyle(color: demoMuted),
        ),
        const SizedBox(height: 16),
        Text(
          '${wallet.trust.length}  trust assigned',
          style: const TextStyle(color: demoMuted),
        ),
        const Spacer(),
        const Icon(Icons.fingerprint, size: 28, color: demoMuted),
        const SizedBox(height: 12),
        const Text(
          'Only what this\nwallet knows.',
          style: TextStyle(color: demoMuted, height: 1.6, fontSize: 13),
        ),
        const SizedBox(height: 12),
        const _Eyebrow('WALLET DEMO / 01'),
      ],
    ),
  );
}

class _Overview extends StatelessWidget {
  const _Overview({required this.wallet, required this.onSelect});

  final WalletDemoFixture wallet;
  final ValueChanged<String> onSelect;

  @override
  Widget build(BuildContext context) => _Panel(
    child: SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const _Eyebrow('YOUR LOCAL VIEW'),
          const SizedBox(height: 32),
          const Icon(Icons.hub_outlined, size: 44, color: demoCyan),
          const SizedBox(height: 24),
          const Text(
            'Every relationship\nhas its own story.',
            style: TextStyle(fontSize: 27, height: 1.25),
          ),
          const SizedBox(height: 16),
          Text(
            'Explore the people in ${wallet.ownerName}’s local fixture. '
            'Select an identity for its evidence and observations.',
            style: const TextStyle(color: demoMuted, height: 1.6),
          ),
          const SizedBox(height: 32),
          const Divider(),
          const SizedBox(height: 24),
          const _Eyebrow('RETAINED PAIRWISE RELATIONSHIPS'),
          const SizedBox(height: 16),
          for (final peer in wallet.people.where((p) => wallet.holds(p.id)))
            ListTile(
              contentPadding: EdgeInsets.zero,
              leading: CircleAvatar(
                backgroundColor: const Color(0xff203449),
                foregroundColor: demoCyan,
                child: Text(peer.name[0]),
              ),
              title: Text(peer.name),
              subtitle: const Text(
                'PW half held locally',
                style: TextStyle(color: demoMuted, fontSize: 12),
              ),
              trailing: const Icon(Icons.arrow_forward, size: 18),
              onTap: () => onSelect(peer.id),
            ),
          const SizedBox(height: 32),
          const Text(
            'Evidence, relationship, trust.',
            style: TextStyle(fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 10),
          const Text(
            'Three separate layers. An introduction or invitation '
            'alone creates neither a retained PW nor local trust.',
            style: TextStyle(color: demoMuted, height: 1.6, fontSize: 13),
          ),
          const SizedBox(height: 32),
          const _Eyebrow('FICTIONAL DATA · LOCAL PERSPECTIVE'),
        ],
      ),
    ),
  );
}

class _PeerPanel extends StatelessWidget {
  const _PeerPanel({
    super.key,
    required this.wallet,
    required this.peer,
    required this.narrow,
    required this.onClose,
  });

  final WalletDemoFixture wallet;
  final String peer;
  final bool narrow;
  final VoidCallback onClose;

  @override
  Widget build(BuildContext context) {
    final person = wallet.person(peer);
    final readiness = wallet.readiness.where((item) => item.peer == peer);
    final messages = wallet.messages.where((item) => item.peer == peer);
    return _Panel(
      child: LayoutBuilder(
        builder: (context, constraints) => SingleChildScrollView(
          key: const ValueKey('peer-details-scroll'),
          child: ConstrainedBox(
            constraints: BoxConstraints(minHeight: constraints.maxHeight),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Padding(
                  padding: const EdgeInsets.fromLTRB(20, 12, 12, 12),
                  child: Row(
                    children: [
                      CircleAvatar(
                        backgroundColor: const Color(0xff24334d),
                        foregroundColor: demoViolet,
                        child: Text(person.name[0]),
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              person.name,
                              style: const TextStyle(fontSize: 20),
                            ),
                            Text(
                              '${wallet.ownerName}’s fixture observation',
                              style: const TextStyle(
                                color: demoMuted,
                                fontSize: 11,
                              ),
                            ),
                          ],
                        ),
                      ),
                      IconButton(
                        key: const ValueKey('close-peer-details'),
                        tooltip: narrow ? 'Back to graph' : 'Close details',
                        onPressed: onClose,
                        icon: Icon(
                          narrow ? Icons.arrow_back : Icons.close,
                          size: 20,
                        ),
                      ),
                    ],
                  ),
                ),
                const Divider(height: 1),
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _Observation(
                        id: 'retained-pw',
                        icon: Icons.link,
                        color: demoCyan,
                        text:
                            'Retained PW: '
                            '${wallet.holds(peer) ? 'held locally' : 'not held locally'}',
                      ),
                      const SizedBox(height: 14),
                      _Observation(
                        id: 'last-readiness',
                        icon: Icons.history,
                        color: demoMuted,
                        text:
                            'Last readiness: '
                            '${readiness.isNotEmpty ? 'sample authenticated response' : 'no observation in fixture'}',
                      ),
                      const SizedBox(height: 14),
                      _Observation(
                        id: 'local-trust',
                        icon: Icons.diamond_outlined,
                        color: wallet.trusts(peer) ? demoAmber : demoMuted,
                        text:
                            'Local trust: '
                            '${wallet.trusts(peer) ? 'assigned by ${wallet.ownerName}' : 'not assigned'}',
                      ),
                      const SizedBox(height: 16),
                      const Text(
                        'Historical fixture observations; no claim '
                        'of current permission or reachability.',
                        style: TextStyle(
                          color: demoMuted,
                          fontSize: 11,
                          height: 1.5,
                        ),
                      ),
                      for (final invitation in wallet.invitations.where(
                        (item) => item.peer == peer,
                      )) ...[
                        const SizedBox(height: 12),
                        Text(
                          'Received invitation only · ${invitation.provenance}',
                          key: const ValueKey('received-invitation'),
                          style: const TextStyle(
                            color: demoMuted,
                            fontSize: 12,
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
                const Divider(height: 1),
                Padding(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      const _Eyebrow('SCRIPTED CONVERSATION'),
                      const SizedBox(height: 8),
                      const Text(
                        'Sample scene · no live transport',
                        style: TextStyle(color: demoMuted, fontSize: 11),
                      ),
                      const SizedBox(height: 20),
                      if (messages.isEmpty)
                        const Text(
                          'No scripted messages in this fixture.',
                          style: TextStyle(color: demoMuted, height: 1.6),
                        ),
                      for (final message in messages) _Bubble(message),
                    ],
                  ),
                ),
                const Padding(
                  padding: EdgeInsets.fromLTRB(20, 8, 20, 20),
                  child: Column(
                    children: [
                      TextField(
                        key: ValueKey('sample-composer'),
                        enabled: false,
                        decoration: InputDecoration(
                          hintText: 'Sample message — sending disabled',
                          hintStyle: TextStyle(color: demoMuted, fontSize: 12),
                          border: OutlineInputBorder(),
                          disabledBorder: OutlineInputBorder(
                            borderSide: BorderSide(color: demoBorder),
                          ),
                          suffixIcon: IconButton(
                            key: ValueKey('sample-send'),
                            tooltip: 'Sending unavailable in demo',
                            onPressed: null,
                            icon: Icon(Icons.arrow_upward, size: 18),
                          ),
                        ),
                      ),
                      SizedBox(height: 12),
                      Text(
                        'Scripted conversation · no live transport',
                        style: TextStyle(color: demoMuted, fontSize: 11),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _Bubble extends StatelessWidget {
  const _Bubble(this.message);

  final DemoMessage message;

  @override
  Widget build(BuildContext context) => Align(
    alignment: message.fromOwner ? Alignment.centerRight : Alignment.centerLeft,
    child: Semantics(
      label: message.provenance,
      child: Container(
        constraints: const BoxConstraints(maxWidth: 258),
        margin: EdgeInsets.only(
          bottom: 12,
          left: message.fromOwner ? 28 : 0,
          right: message.fromOwner ? 0 : 28,
        ),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
        decoration: BoxDecoration(
          color: message.fromOwner
              ? const Color(0xff1b3948)
              : const Color(0xff202d42),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Text(
              message.text,
              style: const TextStyle(fontSize: 13, height: 1.5),
            ),
            const SizedBox(height: 4),
            Text(
              message.time,
              style: const TextStyle(fontSize: 10, color: demoMuted),
            ),
          ],
        ),
      ),
    ),
  );
}

class _Observation extends StatelessWidget {
  const _Observation({
    required this.id,
    required this.icon,
    required this.color,
    required this.text,
  });

  final String id;
  final IconData icon;
  final Color color;
  final String text;

  @override
  Widget build(BuildContext context) => Row(
    key: ValueKey(id),
    crossAxisAlignment: CrossAxisAlignment.start,
    children: [
      Icon(icon, size: 18, color: color),
      const SizedBox(width: 10),
      Expanded(
        child: Text(text, style: const TextStyle(fontSize: 12, height: 1.5)),
      ),
    ],
  );
}

class _LayerToggle extends StatelessWidget {
  const _LayerToggle({
    required this.id,
    required this.label,
    required this.tooltip,
    required this.color,
    required this.icon,
    required this.selected,
    required this.onChanged,
  });

  final String id;
  final String label;
  final String tooltip;
  final Color color;
  final IconData icon;
  final bool selected;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) => FilterChip(
    key: ValueKey('layer-$id'),
    label: Text(
      label,
      style: const TextStyle(fontSize: 12, color: Color(0xffe5ecf5)),
    ),
    avatar: Icon(icon, size: 18, color: color),
    tooltip: tooltip,
    selected: selected,
    showCheckmark: false,
    selectedColor: color.withValues(alpha: .10),
    side: BorderSide(
      color: selected ? color.withValues(alpha: .4) : demoBorder,
    ),
    onSelected: onChanged,
  );
}

class _Panel extends StatelessWidget {
  const _Panel({required this.child});

  final Widget child;

  @override
  Widget build(BuildContext context) => Material(
    color: demoSurface,
    shape: RoundedRectangleBorder(
      side: const BorderSide(color: demoBorder),
      borderRadius: BorderRadius.circular(18),
    ),
    clipBehavior: Clip.antiAlias,
    child: child,
  );
}

class _Eyebrow extends StatelessWidget {
  const _Eyebrow(this.text);

  final String text;

  @override
  Widget build(BuildContext context) => Text(
    text,
    style: const TextStyle(
      color: demoMuted,
      fontSize: 10,
      letterSpacing: 1.4,
      fontWeight: FontWeight.w600,
    ),
  );
}
