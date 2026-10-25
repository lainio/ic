import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'status_client.dart';

void main() => runApp(const IntroTreeApp());

typedef ReadStatus = Future<NodeChoice> Function(String url, String headerPath);
typedef ReadIntroduction = Future<String> Function(
  String url,
  String headerPath,
);
typedef CheckIntroduction = Future<IntroductionCheck> Function(
  String url,
  String headerPath,
  String document,
);

class IntroTreeApp extends StatelessWidget {
  const IntroTreeApp({
    super.key,
    this.readStatus,
    this.readIntroduction,
    this.checkIntroduction,
  });

  final ReadStatus? readStatus;
  final ReadIntroduction? readIntroduction;
  final CheckIntroduction? checkIntroduction;

  @override
  Widget build(BuildContext context) => MaterialApp(
    title: 'IntroTree',
    debugShowCheckedModeBanner: false,
    theme: ThemeData(
      colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xff315e54)),
      useMaterial3: true,
      inputDecorationTheme: const InputDecorationTheme(
        border: OutlineInputBorder(),
        floatingLabelBehavior: FloatingLabelBehavior.always,
      ),
    ),
    home: StatusScreen(
      readStatus: readStatus,
      readIntroduction: readIntroduction,
      checkIntroduction: checkIntroduction,
    ),
  );
}

class StatusScreen extends StatefulWidget {
  const StatusScreen({
    super.key,
    this.readStatus,
    this.readIntroduction,
    this.checkIntroduction,
  });

  final ReadStatus? readStatus;
  final ReadIntroduction? readIntroduction;
  final CheckIntroduction? checkIntroduction;

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen> {
  final _url = TextEditingController();
  final _headerPath = TextEditingController();
  final _introduction = TextEditingController();
  final _client = StatusClient();
  bool _loading = false;
  bool _copying = false;
  bool _copied = false;
  bool _checking = false;
  IntroductionCheck? _checked;
  StatusFailure? _checkFailure;
  int _checkRevision = 0;
  NodeChoice? _choice;
  StatusFailure? _failure;
  int _inputRevision = 0;

  void _inputChanged(String _) {
    setState(() {
      _inputRevision++;
      _choice = null;
      _failure = null;
      _copied = false;
      _invalidateCheck();
    });
  }

  void _invalidateCheck() {
    _checkRevision++;
    _checked = null;
    _checkFailure = null;
  }

  Future<void> _check() async {
    if (_loading) return;
    setState(() {
      _invalidateCheck();
      _loading = true;
      _checking = true;
    });
    final revision = _checkRevision;
    IntroductionCheck? checked;
    StatusFailure? failure;
    try {
      checked = await (widget.checkIntroduction ?? _client.checkIntroduction)(
        _url.text,
        _headerPath.text,
        _introduction.text,
      );
    } on StatusFailure catch (error) {
      failure = error;
    } catch (_) {
      failure = StatusFailure.unreachable;
    }
    if (!mounted) return;
    setState(() {
      _loading = false;
      _checking = false;
      if (revision == _checkRevision) {
        _checked = checked;
        _checkFailure = failure;
      }
    });
  }

  Future<void> _read() async {
    if (_loading) return;
    final revision = _inputRevision;
    setState(() {
      _loading = true;
      _copied = false;
      _choice = null;
      _failure = null;
    });
    NodeChoice? choice;
    StatusFailure? failure;
    try {
      choice = await (widget.readStatus ?? _client.read)(
        _url.text,
        _headerPath.text,
      );
    } on StatusFailure catch (error) {
      failure = error;
    } catch (_) {
      failure = StatusFailure.unreachable;
    }
    if (!mounted) return;
    setState(() {
      _loading = false;
      if (revision == _inputRevision) {
        _choice = choice;
        _failure = failure;
      }
    });
  }

  Future<void> _copy() async {
    if (_loading || _choice != NodeChoice.completed) return;
    final revision = _inputRevision;
    setState(() {
      _loading = true;
      _copying = true;
      _copied = false;
      _failure = null;
    });
    StatusFailure? failure;
    try {
      final document =
          await (widget.readIntroduction ?? _client.readIntroduction)(
            _url.text,
            _headerPath.text,
          );
      if (!mounted || revision != _inputRevision) return;
      try {
        await Clipboard.setData(ClipboardData(text: document));
      } catch (_) {
        throw StatusFailure.clipboard;
      }
      if (!mounted || revision != _inputRevision) return;
      setState(() {
        _copied = true;
      });
    } on StatusFailure catch (error) {
      failure = error;
    } catch (_) {
      failure = StatusFailure.unreachable;
    } finally {
      if (mounted) {
        setState(() {
          _loading = false;
          _copying = false;
          if (revision == _inputRevision && failure != null) {
            _failure = failure;
            _choice = null;
            _copied = false;
          }
        });
      }
    }
  }

  @override
  void dispose() {
    _client.close();
    _url.dispose();
    _headerPath.dispose();
    _introduction.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      appBar: AppBar(title: const Text('IntroTree')),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.fromLTRB(24, 24, 24, 40),
          child: Center(
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 680),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text('My node', style: theme.textTheme.headlineMedium),
                  const SizedBox(height: 8),
                  const Text(
                    'Read saved acceptance state from your local node.',
                  ),
                  const SizedBox(height: 28),
                  TextField(
                    controller: _url,
                    onChanged: _inputChanged,
                    keyboardType: TextInputType.url,
                    textInputAction: TextInputAction.next,
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: const InputDecoration(
                      labelText: 'Owner status URL',
                      hintText: 'Paste the URL printed by node serve',
                    ),
                  ),
                  const SizedBox(height: 24),
                  TextField(
                    controller: _headerPath,
                    onChanged: _inputChanged,
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: const InputDecoration(
                      labelText: 'Authorization header file',
                      hintText: 'Paste the absolute owner.header path',
                    ),
                  ),
                  const SizedBox(height: 20),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: FilledButton(
                      onPressed: _loading ? null : _read,
                      child: const Text('Read status'),
                    ),
                  ),
                  const SizedBox(height: 24),
                  Semantics(
                    liveRegion: true,
                    child: Card.filled(
                      margin: EdgeInsets.zero,
                      child: Padding(
                        padding: const EdgeInsets.all(24),
                        child: _result(theme),
                      ),
                    ),
                  ),
                  if (_choice == NodeChoice.completed) ...[
                    const SizedBox(height: 20),
                    const Text(
                      'Contains your public keys and introduction path. Share deliberately.',
                    ),
                    const SizedBox(height: 12),
                    Align(
                      alignment: Alignment.centerLeft,
                      child: OutlinedButton(
                        onPressed: _loading ? null : _copy,
                        child: const Text('Copy introduction'),
                      ),
                    ),
                  ],
                  if (_copied) ...[
                    const SizedBox(height: 12),
                    Semantics(
                      liveRegion: true,
                      child: const Text('Introduction copied'),
                    ),
                  ],
                  const SizedBox(height: 16),
                  Text(
                    'Local acceptance state; not membership, trust, or delivery confirmation.',
                    style: theme.textTheme.bodyMedium,
                  ),
                  const SizedBox(height: 32),
                  const Divider(),
                  const SizedBox(height: 16),
                  Text(
                    'Check an introduction',
                    style: theme.textTheme.headlineSmall,
                  ),
                  const SizedBox(height: 20),
                  TextField(
                    controller: _introduction,
                    onChanged: (_) => setState(_invalidateCheck),
                    minLines: 4,
                    maxLines: 8,
                    keyboardType: TextInputType.multiline,
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: const InputDecoration(
                      labelText: 'Introduction JSON',
                    ),
                  ),
                  const SizedBox(height: 16),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: FilledButton(
                      onPressed: _loading ? null : _check,
                      child: const Text('Check introduction'),
                    ),
                  ),
                  const SizedBox(height: 20),
                  Semantics(liveRegion: true, child: _checkResult(theme)),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _result(ThemeData theme) {
    final choice = _choice;
    final failure = _failure;
    if (_loading && !_checking) {
      final action = _copying ? 'Copying introduction' : 'Reading status';
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('$action…'),
          const SizedBox(height: 16),
          LinearProgressIndicator(semanticsLabel: action),
        ],
      );
    }
    if (failure != null) {
      return Text(
        failure.message,
        style: TextStyle(color: theme.colorScheme.error),
      );
    }
    if (choice == null) {
      return Text('Not checked', style: theme.textTheme.titleLarge);
    }
    final (title, explanation) = switch (choice) {
      NodeChoice.unselected => (
        'No introduction selected',
        'No saved introduction choice.',
      ),
      NodeChoice.pending => (
        'Acceptance pending',
        'Saved proposal; no saved acceptance.',
      ),
      NodeChoice.completed => (
        'Acceptance saved',
        'Node reports verified acceptance.',
      ),
    };
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(title, style: theme.textTheme.titleLarge),
        const SizedBox(height: 8),
        Text(explanation),
        const SizedBox(height: 12),
        Text(
          choice.name,
          style: theme.textTheme.labelLarge?.copyWith(
            color: theme.colorScheme.onSurfaceVariant,
          ),
        ),
        const SizedBox(height: 16),
        const Text('Observed on this read. Read again to refresh.'),
      ],
    );
  }

  Widget _checkResult(ThemeData theme) {
    if (_checking) {
      return const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Checking introduction…'),
          SizedBox(height: 16),
          LinearProgressIndicator(semanticsLabel: 'Checking introduction'),
        ],
      );
    }
    final failure = _checkFailure;
    if (failure != null) {
      return Text(
        failure.message,
        style: TextStyle(color: theme.colorScheme.error),
      );
    }
    final checked = _checked;
    if (checked == null) return const SizedBox.shrink();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Path and acceptance verified', style: theme.textTheme.titleLarge),
        const SizedBox(height: 12),
        const Text('Subject public key'),
        SelectableText(checked.subjectPublicKeyHex),
        if (checked.isSelf) ...[
          const SizedBox(height: 12),
          const Text('This is your own introduction.'),
        ],
        const SizedBox(height: 12),
        const Text(
          "Checked against this node's configured Root. No connection created.",
        ),
      ],
    );
  }
}
