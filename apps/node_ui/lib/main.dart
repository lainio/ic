import 'package:flutter/material.dart';

import 'status_client.dart';

void main() => runApp(const IntroTreeApp());

typedef ReadStatus = Future<NodeChoice> Function(String url, String headerPath);

class IntroTreeApp extends StatelessWidget {
  const IntroTreeApp({super.key, this.readStatus});

  final ReadStatus? readStatus;

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
    home: StatusScreen(readStatus: readStatus),
  );
}

class StatusScreen extends StatefulWidget {
  const StatusScreen({super.key, this.readStatus});

  final ReadStatus? readStatus;

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen> {
  final _url = TextEditingController();
  final _headerPath = TextEditingController();
  final _client = StatusClient();
  bool _loading = false;
  NodeChoice? _choice;
  StatusFailure? _failure;
  int _inputRevision = 0;

  void _inputChanged(String _) {
    setState(() {
      _inputRevision++;
      _choice = null;
      _failure = null;
    });
  }

  Future<void> _read() async {
    if (_loading) return;
    final revision = _inputRevision;
    setState(() {
      _loading = true;
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

  @override
  void dispose() {
    _client.close();
    _url.dispose();
    _headerPath.dispose();
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
                  const SizedBox(height: 16),
                  Text(
                    'Local acceptance state; not membership, trust, or delivery confirmation.',
                    style: theme.textTheme.bodyMedium,
                  ),
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
    if (_loading) {
      return const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Reading status…'),
          SizedBox(height: 16),
          LinearProgressIndicator(semanticsLabel: 'Reading status'),
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
}
