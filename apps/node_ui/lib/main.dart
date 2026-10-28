import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'publication_section.dart';
import 'received_ad_section.dart';
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

typedef SaveIntroduction = Future<IntroductionSave> Function(
  String url,
  String headerPath,
  String document,
);
typedef ListIntroductions = Future<List<IntroductionCheck>> Function(
  String url,
  String headerPath,
);
typedef FetchIntroduction = Future<IntroductionSave> Function(
  String url,
  String headerPath,
  String peerUrl,
);
typedef VerifyReceived = Future<IntroductionVerification> Function(
  String url,
  String headerPath,
);

typedef BootstrapDevice = Future<DeviceAuthorization> Function(
  String url,
  String headerPath,
);
typedef PublishAd = Future<AdPublication> Function(
  String url,
  String headerPath,
);
typedef FetchPeerAd = Future<AdFetchReceipt> Function(
  String url,
  String headerPath,
  String peerUrl,
);
typedef VerifyPeerAd = Future<AdVerificationReceipt> Function(
  String url,
  String headerPath,
  String subjectPublicKeyHex,
);

class IntroTreeApp extends StatelessWidget {
  const IntroTreeApp({
    super.key,
    this.readStatus,
    this.readIntroduction,
    this.checkIntroduction,
    this.saveIntroduction,
    this.listIntroductions,
    this.fetchIntroduction,
    this.verifyReceived,
    this.bootstrapDevice,
    this.publishAd,
    this.fetchPeerAd,
    this.verifyPeerAd,
  });

  final ReadStatus? readStatus;
  final ReadIntroduction? readIntroduction;
  final CheckIntroduction? checkIntroduction;
  final SaveIntroduction? saveIntroduction;
  final ListIntroductions? listIntroductions;
  final FetchIntroduction? fetchIntroduction;
  final VerifyReceived? verifyReceived;
  final BootstrapDevice? bootstrapDevice;
  final PublishAd? publishAd;
  final FetchPeerAd? fetchPeerAd;
  final VerifyPeerAd? verifyPeerAd;

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
      saveIntroduction: saveIntroduction,
      listIntroductions: listIntroductions,
      fetchIntroduction: fetchIntroduction,
      verifyReceived: verifyReceived,
      bootstrapDevice: bootstrapDevice,
      publishAd: publishAd,
      fetchPeerAd: fetchPeerAd,
      verifyPeerAd: verifyPeerAd,
    ),
  );
}

class StatusScreen extends StatefulWidget {
  const StatusScreen({
    super.key,
    this.readStatus,
    this.readIntroduction,
    this.checkIntroduction,
    this.saveIntroduction,
    this.listIntroductions,
    this.fetchIntroduction,
    this.verifyReceived,
    this.bootstrapDevice,
    this.publishAd,
    this.fetchPeerAd,
    this.verifyPeerAd,
  });

  final ReadStatus? readStatus;
  final ReadIntroduction? readIntroduction;
  final CheckIntroduction? checkIntroduction;
  final SaveIntroduction? saveIntroduction;
  final ListIntroductions? listIntroductions;
  final FetchIntroduction? fetchIntroduction;
  final VerifyReceived? verifyReceived;
  final BootstrapDevice? bootstrapDevice;
  final PublishAd? publishAd;
  final FetchPeerAd? fetchPeerAd;
  final VerifyPeerAd? verifyPeerAd;

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen> {
  final _url = TextEditingController();
  final _headerPath = TextEditingController();
  final _introduction = TextEditingController();
  final _peerUrl = TextEditingController();
  final _client = StatusClient();
  bool _loading = false;
  bool _copying = false;
  bool _copied = false;
  bool _checking = false;
  bool _saving = false;
  bool _listing = false;
  bool _fetching = false;
  bool _verifying = false;
  bool _authorizing = false;
  bool _publishing = false;
  bool _fetchingAd = false;
  bool _verifyingAd = false;
  AdFetchReceipt? _fetchedAd;
  AdVerificationReceipt? _verifiedAd;
  StatusFailure? _adFetchFailure;
  StatusFailure? _adVerifyFailure;
  int _adRevision = 0;
  DeviceAuthorization? _authorized;
  StatusFailure? _authorizationFailure;
  AdPublication? _published;
  StatusFailure? _publicationFailure;
  IntroductionVerification? _verified;
  StatusFailure? _verifyFailure;
  int _verifyRevision = 0;
  IntroductionSave? _fetched;
  StatusFailure? _fetchFailure;
  int _fetchRevision = 0;
  IntroductionSave? _saved;
  StatusFailure? _saveFailure;
  List<IntroductionCheck>? _introductions;
  StatusFailure? _listFailure;
  IntroductionCheck? _checked;
  StatusFailure? _checkFailure;
  int _checkRevision = 0;
  NodeChoice? _choice;
  StatusFailure? _failure;
  int _inputRevision = 0;

  void _inputChanged(String _) {
    setState(() {
      _inputRevision++;
      _authorized = null;
      _authorizationFailure = null;
      _published = null;
      _publicationFailure = null;
      _introductions = null;
      _listFailure = null;
      _choice = null;
      _failure = null;
      _copied = false;
      _invalidateCheck();
      _invalidateFetch();
      _invalidateVerification();
      _invalidateAdFetch();
    });
  }

  void _invalidateCheck() {
    _checkRevision++;
    _saved = null;
    _saveFailure = null;
    _checked = null;
    _checkFailure = null;
  }

  void _invalidateFetch() {
    _fetchRevision++;
    _fetched = null;
    _fetchFailure = null;
  }

  void _invalidateVerification() {
    _verifyRevision++;
    _verified = null;
    _verifyFailure = null;
  }

  void _invalidateAdFetch() {
    _fetchedAd = null;
    _adFetchFailure = null;
    _invalidateAdVerification();
  }

  void _invalidateAdVerification() {
    _adRevision++;
    _verifiedAd = null;
    _adVerifyFailure = null;
  }

  Future<void> _fetchAd() async {
    if (_loading) return;
    setState(() {
      _invalidateAdFetch();
      _invalidateVerification();
      // The introduction transaction can commit before the ad save fails.
      _introductions = null;
      _listFailure = null;
      _loading = true;
      _fetchingAd = true;
    });
    final revision = _adRevision;
    AdFetchReceipt? receipt;
    StatusFailure? failure;
    try {
      receipt = await (widget.fetchPeerAd ?? _client.fetchPeerAd)(
        _url.text,
        _headerPath.text,
        _peerUrl.text,
      );
    } on StatusFailure catch (error) {
      failure = error;
    } catch (_) {
      failure = StatusFailure.adFetchUnknown;
    }
    if (!mounted) return;
    setState(() {
      _loading = false;
      _fetchingAd = false;
      if (revision == _adRevision) {
        _fetchedAd = receipt;
        _adFetchFailure = failure;
      }
    });
  }

  Future<void> _verifyAd() async {
    final subject = _fetchedAd?.subjectPublicKeyHex;
    if (_loading || subject == null) return;
    setState(() {
      _invalidateAdVerification();
      _loading = true;
      _verifyingAd = true;
    });
    final revision = _adRevision;
    AdVerificationReceipt? receipt;
    StatusFailure? failure;
    try {
      final result = await (widget.verifyPeerAd ?? _client.verifyPeerAd)(
        _url.text,
        _headerPath.text,
        subject,
      );
      if (!result.verified || result.subjectPublicKeyHex != subject) {
        throw StatusFailure.adVerifyInvalidResponse;
      }
      receipt = result;
    } on StatusFailure catch (error) {
      failure = error;
    } catch (_) {
      failure = StatusFailure.adVerifyUnknown;
    }
    if (!mounted) return;
    setState(() {
      _loading = false;
      _verifyingAd = false;
      if (revision == _adRevision) {
        _verifiedAd = receipt;
        _adVerifyFailure = failure;
      }
    });
  }

  Future<void> _authorize() async {
    if (_loading) return;
    final revision = _inputRevision;
    setState(() {
      _loading = true;
      _authorizing = true;
      _authorized = null;
      _authorizationFailure = null;
    });
    DeviceAuthorization? authorized;
    StatusFailure? failure;
    try {
      authorized = await (widget.bootstrapDevice ?? _client.bootstrapDevice)(
        _url.text,
        _headerPath.text,
      );
    } on StatusFailure catch (error) {
      failure = error;
    } catch (_) {
      failure = StatusFailure.bootstrapUnknown;
    }
    if (!mounted) return;
    setState(() {
      _loading = false;
      _authorizing = false;
      if (revision == _inputRevision) {
        _authorized = authorized;
        _authorizationFailure = failure;
      }
    });
  }

  Future<void> _publish() async {
    if (_loading) return;
    final revision = _inputRevision;
    setState(() {
      _loading = true;
      _publishing = true;
      _published = null;
      _publicationFailure = null;
    });
    AdPublication? published;
    StatusFailure? failure;
    try {
      published = await (widget.publishAd ?? _client.publishAd)(
        _url.text,
        _headerPath.text,
      );
    } on StatusFailure catch (error) {
      failure = error;
    } catch (_) {
      failure = StatusFailure.publishUnknown;
    }
    if (!mounted) return;
    setState(() {
      _loading = false;
      _publishing = false;
      if (revision == _inputRevision) {
        _published = published;
        _publicationFailure = failure;
      }
    });
  }

  Future<void> _verify() async {
    if (_loading) return;
    setState(() {
      _invalidateVerification();
      _loading = true;
      _verifying = true;
    });
    final revision = _verifyRevision;
    IntroductionVerification? verified;
    StatusFailure? failure;
    try {
      verified = await (widget.verifyReceived ?? _client.verifyReceived)(
        _url.text,
        _headerPath.text,
      );
    } on StatusFailure catch (error) {
      failure = error;
    } catch (_) {
      failure = StatusFailure.verifyUnknown;
    }
    if (!mounted) return;
    setState(() {
      _loading = false;
      _verifying = false;
      if (revision == _verifyRevision) {
        _verified = verified;
        _verifyFailure = failure;
      }
    });
  }

  Future<void> _fetch() async {
    if (_loading) return;
    setState(() {
      _invalidateFetch();
      _invalidateVerification();
      _loading = true;
      _fetching = true;
      // Even an unknown outcome may have changed the saved collection.
      _introductions = null;
      _listFailure = null;
    });
    final revision = _fetchRevision;
    IntroductionSave? fetched;
    StatusFailure? failure;
    try {
      fetched = await (widget.fetchIntroduction ?? _client.fetchIntroduction)(
        _url.text,
        _headerPath.text,
        _peerUrl.text,
      );
    } on StatusFailure catch (error) {
      failure = error;
    } catch (_) {
      failure = StatusFailure.fetchUnknown;
    }
    if (!mounted) return;
    setState(() {
      _loading = false;
      _fetching = false;
      if (revision == _fetchRevision) {
        _fetched = fetched;
        _fetchFailure = failure;
      }
    });
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

  Future<void> _save() async {
    if (_loading || _checked == null) return;
    final revision = _checkRevision;
    setState(() {
      _invalidateVerification();
      _loading = true;
      _saving = true;
      _saved = null;
      _saveFailure = null;
      // Even a lost response can follow a committed save. Require an explicit
      // load to show a current list, including when inputs change mid-request.
      _introductions = null;
      _listFailure = null;
    });
    IntroductionSave? saved;
    StatusFailure? failure;
    try {
      saved = await (widget.saveIntroduction ?? _client.saveIntroduction)(
        _url.text,
        _headerPath.text,
        _introduction.text,
      );
    } on StatusFailure catch (error) {
      failure = error;
    } catch (_) {
      failure = StatusFailure.saveUnreachable;
    }
    if (!mounted) return;
    setState(() {
      _loading = false;
      _saving = false;
      if (revision == _checkRevision) {
        _saved = saved;
        _saveFailure = failure;
      }
    });
  }

  Future<void> _loadIntroductions() async {
    if (_loading) return;
    final revision = _inputRevision;
    setState(() {
      _loading = true;
      _listing = true;
      _introductions = null;
      _listFailure = null;
    });
    List<IntroductionCheck>? introductions;
    StatusFailure? failure;
    try {
      introductions =
          await (widget.listIntroductions ?? _client.listIntroductions)(
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
      _listing = false;
      if (revision == _inputRevision) {
        _introductions = introductions;
        _listFailure = failure;
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
    _peerUrl.dispose();
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
                  const SizedBox(height: 32),
                  const Divider(),
                  const SizedBox(height: 16),
                  Text(
                    'Saved introductions',
                    style: theme.textTheme.headlineSmall,
                  ),
                  const SizedBox(height: 12),
                  const Text('Saved evidence; no connection or trust created.'),
                  const SizedBox(height: 16),
                  TextField(
                    controller: _peerUrl,
                    onChanged: (_) => setState(() {
                      _invalidateFetch();
                      _invalidateAdFetch();
                    }),
                    autocorrect: false,
                    enableSuggestions: false,
                    decoration: const InputDecoration(
                      labelText: 'Peer introduction URL',
                      hintText: 'Paste the other node’s peer introduction URL',
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Printed by the other node’s tdc node serve --peer-listen …. '
                    'This is not your local owner status URL or a credential.',
                  ),
                  const SizedBox(height: 16),
                  Align(
                    alignment: Alignment.centerLeft,
                    child: FilledButton(
                      onPressed: _loading ? null : _fetch,
                      child: const Text('Fetch introduction'),
                    ),
                  ),
                  const SizedBox(height: 16),
                  Semantics(liveRegion: true, child: _fetchResult(theme)),
                  const SizedBox(height: 16),
                  Wrap(
                    spacing: 12,
                    runSpacing: 12,
                    children: [
                      OutlinedButton(
                        onPressed: _loading ? null : _loadIntroductions,
                        child: const Text('Load saved introductions'),
                      ),
                      FilledButton(
                        onPressed: _loading ? null : _verify,
                        child: const Text('Verify received introductions'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  Semantics(liveRegion: true, child: _verifyResult(theme)),
                  const SizedBox(height: 16),
                  Semantics(liveRegion: true, child: _listResult(theme)),
                  const SizedBox(height: 24),
                  ReceivedAdSection(
                    fetching: _fetchingAd,
                    verifying: _verifyingAd,
                    fetched: _fetchedAd,
                    verified: _verifiedAd,
                    fetchFailure: _adFetchFailure,
                    verifyFailure: _adVerifyFailure,
                    onFetch: _loading ? null : _fetchAd,
                    onVerify: _loading ? null : _verifyAd,
                  ),
                  const SizedBox(height: 32),
                  const Divider(),
                  const SizedBox(height: 16),
                  PublicationSection(
                    authorizing: _authorizing,
                    publishing: _publishing,
                    authorized: _authorized,
                    published: _published,
                    authorizationFailure: _authorizationFailure,
                    publicationFailure: _publicationFailure,
                    onAuthorize: _loading ? null : _authorize,
                    onPublish: _loading ? null : _publish,
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
    if (_loading &&
        !_checking &&
        !_saving &&
        !_listing &&
        !_fetching &&
        !_verifying &&
        !_authorizing &&
        !_publishing &&
        !_fetchingAd &&
        !_verifyingAd) {
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
        OutlinedButton(
          onPressed: _loading ? null : _save,
          child: const Text('Save introduction'),
        ),
        if (_saving) const Text('Saving introduction…'),
        if (_saveFailure != null)
          Text(
            _saveFailure!.message,
            style: TextStyle(color: theme.colorScheme.error),
          ),
        if (_saved != null) ...[
          Text(_saved!.created ? 'Introduction saved' : 'Already saved'),
          const Text('Load saved introductions refreshes the list.'),
        ],
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

  Widget _fetchResult(ThemeData theme) {
    if (_fetching) {
      return const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Fetching introduction…'),
          SizedBox(height: 12),
          LinearProgressIndicator(semanticsLabel: 'Fetching introduction'),
        ],
      );
    }
    final failure = _fetchFailure;
    if (failure != null) {
      return Text(
        failure.message,
        style: TextStyle(color: theme.colorScheme.error),
      );
    }
    final fetched = _fetched;
    if (fetched == null) return const SizedBox.shrink();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          fetched.created ? 'Introduction received' : 'Already received',
          style: theme.textTheme.titleLarge,
        ),
        const SizedBox(height: 12),
        const Text('Subject public key'),
        SelectableText(fetched.subjectPublicKeyHex),
        const SizedBox(height: 12),
        const Text('Received evidence; no connection or trust created.'),
      ],
    );
  }

  Widget _verifyResult(ThemeData theme) {
    if (_verifying) {
      return const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Verifying received introductions…'),
          SizedBox(height: 12),
          LinearProgressIndicator(
            semanticsLabel: 'Verifying received introductions',
          ),
        ],
      );
    }
    final failure = _verifyFailure;
    if (failure != null) {
      return Text(
        failure.message,
        style: TextStyle(color: theme.colorScheme.error),
      );
    }
    final verified = _verified;
    if (verified == null) return const SizedBox.shrink();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          verified.newlyKnown > 0
              ? '${verified.newlyKnown} newly verified'
              : verified.knownSubjects.isEmpty
              ? 'No received introductions verified'
              : 'No new introductions verified',
          style: theme.textTheme.titleLarge,
        ),
        if (verified.knownSubjects.isNotEmpty) ...[
          const SizedBox(height: 12),
          const Text('Locally known subject public keys'),
          for (final subject in verified.knownSubjects) SelectableText(subject),
        ],
        const SizedBox(height: 12),
        const Text(
          'Locally verified evidence; no connection or trust created.',
        ),
      ],
    );
  }

  Widget _listResult(ThemeData theme) {
    if (_listing) {
      return const Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Loading saved introductions…'),
          SizedBox(height: 12),
          LinearProgressIndicator(
            semanticsLabel: 'Loading saved introductions',
          ),
        ],
      );
    }
    if (_listFailure != null) {
      return Text(
        _listFailure!.message,
        style: TextStyle(color: theme.colorScheme.error),
      );
    }
    final introductions = _introductions;
    if (introductions == null) {
      return const Text('Saved introductions not loaded.');
    }
    if (introductions.isEmpty) return const Text('No saved introductions.');
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final introduction in introductions)
          Padding(
            padding: const EdgeInsets.only(bottom: 16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                SelectableText(introduction.subjectPublicKeyHex),
                if (introduction.isSelf) const Text('Your own introduction'),
              ],
            ),
          ),
      ],
    );
  }
}
