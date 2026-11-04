import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'pairing_types.dart';
import 'status_client.dart';

/// Configuration is a transient snapshot from this window's owner screen.
/// Fixture identity never enters this route or chooses credentials.
class LivePairingScreen extends StatefulWidget {
  const LivePairingScreen({
    super.key,
    required this.ownerStatusUrl,
    required this.headerPath,
    this.createClient,
  });

  final String ownerStatusUrl;
  final String headerPath;
  final StatusClient Function()? createClient;

  @override
  State<LivePairingScreen> createState() => _LivePairingScreenState();
}

class _LivePairingScreenState extends State<LivePairingScreen> {
  final _recipient = TextEditingController();
  final _bobKey = TextEditingController();
  final _document = TextEditingController();
  StatusClient? _issueClient;
  StatusClient? _redeemClient;
  DirectedInvitationReceipt? _issued;
  RedemptionReceipt? _redeemed;
  String? _issueMessage;
  String? _redeemMessage;
  String? _copyMessage;
  int _issueRevision = 0;
  int _redeemRevision = 0;
  int _copyRevision = 0;
  bool _issuing = false;
  bool _redeeming = false;
  bool _copying = false;
  bool _closed = false;

  bool get _configured =>
      widget.ownerStatusUrl.trim().isNotEmpty &&
      widget.headerPath.trim().isNotEmpty;
  bool get _pending => _issuing || _redeeming;

  void _invalidateIssue() {
    _issueRevision++;
    _copyRevision++;
    _issued = null;
    _issueMessage = null;
    _copyMessage = null;
    _issueClient?.close();
  }

  void _invalidateRedeem() {
    _redeemRevision++;
    _redeemed = null;
    _redeemMessage = null;
    _redeemClient?.close();
  }

  @override
  void didUpdateWidget(covariant LivePairingScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.ownerStatusUrl != oldWidget.ownerStatusUrl ||
        widget.headerPath != oldWidget.headerPath ||
        widget.createClient != oldWidget.createClient) {
      _invalidateIssue();
      _invalidateRedeem();
    }
  }

  bool _currentIssue(int revision) =>
      mounted && !_closed && revision == _issueRevision;
  bool _currentRedeem(int revision) =>
      mounted && !_closed && revision == _redeemRevision;

  Future<void> _issue() async {
    if (_pending || !_configured || _closed) return;
    setState(() {
      _invalidateIssue();
      _issuing = true;
    });
    final revision = _issueRevision;
    try {
      final client = _issueClient =
          widget.createClient?.call() ?? StatusClient();
      final receipt = await client.issueDirectedInvitation(
        widget.ownerStatusUrl,
        widget.headerPath,
        _recipient.text,
      );
      if (_currentIssue(revision)) setState(() => _issued = receipt);
    } catch (error) {
      if (_currentIssue(revision)) {
        setState(() {
          _issueMessage =
              (error is StatusFailure ? error : StatusFailure.issueUnknown)
                  .message;
        });
      }
    } finally {
      _issueClient?.close();
      _issueClient = null;
      if (mounted && !_closed) setState(() => _issuing = false);
    }
  }

  Future<void> _redeem() async {
    if (_pending || !_configured || _closed) return;
    setState(() {
      _invalidateRedeem();
      _redeeming = true;
    });
    final revision = _redeemRevision;
    try {
      final DirectedRedemption input;
      try {
        input = DirectedRedemption.parse(_document.text);
      } on FormatException {
        throw StatusFailure.redeemInput;
      }
      final client = _redeemClient =
          widget.createClient?.call() ?? StatusClient();
      final receipt = await client.redeemInvitation(
        widget.ownerStatusUrl,
        widget.headerPath,
        input,
      );
      if (_currentRedeem(revision)) setState(() => _redeemed = receipt);
    } catch (error) {
      if (_currentRedeem(revision)) {
        setState(() {
          _redeemMessage =
              (error is StatusFailure ? error : StatusFailure.redeemUnknown)
                  .message;
        });
      }
    } finally {
      _redeemClient?.close();
      _redeemClient = null;
      if (mounted && !_closed) setState(() => _redeeming = false);
    }
  }

  Future<void> _copy() async {
    final receipt = _issued;
    if (receipt == null ||
        !pairingPublicKeyHex(_bobKey.text) ||
        _copying ||
        _closed) {
      return;
    }
    final revision = _copyRevision;
    final payload = DirectedRedemption(
      targetPublicKeyHex: _bobKey.text,
      invitationIdHex: receipt.invitationIdHex,
    ).toJson();
    setState(() {
      _copying = true;
      _copyMessage = null;
    });
    String message;
    try {
      await Clipboard.setData(ClipboardData(text: payload));
      message = 'Manual redeem JSON copied';
    } catch (_) {
      message = 'Could not copy the manual redeem JSON.';
    }
    if (mounted && !_closed) {
      setState(() {
        _copying = false;
        if (revision == _copyRevision) _copyMessage = message;
      });
    }
  }

  void _abandon() {
    _closed = true;
    _invalidateIssue();
    _invalidateRedeem();
  }

  @override
  void dispose() {
    _abandon();
    _recipient.dispose();
    _bobKey.dispose();
    _document.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final issued = _issued;
    final redeemed = _redeemed;
    final theme = Theme.of(context);
    return PopScope<void>(
      onPopInvokedWithResult: (didPop, _) {
        if (didPop) _abandon();
      },
      child: Scaffold(
        appBar: AppBar(title: const Text('Live pairing')),
        body: SafeArea(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(20),
            child: Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 760),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      'LIVE LOCAL OWNER ACTIONS',
                      style: theme.textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Use two separate windows: Bob’s owner configuration to '
                      'issue, Alice’s own configuration to redeem. Fixture '
                      'selection does not identify the owner or select a signer.',
                    ),
                    const SizedBox(height: 12),
                    if (_configured) ...[
                      const Text('This window’s owner status URL'),
                      SelectableText(widget.ownerStatusUrl),
                    ] else
                      const Text(
                        'Set the owner status URL and owner.header path on the '
                        'owner screen, then reopen Live pairing. Submissions '
                        'are disabled until both are set.',
                      ),
                    const SizedBox(height: 12),
                    const Text(
                      'SCRIPTED GRAPH AND CHAT remain fixtures. These actions '
                      'do not update graph edges, readiness, trust or messages.',
                    ),
                    const Divider(height: 32),
                    Text(
                      '1. Issue directed invitation (Bob window)',
                      style: theme.textTheme.titleLarge,
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'Only one invitation row may ever exist per Bob Vault, '
                      'even after expiry, revocation or consumption. A second '
                      'issue is refused. The server sets a 15-minute lifetime.',
                    ),
                    const SizedBox(height: 16),
                    _field(
                      'pairing-recipient',
                      _recipient,
                      'Alice’s full real public key hex',
                      (_) => setState(_invalidateIssue),
                    ),
                    const SizedBox(height: 12),
                    FilledButton(
                      key: const ValueKey('issue-invitation'),
                      onPressed: _configured && !_pending ? _issue : null,
                      child: Text(_issuing ? 'Issuing…' : 'Issue invitation'),
                    ),
                    if (_issueMessage != null) _message(_issueMessage!),
                    if (issued != null) ...[
                      _message('Invitation issued · committed receipt'),
                      const Text(
                        'Invitation ID · sensitive eligibility material',
                      ),
                      SelectableText(
                        issued.invitationIdHex,
                        key: const ValueKey('issued-id'),
                      ),
                      const Text('Audience: Directed'),
                      const Text('Recipient public key'),
                      SelectableText(issued.recipientPublicKeyHex),
                      Text('UTC expiry: ${issued.expiryUtc}'),
                    ],
                    const SizedBox(height: 16),
                    _field(
                      'pairing-bob-key',
                      _bobKey,
                      'Bob’s full real public key hex',
                      (_) => setState(() {
                        _copyRevision++;
                        _copyMessage = null;
                      }),
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Bob’s key is operator-supplied, not confirmed by the '
                      'issue receipt. The manual three-field JSON is a clipboard '
                      'convenience, not a signed invitation wire format. '
                      'Share deliberately: it contains sensitive eligibility '
                      'material. Clipboard history is outside this app’s control.',
                    ),
                    const SizedBox(height: 12),
                    OutlinedButton(
                      key: const ValueKey('copy-redeem-json'),
                      onPressed:
                          issued != null &&
                              pairingPublicKeyHex(_bobKey.text) &&
                              !_copying
                          ? _copy
                          : null,
                      child: const Text('Copy manual redeem JSON'),
                    ),
                    if (_copyMessage != null) _message(_copyMessage!),
                    const Divider(height: 32),
                    Text(
                      '2. Redeem invitation (Alice window)',
                      style: theme.textTheme.titleLarge,
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'Alice must already know Bob and have matching received '
                      'and verified current ad evidence. Bob needs an opt-in '
                      '--peer-listen. Go chooses the endpoint and performs the '
                      'authenticated exchange; Flutter contacts only this '
                      'window’s owner origin.',
                    ),
                    const SizedBox(height: 12),
                    const Text(
                      'Only one saved requester attempt per Alice Vault. '
                      'Conflicting target, invitation or audience is refused. '
                      'Go remains authoritative for signatures, Root, ad '
                      'evidence, eligibility and durable acceptance.',
                    ),
                    const SizedBox(height: 16),
                    _field(
                      'pairing-redeem-json',
                      _document,
                      'Directed redeem JSON',
                      (_) => setState(_invalidateRedeem),
                      lines: 5,
                    ),
                    const SizedBox(height: 12),
                    FilledButton(
                      key: const ValueKey('redeem-invitation'),
                      onPressed: _configured && !_pending ? _redeem : null,
                      child: Text(
                        _redeeming ? 'Redeeming…' : 'Redeem invitation',
                      ),
                    ),
                    if (_redeemMessage != null) _message(_redeemMessage!),
                    if (redeemed != null) ...[
                      _message('Acceptance saved locally'),
                      Text(
                        'Local PW held: ${redeemed.localHeld ? 'yes' : 'no'}',
                        key: const ValueKey('local-held'),
                      ),
                      if (!redeemed.localHeld)
                        const Text(
                          'No local holding; this is not a usable relationship.',
                        ),
                      const Text(
                        'Retained local state only. This confirms no current '
                        'peer permission, shared PWOpen, readiness, Trust, '
                        'authenticated first use or chat.',
                      ),
                    ],
                    const SizedBox(height: 16),
                    const Text(
                      'No automatic retries. A lost or invalid acknowledgement '
                      'does not roll back a commit. You may explicitly repeat '
                      'redemption with the same input under Go’s durable '
                      'exact-attempt rules, subject to current guards; successful '
                      'recovery is not guaranteed. Closing this panel discards '
                      'receipts and does not undo node operations.',
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _message(String text) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 12),
    child: Text(text, semanticsLabel: text),
  );

  Widget _field(
    String key,
    TextEditingController controller,
    String label,
    ValueChanged<String> onChanged, {
    int lines = 2,
  }) => TextField(
    key: ValueKey(key),
    controller: controller,
    onChanged: onChanged,
    minLines: lines,
    maxLines: lines,
    autocorrect: false,
    enableSuggestions: false,
    decoration: InputDecoration(
      labelText: label,
      border: const OutlineInputBorder(),
    ),
  );
}
