import 'package:flutter/material.dart';

import 'status_client.dart';

/// Presentational receiver controls; the screen owns revisions and busy state.
class ReceivedAdSection extends StatelessWidget {
  const ReceivedAdSection({
    super.key,
    required this.fetching,
    required this.verifying,
    required this.fetched,
    required this.verified,
    required this.fetchFailure,
    required this.verifyFailure,
    required this.onFetch,
    required this.onVerify,
  });

  final bool fetching;
  final bool verifying;
  final AdFetchReceipt? fetched;
  final AdVerificationReceipt? verified;
  final StatusFailure? fetchFailure;
  final StatusFailure? verifyFailure;
  final VoidCallback? onFetch;
  final VoidCallback? onVerify;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final receipt = fetched;
    final verification = verified;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Peer advertisement', style: theme.textTheme.titleLarge),
        const SizedBox(height: 8),
        const Text('Uses the Peer introduction URL above.'),
        const SizedBox(height: 12),
        FilledButton(
          onPressed: onFetch,
          child: const Text('Fetch peer advertisement'),
        ),
        const SizedBox(height: 12),
        Semantics(
          liveRegion: true,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (fetching) ...[
                const Text('Fetching peer advertisement…'),
                const SizedBox(height: 12),
                const LinearProgressIndicator(
                  semanticsLabel: 'Fetching peer advertisement',
                ),
              ],
              if (fetchFailure != null)
                Text(
                  fetchFailure!.message,
                  style: TextStyle(color: theme.colorScheme.error),
                ),
              if (receipt != null) ...[
                const Text('Received ad claim, not verified'),
                const SizedBox(height: 8),
                const Text('Subject public key'),
                SelectableText(receipt.subjectPublicKeyHex),
                const SizedBox(height: 8),
                Text(
                  receipt.introductionCreated
                      ? 'Introduction evidence newly saved'
                      : 'Introduction evidence already saved',
                ),
                Text(
                  receipt.adChanged
                      ? 'Untrusted ad claim stored or replaced'
                      : 'Untrusted ad claim unchanged',
                ),
              ],
            ],
          ),
        ),
        if (receipt != null) ...[
          const SizedBox(height: 12),
          const Text(
            'You may need to press Verify received introductions first. '
            'If this subject is already Known on the node, you can verify its ad now.',
          ),
          const SizedBox(height: 12),
          FilledButton(
            onPressed: onVerify,
            child: const Text('Verify advertisement'),
          ),
        ],
        const SizedBox(height: 12),
        Semantics(
          liveRegion: true,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (verifying) ...[
                const Text('Verifying advertisement…'),
                const SizedBox(height: 12),
                const LinearProgressIndicator(
                  semanticsLabel: 'Verifying advertisement',
                ),
              ],
              if (verifyFailure != null)
                Text(
                  verifyFailure!.message,
                  style: TextStyle(color: theme.colorScheme.error),
                ),
              if (verification != null) ...[
                Text(
                  'Advertisement verified in this exchange',
                  style: theme.textTheme.titleLarge,
                ),
                const SizedBox(height: 8),
                const Text('Verified subject public key'),
                SelectableText(verification.subjectPublicKeyHex),
                const SizedBox(height: 8),
                Text(
                  verification.changed
                      ? 'Historical verified snapshot saved'
                      : 'Historical verified snapshot unchanged',
                ),
                const Text(
                  'Validity and reachability are not monitored. '
                  'CreatePW still needs fresh evidence.',
                ),
              ],
            ],
          ),
        ),
      ],
    );
  }
}
