import 'package:flutter/material.dart';

import 'status_client.dart';

/// Presentation only; the screen owns requests, busy state and input revisions.
class PublicationSection extends StatelessWidget {
  const PublicationSection({
    super.key,
    required this.authorizing,
    required this.publishing,
    required this.authorized,
    required this.published,
    required this.authorizationFailure,
    required this.publicationFailure,
    required this.onAuthorize,
    required this.onPublish,
  });

  final bool authorizing;
  final bool publishing;
  final DeviceAuthorization? authorized;
  final AdPublication? published;
  final StatusFailure? authorizationFailure;
  final StatusFailure? publicationFailure;
  final VoidCallback? onAuthorize;
  final VoidCallback? onPublish;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final receipt = published;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text('My node publication', style: theme.textTheme.headlineSmall),
        const SizedBox(height: 12),
        const Text(
          "These actions use the node's saved software signer. "
          'Save your own introduction and explicitly verify it using the '
          'introduction workflow above. Publication also requires '
          'node serve --peer-listen.',
        ),
        const SizedBox(height: 12),
        const Text(
          'Authorization is saved on the node across restarts. You can publish '
          'if it was already authorized before opening this UI.',
        ),
        const SizedBox(height: 16),
        Wrap(
          spacing: 12,
          runSpacing: 12,
          children: [
            OutlinedButton(
              onPressed: onAuthorize,
              child: const Text('Authorize local device'),
            ),
            FilledButton(
              onPressed: onPublish,
              child: const Text('Publish advertisement'),
            ),
          ],
        ),
        const SizedBox(height: 16),
        Semantics(
          liveRegion: true,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (authorizing) ...[
                const Text('Authorizing local device…'),
                const SizedBox(height: 12),
                const LinearProgressIndicator(
                  semanticsLabel: 'Authorizing local device',
                ),
              ],
              if (authorizationFailure != null)
                Text(
                  authorizationFailure!.message,
                  style: TextStyle(color: theme.colorScheme.error),
                ),
              if (authorized != null) ...[
                Text(
                  'Local device authorized',
                  style: theme.textTheme.titleLarge,
                ),
                const Text('Signer usability was checked during that request.'),
              ],
              if (publishing) ...[
                const Text('Publishing advertisement…'),
                const SizedBox(height: 12),
                const LinearProgressIndicator(
                  semanticsLabel: 'Publishing advertisement',
                ),
              ],
              if (publicationFailure != null)
                Text(
                  publicationFailure!.message,
                  style: TextStyle(color: theme.colorScheme.error),
                ),
              if (receipt != null) ...[
                const SizedBox(height: 12),
                Text(
                  'Advertisement published',
                  style: theme.textTheme.titleLarge,
                ),
                const SizedBox(height: 12),
                const Text('Advertised introduction URL'),
                SelectableText(receipt.peerIntroductionUrl),
                const SizedBox(height: 12),
                const Text('Expires (UTC)'),
                Text(
                  DateTime.fromMicrosecondsSinceEpoch(
                    receipt.expiresUnixNano ~/ 1000,
                    isUtc: true,
                  ).toIso8601String(),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 12),
        const Text(
          'Publication announces an address; it is not a connection or trust. '
          'These receipts are not a current-state poll. A subsequent '
          'publication replaces the previous advertisement. '
          'Closing the UI does not undo a committed operation.',
        ),
      ],
    );
  }
}
