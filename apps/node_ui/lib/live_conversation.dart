import 'dart:async';

import 'package:flutter/foundation.dart';

import 'demo_config.dart';
import 'status_client.dart';

/// One window's transient submission, never an outgoing-history projection.
/// The owner screen retains this across conversation navigation, and discards
/// it on configuration edits or window disposal. Construction performs no I/O.
class LiveConversation extends ChangeNotifier {
  LiveConversation({required this.config, this.createClient});

  final DemoConfig config;
  final StatusClient Function()? createClient;
  String get counterpart => config.role == 'alice' ? 'bob' : 'alice';

  Timer? _timer;
  StatusClient? _reader;
  StatusClient? _sender;
  int _generation = 0;
  bool _disposed = false;
  bool _active = false;
  bool _reading = false;
  bool _sending = false;
  bool _acknowledged = false;
  bool _outcomeUnknown = false;
  String? _submittedText;
  StatusFailure? _sendFailure;
  StatusFailure? _inboxFailure;
  // Last validated local read, retained independently of refresh availability.
  MessageInbox? _inbox;
  bool _inboxFresh = false;

  bool get active => _active;
  bool get sending => _sending;
  bool get acknowledged => _acknowledged;
  bool get outcomeUnknown => _outcomeUnknown && !_acknowledged;
  String? get submittedText => _submittedText;
  StatusFailure? get sendFailure => _sendFailure;
  StatusFailure? get inboxFailure => _inboxFailure;
  MessageInbox? get inbox => _inbox;
  bool get inboxFresh => _inboxFresh;

  void setActive(bool value) {
    if (_disposed || value == _active) return;
    _active = value;
    _generation++;
    _timer?.cancel();
    _inboxFresh = false;
    _inboxFailure = null;
    if (!value) {
      _reader?.close();
      _sender?.close();
      if (_sending) {
        _sendFailure = StatusFailure.messageUnknown;
        _outcomeUnknown = true;
      }
    }
    notifyListeners();
    if (value) unawaited(_poll());
  }

  bool _current(int generation) =>
      !_disposed && _active && generation == _generation;

  Future<void> _poll() async {
    if (_disposed || !_active || _reading) return;
    final generation = _generation;
    _reading = true;
    StatusClient? client;
    try {
      client = _reader = createClient?.call() ?? StatusClient();
      final result = await client.readMessageInboxV2(
        config.ownerStatusUrl,
        config.ownerHeaderFile,
      );
      if (!_current(generation)) return;
      // There is exactly one immutable inbox slot. Repeated reads of its ID
      // render the same bubble; conflicting history is never an empty inbox.
      if (_inbox case final previous? when previous.present) {
        if (result.messageIdHex != previous.messageIdHex ||
            result.text != previous.text) {
          throw StatusFailure.inboxInvalidResponse;
        }
      }
      _inbox = result;
      _inboxFresh = true;
      _inboxFailure = null;
    } catch (error) {
      if (_current(generation)) {
        _inboxFresh = false;
        _inboxFailure = error is StatusFailure
            ? error
            : StatusFailure.inboxFailed;
      }
    } finally {
      client?.close();
      _reader = null;
      _reading = false;
      if (!_disposed && _active) {
        notifyListeners();
        // Schedule only after completion, including after a cancelled read
        // finally settles. Even a transport that completes late cannot overlap
        // the next read. Slow reads naturally reduce the polling frequency.
        _timer = Timer(const Duration(seconds: 1), () => unawaited(_poll()));
      }
    }
  }

  Future<void> send(String text) async {
    if (_disposed || !_active || _sending || _acknowledged) return;
    if (_submittedText != null && text != _submittedText) {
      _sendFailure = StatusFailure.messageRetryText;
      notifyListeners();
      return;
    }
    final generation = _generation;
    final retry = _submittedText != null;
    _submittedText = text;
    _sending = true;
    _sendFailure = null;
    notifyListeners();
    StatusClient? client;
    var invoked = false;
    try {
      client = _sender = createClient?.call() ?? StatusClient();
      invoked = true;
      await client.sendMessageV2(
        config.ownerStatusUrl,
        config.ownerHeaderFile,
        text,
      );
      if (_current(generation)) _acknowledged = true;
    } catch (error) {
      if (_current(generation)) {
        final failure = error is StatusFailure
            ? error
            : invoked
            ? StatusFailure.messageUnknown
            : StatusFailure.messageNotSent;
        _sendFailure = failure;
        if (failure == StatusFailure.messageUnknown) _outcomeUnknown = true;
        // A failed retry never releases an earlier immutable submission.
        // Only definitive pre-dispatch failures of the first try allow edits.
        if (!retry &&
            const {
              StatusFailure.messageInput,
              StatusFailure.messageRequestTooLarge,
              StatusFailure.messageOwnerUrl,
              StatusFailure.messageCredentials,
              StatusFailure.messageNotSent,
              StatusFailure.messageUnavailable,
            }.contains(failure)) {
          _submittedText = null;
        }
      }
    } finally {
      client?.close();
      _sender = null;
      _sending = false;
      if (!_disposed) notifyListeners();
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _active = false;
    _generation++;
    _timer?.cancel();
    _reader?.close();
    _sender?.close();
    super.dispose();
  }
}
