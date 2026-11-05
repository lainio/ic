import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:ic_node_ui/demo_config.dart';

String publicKey(String byte) =>
    'a5010203262001215820${List.filled(32, byte).join()}'
    '225820${List.filled(32, '44').join()}';

Map<String, Object?> configJson(String role) => {
  'version': 1,
  'role': role,
  'node_public_key_hex': publicKey(role == 'alice' ? '22' : '33'),
  'owner_status_url':
      'http://127.0.0.1:${role == 'alice' ? 10001 : 10003}/owner/status',
  'owner_header_file': '/private/run/tmp/$role/owner.header',
};

void chmod(String path, String mode) {
  expect(Process.runSync('chmod', [mode, '--', path]).exitCode, 0);
}

class ConfigFiles {
  ConfigFiles() {
    directory = Directory.systemTemp.createTempSync('ui-config-test-');
    chmod(directory.path, '700');
    config = Directory('${directory.path}/config')..createSync();
    chmod(config.path, '700');
  }
  late final Directory directory;
  late final Directory config;

  File write(String role, {String? text, List<int>? bytes}) {
    final file = File('${config.path}/$role.json')
      ..writeAsBytesSync(
        bytes ?? utf8.encode(text ?? jsonEncode(configJson(role))),
      );
    chmod(file.path, '600');
    return file;
  }

  void dispose() => directory.deleteSync(recursive: true);
}

void main() {
  test('no arguments require no config or platform file operations', () {
    expect(DemoConfig.fromArguments([]), isNull);
  });

  test('exact argument form, canonical absolute path only', () {
    for (final args in [
      ['--config'],
      ['--help'],
      ['alice.json'],
      ['--config=/private/alice.json'],
      ['--config', '/private/alice.json', 'extra'],
      ['--config', '/private/alice.json', '--config', '/private/bob.json'],
      ['--config', 'relative.json'],
      ['--config', ''],
      ['--config', '/private/../alice.json'],
      ['--config', '/private/./alice.json'],
      ['--config', '//private/alice.json'],
      ['--config', '/private/alice.json\n'],
      ['--config', '/private/alice.json\u0000'],
    ]) {
      expect(
        () => DemoConfig.fromArguments(args),
        throwsA(StartupFailure.arguments),
        reason: '$args',
      );
    }
  });

  test('both roles preserve their full independent key and owner settings', () {
    final files = ConfigFiles();
    addTearDown(files.dispose);
    for (final role in ['alice', 'bob']) {
      final file = files.write(role);
      final config = DemoConfig.fromArguments(['--config', file.path])!;
      final expected = configJson(role);
      expect(config.role, role);
      expect(config.publicKeyHex, expected['node_public_key_hex']);
      expect(config.ownerStatusUrl, expected['owner_status_url']);
      expect(config.ownerHeaderFile, expected['owner_header_file']);
      // The header does not even exist: startup must not read credentials.
      expect(File(config.ownerHeaderFile).existsSync(), isFalse);
    }
  });

  test('reject exact-field, role, version, key, URL and header violations', () {
    final files = ConfigFiles();
    addTearDown(files.dispose);
    final invalid = <Map<String, Object?>>[
      {...configJson('alice')}..remove('version'),
      {...configJson('alice'), 'token': 'never-display-this'},
      for (final value in [0, 2, 1.0, '1', true, null])
        {...configJson('alice'), 'version': value},
      for (final value in ['Alice', 'carol', '', 1, null])
        {...configJson('alice'), 'role': value},
      for (final value in [
        '',
        'abc',
        'AA',
        'ab\n',
        ' ab',
        '0x22',
        'gg',
        List.filled(257, 'a').join(),
        2,
        null,
      ])
        {...configJson('alice'), 'node_public_key_hex': value},
      for (final value in [
        'http://remote.invalid:42/owner/status',
        'https://127.0.0.1:42/owner/status',
        'http://127.0.0.1/owner/status',
        'http://127.0.0.1:0/owner/status',
        'http://127.0.0.1:65536/owner/status',
        'http://127.0.0.1:42/owner/status?token=x',
        'http://127.0.0.1:42/owner/%73tatus',
        'http://user@127.0.0.1:42/owner/status',
        'http://127.0.0.1:42/owner/status#fragment',
        'http://127.0.0.1:42/owner/status\n',
        null,
        2,
      ])
        {...configJson('alice'), 'owner_status_url': value},
      for (final value in [
        'owner.header',
        '/private/unlock',
        '/private/../owner.header',
        '/private//owner.header',
        '/private/./owner.header',
        '/private/\n/owner.header',
        '/private/\u0000/owner.header',
        null,
        2,
      ])
        {...configJson('alice'), 'owner_header_file': value},
    ];
    for (final value in invalid) {
      final file = files.write('alice', text: jsonEncode(value));
      expect(
        () => DemoConfig.fromArguments(['--config', file.path]),
        throwsA(StartupFailure.config),
        reason: '$value',
      );
    }
  });

  test(
    'malformed, oversized, duplicate and escaped duplicate JSON fail closed',
    () {
      final files = ConfigFiles();
      addTearDown(files.dispose);
      final valid = jsonEncode(configJson('alice'));
      for (final text in [
        '',
        '{}',
        '[]',
        'null',
        '$valid$valid',
        '$valid garbage',
        valid.replaceFirst('{', '{"role":"bob",'),
        valid.replaceFirst('{', r'{"ro\u006ce":"bob",'),
        valid.replaceFirst('{', '{"version":1,'),
        valid.replaceFirst('{', '{"version":1,"version":1,'),
        valid.replaceFirst('"version":1', '"version":{"nested":1}'),
        valid.replaceFirst('"version":1', '"version":NaN'),
        valid.replaceFirst('{', '{/*comment*/'),
        valid.replaceFirst('}', ',}'),
        '$valid\u00a0',
        List.filled(demoConfigLimit + 1, ' ').join(),
        valid.replaceFirst('"alice"', '"${List.filled(3000, '猫').join()}"'),
      ]) {
        final file = files.write('alice', text: text);
        expect(
          () => DemoConfig.fromArguments(['--config', file.path]),
          throwsA(StartupFailure.config),
        );
      }
      final invalidUtf8 = files.write('alice', bytes: [0xff]);
      expect(
        () => DemoConfig.fromArguments(['--config', invalidUtf8.path]),
        throwsA(StartupFailure.config),
      );
      final reordered = Map.fromEntries(
        configJson('alice').entries.toList().reversed,
      );
      expect(DemoConfig.parse(' \n${jsonEncode(reordered)}\r\n').role, 'alice');
    },
  );

  test('unsafe config files are refused without following links or blocking on FIFO', () {
    for (final change in [
      'missing',
      'directory',
      'file mode',
      'execute mode',
      'parent mode',
      'ancestor writable',
      'symlink',
      'ancestor symlink',
      'hardlink',
      'fifo',
    ]) {
      final files = ConfigFiles();
      try {
        final file = files.write('alice');
        var path = file.path;
        switch (change) {
          case 'missing':
            file.deleteSync();
          case 'directory':
            file.deleteSync();
            Directory(path).createSync();
          case 'file mode':
            chmod(path, '644');
          case 'execute mode':
            chmod(path, '700');
          case 'parent mode':
            chmod(files.config.path, '755');
          case 'ancestor writable':
            chmod(files.directory.path, '770');
          case 'symlink':
            final target = files.write('bob');
            file.deleteSync();
            Link(path).createSync(target.path);
          case 'ancestor symlink':
            final link = Link('${files.directory.path}/alias')
              ..createSync(files.config.path);
            path = '${link.path}/alice.json';
          case 'hardlink':
            expect(
              Process.runSync('ln', [
                path,
                '${files.directory.path}/link',
              ]).exitCode,
              0,
            );
          case 'fifo':
            file.deleteSync();
            expect(Process.runSync('mkfifo', ['-m', '600', path]).exitCode, 0);
        }
        expect(
          () => DemoConfig.fromArguments(['--config', path]),
          throwsA(StartupFailure.config),
          reason: change,
        );
      } finally {
        files.dispose();
      }
    }
  });
}
