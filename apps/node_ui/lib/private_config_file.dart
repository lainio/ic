import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

bool canonicalAbsolutePath(String path) =>
    path.startsWith('/') &&
    utf8.decode(utf8.encode(path)) == path &&
    !RegExp(r'[\x00-\x1f\x7f]').hasMatch(path) &&
    path
        .substring(1)
        .split('/')
        .every((part) => part.isNotEmpty && part != '.' && part != '..');

// dart:io does not expose UID, link count or no-follow descriptor opens.
// Use Linux libc directly, without a package, subprocess or runner change.
// statx has a fixed Linux UAPI layout on both x64 and arm64 (linux/stat.h),
// unlike struct stat. Unsupported hosts fail closed when --config is used.
final _libc = DynamicLibrary.process();
final _allocate = _libc
    .lookupFunction<
      Pointer<Uint8> Function(Size, Size),
      Pointer<Uint8> Function(int, int)
    >('calloc');
final _free = _libc
    .lookupFunction<
      Void Function(Pointer<Uint8>),
      void Function(Pointer<Uint8>)
    >('free');
final _openAt = _libc
    .lookupFunction<
      Int Function(Int, Pointer<Uint8>, Int),
      int Function(int, Pointer<Uint8>, int)
    >('openat');
final _close = _libc.lookupFunction<Int Function(Int), int Function(int)>(
  'close',
);
final _read = _libc
    .lookupFunction<
      IntPtr Function(Int, Pointer<Uint8>, Size),
      int Function(int, Pointer<Uint8>, int)
    >('read');
final _uid = _libc.lookupFunction<Uint32 Function(), int Function()>('geteuid');
final _statx = _libc
    .lookupFunction<
      Int Function(Int, Pointer<Uint8>, Int, Uint32, Pointer<Uint8>),
      int Function(int, Pointer<Uint8>, int, int, Pointer<Uint8>)
    >('statx');

Never _unsafe() => throw const FormatException('Unsafe configuration file');

Pointer<Uint8> _buffer(int length) {
  final pointer = _allocate(length, 1);
  if (pointer == nullptr) _unsafe();
  return pointer;
}

int _open(int parent, String name, {required bool directory}) {
  final (noFollow, directoryFlag) = switch (Abi.current()) {
    Abi.linuxX64 => (0x20000, 0x10000),
    Abi.linuxArm64 => (0x8000, 0x4000),
    _ => _unsafe(),
  };
  final bytes = utf8.encode(name);
  final pointer = _buffer(bytes.length + 1);
  try {
    pointer.asTypedList(bytes.length).setAll(0, bytes);
    // O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, plus O_DIRECTORY.
    final descriptor = _openAt(
      parent,
      pointer,
      0x80000 | noFollow | 0x800 | (directory ? directoryFlag : 0),
    );
    if (descriptor < 0) _unsafe();
    return descriptor;
  } finally {
    _free(pointer);
  }
}

({int mode, int uid, int links, int size}) _info(int descriptor) {
  final data = _buffer(256);
  final empty = _buffer(1);
  try {
    // AT_EMPTY_PATH; require TYPE, MODE, NLINK, UID and SIZE from this fd.
    const mask = 0x20f;
    if (_statx(descriptor, empty, 0x1000, mask, data) != 0) _unsafe();
    final bytes = ByteData.sublistView(data.asTypedList(256));
    if (bytes.getUint32(0, Endian.host) & mask != mask) _unsafe();
    return (
      mode: bytes.getUint16(28, Endian.host),
      uid: bytes.getUint32(20, Endian.host),
      links: bytes.getUint32(16, Endian.host),
      size: bytes.getUint64(40, Endian.host),
    );
  } finally {
    _free(empty);
    _free(data);
  }
}

/// Read only this bounded launch snapshot; never read the owner credential.
List<int> readPrivateConfig(String path, int limit) {
  if (!Platform.isLinux || !canonicalAbsolutePath(path)) _unsafe();
  final parts = path.substring(1).split('/');
  var directory = _open(-100, '/', directory: true); // AT_FDCWD
  try {
    final systemUid = _info(directory).uid;
    for (final part in parts.take(parts.length - 1)) {
      final child = _open(directory, part, directory: true);
      _close(directory);
      directory = child;
      final info = _info(directory);
      final stickySystem = info.uid == systemUid && info.mode & 0x200 != 0;
      if ((info.uid != _uid() && info.uid != systemUid) ||
          (info.mode & 0x12 != 0 && !stickySystem)) {
        _unsafe(); // No untrusted writable ancestors (except system /tmp).
      }
    }
    final parent = _info(directory);
    if (parent.uid != _uid() || parent.mode & 0xfff != 0x1c0) _unsafe(); // 0700
    final file = _open(directory, parts.last, directory: false);
    try {
      final before = _info(file);
      if (before.mode != 0x8180 || // Regular file, exactly 0600.
          before.uid != _uid() ||
          before.links != 1 ||
          before.size > limit) {
        _unsafe();
      }
      final buffer = _buffer(limit + 1);
      try {
        var length = 0;
        while (length <= limit) {
          final count = _read(file, buffer + length, limit + 1 - length);
          if (count < 0) _unsafe();
          if (count == 0) break;
          length += count;
        }
        if (length > limit || length != before.size || _info(file) != before) {
          _unsafe();
        }
        return List<int>.of(buffer.asTypedList(length));
      } finally {
        _free(buffer);
      }
    } finally {
      _close(file);
    }
  } finally {
    _close(directory);
  }
}
