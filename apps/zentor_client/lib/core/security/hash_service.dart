import 'dart:async';
import 'dart:io';

import 'package:crypto/crypto.dart';

const int maxSelectedHashFileBytes = 512 * 1024 * 1024;

class HashService {
  HashService({
    int maxFileBytes = maxSelectedHashFileBytes,
    FutureOr<void> Function(String path)? afterStatForTesting,
  }) : this._(_requirePositiveHashLimit(maxFileBytes), afterStatForTesting);

  HashService._(this._maxFileBytes, this._afterStatForTesting);

  final int _maxFileBytes;
  final FutureOr<void> Function(String path)? _afterStatForTesting;

  Future<String> sha256ForFile(
    String path, {
    void Function(double progress)? onProgress,
  }) async {
    final file = File(path);
    final entityType = await FileSystemEntity.type(path, followLinks: false);
    if (entityType == FileSystemEntityType.notFound) {
      throw const FileSystemException('Selected file does not exist.');
    }
    if (entityType == FileSystemEntityType.link) {
      throw const FileSystemException(
        'Hashing symbolic links or reparse points is not allowed.',
      );
    }
    if (entityType != FileSystemEntityType.file) {
      throw const FileSystemException(
        'Hashing is limited to a selected file. Folder scanning is not allowed.',
      );
    }

    final stat = await file.stat();
    final total = stat.size;
    if (total > _maxFileBytes) {
      throw const FileSystemException(
        'Selected file exceeds the hash size limit.',
      );
    }
    await _afterStatForTesting?.call(path);
    final typeAfterStat = await FileSystemEntity.type(path, followLinks: false);
    if (typeAfterStat != FileSystemEntityType.file) {
      throw const FileSystemException('Selected file changed before hashing.');
    }
    var read = 0;
    final digestSink = _SingleDigestSink();
    final inputSink = sha256.startChunkedConversion(digestSink);
    final stream = file.openRead();

    await for (final chunk in stream) {
      read += chunk.length;
      if (read > _maxFileBytes) {
        throw const FileSystemException(
          'Selected file exceeds the hash size limit.',
        );
      }
      inputSink.add(chunk);
      if (total > 0) {
        onProgress?.call(read / total);
      }
    }
    inputSink.close();

    onProgress?.call(1);
    return 'sha256:${digestSink.digest}';
  }

  bool get supportsPathHashing =>
      Platform.isWindows || Platform.isLinux || Platform.isMacOS;
}

int _requirePositiveHashLimit(int value) {
  if (value <= 0) {
    throw ArgumentError.value(
      value,
      'maxFileBytes',
      'must be greater than zero',
    );
  }
  return value;
}

class _SingleDigestSink implements Sink<Digest> {
  Digest? _digest;

  Digest get digest {
    final digest = _digest;
    if (digest == null) {
      throw StateError('SHA-256 hashing did not produce a digest.');
    }
    return digest;
  }

  @override
  void add(Digest data) {
    if (_digest != null) {
      throw StateError('SHA-256 hashing produced multiple digests.');
    }
    _digest = data;
  }

  @override
  void close() {}
}
