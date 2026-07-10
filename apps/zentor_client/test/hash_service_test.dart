import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zentor_client/core/security/hash_service.dart';

void main() {
  test('HashService hashes a selected file', () async {
    final directory = await Directory.systemTemp.createTemp('zentor_hash_test');
    try {
      final file = File('${directory.path}${Platform.pathSeparator}sample.bin');
      await file.writeAsString('zentor-test-file');

      final hash = await HashService().sha256ForFile(file.path);

      expect(
        hash,
        'sha256:e4b8dc0aed2e59d0216bdecec200a9c2786a6ced97c117cef8cde85f86d3f9d9',
      );
    } finally {
      await directory.delete(recursive: true);
    }
  });

  test('HashService rejects directories at runtime', () async {
    final directory = await Directory.systemTemp.createTemp(
      'zentor_hash_dir_test',
    );
    try {
      await expectLater(
        HashService().sha256ForFile(directory.path),
        throwsA(
          isA<FileSystemException>().having(
            (error) => error.message,
            'message',
            contains('Hashing is limited to a selected file'),
          ),
        ),
      );
    } finally {
      await directory.delete(recursive: true);
    }
  });

  test('HashService rejects oversized selected files before reading', () async {
    final directory = await Directory.systemTemp.createTemp(
      'zentor_hash_oversized_test',
    );
    try {
      final file = File(
        '${directory.path}${Platform.pathSeparator}oversized.bin',
      );
      await file.writeAsString('too-large');

      var progressCalls = 0;
      await expectLater(
        HashService(
          maxFileBytes: 8,
        ).sha256ForFile(file.path, onProgress: (_) => progressCalls += 1),
        throwsA(
          isA<FileSystemException>().having(
            (error) => error.message,
            'message',
            contains('Selected file exceeds the hash size limit'),
          ),
        ),
      );
      expect(progressCalls, 0);
    } finally {
      await directory.delete(recursive: true);
    }
  });

  test('HashService rejects paths that change after stat', () async {
    final directory = await Directory.systemTemp.createTemp(
      'zentor_hash_race_test',
    );
    try {
      final file = File('${directory.path}${Platform.pathSeparator}race.bin');
      await file.writeAsString('before');
      final service = HashService(
        afterStatForTesting: (path) async {
          await File(path).delete();
          await Directory(path).create();
        },
      );

      await expectLater(
        service.sha256ForFile(file.path),
        throwsA(
          isA<FileSystemException>().having(
            (error) => error.message,
            'message',
            contains('Selected file changed before hashing'),
          ),
        ),
      );
    } finally {
      await directory.delete(recursive: true);
    }
  });

  test('HashService rejects files that grow while streaming', () async {
    final directory = await Directory.systemTemp.createTemp(
      'zentor_hash_growth_test',
    );
    try {
      final file = File('${directory.path}${Platform.pathSeparator}grow.bin');
      await file.writeAsString('small');
      var progressCalls = 0;
      final service = HashService(
        maxFileBytes: 8,
        afterStatForTesting: (path) async {
          await File(
            path,
          ).writeAsString('small-but-now-too-large', flush: true);
        },
      );

      await expectLater(
        service.sha256ForFile(file.path, onProgress: (_) => progressCalls += 1),
        throwsA(
          isA<FileSystemException>().having(
            (error) => error.message,
            'message',
            contains('Selected file exceeds the hash size limit'),
          ),
        ),
      );
      expect(progressCalls, 0);
    } finally {
      await directory.delete(recursive: true);
    }
  });

  test('HashService rejects links and streams selected file hashing', () {
    final source = File(
      'lib/core/security/hash_service.dart',
    ).readAsStringSync();

    expect(source, contains('FileSystemEntity.type(path, followLinks: false)'));
    expect(source, contains('FileSystemEntityType.link'));
    expect(
      source,
      contains('const int maxSelectedHashFileBytes = 512 * 1024 * 1024'),
    );
    expect(source, contains('total > _maxFileBytes'));
    expect(source, contains('read > _maxFileBytes'));
    expect(source, contains('_requirePositiveHashLimit(maxFileBytes)'));
    expect(source, contains('await _afterStatForTesting?.call(path)'));
    expect(source, contains('Selected file exceeds the hash size limit'));
    expect(source, contains('typeAfterStat'));
    expect(source, contains('Selected file changed before hashing'));
    expect(source, contains('startChunkedConversion'));
    expect(source, contains('_SingleDigestSink'));
    expect(source, isNot(contains('file.exists()')));
    expect(source, isNot(contains('BytesBuilder')));
  });
}
