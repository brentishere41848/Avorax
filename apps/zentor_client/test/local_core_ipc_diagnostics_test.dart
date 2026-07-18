import 'dart:io';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:zentor_client/core/local_core/local_core_client.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import 'source_text.dart';

void main() {
  test('Core Service boundary parser accepts authenticated ready evidence', () {
    final health = CoreServiceBoundaryHealth.fromJson(
      _serviceBoundaryFixture(),
    );

    expect(health.status, CoreServiceBoundaryStatus.ready);
    expect(health.authenticatedBoundaryVerified, isTrue);
    expect(health.fullProtectionReady, isTrue);
    expect(health.serverPid, 4242);
    expect(health.servicePid, 4242);
    expect(health.nativeSignatureCount, 12);
    expect(health.nativeRuleCount, 7);
  });

  test('Core Service boundary parser preserves authenticated degradation', () {
    final fixture = _serviceBoundaryFixture()
      ..['ok'] = false
      ..['engineReady'] = false;

    final health = CoreServiceBoundaryHealth.fromJson(fixture);

    expect(health.status, CoreServiceBoundaryStatus.degraded);
    expect(health.authenticatedBoundaryVerified, isTrue);
    expect(health.fullProtectionReady, isFalse);
  });

  test('Core Service boundary diagnostics normalize control characters', () {
    final health = CoreServiceBoundaryHealth.unavailable(
      'service\nprobe\tfailed\u0000visibly',
    );

    expect(health.diagnostic, 'service probe failed visibly');
  });

  test('Core Service boundary parser rejects untrusted protocol variants', () {
    final variants = <Map<String, Object?>>[
      _serviceBoundaryFixture()..['unexpected'] = true,
      _serviceBoundaryFixture()..remove('commandScope'),
      _serviceBoundaryFixture()..['serverPid'] = 9999,
      _serviceBoundaryFixture()..['clientAuthenticated'] = false,
      _serviceBoundaryFixture()..['networkExposed'] = true,
      _serviceBoundaryFixture()..['ok'] = false,
      _serviceBoundaryFixture()..['limitations'] = <Object?>[],
      _serviceBoundaryFixture()
        ..['limitations'] = <Object?>['line one\nline two'],
      _serviceBoundaryFixture()..['nativeRuleCount'] = 10000001,
    ];

    for (final variant in variants) {
      expect(
        () => CoreServiceBoundaryHealth.fromJson(variant),
        throwsFormatException,
      );
    }
  });

  test('Core Service boundary launch is bounded and read-only', () {
    final clientSource = readNormalizedSource(
      'lib/core/local_core/local_core_client.dart',
    );

    expect(clientSource, contains("'--service-ipc-health'"));
    expect(
      clientSource,
      contains('_maxServiceHealthResponseBytes = 16 * 1024'),
    );
    expect(
      clientSource,
      contains('_serviceHealthTimeout = Duration(seconds: 10)'),
    );
    expect(clientSource, contains('_ipcTimeoutTerminationStatus(process)'));
    expect(clientSource, contains('CoreServiceBoundaryHealth.fromJson'));
    expect(clientSource, isNot(contains("'--service-ipc-mutate'")));
  });

  test(
    'Core Service boundary probe verifies a real subprocess response',
    () async {
      if (!Platform.isWindows) return;
      final dir = Directory.systemTemp.createTempSync('avorax-service-health-');
      addTearDown(() => dir.deleteSync(recursive: true));
      final payload = jsonEncode(_serviceBoundaryFixture());
      final script = File('${dir.path}${Platform.pathSeparator}health.dart')
        ..writeAsStringSync('''
import 'dart:io';

void main(List<String> args) {
  if (args.length != 1 || args.single != '--service-ipc-health') {
    stderr.writeln('unexpected arguments');
    exitCode = 9;
    return;
  }
  stdout.writeln(${jsonEncode(payload)});
}
''');
      final client = LocalCoreClient(
        executableOverride: _dartExecutable(),
        executableArguments: [script.path],
      );

      final health = await client.serviceBoundaryHealth();

      expect(health.status, CoreServiceBoundaryStatus.ready);
      expect(health.authenticatedBoundaryVerified, isTrue);
      expect(health.fullProtectionReady, isTrue);
    },
  );

  test(
    'Core Service boundary probe fails closed on oversized output',
    () async {
      if (!Platform.isWindows) return;
      final dir = Directory.systemTemp.createTempSync(
        'avorax-service-health-oversized-',
      );
      addTearDown(() => dir.deleteSync(recursive: true));
      final script = File('${dir.path}${Platform.pathSeparator}oversized.dart')
        ..writeAsStringSync('''
void main() {
  print(''.padRight(17 * 1024, 'x'));
}
''');
      final client = LocalCoreClient(
        executableOverride: _dartExecutable(),
        executableArguments: [script.path],
      );

      final health = await client.serviceBoundaryHealth();

      expect(health.status, CoreServiceBoundaryStatus.unavailable);
      expect(health.diagnostic, contains('exceeded the 16384-byte limit'));
    },
  );

  test('Core Service boundary probe times out and reaps subprocess', () async {
    if (!Platform.isWindows) return;
    final dir = Directory.systemTemp.createTempSync(
      'avorax-service-health-timeout-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = _writeSleepingDartScript(dir, 'service_health_timeout.dart');
    Process? spawned;
    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
      serviceHealthTimeout: const Duration(milliseconds: 100),
      processStarter: (executable, arguments) async {
        spawned = await Process.start(executable, arguments);
        return spawned!;
      },
    );

    final health = await client.serviceBoundaryHealth();

    expect(health.status, CoreServiceBoundaryStatus.unavailable);
    expect(health.diagnostic, contains('timed out'));
    expect(spawned, isNotNull);
    await _expectProcessExited(spawned!, 'Core Service health timeout fixture');
  });

  test(
    'Core Service boundary probe rejects timeout above safe maximum',
    () async {
      if (!Platform.isWindows) return;
      var processStarted = false;
      final client = LocalCoreClient(
        executableOverride: _dartExecutable(),
        serviceHealthTimeout: const Duration(seconds: 11),
        processStarter: (executable, arguments) async {
          processStarted = true;
          return Process.start(executable, arguments);
        },
      );

      final health = await client.serviceBoundaryHealth();

      expect(health.status, CoreServiceBoundaryStatus.unavailable);
      expect(health.diagnostic, contains('outside its safe bounds'));
      expect(processStarted, isFalse);
    },
  );

  test('scan failure reports missing local core executable path', () async {
    final missing = Directory.systemTemp
        .createTempSync('avorax-missing-core-')
        .uri
        .resolve('missing-core.exe')
        .toFilePath();
    addTearDown(() {
      final parent = File(missing).parent;
      if (parent.existsSync()) parent.deleteSync(recursive: true);
    });

    final client = LocalCoreClient(executableOverride: missing);

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/sample.exe',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.engineUnavailable);
    expect(
      report.message,
      contains('Avorax Core Service executable was not found'),
    );
    expect(report.message, contains(missing));
  });
  test(
    'health summary exposes IPC failure as lastError for recovery UI',
    () async {
      final missing = Directory.systemTemp
          .createTempSync('avorax-missing-health-core-')
          .uri
          .resolve('missing-core.exe')
          .toFilePath();
      addTearDown(() {
        final parent = File(missing).parent;
        if (parent.existsSync()) parent.deleteSync(recursive: true);
      });

      final client = LocalCoreClient(executableOverride: missing);

      final health = await client.healthSummary();

      expect(health.coreServiceStatus, 'error');
      expect(
        health.lastError,
        contains('Avorax Core Service executable was not found'),
      );
      expect(health.lastError, contains(missing));
    },
  );

  test('scan failure preserves stderr from local core process', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-core-stderr-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = File('${dir.path}${Platform.pathSeparator}stderr.dart')
      ..writeAsStringSync('''
import 'dart:io';
void main() {
  stderr.writeln('native engine assets missing');
  exitCode = 7;
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/sample.exe',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.engineUnavailable);
    expect(report.message, contains('native engine assets missing'));
    expect(report.message, contains('exit code 7'));
  });

  test('scan failure reports malformed local core JSON', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-core-malformed-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = File('${dir.path}${Platform.pathSeparator}malformed.dart')
      ..writeAsStringSync('''
void main() {
  print('not-json');
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/sample.exe',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.engineUnavailable);
    expect(report.message, contains('malformed JSON'));
    expect(report.message, contains('not-json'));
  });

  test('scan response preserves malformed stdout warnings', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-core-mixed-json-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = File('${dir.path}${Platform.pathSeparator}mixed.dart')
      ..writeAsStringSync('''
import 'dart:convert';

void main() {
  print('not-json-progress');
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'clean',
    'kind': 'custom',
    'actionMode': 'detectOnly',
    'filesScanned': 1,
    'threatsFound': 0,
    'skippedFiles': 0,
    'elapsedMs': 1,
    'threats': <Object?>[],
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/sample.exe',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.completedWithErrors);
    expect(report.scanErrors, contains(contains('malformed JSON on stdout')));
    expect(report.scanErrors, contains(contains('not-json-progress')));
  });

  test('scan response records malformed progress diagnostics', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-core-progress-json-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = File('${dir.path}${Platform.pathSeparator}progress.dart')
      ..writeAsStringSync('''
import 'dart:convert';

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'clean',
    'kind': 'custom',
    'actionMode': 'detectOnly',
    'filesScanned': 1,
    'foldersScanned': 0,
    'bytesScanned': 68,
    'threatsFound': 0,
    'suspiciousFound': 0,
    'quarantinedFiles': 0,
    'skippedFiles': 0,
    'permissionDeniedCount': 0,
    'elapsedMs': 1,
    'threats': <Object?>[],
    'progress': <String, Object?>{
      'job_id': 42,
      'scan_type': 'not-a-kind',
      'status': 'not-a-status',
      'current_path': <String, Object?>{'path': 'bad'},
      'files_scanned': 'many',
      'folders_scanned': -1,
      'bytes_scanned': 3.14,
      'threats_found': null,
      'suspicious_found': 'none',
      'skipped_files': 'zero',
      'permission_denied_count': 'nope',
      'started_at': 'not-a-date',
      'updated_at': 42,
      'elapsed_seconds': 'soon',
      'progress_percent': 120,
    },
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );
    final progressEvents = <ScanProgress>[];

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/sample.exe',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
      onProgress: progressEvents.add,
    );

    expect(progressEvents, isEmpty);
    expect(report.status, ScanStatus.completedWithErrors);
    expect(
      report.scanErrors,
      containsAll(<String>[
        'local core scan progress had malformed job_id',
        'local core scan progress had malformed scan_type',
        'local core scan progress had malformed status',
        'local core scan progress had malformed numeric field files_scanned',
        'local core scan progress had malformed numeric field folders_scanned',
        'local core scan progress had malformed numeric field bytes_scanned',
        'local core scan progress was missing numeric field threats_found',
        'local core scan progress had malformed numeric field suspicious_found',
        'local core scan progress had malformed numeric field skipped_files',
        'local core scan progress had malformed numeric field permission_denied_count',
        'local core scan progress had malformed started_at timestamp',
        'local core scan progress had malformed updated_at timestamp',
        'local core scan progress had malformed numeric field elapsed_seconds',
      ]),
    );
  });

  test('scan response records optional progress diagnostics', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-core-progress-optional-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final script =
        File('${dir.path}${Platform.pathSeparator}progress_optional.dart')
          ..writeAsStringSync('''
import 'dart:convert';

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'clean',
    'kind': 'custom',
    'actionMode': 'detectOnly',
    'filesScanned': 1,
    'foldersScanned': 0,
    'bytesScanned': 68,
    'threatsFound': 0,
    'suspiciousFound': 0,
    'quarantinedFiles': 0,
    'skippedFiles': 0,
    'permissionDeniedCount': 0,
    'elapsedMs': 1,
    'threats': <Object?>[],
    'progress': <String, Object?>{
      'job_id': 'job-fixture',
      'scan_type': 'custom',
      'status': 'running',
      'current_path': <String, Object?>{'path': 'bad'},
      'files_scanned': 1,
      'folders_scanned': 0,
      'bytes_scanned': 68,
      'threats_found': 0,
      'suspicious_found': 0,
      'skipped_files': 0,
      'permission_denied_count': 0,
      'started_at': '2024-01-01T00:00:00Z',
      'updated_at': '2024-01-01T00:00:01Z',
      'elapsed_seconds': 1,
      'progress_percent': 120,
    },
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/sample.exe',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.completedWithErrors);
    expect(report.progress, isNotNull);
    expect(report.progress!.currentPath, isNull);
    expect(report.progress!.progressPercent, isNull);
    expect(
      report.scanErrors,
      containsAll(<String>[
        'local core scan progress had malformed current_path',
        'local core scan progress had out-of-range percentage field progress_percent',
      ]),
    );
  });

  test('scan report rejects malformed scan error list', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-core-scan-errors-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = File('${dir.path}${Platform.pathSeparator}scan_errors.dart')
      ..writeAsStringSync('''
import 'dart:convert';

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'clean',
    'kind': 'custom',
    'actionMode': 'detectOnly',
    'filesScanned': 1,
    'scanErrors': 'not-a-list',
    'threatsFound': 0,
    'skippedFiles': 0,
    'elapsedMs': 1,
    'threats': <Object?>[],
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/sample.exe',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.completedWithErrors);
    expect(
      report.scanErrors,
      contains('local core scan response had malformed scan_errors list'),
    );
  });

  test('scan report records malformed final report fields', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-core-final-report-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = File('${dir.path}${Platform.pathSeparator}final_report.dart')
      ..writeAsStringSync('''
import 'dart:convert';

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 42,
    'kind': 'not-a-kind',
    'action_mode': 'not-a-mode',
    'files_scanned': 'many',
    'folders_scanned': -1,
    'bytes_scanned': 3.14,
    'total_files_estimated': 'unknown',
    'total_bytes_estimated': -5,
    'threats_found': <Object?>[],
    'suspicious_found': null,
    'quarantined_files': 'none',
    'skipped_files': 'zero',
    'permission_denied_count': 'none',
    'elapsed_ms': 'fast',
    'current_path': 7,
    'message': <String, Object?>{'text': 'not-a-string'},
    'threats': <Object?>[],
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/sample.exe',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.engineUnavailable);
    expect(report.kind, ScanKind.custom);
    expect(report.actionMode, ScanActionMode.detectOnly);
    expect(report.currentPath, isNull);
    expect(report.message, isNull);
    expect(report.filesScanned, 0);
    expect(report.totalFilesEstimated, isNull);
    expect(
      report.scanErrors,
      containsAll(<String>[
        'local core scan response had malformed status',
        'local core scan response had malformed kind',
        'local core scan response had malformed action_mode',
        'local core scan response had malformed numeric field files_scanned',
        'local core scan response had malformed numeric field folders_scanned',
        'local core scan response had malformed numeric field bytes_scanned',
        'local core scan response had malformed numeric field total_files_estimated',
        'local core scan response had malformed numeric field total_bytes_estimated',
        'local core scan response had malformed numeric field threats_found',
        'local core scan response was missing numeric field suspicious_found',
        'local core scan response had malformed numeric field quarantined_files',
        'local core scan response had malformed numeric field skipped_files',
        'local core scan response had malformed numeric field permission_denied_count',
        'local core scan response had malformed numeric field elapsed_ms',
        'local core scan response had malformed current_path',
        'local core scan response had malformed message',
      ]),
    );
  });

  test('scan report records malformed threat timestamps', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-core-threat-time-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final hash = 'f' * 64;
    final script = File('${dir.path}${Platform.pathSeparator}threat_time.dart')
      ..writeAsStringSync('''
import 'dart:convert';

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'threatsFound',
    'kind': 'custom',
    'actionMode': 'detectOnly',
    'filesScanned': 1,
    'threatsFound': 1,
    'skippedFiles': 0,
    'elapsedMs': 1,
    'threats': <Object?>[
      <String, Object?>{
        'id': 'threat-1',
        'path': 'C:/Users/Brent/Downloads/eicar.txt',
        'sha256': '$hash',
        'sizeBytes': 68,
        'detectionType': 'signature',
        'threatCategory': 'unknown',
        'threatName': 'Fixture detection',
        'confidence': 'confirmed',
        'engine': 'fixture-engine',
        'detectedAt': 'not-a-date',
        'recommendedAction': 'review',
        'status': 'detected',
        'reasonSummary': 'Fixture signature evidence.',
        'riskScore': <String, Object?>{
          'score': 100,
          'verdict': 'confirmedMalware',
          'confidence': 'confirmed',
          'recommendedAction': 'quarantine',
          'reasons': <Object?>[],
          'enginesUsed': <Object?>['signature'],
        },
      },
    ],
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/eicar.txt',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.infected);
    expect(report.threats, isEmpty);
    expect(
      report.scanErrors,
      contains(
        'local core scan response had malformed threat timestamp detected_at',
      ),
    );
  });

  test('scan report accepts small-threat category evidence', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-core-threat-category-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final hash = 'a' * 64;
    final script =
        File('${dir.path}${Platform.pathSeparator}threat_category.dart')
          ..writeAsStringSync('''
import 'dart:convert';

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'threatsFound',
    'kind': 'quick',
    'actionMode': 'autoQuarantineConfirmedOnly',
    'filesScanned': 1,
    'foldersScanned': 1,
    'bytesScanned': 128,
    'threatsFound': 1,
    'suspiciousFound': 1,
    'quarantinedFiles': 0,
    'skippedFiles': 0,
    'permissionDeniedCount': 0,
    'elapsedMs': 1,
    'threats': <Object?>[
      <String, Object?>{
        'id': 'threat-infostealer',
        'path': 'C:/Users/Brent/Downloads/collector.js',
        'fileName': 'collector.js',
        'sha256': '$hash',
        'sizeBytes': 128,
        'detectionType': 'heuristic',
        'threatCategory': 'infostealer',
        'threatName': 'Suspicious item',
        'confidence': 'medium',
        'engine': 'Avorax Native Engine',
        'detectedAt': '2026-07-06T00:00:00Z',
        'recommendedAction': 'review',
        'status': 'detected',
        'reasonSummary': 'Potential infostealer review evidence.',
        'riskScore': <String, Object?>{
          'score': 55,
          'verdict': 'suspicious',
          'confidence': 'medium',
          'recommendedAction': 'review',
          'reasons': <Object?>[],
          'enginesUsed': <Object?>['heuristic'],
        },
      },
    ],
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/collector.js',
      kind: ScanKind.quick,
      actionMode: ScanActionMode.autoQuarantineConfirmedOnly,
    );

    expect(report.status, ScanStatus.infected);
    expect(report.threats, hasLength(1));
    expect(report.threats.single.threatCategory, ThreatCategory.infostealer);
    expect(report.threats.single.status, ThreatResultStatus.detected);
    expect(report.threats.single.recommendedAction, RecommendedAction.review);
    expect(report.scanErrors, isEmpty);
  });

  test(
    'scan report preserves quarantine evidence for quarantined threats',
    () async {
      final dir = Directory.systemTemp.createTempSync(
        'avorax-core-threat-quarantine-evidence-',
      );
      addTearDown(() => dir.deleteSync(recursive: true));
      final hash = 'c' * 64;
      final script =
          File('${dir.path}${Platform.pathSeparator}threat_quarantine.dart')
            ..writeAsStringSync('''
import 'dart:convert';

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'threatsFound',
    'kind': 'custom',
    'actionMode': 'autoQuarantineConfirmedOnly',
    'filesScanned': 1,
    'foldersScanned': 0,
    'bytesScanned': 32,
    'threatsFound': 1,
    'suspiciousFound': 0,
    'quarantinedFiles': 1,
    'skippedFiles': 0,
    'permissionDeniedCount': 0,
    'elapsedMs': 1,
    'threats': <Object?>[
      <String, Object?>{
        'id': 'threat-eicar',
        'path': 'C:/Users/Brent/Downloads/eicar.com',
        'fileName': 'eicar.com',
        'sha256': '$hash',
        'sizeBytes': 32,
        'detectionType': 'signature',
        'threatCategory': 'unknown',
        'threatName': 'Confirmed threat',
        'confidence': 'confirmed',
        'engine': 'Avorax Native Engine',
        'detectedAt': '2026-07-06T00:00:00Z',
        'recommendedAction': 'quarantine',
        'status': 'quarantined',
        'quarantineId': 'record-eicar',
        'quarantinePath': 'C:/ProgramData/Avorax/Quarantine/record-eicar.avoraxq',
        'quarantineActionTaken': 'quarantined',
        'reasonSummary': 'Confirmed simulator evidence.',
        'riskScore': <String, Object?>{
          'score': 100,
          'verdict': 'confirmedMalware',
          'confidence': 'confirmed',
          'recommendedAction': 'quarantine',
          'reasons': <Object?>[],
          'enginesUsed': <Object?>['signature'],
        },
      },
    ],
  }));
}
''');

      final client = LocalCoreClient(
        executableOverride: _dartExecutable(),
        executableArguments: [script.path],
      );

      final report = await client.scanFile(
        'C:/Users/Brent/Downloads/eicar.com',
        kind: ScanKind.custom,
        actionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      );

      expect(report.status, ScanStatus.infected);
      expect(report.quarantinedFiles, 1);
      expect(report.threats, hasLength(1));
      expect(report.threats.single.status, ThreatResultStatus.quarantined);
      expect(report.threats.single.quarantineId, 'record-eicar');
      expect(report.threats.single.quarantinePath, endsWith('.avoraxq'));
      expect(report.threats.single.quarantineActionTaken, 'quarantined');
      expect(report.scanErrors, isEmpty);
    },
  );

  test('scan report drops threats with missing required evidence', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-core-threat-evidence-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final hash = 'd' * 64;
    final script =
        File('${dir.path}${Platform.pathSeparator}threat_evidence.dart')
          ..writeAsStringSync('''
import 'dart:convert';

Map<String, Object?> threat(Map<String, Object?> overrides) {
  final row = <String, Object?>{
    'id': 'threat-\${overrides.length}',
    'path': 'C:/Users/Brent/Downloads/eicar.txt',
    'sha256': '$hash',
    'sizeBytes': 68,
    'detectionType': 'signature',
    'threatCategory': 'trojan',
    'threatName': 'Fixture detection',
    'confidence': 'confirmed',
    'engine': 'fixture-engine',
    'detectedAt': '2024-01-01T00:00:00Z',
    'recommendedAction': 'review',
    'status': 'detected',
    'reasonSummary': 'Fixture evidence.',
    'riskScore': <String, Object?>{
      'score': 90,
      'verdict': 'confirmedMalware',
      'confidence': 'confirmed',
      'recommendedAction': 'quarantine',
      'reasons': <Object?>[],
      'enginesUsed': <Object?>['signature'],
    },
  };
  row.addAll(overrides);
  return row;
}

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'threatsFound',
    'kind': 'custom',
    'actionMode': 'detectOnly',
    'filesScanned': 6,
    'threatsFound': 6,
    'skippedFiles': 0,
    'elapsedMs': 1,
    'threats': <Object?>[
      threat(<String, Object?>{'threatName': ''}),
      threat(<String, Object?>{'engine': ''}),
      threat(<String, Object?>{'detectedAt': 'not-a-date'}),
      threat(<String, Object?>{'sizeBytes': -1}),
      threat(<String, Object?>{
        'detectionType': 'bogus',
        'threatCategory': 'bogus',
        'confidence': 'bogus',
        'recommendedAction': 'bogus',
        'status': 'bogus',
      }),
      threat(<String, Object?>{'reasonSummary': ''}),
    ],
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/eicar.txt',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.infected);
    expect(report.threats, isEmpty);
    expect(
      report.scanErrors,
      containsAll(<String>[
        'local core scan response dropped malformed threat: threat_name',
        'local core scan response dropped malformed threat: engine',
        'local core scan response had malformed threat timestamp detected_at',
        'local core scan response had malformed threat numeric field size_bytes',
        'local core scan response had malformed threat detection_type',
        'local core scan response had malformed threat threat_category',
        'local core scan response had malformed threat confidence',
        'local core scan response had malformed threat recommended_action',
        'local core scan response had malformed threat status',
        'local core scan response had malformed threat reason_summary',
      ]),
    );
  });

  test('scan report records malformed risk score evidence', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-core-risk-score-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final hash = 'e' * 64;
    final script = File('${dir.path}${Platform.pathSeparator}risk_score.dart')
      ..writeAsStringSync('''
import 'dart:convert';

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'threatsFound',
    'kind': 'custom',
    'actionMode': 'detectOnly',
    'filesScanned': 1,
    'threatsFound': 1,
    'skippedFiles': 0,
    'elapsedMs': 1,
    'threats': <Object?>[
      <String, Object?>{
        'id': 'threat-1',
        'path': 'C:/Users/Brent/Downloads/eicar.txt',
        'sha256': '$hash',
        'sizeBytes': 68,
        'detectionType': 'signature',
        'threatCategory': 'unknown',
        'threatName': 'Fixture detection',
        'confidence': 'confirmed',
        'engine': 'fixture-engine',
        'detectedAt': '2024-01-01T00:00:00Z',
        'recommendedAction': 'review',
        'status': 'detected',
        'reasonSummary': 'Fixture risk evidence.',
        'riskScore': <String, Object?>{
          'score': 200,
          'verdict': 'suspicious',
          'confidence': 'medium',
          'recommendedAction': 'review',
          'reasons': <Object?>['not-a-reason'],
          'enginesUsed': <Object?>['unknown-engine', 42],
        },
      },
    ],
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/eicar.txt',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.infected);
    expect(report.threats, isEmpty);
    expect(
      report.scanErrors,
      contains('local core scan response had malformed risk score'),
    );
    expect(
      report.scanErrors,
      contains('local core scan response dropped malformed risk reason 0'),
    );
    expect(
      report.scanErrors,
      contains('local core scan response dropped unknown risk engine 0'),
    );
    expect(
      report.scanErrors,
      contains('local core scan response dropped malformed risk engine 1'),
    );
  });

  test('scan report drops threats with missing risk score evidence', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-core-risk-required-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final hash = 'c' * 64;
    final script =
        File('${dir.path}${Platform.pathSeparator}risk_required.dart')
          ..writeAsStringSync('''
import 'dart:convert';

Map<String, Object?> threat(Map<String, Object?> riskScore) {
  return <String, Object?>{
    'id': 'threat-\${riskScore.length}',
    'path': 'C:/Users/Brent/Downloads/eicar.txt',
    'sha256': '$hash',
    'sizeBytes': 68,
    'detectionType': 'signature',
    'threatCategory': 'trojan',
    'threatName': 'Fixture detection',
    'confidence': 'confirmed',
    'engine': 'fixture-engine',
    'detectedAt': '2024-01-01T00:00:00Z',
    'recommendedAction': 'review',
    'status': 'detected',
    'reasonSummary': 'Fixture risk evidence.',
    'riskScore': riskScore,
  };
}

Map<String, Object?> risk(Map<String, Object?> overrides) {
  final row = <String, Object?>{
    'score': 90,
    'verdict': 'confirmedMalware',
    'confidence': 'confirmed',
    'recommendedAction': 'quarantine',
    'reasons': <Object?>[
      <String, Object?>{
        'id': 'reason-1',
        'title': 'Fixture reason',
        'weight': 100,
        'severity': 'high',
        'source': 'signature',
      },
    ],
    'enginesUsed': <Object?>['signature'],
  };
  row.addAll(overrides);
  return row;
}

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'threatsFound',
    'kind': 'custom',
    'actionMode': 'detectOnly',
    'filesScanned': 5,
    'foldersScanned': 1,
    'bytesScanned': 68,
    'threatsFound': 5,
    'suspiciousFound': 0,
    'quarantinedFiles': 0,
    'skippedFiles': 0,
    'permissionDeniedCount': 0,
    'elapsedMs': 1,
    'threats': <Object?>[
      threat(risk(<String, Object?>{'score': null})),
      threat(risk(<String, Object?>{'verdict': 'bogus'})),
      threat(risk(<String, Object?>{'confidence': 'bogus'})),
      threat(risk(<String, Object?>{'recommendedAction': 'bogus'})),
      threat(risk(<String, Object?>{
        'reasons': <Object?>[
          <String, Object?>{
            'id': '',
            'title': '',
            'weight': -1,
            'severity': 'bogus',
            'source': 'bogus',
          },
        ],
      })),
    ],
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/eicar.txt',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.infected);
    expect(report.threats, hasLength(1));
    expect(report.threats.single.riskScore.reasons, isEmpty);
    expect(
      report.scanErrors,
      containsAll(<String>[
        'local core scan response was missing risk score',
        'local core scan response had malformed risk_score verdict',
        'local core scan response had malformed risk_score confidence',
        'local core scan response had malformed risk_score recommended_action',
        'local core scan response had malformed risk reason 0 id',
        'local core scan response had malformed risk reason 0 title',
        'local core scan response had malformed risk reason 0 weight',
        'local core scan response had malformed risk reason 0 severity',
        'local core scan response had malformed risk reason 0 source',
      ]),
    );
  });

  test('scan report records malformed threat rows', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-core-threat-row-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = File('${dir.path}${Platform.pathSeparator}threat_row.dart')
      ..writeAsStringSync('''
import 'dart:convert';

void main() {
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'threatsFound',
    'kind': 'custom',
    'actionMode': 'detectOnly',
    'filesScanned': 1,
    'threatsFound': 1,
    'skippedFiles': 0,
    'elapsedMs': 1,
    'threats': <Object?>['not-a-threat-object'],
  }));
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/eicar.txt',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.infected);
    expect(report.threats, isEmpty);
    expect(
      report.scanErrors,
      contains('local core scan response dropped malformed threat row 0'),
    );
  });

  test('scan failure reports local core timeout and kills process', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-core-timeout-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = File('${dir.path}${Platform.pathSeparator}timeout.dart')
      ..writeAsStringSync('''
import 'dart:async';
Future<void> main() async {
  await Future<void>.delayed(const Duration(seconds: 5));
}
''');

    late Process process;
    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
      ipcTimeout: const Duration(milliseconds: 100),
      processStarter: (executable, arguments) async {
        process = await Process.start(executable, arguments);
        return process;
      },
    );

    final report = await client.scanFile(
      'C:/Users/Brent/Downloads/sample.exe',
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );

    expect(report.status, ScanStatus.engineUnavailable);
    expect(report.message, contains('timed out'));
    expect(report.message, contains('100ms'));
    expect(report.message, contains('Termination requested.'));
    expect(report.message, contains('Timed-out process exited with code'));
    await _expectProcessExited(process, 'local core scan timeout fixture');
  });

  test('health summary preserves self-test error fields', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final stateSource = File('lib/app/app_state.dart').readAsStringSync();
    final deviceSource = File(
      'lib/features/device/device_screen.dart',
    ).readAsStringSync();
    final protectionSource = File(
      'lib/features/protection/protection_screen.dart',
    ).readAsStringSync();
    final settingsSource = File(
      'lib/features/settings/settings_screen.dart',
    ).readAsStringSync();

    expect(clientSource, contains('nativeSelfTestError'));
    expect(clientSource, contains('native_self_test_error'));
    expect(clientSource, contains('aiSelfTestError'));
    expect(clientSource, contains('ai_self_test_error'));
    expect(
      stateSource,
      contains('nativeSelfTestError: health.nativeSelfTestError'),
    );
    expect(stateSource, contains('aiSelfTestError: health.aiSelfTestError'));
    expect(stateSource, contains('health.nativeSelfTestError'));
    expect(stateSource, contains('health.aiSelfTestError'));
    expect(deviceSource, contains('Native self-test:'));
    expect(deviceSource, contains('AI self-test:'));
    expect(protectionSource, contains('Native self-test:'));
    expect(protectionSource, contains('AI self-test:'));
    expect(settingsSource, contains('Native self-test error'));
    expect(settingsSource, contains('AI self-test error'));
  });

  test('protection self-test reports malformed step rows', () {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final formatter = clientSource.substring(
      clientSource.indexOf('String _formatProtectionSelfTestSteps'),
      clientSource.indexOf('Future<LocalCoreActionResult> configureGuardMode'),
    );

    expect(formatter, contains('malformed self-test step'));
    expect(formatter, contains('step was not an object'));
    expect(formatter, contains('final rawName'));
    expect(formatter, contains('malformed name'));
    expect(formatter, contains('final rawReason'));
    expect(formatter, contains('malformed reason'));
    expect(formatter, contains('malformed passed flag'));
    expect(formatter, contains('unnamed self-test step'));
    expect(clientSource, isNot(contains('.whereType<Map>()')));
  });

  test('protection self-test reports malformed step rows at runtime', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-guard-self-test-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = File('${dir.path}${Platform.pathSeparator}self_test.dart')
      ..writeAsStringSync('''
import 'dart:convert';

void main() {
  final report = <String, Object?>{
    'steps': <Object?>[
      'not-an-object',
      <String, Object?>{'name': 42, 'reason': 'bad name', 'passed': false},
      <String, Object?>{'reason': 'missing name is explicit', 'passed': true},
      <String, Object?>{'name': 'driver ping', 'reason': 7, 'passed': false},
      <String, Object?>{'name': 'service mode', 'reason': 'bad flag', 'passed': 'yes'},
      <String, Object?>{'name': 'rule cache', 'reason': 'ok', 'passed': true},
    ],
  };
  print(jsonEncode(<String, Object?>{
    'message': jsonEncode(report),
  }));
}
''');

    final client = LocalCoreClient(
      guardExecutableOverride: _dartExecutable(),
      guardExecutableArguments: [script.path],
    );

    final result = await client.runProtectionSelfTest();

    expect(
      result,
      contains('FAIL malformed self-test step 1: step was not an object'),
    );
    expect(result, contains('FAIL malformed self-test step 2: malformed name'));
    expect(
      result,
      contains('PASS unnamed self-test step 3: missing name is explicit'),
    );
    expect(result, contains('FAIL driver ping: malformed reason'));
    expect(
      result,
      contains('FAIL service mode: malformed passed flag; bad flag'),
    );
    expect(result, contains('PASS rule cache: ok'));
  });

  test('protection self-test timeout reports cleanup at runtime', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-guard-self-test-timeout-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = _writeSleepingDartScript(dir, 'self_test_timeout.dart');

    late Process process;
    final client = LocalCoreClient(
      guardExecutableOverride: _dartExecutable(),
      guardExecutableArguments: [script.path],
      protectionSelfTestTimeout: const Duration(milliseconds: 50),
      ipcProcessReapTimeout: const Duration(seconds: 2),
      processStarter: (executable, arguments) async {
        process = await Process.start(executable, arguments);
        return process;
      },
    );

    final result = await client.runProtectionSelfTest();

    expect(result, contains('Protection self-test failed'));
    expect(result, contains('Protection self-test timed out after 50ms'));
    expect(result, contains('Termination requested.'));
    expect(
      result,
      anyOf(
        contains('Timed-out process exited with code'),
        contains('Timed-out process did not exit within'),
      ),
    );
    await _expectProcessExited(process, 'protection self-test timeout fixture');
  });

  test('health summary parser bounds malformed IPC fields', () async {
    final clientSource = readNormalizedSource(
      'lib/core/local_core/local_core_client.dart',
    );

    expect(clientSource, contains('_maxIpcStatusTextLength'));
    expect(clientSource, contains('_maxIpcDiagnosticTextLength'));
    expect(clientSource, contains('_maxIpcStringListEntries'));
    expect(clientSource, contains('_ipcStringOrNull('));
    expect(clientSource, contains('_ipcDiagnosticOrNull('));
    expect(clientSource, contains(r"RegExp(r'[\x00-\x1F\x7F]+')"));
    expect(clientSource, contains('_ipcBool('));
    expect(clientSource, contains('_ipcStringList('));
    expect(clientSource, contains('final healthDiagnostics = <String>[]'));
    expect(clientSource, contains('_healthStringField'));
    expect(clientSource, contains('_healthAllowedStringField'));
    expect(clientSource, contains('required Set<String> allowedValues'));
    expect(clientSource, contains('allowedValues.contains(parsed)'));
    expect(clientSource, contains('_healthDiagnosticField'));
    expect(clientSource, contains('_healthOptionalStringField'));
    expect(
      clientSource,
      contains(
        "healthDiagnostics.addAll(\n      _scanErrorList(_field(response, 'scanErrors', 'scan_errors'))",
      ),
    );
    expect(
      clientSource,
      contains(r'local core health response had malformed $fieldName'),
    );
    expect(
      clientSource,
      contains(r'local core health response was missing $fieldName'),
    );
    expect(
      clientSource,
      contains(r'local core health response had malformed $fieldName'),
    );
    expect(clientSource, contains("fieldName: 'yara_status'"));
    expect(clientSource, contains("fieldName: 'native_engine_status'"));
    expect(clientSource, contains("fieldName: 'native_ml_status'"));
    expect(clientSource, contains("fieldName: 'core_service_status'"));
    expect(clientSource, contains("fieldName: 'guard_status'"));
    expect(clientSource, contains("fieldName: 'driver_status'"));
    for (final status in <String>[
      'compatDisabled',
      'rulesUnavailable',
      'ready',
      'error',
      'unavailable',
      'loaded',
      'developmentModel',
      'modelMissing',
      'running',
      'stopped',
      'missing',
      'installed',
      'unknown',
      'unsupported',
      'off',
    ]) {
      expect(clientSource, contains("'$status'"));
    }
    expect(clientSource, contains('_healthIntField'));
    expect(
      clientSource,
      contains(r'local core health response was missing $snake'),
    );
    expect(
      clientSource,
      contains(r'local core health response had malformed $snake'),
    );
    expect(clientSource, contains("'yara_rule_count'"));
    expect(clientSource, contains("'native_signature_count'"));
    expect(clientSource, contains("'native_rule_count'"));
    expect(clientSource, contains('_healthMalwareEngineStatus'));
    expect(
      clientSource,
      contains('local core health response was missing engine_status'),
    );
    expect(
      clientSource,
      contains('local core health response had malformed engine_status'),
    );
    expect(clientSource, contains('_healthAiModelInfo'));
    expect(clientSource, contains('_aiModelStatusField'));
    expect(
      clientSource,
      contains('local core health response was missing ai_model'),
    );
    expect(
      clientSource,
      contains('local core health response had malformed ai_model'),
    );
    expect(
      clientSource,
      contains('local core health response was missing ai_model.status'),
    );
    expect(
      clientSource,
      contains('local core health response had malformed ai_model.status'),
    );
    expect(clientSource, contains("fieldName: 'ai_model.model_version'"));
    expect(
      clientSource,
      contains("fieldName: 'ai_model.feature_schema_version'"),
    );
    expect(clientSource, isNot(contains("fallback: '1.0.0'")));
    expect(clientSource, contains("'ai_model.message'"));
    expect(clientSource, contains('coreServiceStatusError'));
    expect(clientSource, contains("'core_service_status_error'"));
    expect(
      clientSource,
      contains('healthDiagnostics.add(coreServiceStatusError)'),
    );
    expect(clientSource, contains('guardStatusError'));
    expect(clientSource, contains("'guard_status_error'"));
    expect(clientSource, contains('healthDiagnostics.add(guardStatusError)'));
    expect(clientSource, contains("'native_self_test_error'"));
    expect(clientSource, contains("'ai_self_test_error'"));
    expect(clientSource, contains("'last_error'"));
    expect(clientSource, contains("'native_ml_model_version'"));
    expect(clientSource, contains("'install_path'"));
    expect(clientSource, contains("'engine_directory'"));
    expect(clientSource, contains("'program_data_dir'"));
    expect(
      clientSource,
      contains('nativeMlModelVersion: nativeMlModelVersion'),
    );
    expect(clientSource, contains('installPath: installPath'));
    expect(clientSource, contains('engineDirectory: engineDirectory'));
    expect(
      clientSource,
      contains('programDataDirectory: programDataDirectory'),
    );
    expect(clientSource, contains('enginePathsChecked: enginePathsChecked'));
    expect(clientSource, contains('_healthLastErrorWithDiagnostics'));
    expect(clientSource, contains('productionReady: _ipcBool'));
    expect(clientSource, contains('fieldName: \'ai_model.production_ready\''));
    expect(
      clientSource,
      contains('fieldName: \'compatibility_engines_enabled\''),
    );
    expect(
      clientSource,
      contains(r'local core health response had malformed $fieldName boolean'),
    );
    expect(
      clientSource,
      contains("lastError: _ipcDiagnosticOrNull(response['error'])"),
    );
  });

  test('health responses with protocol warnings surface lastError', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-health-warning-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final payload = jsonEncode(<String, Object?>{
      'ok': true,
      'scanErrors': <String>['malformed prelude before health result'],
      'engineStatus': 'unavailable',
      'aiStatus': 'modelMissing',
      'aiModel': <String, Object?>{
        'status': 'modelMissing',
        'modelVersion': 'unavailable',
        'featureSchemaVersion': 'unavailable',
        'productionReady': false,
      },
      'yaraStatus': 'unavailable',
      'yaraRuleCount': 0,
      'nativeEngineStatus': 'unavailable',
      'nativeSignatureCount': 0,
      'nativeRuleCount': 0,
      'nativeMlStatus': 'modelMissing',
      'nativeMlProductionReady': false,
      'coreServiceStatus': 'unknown',
      'guardStatus': 'unknown',
      'driverStatus': 'unknown',
      'processMonitorStatus': 'off',
      'processMonitorCapability': 'unsupported',
      'behaviorMonitorStatus': 'off',
      'reputationStatus': 'unavailable',
      'compatibilityEnginesEnabled': false,
      'ipc': 'stdio',
    });
    final script = File('${dir.path}${Platform.pathSeparator}health.dart')
      ..writeAsStringSync('void main() { print(${jsonEncode(payload)}); }\n');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final health = await client.healthSummary();

    expect(
      health.lastError,
      contains('malformed prelude before health result'),
    );
    expect(health.malwareEngineStatus, MalwareEngineStatus.unavailable);
    expect(health.ipcMode, 'stdio');
  });

  test('health responses record malformed field diagnostics at runtime', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-health-fields-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final payload = jsonEncode(<String, Object?>{
      'ok': true,
      'engineStatus': 42,
      'aiStatus': 42,
      'aiModel': <String, Object?>{
        'status': 42,
        'modelVersion': 7,
        'featureSchemaVersion': <String, Object?>{'schema': 'bad'},
        'message': <Object?>['not text'],
        'productionReady': 'yes',
      },
      'yaraStatus': 42,
      'yaraRuleCount': 'many',
      'nativeEngineStatus': 'bogus',
      'nativeSignatureCount': -1,
      'nativeRuleCount': 'zero',
      'nativeMlStatus': 42,
      'nativeMlProductionReady': 'true',
      'nativeError': 42,
      'coreServiceStatus': 42,
      'guardStatus': 'bogus',
      'driverStatus': 42,
      'processMonitorStatus': 42,
      'processMonitorCapability': 42,
      'behaviorMonitorStatus': 42,
      'reputationStatus': 42,
      'installPath': 42,
      'engineDirectory': <Object?>['bad'],
      'programDataDir': 42,
      'ipc': 42,
      'networkExposed': 'no',
      'compatibilityEnginesEnabled': 'yes',
    });
    final script = File(
      '${dir.path}${Platform.pathSeparator}health_fields.dart',
    )..writeAsStringSync('void main() { print(${jsonEncode(payload)}); }\n');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final health = await client.healthSummary();

    expect(health.malwareEngineStatus, MalwareEngineStatus.unavailable);
    expect(health.aiModelInfo.featureSchemaVersion, 'unavailable');
    expect(health.yaraRuleCount, 0);
    expect(health.nativeSignatureCount, 0);
    expect(health.nativeRuleCount, 0);
    expect(
      health.lastError,
      allOf(<Matcher>[
        contains('local core health response had malformed engine_status'),
        contains('local core health response had malformed ai_status'),
        contains('local core health response had malformed ai_model.status'),
        contains(
          'local core health response had malformed ai_model.model_version',
        ),
        contains(
          'local core health response had malformed ai_model.feature_schema_version',
        ),
        contains('local core health response had malformed ai_model.message'),
        contains(
          'local core health response had malformed ai_model.production_ready boolean',
        ),
        contains('local core health response had malformed yara_rule_count'),
        contains(
          'local core health response had malformed native_signature_count',
        ),
        contains('local core health response had malformed native_rule_count'),
        contains('local core health response had malformed native_error'),
        contains('local core health response had malformed install_path'),
        contains('local core health response had malformed engine_directory'),
        contains('local core health response had malformed ipc'),
        contains(
          'local core health response had malformed network_exposed boolean',
        ),
      ]),
    );
  });

  test('health summary list diagnostics are bounded and visible', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final healthParser = clientSource.substring(
      clientSource.indexOf('Future<LocalCoreHealth> healthSummary'),
      clientSource.indexOf('Future<List<QuarantineRecord>> listQuarantine'),
    );
    final listParser = clientSource.substring(
      clientSource.indexOf('List<String> _ipcStringList'),
      clientSource.indexOf('String _truncateIpcText'),
    );

    expect(healthParser, contains("fieldName: 'engine_paths_checked'"));
    expect(healthParser, contains('diagnostics: healthDiagnostics'));
    expect(healthParser, contains('_healthLastErrorWithDiagnostics'));
    expect(listParser, contains('inspectedItems >= maxEntries'));
    expect(
      listParser,
      contains(r'local core health response had malformed $fieldName list'),
    );
    expect(
      listParser,
      contains(r'local core health response truncated $fieldName list'),
    );
    expect(listParser, contains(r'dropped $malformedItems'));
  });

  test('home last scan summary preserves coverage warnings', () async {
    final homeSource = File(
      'lib/features/home/home_screen.dart',
    ).readAsStringSync();

    expect(homeSource, contains('_lastScanDetail'));
    expect(homeSource, contains('report.message?.trim()'));
    expect(homeSource, contains('report.scanErrors.isNotEmpty'));
    expect(homeSource, contains('skipped files were not reported clean'));
  });

  test('action result parser rejects malformed IPC responses', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final actionParser = clientSource.substring(
      clientSource.indexOf('LocalCoreActionResult _actionResult'),
      clientSource.indexOf('String? _watcherProtocolError'),
    );

    expect(actionParser, contains('response == null'));
    expect(actionParser, contains('returned no response'));
    expect(actionParser, contains('ok != false'));
    expect(actionParser, contains('malformed action response'));
    expect(
      actionParser,
      contains("final error = _ipcDiagnosticOrNull(response['error'])"),
    );
    expect(actionParser, isNot(contains('error.trim()')));
    expect(actionParser, contains("final protocolWarnings = _scanErrorList("));
    expect(actionParser, contains('protocolWarnings.isNotEmpty'));
    expect(actionParser, contains('action success with protocol warnings'));
    expect(actionParser, contains("return const LocalCoreActionResult.ok()"));
  });

  test('watcher parser rejects malformed IPC responses', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final watcherParser = clientSource.substring(
      clientSource.indexOf('String? _watcherProtocolError'),
      clientSource.indexOf('Future<void> _sendCancelScanRequest'),
    );

    expect(watcherParser, contains('_watcherProtocolError'));
    expect(watcherParser, contains('returned no watcher response'));
    expect(watcherParser, contains('malformed watcher response'));
    expect(
      watcherParser,
      contains("final error = _ipcDiagnosticOrNull(response['error'])"),
    );
    expect(watcherParser, isNot(contains('error.trim()')));
    expect(watcherParser, contains("final protocolWarnings = _scanErrorList("));
    expect(watcherParser, contains('protocolWarnings.isNotEmpty'));
    expect(watcherParser, contains('watcher success with protocol warnings'));
    expect(watcherParser, contains('return null'));
    expect(clientSource, contains("final watcher = response!['watcher'];"));
  });

  test('action responses with protocol warnings fail at runtime', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-action-warning-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final payload = jsonEncode(<String, Object?>{
      'ok': true,
      'scanErrors': <String>['malformed prelude before action result'],
    });
    final script = File('${dir.path}${Platform.pathSeparator}action.dart')
      ..writeAsStringSync('void main() { print(${jsonEncode(payload)}); }\n');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final result = await client.configureGuardMode(ProtectionMode.monitorOnly);

    expect(result.ok, isFalse);
    expect(result.error, contains('action success with protocol warnings'));
    expect(result.error, contains('malformed prelude before action result'));
  });

  test('watcher responses with protocol warnings fail at runtime', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-watcher-warning-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final payload = jsonEncode(<String, Object?>{
      'ok': true,
      'scanErrors': <String>['malformed prelude before watcher result'],
      'watcher': <String, Object?>{
        'active': true,
        'mode': 'userModeBestEffort',
        'watchedPaths': <String>['C:/Users/Brent/Downloads'],
        'limitations': <String>[],
      },
    });
    final script = File('${dir.path}${Platform.pathSeparator}watcher.dart')
      ..writeAsStringSync('void main() { print(${jsonEncode(payload)}); }\n');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final state = await client.startWatch(['C:/Users/Brent/Downloads']);

    expect(state.active, isFalse);
    expect(state.mode, 'off');
    expect(state.error, contains('watcher success with protocol warnings'));
    expect(state.error, contains('malformed prelude before watcher result'));
  });

  test('watch-poll scan parser exposes bounded poll summary', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-watch-poll-ipc-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final payload = jsonEncode(<String, Object?>{
      'ok': true,
      'watcher': <String, Object?>{
        'active': true,
        'mode': 'userModeBestEffort',
        'watchedPaths': <String>['C:/Users/Brent/Downloads'],
        'limitations': <String>[],
      },
      'poll': <String, Object?>{
        'active': true,
        'mode': 'finiteUserModePolling',
        'duration_ms': 4000,
        'poll_interval_ms': 200,
        'max_events': 8,
        'initial_files_observed': 3,
        'polls_completed': 4,
        'events_observed': 1,
        'files_scanned': 1,
        'threats_found': 1,
        'quarantined_files': 1,
        'scan_errors': <String>['watch scan diagnostic'],
        'limitations': <String>[
          'finite-polling-session-only',
          'post-write-detection-only',
        ],
      },
    });
    final script = File('${dir.path}${Platform.pathSeparator}watch_poll.dart')
      ..writeAsStringSync('void main() { print(${jsonEncode(payload)}); }\n');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final result = await client.watchPollScan(
      ['C:/Users/Brent/Downloads'],
      duration: const Duration(seconds: 4),
      pollInterval: const Duration(milliseconds: 200),
      maxEvents: 8,
    );

    expect(result.ok, isTrue);
    expect(result.watcher.active, isTrue);
    expect(result.poll.mode, 'finiteUserModePolling');
    expect(result.poll.durationMs, 4000);
    expect(result.poll.pollIntervalMs, 200);
    expect(result.poll.maxEvents, 8);
    expect(result.poll.initialFilesObserved, 3);
    expect(result.poll.pollsCompleted, 4);
    expect(result.poll.eventsObserved, 1);
    expect(result.poll.filesScanned, 1);
    expect(result.poll.threatsFound, 1);
    expect(result.poll.quarantinedFiles, 1);
    expect(result.poll.scanErrors, contains('watch scan diagnostic'));
    expect(result.poll.limitations, contains('post-write-detection-only'));
  });

  test('watch-poll parser rejects contradictory success evidence', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-watch-poll-contradiction-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final payloads = <Map<String, Object?>>[
      {
        'ok': true,
        'watcher': <String, Object?>{
          'active': false,
          'mode': 'stopped',
          'watchedPaths': <String>[],
          'limitations': <String>[],
        },
        'poll': _watchPollFixture(mode: 'finiteUserModePolling'),
      },
      {
        'ok': true,
        'watcher': <String, Object?>{
          'active': true,
          'mode': 'userModeBestEffort',
          'watchedPaths': <String>['C:/Users/Brent/Downloads'],
          'limitations': <String>[],
        },
        'poll': _watchPollFixture(mode: 'unexpectedMode'),
      },
    ];

    final errors = <String>[];
    for (var index = 0; index < payloads.length; index += 1) {
      final payload = jsonEncode(payloads[index]);
      final script = File(
        '${dir.path}${Platform.pathSeparator}watch_poll_$index.dart',
      )..writeAsStringSync('void main() { print(${jsonEncode(payload)}); }\n');
      final client = LocalCoreClient(
        executableOverride: _dartExecutable(),
        executableArguments: [script.path],
      );

      final result = await client.watchPollScan(['C:/Users/Brent/Downloads']);

      expect(result.ok, isFalse);
      errors.add(result.error ?? '');
    }

    expect(errors[0], contains('contradictory watcher and poll activity'));
    expect(errors[1], contains('invalid active poll mode'));
  });

  test('watch-poll parser rejects malformed IPC responses', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final parser = clientSource.substring(
      clientSource.indexOf(
        'WatchPollScanResult _watchPollScanResultFromResponse',
      ),
      clientSource.indexOf(
        'ProcessSnapshotReport _processSnapshotReportFromResponse',
      ),
    );

    expect(clientSource, contains("Future<WatchPollScanResult> watchPollScan"));
    expect(clientSource, contains("'command': 'watch_poll_scan'"));
    expect(clientSource, contains("'duration_ms': duration.inMilliseconds"));
    expect(
      clientSource,
      contains("'poll_interval_ms': pollInterval.inMilliseconds"),
    );
    expect(clientSource, contains("'max_events': maxEvents"));
    expect(parser, contains('returned no watch-poll response'));
    expect(parser, contains('Watch-poll scan request failed.'));
    expect(parser, contains('watch-poll response had malformed ok'));
    expect(
      parser,
      contains('Watch-poll response did not include watcher state'),
    );
    expect(parser, contains('watch-poll response was missing poll summary'));
    expect(parser, contains('_watchPollIntField'));
    expect(parser, contains('_watchPollConsistencyError'));
    expect(parser, contains('local core watch-poll response had malformed'));
  });

  test('watcher state parser bounds IPC fields', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    final parser = clientSource.substring(
      clientSource.indexOf('factory RealtimeWatcherState.fromJson'),
      clientSource.indexOf('class LocalCoreHealth'),
    );

    expect(parser, contains('final active = _watcherBool'));
    expect(parser, contains('active: active'));
    expect(parser, contains('mode: _watcherMode'));
    expect(parser, contains("'userModeBestEffort'"));
    expect(parser, contains("'stopped'"));
    expect(parser, contains("'off'"));
    expect(parser, contains("'unknown'"));
    expect(parser, contains('Watcher response had unsupported mode.'));
    expect(parser, contains("fieldName: 'watched_paths'"));
    expect(parser, contains("fieldName: 'limitations'"));
    expect(parser, contains("fieldName: 'active'"));
    expect(parser, contains('error: _watcherErrorWithDiagnostics'));
    expect(parser, contains('inspectedItems >= 64'));
  });

  test('watcher state exposes malformed list diagnostics', () {
    final state = RealtimeWatcherState.fromJson({
      'active': true,
      'mode': 'watching',
      'watchedPaths': 'not-a-list',
      'limitations': 'not-a-list',
    });

    expect(state.active, isTrue);
    expect(state.watchedPaths, isEmpty);
    expect(state.limitations.single, contains('malformed limitations list'));
    expect(state.error, contains('malformed watched_paths list'));
    expect(state.error, contains('malformed limitations list'));
  });

  test('watcher state exposes malformed active diagnostics', () {
    final state = RealtimeWatcherState.fromJson({
      'active': 'yes',
      'mode': 'watching',
      'watchedPaths': const <String>[],
      'limitations': const <String>[],
    });

    expect(state.active, isFalse);
    expect(state.error, contains('malformed active boolean'));
    expect(state.mode, 'unknown');
    expect(state.error, contains('unsupported mode'));
  });

  test('watcher state exposes active without paths diagnostics', () {
    final state = RealtimeWatcherState.fromJson({
      'active': true,
      'mode': 'userModeBestEffort',
      'watchedPaths': const <String>[],
      'limitations': const <String>[],
    });

    expect(state.active, isTrue);
    expect(state.watchedPaths, isEmpty);
    expect(
      state.limitations,
      contains('Watcher response reported active without watched paths.'),
    );
    expect(state.error, contains('active without watched paths'));
  });

  test('watcher state list diagnostics are bounded and visible', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final parser = clientSource.substring(
      clientSource.indexOf('factory RealtimeWatcherState.fromJson'),
      clientSource.indexOf('class LocalCoreHealth'),
    );

    expect(parser, contains('_watcherErrorWithDiagnostics'));
    expect(
      parser,
      contains('Watcher response had malformed \$fieldName list.'),
    );
    expect(parser, contains('Watcher response truncated \$fieldName list.'));
    expect(
      parser,
      contains('Watcher response dropped \$malformedItems malformed'),
    );
    expect(parser, contains("parts.join(' ')"));
  });

  test('scan report parser records malformed numeric fields', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    expect(clientSource, contains('_scanIntField'));
    expect(clientSource, contains('_optionalScanIntField'));
    expect(clientSource, contains('_parseNonNegativeInt'));
    expect(clientSource, isNot(contains('int _intField(')));
    expect(
      clientSource,
      contains('local core scan response had malformed numeric field'),
    );
    expect(
      clientSource,
      contains('local core scan response was missing numeric field'),
    );
    expect(clientSource, contains('_parseProgressPercent'));
  });

  test('scan report parser validates scan error lists', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    expect(clientSource, contains('List<String> _scanErrorList'));
    expect(
      clientSource,
      contains('local core scan response had malformed scan_errors list'),
    );
    expect(
      clientSource,
      contains('local core scan response truncated scan_errors list'),
    );
    expect(
      clientSource,
      contains('local core scan response dropped \$malformedItems malformed'),
    );
    expect(clientSource, contains('_ipcDiagnosticOrNull(item)'));
  });

  test('scan IPC protocol warnings are bounded and surfaced', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    expect(clientSource, contains('_maxIpcProtocolWarnings'));
    expect(clientSource, contains('_recordIpcProtocolWarning'));
    expect(clientSource, contains('_responseWithIpcProtocolWarnings'));
    expect(clientSource, contains('const Utf8Decoder(allowMalformed: true)'));
    expect(clientSource, contains('_boundedIpcStdoutLines(process.stdout)'));
    expect(clientSource, contains('_maxIpcStdoutLineLength'));
    expect(clientSource, contains('_ipcStdoutLineTruncationSuffix'));
    expect(clientSource, contains('Stream<String> _boundedIpcStdoutLines'));
    expect(clientSource, contains('String _truncatedIpcStdoutLine'));
    expect(clientSource, contains('returned non-object JSON on stdout'));
    expect(clientSource, contains('malformed progress JSON on stdout'));
  });

  test('local core subprocess diagnostics are bounded', () async {
    final clientSource = readNormalizedSource(
      'lib/core/local_core/local_core_client.dart',
    );
    final selfTest = clientSource.substring(
      clientSource.indexOf('Future<String> runProtectionSelfTest'),
      clientSource.indexOf('Future<LocalCoreActionResult> configureGuardMode'),
    );
    final callMethod = clientSource.substring(
      clientSource.indexOf('Future<Map<String, Object?>?> _call'),
      clientSource.indexOf('String _formatDuration'),
    );
    final powerShell = clientSource.substring(
      clientSource.indexOf('Future<String?> _runElevatedPowerShell'),
      clientSource.indexOf('String _powershellEncodedCommand'),
    );
    final cancelMethod = clientSource.substring(
      clientSource.indexOf('Future<void> _sendCancelScanRequest'),
      clientSource.indexOf('String? _localCoreExecutable'),
    );

    expect(clientSource, contains('Future<String> _collectBoundedIpcText'));
    expect(clientSource, contains('Utf8Decoder(allowMalformed: true)'));
    expect(selfTest, contains('_collectBoundedIpcText(process.stdout)'));
    expect(selfTest, contains('_collectBoundedIpcText(process.stderr)'));
    expect(selfTest, contains('(processStarter ?? Process.start)'));
    expect(selfTest, contains('guardExecutableArguments'));
    expect(
      selfTest,
      contains("_executableLaunchBlocker(\n      'Avorax Guard Service'"),
    );
    expect(selfTest, contains('_protectionSelfTestTimeout'));
    expect(selfTest, contains('await _ipcTimeoutTerminationStatus'));
    expect(selfTest, contains('await _ipcReapStatus(process)'));
    expect(selfTest, contains('Protection self-test timed out after'));
    expect(
      selfTest,
      isNot(contains('process.stdout.transform(utf8.decoder).join()')),
    );
    expect(callMethod, contains('_collectBoundedIpcText(process.stderr)'));
    expect(callMethod, contains('(processStarter ?? Process.start)'));
    expect(
      callMethod,
      contains("_executableLaunchBlocker(\n      'Avorax Core Service'"),
    );
    expect(powerShell, contains('_collectBoundedIpcText(process.stderr)'));
    expect(powerShell, contains("_ipcDiagnosticOrNull('\$error')"));
    expect(powerShell, contains('_windowsPowerShellExecutable()'));
    expect(powerShell, contains('_powershellSingleQuoted(powerShell)'));
    expect(powerShell, contains("'-EncodedCommand'"));
    expect(powerShell, contains('_powershellEncodedCommand(launcher)'));
    expect(powerShell, isNot(contains("Process.start('powershell.exe'")));
    expect(powerShell, isNot(contains("'-Command'")));
    expect(cancelMethod, contains('_cancelIpcTimeout'));
    expect(cancelMethod, contains('(processStarter ?? Process.start)'));
    expect(
      cancelMethod,
      contains("_executableLaunchBlocker(\n      'Avorax Core Service'"),
    );
    expect(
      cancelMethod,
      contains('_collectLastIpcJsonResponse(process.stdout)'),
    );
    expect(cancelMethod, contains('await _ipcTimeoutTerminationStatus'));
    expect(cancelMethod, contains('await _ipcReapStatus(process)'));
    expect(cancelMethod, contains('Cancel IPC timed out after'));
    expect(cancelMethod, isNot(contains('process.stdout.drain')));
    expect(powerShell, contains('_elevatedPowerShellTimeout'));
    expect(powerShell, contains('_collectBoundedIpcText(process.stdout)'));
    expect(powerShell, contains('_powerShellLaunchDiagnostic('));
    expect(powerShell, contains('_timedOutIpcText(stdoutFuture)'));
    expect(powerShell, contains('_timedOutIpcText(stderrFuture)'));
    expect(powerShell, contains('stdout: stdout'));
    expect(powerShell, contains('stderr: stderr'));
    expect(powerShell, contains('await _ipcTimeoutTerminationStatus'));
    expect(powerShell, contains('await _ipcReapStatus(process)'));
    expect(powerShell, contains('PowerShell timed out after'));
    expect(clientSource, contains('String _ipcTerminationStatus(bool killed)'));
    expect(
      clientSource,
      contains('Future<String> _ipcTimeoutTerminationStatus'),
    );
    expect(clientSource, contains('_windowsTaskkillExecutable()'));
    expect(clientSource, contains('taskkill.exe'));
    expect(clientSource, contains("'/T'"));
    expect(clientSource, contains("'/F'"));
    expect(clientSource, contains('Future<String> _ipcReapStatus'));
    expect(clientSource, contains('_ipcProcessReapTimeout'));
    expect(clientSource, contains('Timed-out process did not exit within'));
    expect(
      clientSource,
      contains('stream collection did not finish after timeout cleanup'),
    );
    expect(
      powerShell,
      isNot(contains('process.stderr.transform(utf8.decoder).join()')),
    );
    expect(clientSource, contains('String _powerShellLaunchDiagnostic({'));
    expect(clientSource, contains('String _powershellSingleQuoted'));
    expect(clientSource, contains('String _windowsPowerShellExecutable'));
    expect(clientSource, contains('String _windowsSystemRoot'));
    expect(
      clientSource,
      contains("_checkedWindowsSystemRootEnvironmentPath('SystemRoot'"),
    );
    expect(
      clientSource,
      contains("_checkedWindowsSystemRootEnvironmentPath('WINDIR'"),
    );
    expect(clientSource, contains('_nonEmptyEnvironmentPath(name)'));
    expect(
      clientSource,
      contains('SystemRoot or WINDIR is required to locate'),
    );
    expect(clientSource, contains('root must be a local Windows drive path'));
    expect(clientSource, isNot(contains(r'C:\Windows')));
    expect(clientSource, contains('WindowsPowerShell'));
  });

  test(
    'service repair does not silence unexpected service-query failures',
    () async {
      final clientSource = File(
        'lib/core/local_core/local_core_client.dart',
      ).readAsStringSync();
      final repairMethod = clientSource.substring(
        clientSource.indexOf('Future<String> repairInstallation'),
        clientSource.indexOf('Future<String> openInstallReport'),
      );

      expect(repairMethod, contains("Get-Service -Name 'avorax_core_service'"));
      expect(repairMethod, contains('-ErrorAction Stop'));
      expect(
        repairMethod,
        contains("CategoryInfo.Category -ne 'ObjectNotFound'"),
      );
      expect(repairMethod, contains('throw'));
      expect(repairMethod, isNot(contains('SilentlyContinue')));
    },
  );

  test('source marker: cancel IPC verifies local core response', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final cancelMethod = clientSource.substring(
      clientSource.indexOf('Future<void> _sendCancelScanRequest'),
      clientSource.indexOf('String? _localCoreExecutable'),
    );

    expect(clientSource, contains('class _IpcJsonResponseCapture'));
    expect(
      clientSource,
      contains('Future<_IpcJsonResponseCapture> _collectLastIpcJsonResponse'),
    );
    expect(
      cancelMethod,
      contains('_collectLastIpcJsonResponse(process.stdout)'),
    );
    expect(cancelMethod, contains('_collectBoundedIpcText(process.stderr)'));
    expect(cancelMethod, contains('final exitCode = results[2] as int'));
    expect(cancelMethod, contains('if (exitCode != 0)'));
    expect(cancelMethod, contains("final ok = response['ok']"));
    expect(cancelMethod, contains('stdout.protocolWarnings.isNotEmpty'));
    expect(
      cancelMethod,
      contains('Cancel IPC returned response with protocol warnings'),
    );
    expect(cancelMethod, contains('if (ok == true) return'));
    expect(
      cancelMethod.indexOf('stdout.protocolWarnings.isNotEmpty'),
      lessThan(cancelMethod.indexOf('if (ok == true) return')),
    );
    expect(cancelMethod, contains('Cancel IPC returned no response.'));
    expect(cancelMethod, contains('Cancel IPC request failed.'));
    expect(cancelMethod, contains('Cancel IPC returned a malformed response'));
    expect(cancelMethod, isNot(contains('process.stdout.drain')));
    expect(cancelMethod, isNot(contains('process.stderr.drain')));
  });

  test('cancel responses with protocol warnings fail at runtime', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-cancel-warning-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final payload = jsonEncode(<String, Object?>{'ok': true});
    final script = File('${dir.path}${Platform.pathSeparator}cancel.dart')
      ..writeAsStringSync('''
void main() {
  print('malformed prelude before cancel result');
  print(${jsonEncode(payload)});
}
''');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final result = await client.cancelActiveScan();

    expect(result, isNotNull);
    expect(result, contains('Avorax local core cancel IPC failed'));
    expect(result, contains('no active scan process was available'));
    expect(
      result,
      contains('Cancel IPC returned response with protocol warnings'),
    );
    expect(result, contains('malformed prelude before cancel result'));
  });

  test('cancel IPC timeout reports cleanup at runtime', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-cancel-timeout-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = _writeSleepingDartScript(dir, 'cancel_timeout.dart');

    late Process process;
    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
      cancelIpcTimeout: const Duration(milliseconds: 50),
      ipcProcessReapTimeout: const Duration(seconds: 2),
      processStarter: (executable, arguments) async {
        process = await Process.start(executable, arguments);
        return process;
      },
    );

    final result = await client.cancelActiveScan();

    expect(result, isNotNull);
    expect(result, contains('Avorax local core cancel IPC failed'));
    expect(result, contains('Cancel IPC timed out after 50ms'));
    expect(result, contains('Termination requested.'));
    expect(
      result,
      anyOf(
        contains('Timed-out process exited with code'),
        contains('Timed-out process did not exit within'),
      ),
    );
    await _expectProcessExited(process, 'cancel IPC timeout fixture');
  });

  test('elevated PowerShell timeout reports cleanup at runtime', () async {
    if (!Platform.isWindows) return;
    final dir = Directory.systemTemp.createTempSync(
      'avorax-elevated-powershell-timeout-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final script = _writeSleepingDartScript(dir, 'elevated_timeout.dart');

    late Process process;
    final client = LocalCoreClient(
      processStarter: (_, _) async {
        process = await Process.start(_dartExecutable(), [script.path]);
        return process;
      },
      elevatedPowerShellTimeout: const Duration(milliseconds: 50),
      ipcProcessReapTimeout: const Duration(seconds: 2),
    );

    final result = await client.startCoreService();

    expect(result, contains('Avorax Core Service start failed'));
    expect(result, contains('PowerShell timed out after 50ms'));
    expect(result, contains('Termination requested.'));
    expect(
      result,
      anyOf(
        contains('Timed-out process exited with code'),
        contains('Timed-out process did not exit within'),
      ),
    );
    await _expectProcessExited(process, 'elevated PowerShell timeout fixture');
  });

  test('local core exception diagnostics are bounded', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final selfTest = clientSource.substring(
      clientSource.indexOf('Future<String> runProtectionSelfTest'),
      clientSource.indexOf('String _formatProtectionSelfTestSteps'),
    );
    final installReport = clientSource.substring(
      clientSource.indexOf('Future<String> openInstallReport'),
      clientSource.indexOf('Future<String?> cancelActiveScan'),
    );
    final cancelActive = clientSource.substring(
      clientSource.indexOf('Future<String?> cancelActiveScan'),
      clientSource.indexOf('Future<ScanReport> _scanCommand'),
    );
    final callMethod = clientSource.substring(
      clientSource.indexOf('Future<Map<String, Object?>?> _call'),
      clientSource.indexOf('String _formatDuration'),
    );
    final cancelIpc = clientSource.substring(
      clientSource.indexOf('Future<void> _sendCancelScanRequest'),
      clientSource.indexOf('String? _localCoreExecutable'),
    );
    final fileProbe = clientSource.substring(
      clientSource.indexOf('_FileProbeResult _regularFileProbe'),
      clientSource.indexOf('String _missingRegularFileMessage'),
    );

    for (final section in [
      selfTest,
      installReport,
      cancelActive,
      callMethod,
      cancelIpc,
      fileProbe,
    ]) {
      expect(section, contains('_ipcDiagnosticOrNull'));
      expect(section, isNot(contains(r'failed: $error')));
      expect(section, isNot(contains(r'report: $error')));
      expect(section, isNot(contains(r'fallback: $cancelError')));
      expect(section, isNot(contains(r'IPC failed: $error')));
      expect(section, isNot(contains(r'Unable to inspect $path: $error')));
    }
  });

  test('scan command fallback errors are bounded diagnostics', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    final scanCommand = clientSource.substring(
      clientSource.indexOf('Future<ScanReport> _scanCommand'),
      clientSource.indexOf('Future<Map<String, Object?>?> _call'),
    );

    expect(
      scanCommand,
      contains("final error = _ipcDiagnosticOrNull(response?['error'])"),
    );
    expect(scanCommand, contains('final protocolErrors = response == null'));
    expect(scanCommand, contains('scanErrors: scanErrors'));
    expect(scanCommand, contains('protocolErrors.first'));
  });

  test(
    'local core executable and report probes expose filesystem failures',
    () async {
      final clientSource = File(
        'lib/core/local_core/local_core_client.dart',
      ).readAsStringSync();
      final launcherSlice = clientSource.substring(
        clientSource.indexOf('Future<String> runProtectionSelfTest'),
        clientSource.indexOf('Future<String?> _runElevatedPowerShell'),
      );

      expect(launcherSlice, contains('_regularFileProbe(executable)'));
      expect(launcherSlice, contains('_regularFileProbe(candidate)'));
      expect(launcherSlice, contains('_missingRegularFileMessage('));
      expect(
        launcherSlice,
        contains('FileSystemEntity.typeSync(path, followLinks: false)'),
      );
      expect(launcherSlice, contains('FileSystemEntityType.file'));
      expect(launcherSlice, contains('on FileSystemException catch (error)'));
      expect(launcherSlice, contains('on ArgumentError catch (error)'));
      expect(launcherSlice, contains(r'Unable to inspect $path'));
      expect(launcherSlice, contains('probeErrors.take(3).join'));
      expect(launcherSlice, contains('_environmentPathOverride('));
      expect(launcherSlice, contains('Platform.environment[name]?.trim()'));
      expect(launcherSlice, contains('value == null || value.isEmpty'));
      expect(
        launcherSlice,
        contains('_checkedEnvironmentExecutablePath(primary)'),
      );
      expect(
        launcherSlice,
        contains('_checkedEnvironmentExecutablePath(legacy)'),
      );
      expect(
        launcherSlice,
        contains('must be an absolute local executable path'),
      );
      expect(launcherSlice, contains('_requiredResolvedExecutableParentPath('));
      expect(launcherSlice, contains('Platform.resolvedExecutable'));
      expect(launcherSlice, contains('_isAbsoluteLocalPath(parent)'));
      expect(launcherSlice, contains('must be an absolute local path.'));
      expect(launcherSlice, contains('_developmentExecutableCandidates('));
      expect(launcherSlice, contains('_candidateDevelopmentRepoRoots()'));
      expect(launcherSlice, contains('_isDevelopmentRepoRoot('));
      expect(launcherSlice, contains('apps'));
      expect(launcherSlice, contains('zentor_client'));
      expect(launcherSlice, contains('pubspec.yaml'));
      expect(launcherSlice, contains('Cargo.toml'));
      expect(
        launcherSlice,
        contains('final executablePath = File(executable).absolute.path'),
      );
      expect(launcherSlice, contains('_executableLaunchBlocker('));
      expect(
        launcherSlice,
        contains('executable path must be a local Windows drive path'),
      );
      expect(launcherSlice, contains('_regularFileProbe(path)'));
      expect(launcherSlice, contains('_isWindowsRemoteOrDevicePath(path)'));
      expect(
        launcherSlice,
        contains('final escapedExecutable = executablePath.replaceAll'),
      );
      expect(
        launcherSlice,
        isNot(contains('File(Platform.resolvedExecutable).parent.path')),
      );
      expect(launcherSlice, isNot(contains('File(executable).existsSync()')));
      expect(launcherSlice, isNot(contains('File(override).existsSync()')));
      expect(launcherSlice, isNot(contains('file.existsSync()')));
      expect(launcherSlice, isNot(contains('_regularFileExists')));
      expect(
        launcherSlice,
        isNot(
          contains(
            r'${Directory.current.path}${Platform.pathSeparator}$primaryName',
          ),
        ),
      );
      expect(
        launcherSlice,
        isNot(
          contains(
            r'${Directory.current.path}${Platform.pathSeparator}$legacyName',
          ),
        ),
      );
      expect(
        launcherSlice,
        isNot(
          contains(
            r'core${Platform.pathSeparator}zentor_local_core${Platform.pathSeparator}target',
          ),
        ),
      );
    },
  );

  test('install report Explorer launch validates local report path', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final installReport = clientSource.substring(
      clientSource.indexOf('Future<String> openInstallReport'),
      clientSource.indexOf('Future<String?> cancelActiveScan'),
    );
    final installReportValidation = clientSource.substring(
      clientSource.indexOf('String? _installReportLaunchBlocker'),
      clientSource.indexOf('_FileProbeResult _regularFileProbe'),
    );

    expect(installReport, contains('_installReportLaunchBlocker(report)'));
    expect(
      installReport,
      contains('final explorer = _windowsExplorerExecutable()'),
    );
    expect(
      installReport,
      contains('Process.start(explorer, _explorerSelectArguments(report))'),
    );
    expect(installReport, contains('_explorerSelectArguments(report)'));
    expect(installReportValidation, contains('_regularFileProbe(path)'));
    expect(installReportValidation, contains('_installReportAllowedRoots()'));
    expect(installReportValidation, contains('_localPathInside(root, path)'));
    expect(clientSource, contains('_installReportCandidates()'));
    expect(clientSource, contains('_programDataRoots()'));
    expect(clientSource, contains('_programFilesRoots()'));
    expect(clientSource, contains('_checkedEnvironmentDirectoryPath(name)'));
    expect(clientSource, contains("'ProgramData', 'PROGRAMDATA'"));
    expect(clientSource, contains("'ProgramFiles'"));
    expect(clientSource, contains("'ProgramW6432'"));
    expect(clientSource, contains("'ProgramFiles(x86)'"));
    expect(clientSource, contains('must be an absolute local directory path.'));
    expect(clientSource, contains('_resolvedExecutableParentPath()'));
    expect(
      installReportValidation,
      contains('String _windowsExplorerExecutable()'),
    );
    expect(installReportValidation, contains("'Windows Explorer'"));
    expect(installReportValidation, contains("'/select,'"));
    expect(installReportValidation, contains('report.absolute.path'));
    expect(clientSource, isNot(contains(r'C:\ProgramData\Avorax\reports')));
    expect(clientSource, isNot(contains(r'C:\Program Files\Avorax')));
    expect(installReportValidation, contains('_isWindowsRemoteOrDevicePath'));
    expect(installReportValidation, contains("normalized.startsWith(r'\\\\')"));
    expect(
      installReportValidation,
      contains("RegExp(r'^[A-Za-z]:\\\\').hasMatch(normalized)"),
    );
    expect(
      installReportValidation,
      contains("throw StateError('install report path contains traversal.')"),
    );
    expect(
      installReport,
      isNot(
        contains("Process.start('explorer.exe', ['/select,\${report.path}'])"),
      ),
    );
    expect(installReport, isNot(contains("Process.start('explorer.exe'")));
  });

  test('repair installation refuses development checkout executable', () async {
    if (!Platform.isWindows) return;
    final devExecutable = File(
      '../../target/release/zentor_local_core.exe',
    ).absolute;
    if (!devExecutable.existsSync()) return;

    var attemptedLaunch = false;
    final client = LocalCoreClient(
      executableOverride: devExecutable.path,
      processStarter: (_, _) {
        attemptedLaunch = true;
        throw StateError('repair should not launch PowerShell');
      },
    );

    final result = await client.repairInstallation();

    expect(attemptedLaunch, isFalse);
    expect(
      result,
      contains('Refusing to register a development checkout executable'),
    );
    expect(result, contains('Build and install Avorax first'));
  });

  test('source marker: repair installation uses installed-only executable', () {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final repairInstallation = clientSource.substring(
      clientSource.indexOf('Future<String> repairInstallation'),
      clientSource.indexOf('Future<String> openInstallReport'),
    );
    final installedResolver = clientSource.substring(
      clientSource.indexOf('String? _installedLocalCoreExecutableForRepair'),
      clientSource.indexOf('String? _guardServiceExecutable'),
    );

    expect(
      repairInstallation,
      contains('_installedLocalCoreExecutableForRepair()'),
    );
    expect(
      repairInstallation,
      contains('_developmentServiceRegistrationBlocker('),
    );
    expect(
      repairInstallation,
      contains('if (devCheckoutBlocker != null) return devCheckoutBlocker'),
    );
    expect(
      installedResolver,
      isNot(contains('_developmentExecutableCandidates(')),
    );
    expect(
      installedResolver,
      contains('Refusing to register a development checkout executable'),
    );
  });

  test('scan report and progress parsers bound string IPC fields', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    final reportParser = clientSource.substring(
      clientSource.indexOf('ScanReport _scanReportFromJson'),
      clientSource.indexOf('List<String> _scanErrorList'),
    );
    final progressParser = clientSource.substring(
      clientSource.indexOf('ScanProgress? _scanProgressFromJson'),
      clientSource.indexOf('double? _parseProgressPercent'),
    );
    final progressScanTypeHelper = clientSource.substring(
      clientSource.indexOf('ScanKind? _progressScanTypeField'),
      clientSource.indexOf('ScanJobStatus? _progressStatusField'),
    );
    final progressStatusHelper = clientSource.substring(
      clientSource.indexOf('ScanJobStatus? _progressStatusField'),
      clientSource.indexOf('String? _progressJobIdField'),
    );
    final progressJobIdHelper = clientSource.substring(
      clientSource.indexOf('String? _progressJobIdField'),
      clientSource.indexOf('String? _progressCurrentPathField'),
    );
    final progressDateTimeHelper = clientSource.substring(
      clientSource.indexOf('DateTime? _progressDateTimeField'),
      clientSource.indexOf('int? _progressIntField'),
    );
    final progressIntHelper = clientSource.substring(
      clientSource.indexOf('int? _progressIntField'),
      clientSource.indexOf('int? _progressOptionalIntField'),
    );
    final callParser = clientSource.substring(
      clientSource.indexOf('Future<Map<String, Object?>?> _call'),
      clientSource.indexOf('LocalCoreActionResult _actionResult'),
    );

    expect(
      reportParser,
      contains("_scanReportStatusField(json['status'], scanErrors)"),
    );
    expect(
      reportParser,
      contains('final status = _scanReportStatusWithErrorEvidence('),
    );
    expect(reportParser, contains('status: status'));
    expect(
      clientSource,
      contains('ScanStatus _scanReportStatusWithErrorEvidence'),
    );
    expect(
      clientSource,
      contains('status == ScanStatus.clean && scanErrors.isNotEmpty'),
    );
    expect(clientSource, contains('return ScanStatus.completedWithErrors'));
    expect(reportParser, contains('final parsedKind = _scanReportKindField'));
    expect(
      reportParser,
      contains('final parsedActionMode = _scanReportActionModeField'),
    );
    expect(reportParser, contains("final progress = _scanProgressField"));
    expect(
      reportParser.indexOf("final progress = _scanProgressField"),
      lessThan(
        reportParser.indexOf(
          'final status = _scanReportStatusWithErrorEvidence',
        ),
      ),
    );
    expect(reportParser, contains('kind: parsedKind'));
    expect(reportParser, contains('actionMode: parsedActionMode'));
    expect(
      reportParser,
      contains('local core scan response was missing status'),
    );
    expect(
      reportParser,
      contains('local core scan response had malformed status'),
    );
    expect(reportParser, contains('local core scan response was missing kind'));
    expect(
      reportParser,
      contains('local core scan response had malformed kind'),
    );
    expect(
      reportParser,
      contains('local core scan response was missing action_mode'),
    );
    expect(
      reportParser,
      contains('local core scan response had malformed action_mode'),
    );
    expect(
      reportParser,
      contains('final currentPath = _scanReportCurrentPathField'),
    );
    expect(
      reportParser,
      contains('local core scan response had malformed current_path'),
    );
    expect(reportParser, contains('final message = _scanReportMessageField'));
    expect(
      reportParser,
      contains('local core scan response had malformed message'),
    );
    expect(reportParser, contains('_scanProgressField(json[\'progress\']'));
    expect(clientSource, contains('ScanStatus? _scanStatusOrNull'));
    expect(clientSource, isNot(contains('ScanStatus _scanStatus(')));
    expect(progressParser, contains('final rawJobId'));
    expect(progressParser, contains('final jobId = _progressJobIdField'));
    expect(
      progressParser,
      contains('local core scan progress was missing job_id'),
    );
    expect(
      progressParser,
      contains('local core scan progress had malformed job_id'),
    );
    expect(progressParser, contains('final rawScanType'));
    expect(progressParser, contains('final rawStatus'));
    expect(progressParser, contains('final rawCurrentPath'));
    expect(progressParser, contains('final scanType = _progressScanTypeField'));
    expect(progressParser, contains('final status = _progressStatusField'));
    expect(
      progressParser,
      contains('local core scan progress was missing scan_type'),
    );
    expect(
      progressParser,
      contains('local core scan progress had malformed scan_type'),
    );
    expect(
      progressParser,
      contains('local core scan progress was missing status'),
    );
    expect(
      progressParser,
      contains('local core scan progress had malformed status'),
    );
    expect(progressParser, contains('currentPath: _progressCurrentPathField'));
    expect(
      progressParser,
      contains('local core scan progress had malformed current_path'),
    );
    expect(progressParser, contains('_progressIntField'));
    for (final field in <String>[
      'filesScanned',
      'foldersScanned',
      'bytesScanned',
      'threatsFound',
      'suspiciousFound',
      'skippedFiles',
      'permissionDeniedCount',
      'elapsedSeconds',
    ]) {
      expect(progressParser, contains('final $field = _progressIntField'));
      expect(progressParser, contains('$field == null'));
      expect(progressParser, contains('$field: $field'));
    }
    expect(
      progressParser,
      contains('final startedAt = _progressDateTimeField'),
    );
    expect(
      progressParser,
      contains('final updatedAt = _progressDateTimeField'),
    );
    expect(progressParser, contains('startedAt == null'));
    expect(progressParser, contains('updatedAt == null'));
    expect(progressParser, contains('jobId == null'));
    expect(progressParser, contains('scanType == null'));
    expect(progressParser, contains('status == null'));
    expect(progressParser, contains('return null;'));
    expect(progressParser, contains('jobId: jobId'));
    expect(progressParser, contains('scanType: scanType'));
    expect(progressParser, contains('status: status'));
    expect(progressParser, contains('startedAt: startedAt'));
    expect(progressParser, contains('updatedAt: updatedAt'));
    expect(progressParser, contains('_progressOptionalIntField'));
    expect(progressParser, contains('_progressPercentField'));
    expect(progressParser, contains('_progressDateTimeField'));
    expect(
      progressParser,
      contains(r'local core scan progress had malformed $snake timestamp'),
    );
    expect(
      progressParser,
      contains(r'local core scan progress was missing $snake timestamp'),
    );
    expect(
      progressParser,
      contains(r'local core scan progress had malformed numeric field $snake'),
    );
    expect(
      progressParser,
      contains(r'local core scan progress was missing numeric field $snake'),
    );
    expect(
      progressParser,
      contains(
        r'local core scan progress had out-of-range percentage field $snake',
      ),
    );
    expect(clientSource, contains('malformed progress object'));
    expect(progressScanTypeHelper, contains('return null;'));
    expect(progressScanTypeHelper, isNot(contains('ScanKind.custom')));
    expect(progressStatusHelper, contains('return null;'));
    expect(progressStatusHelper, isNot(contains('ScanJobStatus.running')));
    expect(progressJobIdHelper, contains('return null;'));
    expect(progressJobIdHelper, isNot(contains("return '';")));
    expect(progressDateTimeHelper, contains('return null;'));
    expect(progressDateTimeHelper, isNot(contains('DateTime.now().toUtc()')));
    expect(progressIntHelper, contains('return null;'));
    expect(progressIntHelper, isNot(contains('return 0;')));
    expect(callParser, contains('final progressDiagnostics = <String>[]'));
    expect(callParser, contains('_recordIpcProtocolWarning'));
    expect(callParser, contains('progress != null && onProgress != null'));
  });

  test('scan report parser drops malformed threat evidence', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    expect(clientSource, contains('_requiredThreatString'));
    expect(clientSource, contains('_requiredThreatSha256'));
    expect(clientSource, contains('_isSha256'));
    expect(
      clientSource,
      contains('local core scan response dropped malformed threat row'),
    );
    expect(clientSource, isNot(contains('threats.whereType<Map>()')));
    expect(
      clientSource,
      contains('local core scan response dropped malformed threat'),
    );
    expect(clientSource, contains('_boundedInt'));
  });

  test('threat parser bounds optional IPC fields', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    final parser = clientSource.substring(
      clientSource.indexOf('ThreatResult? _threatFromJson'),
      clientSource.indexOf('String? _requiredThreatString'),
    );

    expect(parser, contains('_requiredThreatString'));
    expect(parser, contains('_requiredThreatSha256'));
    expect(parser, contains("final threatName = _requiredThreatString("));
    expect(
      parser,
      contains("final engine = _requiredThreatString(json, 'engine', 'engine'"),
    );
    expect(parser, contains('threatName == null'));
    expect(parser, contains('engine == null'));
    expect(parser, contains('final detectedAt = _threatDateTimeField('));
    expect(parser, contains('detectedAt == null'));
    expect(parser, contains('final sizeBytes = _threatIntField('));
    expect(parser, contains('sizeBytes == null'));
    expect(parser, contains('final detectionType = _threatEnumField('));
    expect(parser, contains('final threatCategory = _threatEnumField('));
    expect(parser, contains('final confidence = _threatEnumField('));
    expect(parser, contains('final recommendedAction = _threatEnumField('));
    expect(parser, contains('final status = _threatEnumField('));
    expect(parser, contains('final riskScore = _riskScoreFromJson('));
    expect(
      parser,
      contains('final reasonSummary = _requiredThreatDiagnosticField('),
    );
    expect(parser, contains('detectionType == null'));
    expect(parser, contains('threatCategory == null'));
    expect(parser, contains('confidence == null'));
    expect(parser, contains('recommendedAction == null'));
    expect(parser, contains('status == null'));
    expect(parser, contains('riskScore == null'));
    expect(parser, contains('reasonSummary == null'));
    expect(parser, contains('_optionalThreatStringField'));
    expect(parser, contains('_threatDateTimeField'));
    expect(parser, contains('_threatIntField'));
    expect(parser, contains('_threatEnumField'));
    expect(parser, contains('_requiredThreatDiagnosticField'));
    expect(parser, contains("'detection_type'"));
    expect(parser, contains("'threat_category'"));
    expect(parser, contains("'threat_name'"));
    expect(parser, contains("'recommended_action'"));
    expect(parser, contains("'reason_summary'"));
    expect(parser, contains('threatName: threatName'));
    expect(parser, contains('engine: engine'));
    expect(parser, contains('detectedAt: detectedAt'));
    expect(parser, contains('sizeBytes: sizeBytes'));
    expect(parser, contains('detectionType: detectionType'));
    expect(parser, contains('threatCategory: threatCategory'));
    expect(parser, contains('confidence: confidence'));
    expect(parser, contains('recommendedAction: recommendedAction'));
    expect(parser, contains('status: status'));
    expect(parser, contains('riskScore: riskScore'));
    expect(parser, contains('reasonSummary: reasonSummary'));
    expect(
      clientSource,
      contains(r'local core scan response had malformed threat $fieldName'),
    );
    expect(
      clientSource,
      contains(
        r'local core scan response had malformed threat numeric field $snake',
      ),
    );
    expect(
      clientSource,
      contains(
        r'local core scan response was missing threat numeric field $snake',
      ),
    );
    final threatIntHelper = clientSource.substring(
      clientSource.indexOf('int? _threatIntField'),
      clientSource.indexOf('T? _threatEnumField'),
    );
    expect(threatIntHelper, contains('return null;'));
    expect(threatIntHelper, isNot(contains('return 0;')));
    final threatEnumHelper = clientSource.substring(
      clientSource.indexOf('T? _threatEnumField'),
      clientSource.indexOf('DateTime? _threatDateTimeField'),
    );
    final requiredThreatDiagnosticHelper = clientSource.substring(
      clientSource.indexOf('String? _requiredThreatDiagnosticField'),
      clientSource.indexOf('int? _threatIntField'),
    );
    expect(
      threatEnumHelper,
      contains(r'local core scan response was missing threat $fieldName'),
    );
    expect(threatEnumHelper, contains('return null;'));
    expect(threatEnumHelper, isNot(contains('fallback')));
    expect(
      requiredThreatDiagnosticHelper,
      contains(r'local core scan response was missing threat $fieldName'),
    );
    expect(requiredThreatDiagnosticHelper, contains('return null;'));
    expect(
      requiredThreatDiagnosticHelper,
      contains('_optionalThreatDiagnosticField(raw, fieldName, scanErrors)'),
    );
    expect(parser, isNot(contains("_ipcStringOrNull(_field(json, 'fileName'")));
    expect(parser, isNot(contains('threatName: _ipcString')));
    expect(parser, isNot(contains("engine: _ipcString(json['engine']")));
    expect(clientSource, isNot(contains('String _threatStringField')));
    expect(parser, isNot(contains("fallback: 'Suspicious file'")));
    expect(parser, isNot(contains("fallback: 'zentor'")));
    expect(parser, isNot(contains('DetectionType.unknown')));
    expect(parser, isNot(contains('ThreatCategory.unknown')));
    expect(parser, isNot(contains('ThreatConfidence.low')));
    expect(parser, isNot(contains('RecommendedAction.review')));
    expect(parser, isNot(contains('ThreatResultStatus.detected')));
    expect(parser, isNot(contains("??\n          ''")));
    expect(
      parser,
      isNot(
        contains("reasonSummary:\n          _optionalThreatDiagnosticField"),
      ),
    );
    expect(parser, isNot(contains("_ipcStringOrNull(json['status'])")));
  });

  test('threat timestamp parser reports malformed IPC fields', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final threatTimestampParser = clientSource.substring(
      clientSource.indexOf('ThreatResult? _threatFromJson'),
      clientSource.indexOf('bool _isSha256'),
    );

    expect(clientSource, contains('_maxIpcTimestampTextLength'));
    expect(clientSource, contains('DateTime? _threatDateTimeField'));
    expect(
      clientSource,
      contains('local core scan response had malformed threat timestamp'),
    );
    expect(
      clientSource,
      contains('local core scan response was missing threat timestamp'),
    );
    expect(clientSource, contains('DateTime.tryParse(text)'));
    expect(threatTimestampParser, isNot(contains('DateTime.now().toUtc()')));
  });

  test('risk score parser bounds IPC evidence payloads', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    final parser = clientSource.substring(
      clientSource.indexOf('RiskScore? _riskScoreFromJson'),
      clientSource.indexOf('int? _boundedInt'),
    );
    final riskScoreHead = clientSource.substring(
      clientSource.indexOf('RiskScore? _riskScoreFromJson'),
      clientSource.indexOf('String? _riskReasonStringField'),
    );
    final riskReasonHelpers = clientSource.substring(
      clientSource.indexOf('String? _riskReasonStringField'),
      clientSource.indexOf('T? _riskScoreEnumField'),
    );
    final riskScoreEnumHelper = clientSource.substring(
      clientSource.indexOf('T? _riskScoreEnumField'),
      clientSource.indexOf('int? _boundedInt'),
    );

    expect(parser, contains('RiskScore? _riskScoreFromJson'));
    expect(
      parser,
      contains('local core scan response was missing risk_score object'),
    );
    expect(parser, contains('return null;'));
    expect(parser, contains('_maxRiskReasons'));
    expect(parser, contains('_maxRiskEngines'));
    expect(parser, contains('parsedReasons.length >= _maxRiskReasons'));
    expect(parser, contains('parsedEngines.length >= _maxRiskEngines'));
    expect(parser, contains('scanErrors?.add'));
    expect(parser, contains('_riskReasonStringField'));
    expect(parser, contains('_optionalRiskReasonDiagnosticField'));
    expect(parser, contains('_riskReasonIntField'));
    expect(parser, contains('_riskReasonEnumField'));
    expect(parser, contains('_riskScoreEnumField'));
    expect(parser, contains('local core scan response was missing risk score'));
    expect(
      parser,
      contains(r'local core scan response was missing risk_score $fieldName'),
    );
    expect(
      parser,
      contains(r'local core scan response had malformed risk_score $fieldName'),
    );
    expect(
      parser,
      contains(
        r'local core scan response was missing risk reason $index $fieldName',
      ),
    );
    expect(
      parser,
      contains(
        r'local core scan response had malformed risk reason $index $fieldName',
      ),
    );
    expect(
      parser,
      contains('local core scan response had malformed risk score'),
    );
    expect(parser, contains('final id = _riskReasonStringField('));
    expect(parser, contains('final title = _riskReasonStringField('));
    expect(parser, contains('final weight = _riskReasonIntField('));
    expect(parser, contains('final severity = _riskReasonEnumField('));
    expect(parser, contains('final source = _riskReasonEnumField('));
    expect(parser, contains('id == null'));
    expect(parser, contains('title == null'));
    expect(parser, contains('weight == null'));
    expect(parser, contains('severity == null'));
    expect(parser, contains('source == null'));
    expect(parser, contains('id: id'));
    expect(parser, contains('title: title'));
    expect(parser, contains('weight: weight'));
    expect(parser, contains('severity: severity'));
    expect(parser, contains('source: source'));
    expect(parser, contains('final verdict = _riskScoreEnumField('));
    expect(parser, contains('final confidence = _riskScoreEnumField('));
    expect(parser, contains('final recommendedAction = _riskScoreEnumField('));
    expect(parser, contains('score == null'));
    expect(parser, contains('verdict == null'));
    expect(parser, contains('confidence == null'));
    expect(parser, contains('recommendedAction == null'));
    expect(parser, contains('score: score'));
    expect(parser, contains('verdict: verdict'));
    expect(parser, contains('confidence: confidence'));
    expect(parser, contains('recommendedAction: recommendedAction'));
    expect(
      parser,
      contains('local core scan response dropped malformed risk reason'),
    );
    expect(
      parser,
      contains('local core scan response dropped malformed risk engine'),
    );
    expect(riskScoreEnumHelper, contains('return null;'));
    expect(riskScoreEnumHelper, isNot(contains('fallback')));
    expect(riskScoreHead, isNot(contains('score: score ?? 0')));
    expect(riskScoreHead, isNot(contains('RiskVerdict.unknown')));
    expect(riskScoreHead, isNot(contains('ThreatConfidence.low')));
    expect(riskScoreHead, isNot(contains('RecommendedAction.review')));
    expect(riskReasonHelpers, contains('String? _riskReasonStringField'));
    expect(riskReasonHelpers, contains('int? _riskReasonIntField'));
    expect(riskReasonHelpers, contains('T? _riskReasonEnumField'));
    expect(riskReasonHelpers, contains('return null;'));
    expect(riskReasonHelpers, isNot(contains("return '';")));
    expect(riskReasonHelpers, isNot(contains('return 0;')));
    expect(riskReasonHelpers, isNot(contains('fallback')));
    expect(riskScoreHead, isNot(contains('RiskSeverity.info')));
    expect(riskScoreHead, isNot(contains('RiskReasonSource.heuristic')));
    expect(
      parser,
      isNot(contains("detail: _ipcDiagnosticOrNull(reason['detail'])")),
    );
    expect(parser, isNot(contains("_ipcStringOrNull(json['verdict'])")));
  });

  test('record parsers validate actionable record fields', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final parser = clientSource.substring(
      clientSource.indexOf('QuarantineRecord? _quarantineRecordFromJson'),
      clientSource.indexOf('Future<LocalCoreActionResult> quarantineThreat'),
    );

    expect(clientSource, contains('_quarantineRecordFromJson'));
    expect(clientSource, contains('Quarantine response record \$index'));
    expect(clientSource, contains('Allowlist response entry \$index'));
    expect(clientSource, contains('String? _recordPathField(Object? value)'));
    expect(clientSource, contains('_ipcStringOrNull('));
    expect(clientSource, contains('String? _recordId(Object? value)'));
    expect(clientSource, contains(r"RegExp(r'^[A-Za-z0-9_-]{1,128}$')"));
    expect(clientSource, contains('_normalizedSha256'));
    expect(clientSource, contains('_recordDateTimeOrNull'));
    expect(clientSource, contains('_optionalRecordBool'));
    expect(
      clientSource,
      isNot(contains('DateTime.fromMillisecondsSinceEpoch(0)')),
    );
    expect(parser, isNot(contains('QuarantineItemStatus.quarantined')));
    expect(clientSource, contains('status == null'));
    expect(clientSource, contains('type == null'));
    expect(clientSource, contains('sha256 == null && json'));
  });

  test('record list parsers reject malformed IPC rows', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final quarantineList = clientSource.substring(
      clientSource.indexOf('Future<List<QuarantineRecord>> listQuarantine'),
      clientSource.indexOf('QuarantineRecord? _quarantineRecordFromJson'),
    );
    final allowlistList = clientSource.substring(
      clientSource.indexOf('Future<List<AllowlistEntry>> listAllowlist'),
      clientSource.indexOf(
        'Future<LocalCoreActionResult> removeAllowlistEntry',
      ),
    );

    expect(quarantineList, contains('for (var index = 0;'));
    expect(quarantineList, contains('was not an object'));
    expect(quarantineList, contains('was malformed'));
    expect(quarantineList, isNot(contains('whereType<QuarantineRecord>()')));
    expect(allowlistList, contains('for (var index = 0;'));
    expect(allowlistList, contains('was not an object'));
    expect(allowlistList, contains('was malformed'));
    expect(allowlistList, isNot(contains('whereType<AllowlistEntry>()')));
  });

  test('manual quarantine IPC sends explicit file labels', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-manual-quarantine-ipc-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final script =
        File('${dir.path}${Platform.pathSeparator}manual_quarantine.dart')
          ..writeAsStringSync(r'''
import 'dart:convert';
import 'dart:io';

Future<void> main() async {
  final raw = await stdin.transform(utf8.decoder).join();
  final command = jsonDecode(raw) as Map<String, Object?>;
  print(jsonEncode(<String, Object?>{
    'ok': command['command'] == 'quarantine_file' &&
        command['path'] == 'C:/Users/Brent/Downloads/manual.bin' &&
        command['threat_name'] == 'Manual quarantine' &&
        command['engine'] == 'avorax-ui-manual-quarantine',
  }));
}
''');
    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final result = await client.quarantineFile(
      'C:/Users/Brent/Downloads/manual.bin',
      threatName: 'Manual quarantine',
      engine: 'avorax-ui-manual-quarantine',
    );

    expect(result.ok, isTrue);
  });

  test(
    'quarantine list rejects records with missing required evidence',
    () async {
      final variants = <String, Map<String, Object?>>{
        'id': {'quarantineId': 'bad id'},
        'quarantined timestamp': {'quarantinedAt': null},
        'status': {'status': null},
        'blocked-before-execution': {'blockedBeforeExecution': null},
        'process-started': {'processStarted': null},
        'file size': {'fileSize': null},
        'detection label': {'detectionName': ''},
        'engine label': {'engine': ''},
        'original path': {'originalPath': 'relative\\sample.exe'},
        'quarantine path': {'quarantinePath': null},
        'source': {'source': null},
        'action': {'actionTaken': null},
      };

      for (final entry in variants.entries) {
        final dir = Directory.systemTemp.createTempSync(
          'avorax-quarantine-record-${entry.key.replaceAll(' ', '-')}-',
        );
        addTearDown(() => dir.deleteSync(recursive: true));
        final record = _quarantineRecordFixture(entry.value);
        final payload = jsonEncode(<String, Object?>{
          'ok': true,
          'records': <Object?>[record],
        });
        final script =
            File('${dir.path}${Platform.pathSeparator}quarantine.dart')
              ..writeAsStringSync(
                'void main() { print(${jsonEncode(payload)}); }\n',
              );

        final client = LocalCoreClient(
          executableOverride: _dartExecutable(),
          executableArguments: [script.path],
        );

        await expectLater(
          client.listQuarantine(),
          throwsA(
            isA<StateError>().having(
              (error) => error.message,
              entry.key,
              contains('Quarantine response record 0 was malformed.'),
            ),
          ),
        );
      }
    },
  );

  test(
    'allowlist list rejects entries with missing required evidence',
    () async {
      final variants = <String, Map<String, Object?>>{
        'id': {'id': 'bad id'},
        'type': {'entryType': null},
        'active': {'active': null},
        'created timestamp': {'createdAt': null},
        'reason': {'reason': ''},
        'creator': {'createdBy': ''},
        'file sha': {'sha256': null},
        'file path': {'path': 'relative\\safe.exe'},
        'hash path': {
          'entryType': 'hash',
          'path': 'not-a-sha256',
          'sha256': null,
        },
        'hash sha': {
          'entryType': 'hash',
          'path': 'hash-alias',
          'sha256': 'bad',
        },
      };

      for (final entry in variants.entries) {
        final dir = Directory.systemTemp.createTempSync(
          'avorax-allowlist-entry-${entry.key.replaceAll(' ', '-')}-',
        );
        addTearDown(() => dir.deleteSync(recursive: true));
        final allowlistEntry = _allowlistEntryFixture(entry.value);
        final payload = jsonEncode(<String, Object?>{
          'ok': true,
          'entries': <Object?>[allowlistEntry],
        });
        final script =
            File('${dir.path}${Platform.pathSeparator}allowlist.dart')
              ..writeAsStringSync(
                'void main() { print(${jsonEncode(payload)}); }\n',
              );

        final client = LocalCoreClient(
          executableOverride: _dartExecutable(),
          executableArguments: [script.path],
        );

        await expectLater(
          client.listAllowlist(),
          throwsA(
            isA<StateError>().having(
              (error) => error.message,
              entry.key,
              contains('Allowlist response entry 0 was malformed.'),
            ),
          ),
        );
      }
    },
  );

  test('source marker: list response errors are bounded diagnostics', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final quarantineList = clientSource.substring(
      clientSource.indexOf('Future<List<QuarantineRecord>> listQuarantine'),
      clientSource.indexOf('QuarantineRecord? _quarantineRecordFromJson'),
    );
    final allowlistList = clientSource.substring(
      clientSource.indexOf('Future<List<AllowlistEntry>> listAllowlist'),
      clientSource.indexOf(
        'Future<LocalCoreActionResult> removeAllowlistEntry',
      ),
    );

    expect(
      quarantineList,
      contains("final error = _ipcDiagnosticOrNull(response?['error'])"),
    );
    expect(
      allowlistList,
      contains("final error = _ipcDiagnosticOrNull(response?['error'])"),
    );
    expect(quarantineList, contains('_rejectListProtocolWarnings('));
    expect(allowlistList, contains('_rejectListProtocolWarnings('));
    expect(clientSource, contains('void _rejectListProtocolWarnings'));
    expect(
      clientSource,
      contains("_scanErrorList(_field(response, 'scanErrors', 'scan_errors'))"),
    );
    expect(
      clientSource,
      contains(r'$responseName response had protocol warnings'),
    );
    expect(quarantineList, isNot(contains('error.trim()')));
    expect(allowlistList, isNot(contains('error.trim()')));
  });

  test('list responses with protocol warnings fail at runtime', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-list-warning-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final payload = jsonEncode(<String, Object?>{
      'ok': true,
      'scanErrors': <String>['malformed prelude before list result'],
      'records': <Object?>[_quarantineRecordFixture(const {})],
    });
    final script = File('${dir.path}${Platform.pathSeparator}list.dart')
      ..writeAsStringSync('void main() { print(${jsonEncode(payload)}); }\n');

    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    await expectLater(
      client.listQuarantine(),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          allOf(
            contains('Quarantine list response had protocol warnings'),
            contains('malformed prelude before list result'),
          ),
        ),
      ),
    );
  });

  test('quarantine parser bounds optional IPC fields', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    final parser = clientSource.substring(
      clientSource.indexOf('QuarantineRecord? _quarantineRecordFromJson'),
      clientSource.indexOf('Future<LocalCoreActionResult> quarantineThreat'),
    );
    final recordIntHelper = clientSource.substring(
      clientSource.indexOf('int? _recordIntField'),
      clientSource.indexOf('String? _recordStringField'),
    );
    final recordBoolHelper = clientSource.substring(
      clientSource.indexOf('bool? _optionalRecordBool'),
      clientSource.indexOf('RiskScore? _riskScoreFromJson'),
    );
    final recordStringHelper = clientSource.substring(
      clientSource.indexOf('String? _recordStringField'),
      clientSource.indexOf('bool? _optionalRecordBool'),
    );

    expect(parser, contains("final quarantineId = _recordId("));
    expect(parser, contains("final originalPath = _recordPathField("));
    expect(parser, contains("final quarantinePath = _recordPathField("));
    expect(parser, contains('_recordIntField'));
    expect(recordIntHelper, contains('if (value == null) return null;'));
    expect(recordIntHelper, isNot(contains('if (value == null) return 0;')));
    expect(parser, contains('_recordStringField'));
    expect(parser, contains('final userNoteValue'));
    expect(parser, contains('(userNoteValue != null && userNote == null)'));
    expect(parser, contains('final fileSizeValue'));
    expect(parser, contains('fileSizeValue == null'));
    expect(parser, contains('final blockedBeforeExecutionValue'));
    expect(parser, contains('blockedBeforeExecutionValue == null'));
    expect(parser, contains('final processStartedValue'));
    expect(parser, contains('processStartedValue == null'));
    expect(parser, contains('final processIdValue'));
    expect(parser, contains('(processIdValue != null && processId == null)'));
    expect(
      parser,
      contains('final statusName = _ipcStringOrNull(statusValue)'),
    );
    expect(parser, contains('statusValue == null'));
    expect(parser, contains('_recordDateTimeOrNull'));
    expect(parser, contains("final detectionName = _recordStringField("));
    expect(
      parser,
      contains("final engine = _recordStringField(map, 'engine', 'engine')"),
    );
    expect(
      parser,
      contains("final source = _recordStringField(map, 'source', 'source')"),
    );
    expect(parser, contains('source == null'));
    expect(parser, contains('actionTaken == null'));
    expect(
      parser,
      contains('_quarantineActionMatchesStatus(actionTaken, status)'),
    );
    expect(parser, contains('_quarantineSourceEvidenceIsValid('));
    expect(parser, contains('source,'));
    expect(parser, contains('blockedBeforeExecution,'));
    expect(parser, contains('processStarted,'));
    expect(parser, contains('processId,'));
    expect(parser, isNot(contains("fallback: ''")));
    expect(parser, isNot(contains("fallback: 'scanner'")));
    expect(parser, isNot(contains("fallback: 'quarantined'")));
    expect(parser, contains('_optionalRecordBool'));
    expect(recordStringHelper, contains('_quarantineActionMatchesStatus'));
    expect(recordStringHelper, contains('QuarantineItemStatus.quarantined'));
    expect(recordStringHelper, contains("actionTaken == 'quarantined'"));
    expect(recordStringHelper, contains("actionTaken == 'restored'"));
    expect(recordStringHelper, contains("actionTaken == 'deleted'"));
    expect(recordStringHelper, contains('_quarantineSourceEvidenceIsValid'));
    expect(recordStringHelper, contains("source != 'scanner'"));
    expect(
      recordStringHelper,
      contains(
        '!blockedBeforeExecution && !processStarted && processId == null',
      ),
    );
    expect(recordBoolHelper, contains('if (value == null) return null;'));
    expect(recordBoolHelper, isNot(contains('defaultWhenMissing')));
    expect(recordBoolHelper, isNot(contains('return false;')));
    expect(recordStringHelper, contains('if (value == null) return null;'));
    expect(recordStringHelper, isNot(contains('String? fallback')));
    expect(recordStringHelper, isNot(contains('return fallback')));
    expect(parser, contains('blockedBeforeExecution: blockedBeforeExecution'));
    expect(parser, contains('processStarted: processStarted'));
    expect(parser, contains('actionTaken: actionTaken'));
    expect(parser, isNot(contains("fileSize: _intField")));
    expect(parser, isNot(contains("final originalPath = _nonEmptyString(")));
    expect(parser, isNot(contains("final quarantinePath = _nonEmptyString(")));
    expect(parser, isNot(contains('detectionName: _ipcString')));
    expect(parser, isNot(contains("engine: _ipcString(map['engine']")));
    expect(parser, isNot(contains('userNote: _ipcDiagnosticOrNull')));
    expect(parser, isNot(contains('actionTaken: _ipcString')));
  });

  test('allowlist parser bounds optional IPC fields', () async {
    final clientSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();

    final parser = clientSource.substring(
      clientSource.indexOf('AllowlistEntry? _allowlistEntryFromJson'),
      clientSource.indexOf('RiskScore? _riskScoreFromJson'),
    );

    expect(parser, contains('final reasonValue'));
    expect(parser, contains('final reasonText = reason'));
    expect(parser, contains('reasonValue == null'));
    expect(parser, contains('reasonText == null'));
    expect(parser, contains('_recordStringField'));
    expect(parser, contains('final typeName = _ipcStringOrNull(rawType)'));
    expect(parser, contains("final id = _recordId(json['id'])"));
    expect(
      parser,
      contains("final path = _allowlistPathField(json['path'], type)"),
    );
    expect(parser, contains('rawType == null'));
    expect(parser, contains('typeName == null'));
    expect(parser, contains('_recordDateTimeOrNull'));
    expect(parser, contains("json['active'] == null"));
    expect(parser, contains('bool? _optionalRecordBool(Object? value)'));
    expect(parser, contains('if (value == null) return null;'));
    expect(parser, contains('_allowlistTypeRequiresSha256(type)'));
    expect(
      parser,
      contains('_allowlistHashEntryHasSha256Evidence(type, path, sha256)'),
    );
    expect(parser, isNot(contains('defaultWhenMissing: true')));
    expect(parser, isNot(contains('defaultWhenMissing = false')));
    expect(parser, isNot(contains("fallback: 'local_user'")));
    expect(parser, contains('active: active'));
    expect(parser, contains('reason: reasonText'));
    expect(parser, isNot(contains("reason: reason ?? ''")));
    expect(parser, contains('createdBy: createdBy'));
    expect(parser, contains('String? _allowlistPathField'));
    expect(parser, contains(r"parsed.contains('\u0000')"));
    expect(parser, contains('AllowlistEntryType.hash => parsed'));
    expect(parser, contains('_isAbsoluteLocalPath(parsed)'));
    expect(parser, isNot(contains('reason: _ipcDiagnosticOrNull')));
    expect(parser, isNot(contains('createdBy: _ipcString')));
    expect(
      parser,
      isNot(contains("final path = _nonEmptyString(json['path'])")),
    );
    expect(
      clientSource,
      contains("trimmed.toLowerCase().startsWith('sha256:')"),
    );
    expect(clientSource, contains("trimmed.substring('sha256:'.length)"));
    expect(clientSource, contains('bool _allowlistHashEntryHasSha256Evidence'));
    expect(clientSource, contains('type != AllowlistEntryType.hash'));
  });

  test('process snapshot IPC sends observations and parses findings', () async {
    final dir = Directory.systemTemp.createTempSync('avorax-process-snapshot-');
    addTearDown(() => dir.deleteSync(recursive: true));
    final script =
        File('${dir.path}${Platform.pathSeparator}process_snapshot.dart')
          ..writeAsStringSync(r'''
import 'dart:convert';
import 'dart:io';

Future<void> main() async {
  final raw = await stdin.transform(utf8.decoder).join();
  final command = jsonDecode(raw) as Map<String, Object?>;
  final observations = command['process_observations'] as List<Object?>;
  final observation = observations.single as Map<String, Object?>;
  final policy = command['process_monitor_policy'] as Map<String, Object?>;
  print(jsonEncode(<String, Object?>{
    'ok': command['command'] == 'evaluate_process_snapshot' &&
        observations.length == 1 &&
        observation['command_line_truncated'] == true &&
        policy['suspicious_threshold'] == 40,
    'status': 'notActive',
    'capability': 'userModeSnapshot',
    'status_reason': 'snapshot-only fixture',
    'observed_processes': observations.length,
    'skipped_processes': 0,
    'findings': <Object?>[
      <String, Object?>{
        'pid': 42,
        'image_path': 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
        'score': 45,
        'verdict': 'suspiciousProcess',
        'reasons': <String>['encoded or hidden execution flags'],
      }
    ],
  }));
}
''');
    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.evaluateProcessSnapshot(const [
      ProcessObservation(
        pid: 42,
        imagePath: 'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
        commandLine:
            'powershell.exe -WindowStyle Hidden -EncodedCommand benignfixture',
        commandLineTruncated: true,
        signerTrusted: true,
      ),
    ]);

    expect(report.ok, isTrue);
    expect(report.status, 'notActive');
    expect(report.capability, 'userModeSnapshot');
    expect(report.observedProcesses, 1);
    expect(report.findings, hasLength(1));
    expect(report.findings.single.verdict, 'suspiciousProcess');
    expect(report.findings.single.reasons.single, contains('encoded'));
    expect(report.diagnostics, isEmpty);
  });

  test('process snapshot IPC keeps protocol warnings visible', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-process-snapshot-warning-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final script =
        File(
          '${dir.path}${Platform.pathSeparator}process_snapshot_warning.dart',
        )..writeAsStringSync(r'''
import 'dart:convert';
void main() {
  print('not-json');
  print(jsonEncode(<String, Object?>{
    'ok': true,
    'status': 'notActive',
    'capability': 'userModeSnapshot',
    'status_reason': 'snapshot-only fixture',
    'observed_processes': 0,
    'skipped_processes': 0,
    'findings': <Object?>[],
  }));
}
''');
    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final report = await client.evaluateProcessSnapshot(const []);

    expect(report.ok, isTrue);
    expect(report.diagnostics, isNotEmpty);
    expect(report.diagnostics.single, contains('malformed JSON'));
  });

  test('process monitor health accepts snapshot capability label', () async {
    final dir = Directory.systemTemp.createTempSync(
      'avorax-health-process-snapshot-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final payload = jsonEncode(<String, Object?>{
      'ok': true,
      'engineStatus': 'unavailable',
      'aiStatus': 'modelMissing',
      'aiModel': <String, Object?>{
        'status': 'modelMissing',
        'modelVersion': 'unavailable',
        'featureSchemaVersion': 'unavailable',
        'productionReady': false,
      },
      'yaraStatus': 'rulesUnavailable',
      'yaraRuleCount': 0,
      'nativeEngineStatus': 'unavailable',
      'nativeSignatureCount': 0,
      'nativeRuleCount': 0,
      'nativeMlStatus': 'modelMissing',
      'nativeMlProductionReady': false,
      'coreServiceStatus': 'unknown',
      'guardStatus': 'unknown',
      'driverStatus': 'unknown',
      'processMonitorStatus': 'notActive',
      'processMonitorCapability': 'userModeSnapshot',
      'processMonitorStatusReason': 'snapshot-only fixture',
      'behaviorMonitorStatus': 'notActive',
      'reputationStatus': 'unavailable',
      'compatibilityEnginesEnabled': false,
      'ipc': 'stdio',
    });
    final script = File(
      '${dir.path}${Platform.pathSeparator}health_snapshot.dart',
    )..writeAsStringSync('void main() { print(${jsonEncode(payload)}); }\n');
    final client = LocalCoreClient(
      executableOverride: _dartExecutable(),
      executableArguments: [script.path],
    );

    final health = await client.healthSummary();

    expect(health.processMonitorStatus, 'notActive');
    expect(health.processMonitorCapability, 'userModeSnapshot');
    expect(health.processMonitorStatusReason, 'snapshot-only fixture');
    expect(
      health.lastError ?? '',
      isNot(contains('process_monitor_capability')),
    );
  });
}

Map<String, Object?> _watchPollFixture({required String mode}) =>
    <String, Object?>{
      'active': true,
      'mode': mode,
      'duration_ms': 4000,
      'poll_interval_ms': 200,
      'max_events': 8,
      'initial_files_observed': 3,
      'polls_completed': 4,
      'events_observed': 0,
      'files_scanned': 0,
      'threats_found': 0,
      'quarantined_files': 0,
      'scan_errors': <String>[],
      'limitations': <String>['finite-polling-session-only'],
    };

Map<String, Object?> _serviceBoundaryFixture() => <String, Object?>{
  'ok': true,
  'protocolVersion': 1,
  'transport': 'windowsNamedPipe',
  'networkExposed': false,
  'commandScope': 'healthOnly',
  'clientAuthenticated': true,
  'serverAuthenticated': true,
  'serverPid': 4242,
  'servicePid': 4242,
  'serviceReady': true,
  'engineReady': true,
  'nativeSignatureCount': 12,
  'nativeRuleCount': 7,
  'nativeMlProductionReady': false,
  'limitations': <Object?>[
    'mutating commands are denied',
    'user-mode service IPC does not provide pre-execution blocking',
  ],
};

String _dartExecutable() {
  final flutterRoot = Platform.environment['FLUTTER_ROOT'];
  final candidates = [
    if (flutterRoot != null)
      '$flutterRoot${Platform.pathSeparator}bin${Platform.pathSeparator}cache${Platform.pathSeparator}dart-sdk${Platform.pathSeparator}bin${Platform.pathSeparator}dart.exe',
    r'C:\Users\Brent\develop\flutter\bin\cache\dart-sdk\bin\dart.exe',
    Platform.resolvedExecutable,
  ];
  return candidates.firstWhere((path) => File(path).existsSync());
}

File _writeSleepingDartScript(Directory dir, String name) {
  return File('${dir.path}${Platform.pathSeparator}$name')
    ..writeAsStringSync('''
import 'dart:async';

Future<void> main() async {
  print('fixture stdout before sleep');
  await Future<void>.delayed(const Duration(seconds: 30));
}
''');
}

Future<void> _expectProcessExited(Process process, String label) async {
  try {
    await process.exitCode.timeout(const Duration(seconds: 2));
  } on Object catch (error) {
    final killed = process.kill();
    try {
      await process.exitCode.timeout(const Duration(seconds: 2));
    } on Object {
      // Best-effort cleanup before failing the test.
    }
    fail(
      '$label process ${process.pid} was still running after timeout cleanup; '
      'killRequested=$killed; observation=$error',
    );
  }
}

Map<String, Object?> _quarantineRecordFixture(Map<String, Object?> overrides) {
  final record = <String, Object?>{
    'quarantineId': 'record_fixture',
    'originalPath': 'C:/Users/Brent/Downloads/eicar.txt',
    'quarantinePath': 'C:/ProgramData/Avorax/Quarantine/record_fixture.avoraxq',
    'sha256': 'a' * 64,
    'quarantinedAt': '2024-01-01T00:00:00Z',
    'status': 'quarantined',
    'fileSize': 68,
    'detectionName': 'EICAR-Test-File',
    'engine': 'fixture-engine',
    'source': 'scanner',
    'actionTaken': 'quarantined',
    'blockedBeforeExecution': false,
    'processStarted': false,
  };
  record.addAll(overrides);
  return record;
}

Map<String, Object?> _allowlistEntryFixture(Map<String, Object?> overrides) {
  final entry = <String, Object?>{
    'id': 'allow_fixture',
    'entryType': 'file',
    'path': 'C:/Users/Brent/Downloads/safe.exe',
    'sha256': 'b' * 64,
    'createdAt': '2024-01-01T00:00:00Z',
    'active': true,
    'reason': 'User-approved benign fixture.',
    'createdBy': 'local_user',
  };
  entry.addAll(overrides);
  return entry;
}
