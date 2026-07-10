import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:zentor_client/core/network/api_result.dart';
import 'package:zentor_client/core/network/zentor_api_client.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

void main() {
  test('API client returns failure when endpoint is unavailable', () async {
    final client = ZentorApiClient(
      httpClient: MockClient((request) async {
        throw Exception('connection refused');
      }),
    );

    final result = await client.healthCheck(
      const ZentorConfig(
        apiBaseUrl: 'http://127.0.0.1:1',
        projectId: 'project',
        publicClientKey: 'key',
      ),
    );

    expect(result, isA<ApiFailure<void>>());
  });

  test('API client does not fake non-2xx success', () async {
    final client = ZentorApiClient(
      httpClient: MockClient(
        (request) async => http.Response('not healthy', 503),
      ),
    );

    final result = await client.healthCheck(
      const ZentorConfig(
        apiBaseUrl: 'http://localhost:8080',
        projectId: 'project',
        publicClientKey: 'key',
      ),
    );

    expect(result, isA<ApiFailure<void>>());
  });

  test('API client rejects malformed 2xx health responses', () async {
    final client = ZentorApiClient(
      httpClient: MockClient(
        (request) async => http.Response('not healthy', 200),
      ),
    );

    final result = await client.healthCheck(
      const ZentorConfig(
        apiBaseUrl: 'http://localhost:8080',
        projectId: 'project',
        publicClientKey: 'key',
      ),
    );

    expect(result, isA<ApiFailure<void>>());
  });

  test('API client rejects empty 2xx health responses', () async {
    final client = ZentorApiClient(
      httpClient: MockClient((request) async => http.Response('', 204)),
    );

    final result = await client.healthCheck(
      const ZentorConfig(
        apiBaseUrl: 'http://localhost:8080',
        projectId: 'project',
        publicClientKey: 'key',
      ),
    );

    expect(result, isA<ApiFailure<void>>());
  });

  test('API client accepts structured healthy cloud responses', () async {
    final client = ZentorApiClient(
      httpClient: MockClient(
        (request) async => http.Response('{"status":"healthy"}', 200),
      ),
    );

    final result = await client.healthCheck(
      const ZentorConfig(
        apiBaseUrl: 'http://localhost:8080',
        projectId: 'project',
        publicClientKey: 'key',
      ),
    );

    expect(result, isA<ApiSuccess<void>>());
  });

  test(
    'API client rejects oversized streamed cloud health responses',
    () async {
      final client = ZentorApiClient(
        maxJsonResponseBytes: 16,
        httpClient: _StreamingClient(
          (request) async => http.StreamedResponse(
            Stream<List<int>>.fromIterable([
              utf8.encode('{"status":"'),
              utf8.encode('healthy-but-too-large"}'),
            ]),
            200,
            request: request,
          ),
        ),
      );

      final result = await client.healthCheck(_configuredCloudConfig());

      expect(result, isA<ApiFailure<void>>());
      expect(
        (result as ApiFailure<void>).message,
        contains('Health response exceeded the JSON size limit'),
      );
    },
  );

  test('API client fails cloud health when response stream stalls', () async {
    final controller = StreamController<List<int>>();
    addTearDown(controller.close);
    final client = ZentorApiClient(
      cloudResponseReadTimeout: const Duration(milliseconds: 20),
      httpClient: _StreamingClient(
        (request) async =>
            http.StreamedResponse(controller.stream, 200, request: request),
      ),
    );

    final result = await client.healthCheck(_configuredCloudConfig());

    expect(result, isA<ApiFailure<void>>());
    expect(
      (result as ApiFailure<void>).message,
      contains('Avorax Cloud is offline:'),
    );
    expect(result.message, contains('TimeoutException'));
  });

  test('API client rejects blank protection run IDs from cloud', () async {
    final client = ZentorApiClient(
      httpClient: MockClient(
        (request) async => http.Response(
          '{"protection_run_id":"   ","expires_at":"2026-01-01T01:00:00Z"}',
          200,
        ),
      ),
    );

    final result = await client.createProtectionRun(_configuredCloudConfig());

    expect(result, isA<ApiFailure<ProtectionRun>>());
  });

  test('API client rejects invalid protection run expiry from cloud', () async {
    final client = ZentorApiClient(
      httpClient: MockClient(
        (request) async => http.Response(
          '{"protection_run_id":"run","expires_at":"not-a-date"}',
          200,
        ),
      ),
    );

    final result = await client.createProtectionRun(_configuredCloudConfig());

    expect(result, isA<ApiFailure<ProtectionRun>>());
  });

  test('API client rejects unsafe protection run IDs from cloud', () async {
    final client = ZentorApiClient(
      httpClient: MockClient(
        (request) async => http.Response(
          '{"protection_run_id":"run/with spaces","expires_at":"2026-01-01T01:00:00Z"}',
          200,
        ),
      ),
    );

    final result = await client.createProtectionRun(_configuredCloudConfig());

    expect(result, isA<ApiFailure<ProtectionRun>>());
  });

  test('API client trims valid protection run IDs from cloud', () async {
    final client = ZentorApiClient(
      httpClient: MockClient(
        (request) async => http.Response(
          '{"protection_run_id":"  run  ","expires_at":"2026-01-01T01:00:00Z"}',
          200,
        ),
      ),
    );

    final result = await client.createProtectionRun(_configuredCloudConfig());

    expect(result, isA<ApiSuccess<ProtectionRun>>());
    expect((result as ApiSuccess<ProtectionRun>).value.protectionRunId, 'run');
  });

  test(
    'API client rejects invalid protection-run payload before network calls',
    () async {
      var called = false;
      final client = ZentorApiClient(
        httpClient: MockClient((request) async {
          called = true;
          return http.Response('{"protection_run_id":"run"}', 200);
        }),
      );

      final result = await client.createProtectionRun(
        _configuredCloudConfig().copyWith(
          protectedAppConfig: const ProtectedAppConfig(
            appName: 'Sample',
            appPath: r'C:\sample.exe',
            platform: 'windows',
            lastCalculatedHash: 'not-a-sha256',
          ),
        ),
      );

      expect(result, isA<ApiFailure<ProtectionRun>>());
      expect(called, isFalse);
    },
  );

  test(
    'API client rejects malformed successful write acknowledgements',
    () async {
      final client = ZentorApiClient(
        httpClient: MockClient(
          (request) async => http.Response('not-json', 200),
        ),
      );

      final result = await client.reportDetection(
        const ZentorConfig(
          apiBaseUrl: 'http://localhost:8080',
          projectId: 'project',
          publicClientKey: 'key',
        ),
        const ScanReport(
          status: ScanStatus.clean,
          kind: ScanKind.quick,
          actionMode: ScanActionMode.detectOnly,
          filesScanned: 1,
          threatsFound: 0,
          skippedFiles: 0,
          elapsedMs: 10,
          threats: [],
        ),
      );

      expect(result, isA<ApiFailure<void>>());
    },
  );

  test(
    'API client rejects explicit cloud write failure acknowledgements',
    () async {
      final client = ZentorApiClient(
        httpClient: MockClient(
          (request) async =>
              http.Response('{"ok":false,"error":"denied"}', 200),
        ),
      );

      final result = await client.uploadQuarantineMetadata(
        const ZentorConfig(
          apiBaseUrl: 'http://localhost:8080',
          projectId: 'project',
          publicClientKey: 'key',
        ),
        QuarantineRecord(
          quarantineId: 'qid',
          originalPath: r'C:\sample.txt',
          quarantinePath: r'C:\Avorax\quarantine\opaque.bin',
          sha256:
              'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          fileSize: 68,
          detectionName: 'EICAR-Test-File',
          engine: 'test',
          quarantinedAt: DateTime.utc(2026),
          status: QuarantineItemStatus.quarantined,
          source: 'scanner',
          blockedBeforeExecution: false,
          processStarted: false,
          actionTaken: 'quarantined',
        ),
      );

      expect(result, isA<ApiFailure<void>>());
    },
  );

  test('API client rejects empty successful write acknowledgements', () async {
    final client = ZentorApiClient(
      httpClient: MockClient((request) async => http.Response('', 204)),
    );

    final result = await client.sendHeartbeat(
      const ZentorConfig(
        apiBaseUrl: 'http://localhost:8080',
        projectId: 'project',
        publicClientKey: 'key',
      ),
      ProtectionRun(
        protectionRunId: 'run',
        startedAt: DateTime.utc(2026),
        expiresAt: DateTime.utc(2026, 1, 1, 1),
      ),
    );

    expect(result, isA<ApiFailure<void>>());
  });

  test(
    'API client validates cloud write config before network calls',
    () async {
      var called = false;
      final client = ZentorApiClient(
        httpClient: MockClient((request) async {
          called = true;
          return http.Response('', 204);
        }),
      );

      final result = await client.reportDetection(
        const ZentorConfig(
          apiBaseUrl: '',
          projectId: 'project',
          publicClientKey: 'key',
        ),
        const ScanReport(
          status: ScanStatus.clean,
          kind: ScanKind.quick,
          actionMode: ScanActionMode.detectOnly,
          filesScanned: 1,
          threatsFound: 0,
          skippedFiles: 0,
          elapsedMs: 10,
          threats: [],
        ),
      );

      expect(result, isA<ApiFailure<void>>());
      expect(called, isFalse);
    },
  );

  test(
    'API client trims cloud config values before outbound requests',
    () async {
      late http.Request observedRequest;
      final client = ZentorApiClient(
        httpClient: MockClient((request) async {
          observedRequest = request;
          return http.Response('{"ok":true}', 200);
        }),
      );

      final result = await client.reportDetection(
        const ZentorConfig(
          apiBaseUrl: '  http://localhost:8080/base  ',
          projectId: '  project  ',
          publicClientKey: '  key  ',
        ),
        const ScanReport(
          status: ScanStatus.clean,
          kind: ScanKind.quick,
          actionMode: ScanActionMode.detectOnly,
          filesScanned: 1,
          threatsFound: 0,
          skippedFiles: 0,
          elapsedMs: 10,
          threats: [],
        ),
      );

      expect(result, isA<ApiSuccess<void>>());
      expect(
        observedRequest.url.toString(),
        'http://localhost:8080/v1/detections',
      );
      expect(observedRequest.headers['authorization'], 'Bearer key');
      expect(
        jsonDecode(observedRequest.body) as Map<String, Object?>,
        containsPair('project_id', 'project'),
      );
    },
  );

  test(
    'API client rejects invalid detection metadata before network calls',
    () async {
      var called = false;
      final client = ZentorApiClient(
        httpClient: MockClient((request) async {
          called = true;
          return http.Response('', 204);
        }),
      );

      final result = await client.reportDetection(
        _configuredCloudConfig(),
        ScanReport(
          status: ScanStatus.infected,
          kind: ScanKind.quick,
          actionMode: ScanActionMode.detectOnly,
          filesScanned: 1,
          threatsFound: 1,
          skippedFiles: 0,
          elapsedMs: 10,
          threats: [
            _threatResult(
              sha256: 'not-a-sha256',
              engine: 'signature',
              threatName: 'EICAR-Test-File',
            ),
          ],
        ),
      );

      expect(result, isA<ApiFailure<void>>());
      expect(called, isFalse);
    },
  );

  test(
    'API client rejects invalid quarantine metadata before network calls',
    () async {
      var called = false;
      final client = ZentorApiClient(
        httpClient: MockClient((request) async {
          called = true;
          return http.Response('', 204);
        }),
      );

      final result = await client.uploadQuarantineMetadata(
        _configuredCloudConfig(),
        QuarantineRecord(
          quarantineId: 'qid',
          originalPath: r'C:\sample.txt',
          quarantinePath: r'C:\Avorax\quarantine\opaque.bin',
          sha256:
              'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          fileSize: 68,
          detectionName: '   ',
          engine: 'test',
          quarantinedAt: DateTime.utc(2026),
          status: QuarantineItemStatus.quarantined,
          source: 'scanner',
          blockedBeforeExecution: false,
          processStarted: false,
          actionTaken: 'quarantined',
        ),
      );

      expect(result, isA<ApiFailure<void>>());
      expect(called, isFalse);
    },
  );

  test(
    'API client rejects inconsistent quarantine evidence before network calls',
    () async {
      var called = false;
      final client = ZentorApiClient(
        httpClient: MockClient((request) async {
          called = true;
          return http.Response('', 204);
        }),
      );

      final result = await client.uploadQuarantineMetadata(
        _configuredCloudConfig(),
        QuarantineRecord(
          quarantineId: 'qid',
          originalPath: r'C:\sample.txt',
          quarantinePath: r'C:\Avorax\quarantine\opaque.bin',
          sha256:
              'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          fileSize: 68,
          detectionName: 'EICAR-Test-File',
          engine: 'test',
          quarantinedAt: DateTime.utc(2026),
          status: QuarantineItemStatus.restored,
          source: 'scanner',
          blockedBeforeExecution: false,
          processStarted: false,
          actionTaken: 'quarantined',
        ),
      );

      expect(result, isA<ApiFailure<void>>());
      expect(called, isFalse);
    },
  );

  test(
    'API client includes quarantine evidence in cloud upload payload',
    () async {
      late Map<String, Object?> observedPayload;
      final client = ZentorApiClient(
        httpClient: MockClient((request) async {
          observedPayload = jsonDecode(request.body) as Map<String, Object?>;
          return http.Response('{"ok":true}', 200);
        }),
      );

      final result = await client.uploadQuarantineMetadata(
        _configuredCloudConfig(),
        QuarantineRecord(
          quarantineId: 'qid',
          originalPath: r'C:\sample.txt',
          quarantinePath: r'C:\Avorax\quarantine\opaque.bin',
          sha256:
              'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          fileSize: 68,
          detectionName: 'EICAR-Test-File',
          engine: 'test',
          quarantinedAt: DateTime.utc(2026),
          status: QuarantineItemStatus.quarantined,
          source: 'scanner',
          blockedBeforeExecution: false,
          processStarted: false,
          actionTaken: 'quarantined',
        ),
      );

      expect(result, isA<ApiSuccess<void>>());
      expect(observedPayload, containsPair('action_taken', 'quarantined'));
      expect(observedPayload, containsPair('source', 'scanner'));
      expect(observedPayload, containsPair('blocked_before_execution', false));
      expect(observedPayload, containsPair('process_started', false));
    },
  );

  test(
    'API client rejects empty protection run IDs before heartbeat',
    () async {
      var called = false;
      final client = ZentorApiClient(
        httpClient: MockClient((request) async {
          called = true;
          return http.Response('', 204);
        }),
      );

      final result = await client.sendHeartbeat(
        const ZentorConfig(
          apiBaseUrl: 'http://localhost:8080',
          projectId: 'project',
          publicClientKey: 'key',
        ),
        ProtectionRun(
          protectionRunId: '   ',
          startedAt: DateTime.utc(2026),
          expiresAt: DateTime.utc(2026, 1, 1, 1),
        ),
      );

      expect(result, isA<ApiFailure<void>>());
      expect(called, isFalse);
    },
  );

  test(
    'API client rejects unsafe protection run IDs before heartbeat',
    () async {
      var called = false;
      final client = ZentorApiClient(
        httpClient: MockClient((request) async {
          called = true;
          return http.Response('', 204);
        }),
      );

      final result = await client.sendHeartbeat(
        const ZentorConfig(
          apiBaseUrl: 'http://localhost:8080/base',
          projectId: 'project',
          publicClientKey: 'key',
        ),
        ProtectionRun(
          protectionRunId: 'run/with spaces',
          startedAt: DateTime.utc(2026),
          expiresAt: DateTime.utc(2026, 1, 1, 1),
        ),
      );

      expect(result, isA<ApiFailure<void>>());
      expect(called, isFalse);
    },
  );

  test(
    'API client does not fake end-run success for missing endpoints',
    () async {
      final client = ZentorApiClient(
        httpClient: MockClient(
          (request) async => http.Response('missing', 404),
        ),
      );

      final result = await client.endProtectionRun(
        const ZentorConfig(
          apiBaseUrl: 'http://localhost:8080',
          projectId: 'project',
          publicClientKey: 'key',
        ),
        ProtectionRun(
          protectionRunId: 'run',
          startedAt: DateTime.utc(2026),
          expiresAt: DateTime.utc(2026, 1, 1, 1),
        ),
      );

      expect(result, isA<ApiFailure<void>>());
    },
  );

  test('source marker: write API responses require structured ack', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();

    expect(source, contains('_validateWriteAck(response'));
    expect(source, contains("response did not include ok=true"));
    expect(source, contains('was rejected by Avorax Cloud'));
    expect(source, isNot(contains('if (body.isEmpty)')));
  });

  test('source marker: protection run creation validates response fields', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();

    expect(source, contains("_cloudIdToken(decoded['protection_run_id'])"));
    expect(source, contains('_maxCloudIdChars'));
    expect(
      source,
      contains(r"_cloudIdTokenPattern = RegExp(r'^[A-Za-z0-9_-]+$')"),
    );
    expect(source, contains("_optionalDateTime(decoded['expires_at'])"));
    expect(source, contains('invalid expires_at timestamp'));
  });

  test('source marker: protection run IDs are bounded safe tokens', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();
    final heartbeatMethod = source.substring(
      source.indexOf('Future<ApiResult<void>> sendHeartbeat'),
      source.indexOf('Future<ApiResult<void>> endProtectionRun'),
    );
    final endMethod = source.substring(
      source.indexOf('Future<ApiResult<void>> endProtectionRun'),
      source.indexOf('Future<ApiResult<void>> reportDetection'),
    );

    expect(source, contains('String? _cloudIdToken(Object? value)'));
    expect(source, contains("_cloudIdTokenPattern.hasMatch(trimmed)"));
    expect(
      heartbeatMethod,
      contains('_cloudIdToken(protectionRun.protectionRunId)'),
    );
    expect(endMethod, contains('_cloudIdToken(protectionRun.protectionRunId)'));
    expect(source, isNot(contains('protectionRun.protectionRunId.trim()')));
  });

  test('source marker: protection-run cloud errors use user-facing copy', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();
    final createMethod = source.substring(
      source.indexOf('Future<ApiResult<ProtectionRun>> createProtectionRun'),
      source.indexOf('Future<ApiResult<void>> sendHeartbeat'),
    );
    final endMethod = source.substring(
      source.indexOf('Future<ApiResult<void>> endProtectionRun'),
      source.indexOf('Future<ApiResult<void>> reportDetection'),
    );
    final visibleCopy = '$createMethod\n$endMethod';

    expect(createMethod, contains('Protection run creation failed'));
    expect(
      createMethod,
      contains('Protection run creation response was not a JSON object.'),
    );
    expect(
      createMethod,
      contains(
        'Protection run creation response did not include protection_run_id.',
      ),
    );
    expect(endMethod, contains("operation: 'End protection run'"));
    expect(endMethod, contains('End protection run failed'));
    expect(visibleCopy, isNot(contains('Protection protectionRun')));
    expect(visibleCopy, isNot(contains('End protectionRun')));
    expect(visibleCopy, isNot(contains('ProtectionRun response')));
  });

  test('source marker: protection run payload metadata is validated', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();
    final createMethod = source.substring(
      source.indexOf('Future<ApiResult<ProtectionRun>> createProtectionRun'),
      source.indexOf('Future<ApiResult<void>> sendHeartbeat'),
    );

    expect(source, contains('_maxCloudPayloadPlatformChars = 64'));
    expect(
      source,
      contains(
        'ApiFailure<ProtectionRun>? _validateProtectionRunPayloadForCloud',
      ),
    );
    expect(createMethod, contains('_validateProtectionRunPayloadForCloud'));
    expect(createMethod, contains("'platform': _cloudPayloadText("));
    expect(createMethod, contains("'file_hash': _cloudPayloadText("));
    expect(createMethod, contains("'client_version': 'avorax-client'"));
    expect(createMethod, isNot(contains('zentor-client')));
    expect(
      createMethod.indexOf('_validateProtectionRunPayloadForCloud'),
      lessThan(createMethod.indexOf("replace(path: '/v1/protection-runs')")),
    );
    expect(createMethod, isNot(contains('final uri = Uri.parse')));
  });

  test('source marker: heartbeat telemetry uses Avorax copy', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();
    final heartbeatMethod = source.substring(
      source.indexOf('Future<ApiResult<void>> sendHeartbeat'),
      source.indexOf('Future<ApiResult<void>> endProtectionRun'),
    );

    expect(
      heartbeatMethod,
      contains("'signed_payload': 'visible-avorax-client-heartbeat'"),
    );
    expect(heartbeatMethod, isNot(contains('visible-zentor-client-heartbeat')));
  });

  test('source marker: cloud timestamps are bounded before parsing', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();
    final dateTimeMethod = source.substring(
      source.indexOf('DateTime? _optionalDateTime'),
      source.indexOf('Object? _decodeCloudJsonResponse'),
    );

    expect(source, contains('static const _maxCloudTimestampChars = 64'));
    expect(
      dateTimeMethod,
      contains('trimmed.length > _maxCloudTimestampChars'),
    );
    expect(dateTimeMethod, contains('DateTime.tryParse(trimmed)'));
  });

  test('source marker: cloud response strings are bounded', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();
    final boundedStringMethod = source.substring(
      source.indexOf('String? _boundedCloudString'),
      source.indexOf('String _cloudDiagnosticText'),
    );

    expect(source, contains('_maxCloudDiagnosticChars'));
    expect(source, contains('_maxCloudStatusChars'));
    expect(source, contains('String? _boundedCloudString'));
    expect(boundedStringMethod, contains(r"RegExp(r'[\x00-\x1F\x7F]+')"));
    expect(boundedStringMethod, contains('replaceAll('));
    expect(boundedStringMethod, contains('trimmed.substring(0, maxLength)'));
    expect(source, contains("decoded['error']"));
    expect(source, contains('maxLength: _maxCloudDiagnosticChars'));
  });

  test('source marker: cloud exception diagnostics are bounded', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();
    final diagnosticMethod = source.substring(
      source.indexOf('String _cloudDiagnosticText'),
      source.indexOf('DateTime? _optionalDateTime'),
    );

    expect(source, contains('_cloudDiagnosticText(error)'));
    expect(source, isNot(contains(r'failed: $error')));
    expect(source, isNot(contains(r'offline: $error')));
    expect(diagnosticMethod, contains('_maxCloudDiagnosticChars'));
    expect(diagnosticMethod, contains(r"RegExp(r'[\x00-\x1F\x7F]+')"));
    expect(diagnosticMethod, contains("return 'unknown error'"));
  });

  test('source marker: cloud JSON responses are size bounded', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();
    final transportMethod = source.substring(
      source.indexOf('Future<http.Response> _sendCloudRequest'),
      source.indexOf('Object? _decodeCloudJsonResponse'),
    );
    final decoderMethod = source.substring(
      source.indexOf('Object? _decodeCloudJsonResponse'),
      source.indexOf('ApiResult<void>? _validateHealthAck'),
    );
    final createMethod = source.substring(
      source.indexOf('Future<ApiResult<ProtectionRun>> createProtectionRun'),
      source.indexOf('Future<ApiResult<void>> sendHeartbeat'),
    );
    final healthMethod = source.substring(
      source.indexOf('ApiResult<void>? _validateHealthAck'),
      source.indexOf('ApiResult<void>? _validateWriteAck'),
    );
    final writeMethod = source.substring(
      source.indexOf('ApiResult<void>? _validateWriteAck'),
      source.length,
    );

    expect(
      source,
      contains('static const _maxCloudJsonResponseBytes = 256 * 1024'),
    );
    expect(source, contains('static const _cloudResponseReadTimeout'));
    expect(
      source,
      contains('int maxJsonResponseBytes = _maxCloudJsonResponseBytes'),
    );
    expect(
      source,
      contains('Duration cloudResponseReadTimeout = _cloudResponseReadTimeout'),
    );
    expect(
      source,
      contains('_maxJsonResponseBytes = _requirePositiveCloudByteLimit'),
    );
    expect(
      source,
      contains('_cloudResponseReadTimeoutValue = _requirePositiveCloudTimeout'),
    );
    expect(
      transportMethod,
      contains('_httpClient.send(request).timeout(requestTimeout)'),
    );
    expect(transportMethod, contains('streamed.stream.timeout('));
    expect(transportMethod, contains('_cloudResponseReadTimeoutValue'));
    expect(transportMethod, contains('totalBytes += chunk.length'));
    expect(transportMethod, contains('totalBytes > _maxJsonResponseBytes'));
    expect(transportMethod, contains('http.Response.bytes('));
    expect(transportMethod, contains("_rejectOversizedCloudJsonHeader"));
    expect(source, isNot(contains('_httpClient.get(')));
    expect(source, isNot(contains('_httpClient.post(')));
    expect(source, isNot(contains('response.bodyBytes.length')));
    expect(decoderMethod, contains('jsonDecode(response.body)'));
    expect(createMethod, contains('_decodeCloudJsonResponse'));
    expect(healthMethod, contains('_decodeCloudJsonResponse'));
    expect(writeMethod, contains('_decodeCloudJsonResponse'));
    expect(healthMethod, contains('response could not be parsed'));
    expect(writeMethod, contains('response could not be parsed'));
    expect(healthMethod, contains('_cloudDiagnosticText(error)'));
    expect(writeMethod, contains('_cloudDiagnosticText(error)'));
    expect(source, isNot(contains('response was not valid JSON.')));
  });

  test('source marker: write API calls preflight config and run IDs', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();

    expect(source, contains('_validateCloudWriteConfig(config)'));
    expect(source, contains('config.validateCloudConfiguration()'));
    expect(source, contains('_cloudIdToken(protectionRun.protectionRunId)'));
    expect(
      source,
      contains('A valid protection run ID is required for heartbeat.'),
    );
  });

  test('source marker: cloud config values are normalized at use', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();

    expect(source, contains('Uri _cloudBaseUri(ZentorConfig config)'));
    expect(source, contains('Uri.parse(config.apiBaseUrl.trim())'));
    expect(
      source,
      contains("'project_id': _cloudPayloadText(config.projectId)"),
    );
    expect(
      source,
      contains(
        "'authorization': 'Bearer \${_cloudPayloadText(config.publicClientKey)}'",
      ),
    );
    expect(source, isNot(contains('Uri.parse(config.apiBaseUrl).replace')));
  });

  test('source marker: cloud detection reports are count bounded', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();
    final reportValidator = source.substring(
      source.indexOf('ApiFailure<void>? _validateDetectionReportForCloud'),
      source.indexOf('ApiFailure<void>? _validateQuarantineMetadataForCloud'),
    );

    expect(source, contains('static const maxCloudDetectionsPerReport = 256'));
    expect(
      reportValidator,
      contains('report.threats.length > maxCloudDetectionsPerReport'),
    );
    expect(
      reportValidator,
      contains(
        'Detection report contains too many detections for cloud reporting',
      ),
    );
  });

  test('source marker: cloud outbound metadata fields are validated', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();
    final reportMethod = source.substring(
      source.indexOf('Future<ApiResult<void>> reportDetection'),
      source.indexOf('Future<ApiResult<void>> uploadQuarantineMetadata'),
    );
    final quarantineMethod = source.substring(
      source.indexOf('Future<ApiResult<void>> uploadQuarantineMetadata'),
      source.indexOf('Map<String, String> _headers'),
    );
    final quarantineValidator = source.substring(
      source.indexOf('ApiFailure<void>? _validateQuarantineMetadataForCloud'),
      source.indexOf('bool _quarantineActionMatchesStatus'),
    );
    final payloadTextValidator = source.substring(
      source.indexOf('bool _isCloudPayloadText'),
      source.indexOf('bool _isSha256'),
    );

    expect(source, contains('_maxCloudPayloadNameChars = 256'));
    expect(source, contains('_maxCloudPayloadEngineChars = 128'));
    expect(source, contains('_maxCloudPayloadIdChars = 256'));
    expect(
      source,
      contains("_cloudPayloadControlPattern = RegExp(r'[\\x00-\\x1F\\x7F]')"),
    );
    expect(
      source,
      contains('ApiFailure<void>? _validateDetectionReportForCloud'),
    );
    expect(
      source,
      contains('ApiFailure<void>? _validateQuarantineMetadataForCloud'),
    );
    expect(source, contains('bool _quarantineActionMatchesStatus'));
    expect(source, contains('bool _quarantineSourceEvidenceIsValid'));
    expect(source, contains(r"RegExp(r'^[a-fA-F0-9]{64}$')"));
    expect(
      payloadTextValidator,
      contains(
        'if (_cloudPayloadControlPattern.hasMatch(value)) return false;',
      ),
    );
    expect(reportMethod, contains('_validateDetectionReportForCloud(report)'));
    expect(
      quarantineMethod,
      contains('_validateQuarantineMetadataForCloud(record)'),
    );
    expect(
      quarantineValidator,
      contains(
        '_quarantineActionMatchesStatus(record.actionTaken, record.status)',
      ),
    );
    expect(
      quarantineValidator,
      contains('_quarantineSourceEvidenceIsValid(record)'),
    );
    expect(
      reportMethod,
      contains("'engine': _cloudPayloadText(threat.engine)"),
    );
    expect(
      quarantineMethod,
      contains("'detection_name': _cloudPayloadText(record.detectionName)"),
    );
    expect(
      quarantineMethod,
      contains("'action_taken': _cloudPayloadText(record.actionTaken)"),
    );
    expect(
      quarantineMethod,
      contains("'source': _cloudPayloadText(record.source)"),
    );
    expect(
      quarantineMethod,
      contains("'blocked_before_execution': record.blockedBeforeExecution"),
    );
    expect(
      quarantineMethod,
      contains("'process_started': record.processStarted"),
    );
    expect(
      reportMethod.indexOf('_validateDetectionReportForCloud(report)'),
      lessThan(reportMethod.indexOf('_cloudBaseUri(config)')),
    );
    expect(
      quarantineMethod.indexOf('_validateQuarantineMetadataForCloud(record)'),
      lessThan(quarantineMethod.indexOf('_cloudBaseUri(config)')),
    );
  });

  test('source marker: run-scoped API URLs use encoded path segments', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();

    expect(source, contains('_protectionRunUri(config, runId'));
    expect(
      source,
      contains("pathSegments: ['v1', 'protection-runs', runId, action]"),
    );
    expect(
      source,
      isNot(
        contains('response.statusCode == 404 || response.statusCode == 405'),
      ),
    );
  });

  test('source marker: cloud health response requires healthy marker', () {
    final source = File(
      'lib/core/network/zentor_api_client.dart',
    ).readAsStringSync();

    expect(source, contains('_validateHealthAck(response)'));
    expect(
      source,
      contains('health response did not include a healthy marker'),
    );
    expect(source, contains("normalized == 'ok' || normalized == 'healthy'"));
  });
}

ZentorConfig _configuredCloudConfig() => const ZentorConfig(
  apiBaseUrl: 'http://localhost:8080',
  projectId: 'project',
  publicClientKey: 'key',
  protectedAppConfig: ProtectedAppConfig(
    appName: 'Sample',
    appPath: r'C:\sample.exe',
    platform: 'windows',
    lastCalculatedHash:
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  ),
);

ThreatResult _threatResult({
  required String sha256,
  required String engine,
  required String threatName,
}) => ThreatResult(
  id: 'threat-1',
  path: r'C:\sample.txt',
  fileName: 'sample.txt',
  sha256: sha256,
  sizeBytes: 68,
  detectionType: DetectionType.signature,
  threatCategory: ThreatCategory.unknown,
  threatName: threatName,
  confidence: ThreatConfidence.confirmed,
  engine: engine,
  detectedAt: DateTime.utc(2026),
  recommendedAction: RecommendedAction.quarantine,
  status: ThreatResultStatus.detected,
  riskScore: const RiskScore(
    score: 100,
    verdict: RiskVerdict.confirmedMalware,
    confidence: ThreatConfidence.confirmed,
    reasons: [],
    recommendedAction: RecommendedAction.quarantine,
    enginesUsed: [DetectionType.signature],
  ),
);

class _StreamingClient extends http.BaseClient {
  _StreamingClient(this._handler);

  final Future<http.StreamedResponse> Function(http.BaseRequest request)
  _handler;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    return _handler(request);
  }
}
