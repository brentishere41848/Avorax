import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;
import 'package:zentor_protocol/zentor_protocol.dart';

import 'api_result.dart';

class ZentorApiClient {
  ZentorApiClient({
    http.Client? httpClient,
    int maxJsonResponseBytes = _maxCloudJsonResponseBytes,
    Duration cloudResponseReadTimeout = _cloudResponseReadTimeout,
  }) : _httpClient = httpClient ?? http.Client(),
       _maxJsonResponseBytes = _requirePositiveCloudByteLimit(
         maxJsonResponseBytes,
       ),
       _cloudResponseReadTimeoutValue = _requirePositiveCloudTimeout(
         cloudResponseReadTimeout,
       );

  final http.Client _httpClient;
  final int _maxJsonResponseBytes;
  final Duration _cloudResponseReadTimeoutValue;
  static const _maxCloudIdChars = 256;
  static const _maxCloudDiagnosticChars = 2048;
  static const _maxCloudStatusChars = 128;
  static const _maxCloudJsonResponseBytes = 256 * 1024;
  static const _maxCloudTimestampChars = 64;
  static const _maxCloudPayloadNameChars = 256;
  static const _maxCloudPayloadEngineChars = 128;
  static const _maxCloudPayloadIdChars = 256;
  static const _maxCloudPayloadPlatformChars = 64;
  static const _cloudResponseReadTimeout = Duration(seconds: 10);
  static const maxCloudDetectionsPerReport = 256;
  static final _cloudIdTokenPattern = RegExp(r'^[A-Za-z0-9_-]+$');
  static final _cloudPayloadControlPattern = RegExp(r'[\x00-\x1F\x7F]');

  Future<ApiResult<void>> healthCheck(ZentorConfig config) async {
    final validation = config.validateCloudConfiguration();
    if (validation.isNotEmpty) {
      return ApiFailure(validation.join(' '));
    }
    final uri = _cloudBaseUri(config).replace(path: '/v1/health');
    try {
      final response = await _sendCloudRequest(
        http.Request('GET', uri),
        operation: 'Health',
        requestTimeout: const Duration(seconds: 6),
      );
      final readiness = _validateHealthAck(response);
      if (readiness != null) return readiness;
      return ApiFailure(
        'Avorax Cloud returned HTTP ${response.statusCode}.',
        statusCode: response.statusCode,
      );
    } on Object catch (error) {
      return ApiFailure(
        'Avorax Cloud is offline: ${_cloudDiagnosticText(error)}',
      );
    }
  }

  Future<ApiResult<ProtectionRun>> createProtectionRun(
    ZentorConfig config,
  ) async {
    final validation = config.validateCloudConfiguration();
    if (validation.isNotEmpty) {
      return ApiFailure(validation.join(' '));
    }
    if (!config.protectedAppConfig.isConfigured) {
      return const ApiFailure('No supported app is selected.');
    }
    final payloadValidation = _validateProtectionRunPayloadForCloud(
      config.protectedAppConfig,
    );
    if (payloadValidation != null) return payloadValidation;
    final uri = _cloudBaseUri(config).replace(path: '/v1/protection-runs');
    final now = DateTime.now().toUtc();
    final body = {
      'project_id': _cloudPayloadText(config.projectId),
      'platform': _cloudPayloadText(config.protectedAppConfig.platform),
      'client_version': 'avorax-client',
      'file_hash': _cloudPayloadText(
        config.protectedAppConfig.lastCalculatedHash,
      ),
      'device_fingerprint_hash': 'device-hash-managed-locally',
      'nonce': now.microsecondsSinceEpoch.toString(),
      'expires_at': now.add(const Duration(hours: 1)).toIso8601String(),
    };
    try {
      final response = await _sendCloudRequest(
        http.Request('POST', uri)
          ..headers.addAll(_headers(config))
          ..body = jsonEncode(body),
        operation: 'Protection run creation',
        requestTimeout: const Duration(seconds: 10),
      );
      if (response.statusCode < 200 || response.statusCode >= 300) {
        return ApiFailure(
          'Protection run creation failed with HTTP ${response.statusCode}.',
          statusCode: response.statusCode,
        );
      }
      final decoded = _decodeCloudJsonResponse(
        response,
        operation: 'Protection run creation',
      );
      if (decoded is! Map<String, Object?>) {
        return const ApiFailure(
          'Protection run creation response was not a JSON object.',
        );
      }
      final protectionRunId = _cloudIdToken(decoded['protection_run_id']);
      if (protectionRunId == null) {
        return const ApiFailure(
          'Protection run creation response did not include protection_run_id.',
        );
      }
      final expiresAt = _optionalDateTime(decoded['expires_at']);
      if (decoded.containsKey('expires_at') && expiresAt == null) {
        return const ApiFailure(
          'Protection run creation response included an invalid expires_at timestamp.',
        );
      }
      return ApiSuccess(
        ProtectionRun(
          protectionRunId: protectionRunId,
          startedAt: now,
          expiresAt: expiresAt,
        ),
      );
    } on Object catch (error) {
      return ApiFailure(
        'Protection run creation failed: ${_cloudDiagnosticText(error)}',
      );
    }
  }

  Future<ApiResult<void>> sendHeartbeat(
    ZentorConfig config,
    ProtectionRun protectionRun,
  ) async {
    final validation = _validateCloudWriteConfig(config);
    if (validation != null) return validation;
    final runId = _cloudIdToken(protectionRun.protectionRunId);
    if (runId == null) {
      return const ApiFailure(
        'A valid protection run ID is required for heartbeat.',
      );
    }
    final uri = _protectionRunUri(config, runId, 'heartbeat');
    final body = {
      'protection_run_id': runId,
      'monotonic_time': DateTime.now().millisecondsSinceEpoch,
      'client_timestamp': DateTime.now().toUtc().toIso8601String(),
      'signed_payload': 'visible-avorax-client-heartbeat',
      'environment': {
        'agent_visible': true,
        'kernel_driver': false,
        'unrelated_file_scan': false,
      },
    };
    try {
      final response = await _sendCloudRequest(
        http.Request('POST', uri)
          ..headers.addAll(_headers(config))
          ..body = jsonEncode(body),
        operation: 'Heartbeat',
        requestTimeout: const Duration(seconds: 10),
      );
      final ack = _validateWriteAck(response, operation: 'Heartbeat');
      if (ack != null) return ack;
      return ApiFailure(
        'Heartbeat failed with HTTP ${response.statusCode}.',
        statusCode: response.statusCode,
      );
    } on Object catch (error) {
      return ApiFailure('Heartbeat failed: ${_cloudDiagnosticText(error)}');
    }
  }

  Future<ApiResult<void>> endProtectionRun(
    ZentorConfig config,
    ProtectionRun protectionRun,
  ) async {
    final validation = _validateCloudWriteConfig(config);
    if (validation != null) return validation;
    final runId = _cloudIdToken(protectionRun.protectionRunId);
    if (runId == null) {
      return const ApiFailure(
        'A valid protection run ID is required to end a run.',
      );
    }
    final uri = _protectionRunUri(config, runId, 'end');
    try {
      final response = await _sendCloudRequest(
        http.Request('POST', uri)..headers.addAll(_headers(config)),
        operation: 'End protection run',
        requestTimeout: const Duration(seconds: 8),
      );
      final ack = _validateWriteAck(response, operation: 'End protection run');
      if (ack != null) return ack;
      return ApiFailure(
        'End protection run failed with HTTP ${response.statusCode}.',
        statusCode: response.statusCode,
      );
    } on Object catch (error) {
      return ApiFailure(
        'End protection run failed: ${_cloudDiagnosticText(error)}',
      );
    }
  }

  Future<ApiResult<void>> reportDetection(
    ZentorConfig config,
    ScanReport report,
  ) async {
    final validation = _validateCloudWriteConfig(config);
    if (validation != null) return validation;
    final reportValidation = _validateDetectionReportForCloud(report);
    if (reportValidation != null) return reportValidation;
    final uri = _cloudBaseUri(config).replace(path: '/v1/detections');
    try {
      final response = await _sendCloudRequest(
        http.Request('POST', uri)
          ..headers.addAll(_headers(config))
          ..body = jsonEncode({
            'project_id': _cloudPayloadText(config.projectId),
            'scan_kind': report.kind.name,
            'action_mode': report.actionMode.name,
            'files_scanned': report.filesScanned,
            'threats_found': report.threatsFound,
            'skipped_files': report.skippedFiles,
            'detections': [
              for (final threat in report.threats)
                {
                  'path_hash': _cloudPayloadText(threat.sha256),
                  'engine': _cloudPayloadText(threat.engine),
                  'threat_name': _cloudPayloadText(threat.threatName),
                  'detection_type': threat.detectionType.name,
                  'threat_category': threat.threatCategory.name,
                  'confidence': threat.confidence.name,
                  'status': threat.status.name,
                  'detected_at': threat.detectedAt.toIso8601String(),
                },
            ],
          }),
        operation: 'Detection report',
        requestTimeout: const Duration(seconds: 10),
      );
      final ack = _validateWriteAck(response, operation: 'Detection report');
      if (ack != null) return ack;
      return ApiFailure(
        'Detection report failed with HTTP ${response.statusCode}.',
        statusCode: response.statusCode,
      );
    } on Object catch (error) {
      return ApiFailure(
        'Detection report failed: ${_cloudDiagnosticText(error)}',
      );
    }
  }

  Future<ApiResult<void>> uploadQuarantineMetadata(
    ZentorConfig config,
    QuarantineRecord record,
  ) async {
    final validation = _validateCloudWriteConfig(config);
    if (validation != null) return validation;
    final metadataValidation = _validateQuarantineMetadataForCloud(record);
    if (metadataValidation != null) return metadataValidation;
    final uri = _cloudBaseUri(config).replace(path: '/v1/quarantine');
    try {
      final response = await _sendCloudRequest(
        http.Request('POST', uri)
          ..headers.addAll(_headers(config))
          ..body = jsonEncode({
            'project_id': _cloudPayloadText(config.projectId),
            'quarantine_id': _cloudPayloadText(record.quarantineId),
            'sha256': _cloudPayloadText(record.sha256),
            'detection_name': _cloudPayloadText(record.detectionName),
            'engine': _cloudPayloadText(record.engine),
            'quarantined_at': record.quarantinedAt.toIso8601String(),
            'status': record.status.name,
            'action_taken': _cloudPayloadText(record.actionTaken),
            'source': _cloudPayloadText(record.source),
            'blocked_before_execution': record.blockedBeforeExecution,
            'process_started': record.processStarted,
          }),
        operation: 'Quarantine metadata upload',
        requestTimeout: const Duration(seconds: 10),
      );
      final ack = _validateWriteAck(
        response,
        operation: 'Quarantine metadata upload',
      );
      if (ack != null) return ack;
      return ApiFailure(
        'Quarantine metadata upload failed with HTTP ${response.statusCode}.',
        statusCode: response.statusCode,
      );
    } on Object catch (error) {
      return ApiFailure(
        'Quarantine metadata upload failed: ${_cloudDiagnosticText(error)}',
      );
    }
  }

  Map<String, String> _headers(ZentorConfig config) => {
    'content-type': 'application/json',
    'authorization': 'Bearer ${_cloudPayloadText(config.publicClientKey)}',
  };

  Uri _protectionRunUri(ZentorConfig config, String runId, String action) =>
      _cloudBaseUri(
        config,
      ).replace(pathSegments: ['v1', 'protection-runs', runId, action]);

  Uri _cloudBaseUri(ZentorConfig config) => Uri.parse(config.apiBaseUrl.trim());

  ApiFailure<void>? _validateCloudWriteConfig(ZentorConfig config) {
    final validation = config.validateCloudConfiguration();
    if (validation.isEmpty) return null;
    return ApiFailure(validation.join(' '));
  }

  ApiFailure<ProtectionRun>? _validateProtectionRunPayloadForCloud(
    ProtectedAppConfig appConfig,
  ) {
    if (!_isCloudPayloadText(
          appConfig.platform,
          maxLength: _maxCloudPayloadPlatformChars,
        ) ||
        !_isSha256(appConfig.lastCalculatedHash)) {
      return const ApiFailure(
        'Protected app metadata is incomplete for cloud protection.',
      );
    }
    return null;
  }

  ApiFailure<void>? _validateDetectionReportForCloud(ScanReport report) {
    if (report.threats.length > maxCloudDetectionsPerReport) {
      return const ApiFailure(
        'Detection report contains too many detections for cloud reporting.',
      );
    }
    for (final threat in report.threats) {
      if (!_isSha256(threat.sha256) ||
          !_isCloudPayloadText(
            threat.engine,
            maxLength: _maxCloudPayloadEngineChars,
          ) ||
          !_isCloudPayloadText(
            threat.threatName,
            maxLength: _maxCloudPayloadNameChars,
          )) {
        return const ApiFailure(
          'Detection report contains invalid cloud metadata.',
        );
      }
    }
    return null;
  }

  ApiFailure<void>? _validateQuarantineMetadataForCloud(
    QuarantineRecord record,
  ) {
    if (!_isCloudPayloadText(
          record.quarantineId,
          maxLength: _maxCloudPayloadIdChars,
        ) ||
        !_isSha256(record.sha256) ||
        !_isCloudPayloadText(
          record.detectionName,
          maxLength: _maxCloudPayloadNameChars,
        ) ||
        !_isCloudPayloadText(
          record.engine,
          maxLength: _maxCloudPayloadEngineChars,
        ) ||
        !_quarantineActionMatchesStatus(record.actionTaken, record.status) ||
        !_quarantineSourceEvidenceIsValid(record)) {
      return const ApiFailure(
        'Quarantine metadata contains invalid cloud fields.',
      );
    }
    return null;
  }

  bool _quarantineActionMatchesStatus(
    String actionTaken,
    QuarantineItemStatus status,
  ) {
    return switch (status) {
      QuarantineItemStatus.quarantined => actionTaken == 'quarantined',
      QuarantineItemStatus.restored => actionTaken == 'restored',
      QuarantineItemStatus.deleted => actionTaken == 'deleted',
    };
  }

  bool _quarantineSourceEvidenceIsValid(QuarantineRecord record) {
    if (record.source != 'scanner') return false;
    return !record.blockedBeforeExecution && !record.processStarted;
  }

  bool _isCloudPayloadText(String value, {required int maxLength}) {
    if (_cloudPayloadControlPattern.hasMatch(value)) return false;
    final trimmed = value.trim();
    return trimmed.isNotEmpty && trimmed.length <= maxLength;
  }

  bool _isSha256(String value) {
    final trimmed = value.trim();
    if (trimmed.length != 64) return false;
    return RegExp(r'^[a-fA-F0-9]{64}$').hasMatch(trimmed);
  }

  String _cloudPayloadText(String value) => value.trim();

  String? _cloudIdToken(Object? value) {
    if (value is! String) return null;
    final trimmed = value.trim();
    if (trimmed.isEmpty || trimmed.length > _maxCloudIdChars) return null;
    if (!_cloudIdTokenPattern.hasMatch(trimmed)) return null;
    return trimmed;
  }

  String? _boundedCloudString(Object? value, {required int maxLength}) {
    if (value is! String) return null;
    final trimmed = value.replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ').trim();
    if (trimmed.isEmpty) return null;
    if (trimmed.length <= maxLength) return trimmed;
    return trimmed.substring(0, maxLength);
  }

  String _cloudDiagnosticText(Object error) {
    final text = error
        .toString()
        .replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ')
        .trim();
    if (text.isEmpty) return 'unknown error';
    if (text.length <= _maxCloudDiagnosticChars) return text;
    return text.substring(0, _maxCloudDiagnosticChars);
  }

  DateTime? _optionalDateTime(Object? value) {
    if (value == null) return null;
    if (value is! String) return null;
    final trimmed = value.trim();
    if (trimmed.isEmpty) return null;
    if (trimmed.length > _maxCloudTimestampChars) return null;
    return DateTime.tryParse(trimmed);
  }

  Future<http.Response> _sendCloudRequest(
    http.Request request, {
    required String operation,
    required Duration requestTimeout,
  }) async {
    final streamed = await _httpClient.send(request).timeout(requestTimeout);
    return _cloudResponseFromBoundedStreamedResponse(streamed, operation);
  }

  Future<http.Response> _cloudResponseFromBoundedStreamedResponse(
    http.StreamedResponse streamed,
    String operation,
  ) async {
    _rejectOversizedCloudJsonHeader(
      streamed.headers['content-length'],
      operation,
    );
    final bytes = <int>[];
    var totalBytes = 0;
    await for (final chunk in streamed.stream.timeout(
      _cloudResponseReadTimeoutValue,
    )) {
      totalBytes += chunk.length;
      if (totalBytes > _maxJsonResponseBytes) {
        throw FormatException(
          '$operation response exceeded the JSON size limit.',
        );
      }
      bytes.addAll(chunk);
    }
    return http.Response.bytes(
      bytes,
      streamed.statusCode,
      request: streamed.request,
      headers: streamed.headers,
      isRedirect: streamed.isRedirect,
      persistentConnection: streamed.persistentConnection,
      reasonPhrase: streamed.reasonPhrase,
    );
  }

  void _rejectOversizedCloudJsonHeader(
    String? contentLength,
    String operation,
  ) {
    if (contentLength == null || contentLength.trim().isEmpty) return;
    final length = int.tryParse(contentLength.trim());
    if (length == null || length < 0) {
      throw FormatException('$operation response Content-Length was invalid.');
    }
    if (length > _maxJsonResponseBytes) {
      throw FormatException(
        '$operation response exceeded the JSON size limit.',
      );
    }
  }

  Object? _decodeCloudJsonResponse(
    http.Response response, {
    required String operation,
  }) {
    return jsonDecode(response.body);
  }

  ApiResult<void>? _validateHealthAck(http.Response response) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      return null;
    }
    Object? decoded;
    try {
      decoded = _decodeCloudJsonResponse(response, operation: 'Health');
    } on Object catch (error) {
      return ApiFailure(
        'Avorax Cloud health response could not be parsed: '
        '${_cloudDiagnosticText(error)}',
        statusCode: response.statusCode,
      );
    }
    if (decoded is! Map<String, Object?>) {
      return ApiFailure(
        'Avorax Cloud health response was not a JSON object.',
        statusCode: response.statusCode,
      );
    }
    final ok = decoded['ok'];
    if (ok == true) {
      return const ApiSuccess(null);
    }
    if (ok == false) {
      return ApiFailure(
        'Avorax Cloud health endpoint reported unhealthy.',
        statusCode: response.statusCode,
      );
    }
    final status = decoded['status'];
    final statusText = _boundedCloudString(
      status,
      maxLength: _maxCloudStatusChars,
    );
    if (statusText != null) {
      final normalized = statusText.toLowerCase();
      if (normalized == 'ok' || normalized == 'healthy') {
        return const ApiSuccess(null);
      }
      if (normalized.isNotEmpty) {
        return ApiFailure(
          'Avorax Cloud health endpoint reported $normalized.',
          statusCode: response.statusCode,
        );
      }
    }
    return ApiFailure(
      'Avorax Cloud health response did not include a healthy marker.',
      statusCode: response.statusCode,
    );
  }

  ApiResult<void>? _validateWriteAck(
    http.Response response, {
    required String operation,
  }) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      return null;
    }
    Object? decoded;
    try {
      decoded = _decodeCloudJsonResponse(response, operation: operation);
    } on Object catch (error) {
      return ApiFailure(
        '$operation response could not be parsed: '
        '${_cloudDiagnosticText(error)}',
        statusCode: response.statusCode,
      );
    }
    if (decoded is! Map<String, Object?>) {
      return ApiFailure(
        '$operation response was not a JSON object.',
        statusCode: response.statusCode,
      );
    }
    final ok = decoded['ok'];
    if (ok == true) {
      return const ApiSuccess(null);
    }
    final error = _boundedCloudString(
      decoded['error'],
      maxLength: _maxCloudDiagnosticChars,
    );
    if (ok == false) {
      return ApiFailure(
        error != null
            ? '$operation was rejected by Avorax Cloud: $error'
            : '$operation was rejected by Avorax Cloud.',
        statusCode: response.statusCode,
      );
    }
    return ApiFailure(
      '$operation response did not include ok=true.',
      statusCode: response.statusCode,
    );
  }
}

int _requirePositiveCloudByteLimit(int value) {
  if (value <= 0) {
    throw ArgumentError.value(
      value,
      'maxJsonResponseBytes',
      'must be greater than zero',
    );
  }
  return value;
}

Duration _requirePositiveCloudTimeout(Duration value) {
  if (value <= Duration.zero) {
    throw ArgumentError.value(
      value,
      'cloudResponseReadTimeout',
      'must be greater than zero',
    );
  }
  return value;
}
