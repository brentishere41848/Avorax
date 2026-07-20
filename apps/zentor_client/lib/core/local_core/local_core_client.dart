import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:zentor_protocol/zentor_protocol.dart';

typedef LocalCoreProcessStarter =
    Future<Process> Function(String executable, List<String> arguments);

class LocalCoreClient {
  const LocalCoreClient({
    this.executableOverride,
    this.executableArguments = const [],
    this.guardExecutableOverride,
    this.guardExecutableArguments = const [],
    this.ipcTimeout = const Duration(minutes: 30),
    this.processStarter,
    this.protectionSelfTestTimeout,
    this.cancelIpcTimeout,
    this.elevatedPowerShellTimeout,
    this.ipcProcessReapTimeout,
    this.serviceHealthTimeout,
  });

  final String? executableOverride;
  final List<String> executableArguments;
  final String? guardExecutableOverride;
  final List<String> guardExecutableArguments;
  final Duration ipcTimeout;
  final LocalCoreProcessStarter? processStarter;
  final Duration? protectionSelfTestTimeout;
  final Duration? cancelIpcTimeout;
  final Duration? elevatedPowerShellTimeout;
  final Duration? ipcProcessReapTimeout;
  final Duration? serviceHealthTimeout;

  static Process? _activeScanProcess;
  static const _maxIpcStatusTextLength = 256;
  static const _maxIpcDiagnosticTextLength = 2048;
  static const _maxIpcStdoutLineLength = 64 * 1024;
  static const _ipcStdoutLineTruncationSuffix = '...[truncated]';
  static const _maxIpcTimestampTextLength = 64;
  static const _maxIpcStringListEntries = 64;
  static const _maxIpcProtocolWarnings = 8;
  static const _maxRiskReasons = 32;
  static const _maxRiskEngines = 16;
  static const _protectionSelfTestTimeout = Duration(seconds: 30);
  static const _cancelIpcTimeout = Duration(seconds: 5);
  static const _elevatedPowerShellTimeout = Duration(minutes: 2);
  static const _ipcProcessReapTimeout = Duration(seconds: 5);
  static const _windowsProcessTreeKillTimeout = Duration(seconds: 5);
  static const _serviceHealthTimeout = Duration(seconds: 10);
  static const _maxServiceHealthResponseBytes = 16 * 1024;

  bool get isDesktop =>
      Platform.isWindows || Platform.isMacOS || Platform.isLinux;

  Future<MalwareEngineStatus> health() async {
    return (await healthSummary()).malwareEngineStatus;
  }

  Future<CoreServiceBoundaryHealth> serviceBoundaryHealth() async {
    if (!Platform.isWindows) {
      return const CoreServiceBoundaryHealth(
        status: CoreServiceBoundaryStatus.unsupported,
        diagnostic:
            'Authenticated Core Service IPC is available only on Windows.',
      );
    }
    final executable = _localCoreExecutable();
    final executableProbe = executable == null
        ? null
        : _regularFileProbe(executable);
    if (executable == null || executableProbe!.isNotRegularFile) {
      return CoreServiceBoundaryHealth.unavailable(
        _missingRegularFileMessage(
          'Avorax Core Service',
          executable,
          probe: executableProbe,
          guidance: 'Authenticated service health could not be verified.',
        ),
      );
    }
    final executablePath = File(executable).absolute.path;
    final launchBlocker = _executableLaunchBlocker(
      'Avorax Core Service',
      executablePath,
      guidance: 'Authenticated service health could not be verified.',
    );
    if (launchBlocker != null) {
      return CoreServiceBoundaryHealth.unavailable(launchBlocker);
    }

    try {
      final timeout = serviceHealthTimeout ?? _serviceHealthTimeout;
      if (timeout.inMicroseconds <= 0 || timeout > _serviceHealthTimeout) {
        return CoreServiceBoundaryHealth.unavailable(
          'Core Service health timeout was outside its safe bounds.',
        );
      }
      final process = await (processStarter ?? Process.start)(executablePath, [
        ...executableArguments,
        '--service-ipc-health',
      ]);
      await process.stdin.close();
      final results =
          await Future.wait<Object>([
            _collectBoundedUtf8Text(
              process.stdout,
              maxBytes: _maxServiceHealthResponseBytes,
            ),
            _collectBoundedIpcText(process.stderr),
            process.exitCode,
          ]).timeout(
            timeout,
            onTimeout: () async {
              final terminationStatus = await _ipcTimeoutTerminationStatus(
                process,
              );
              final reapStatus = await _ipcReapStatus(process);
              throw TimeoutException(
                'Core Service health probe timed out after ${_formatDuration(timeout)}. '
                '$terminationStatus $reapStatus',
              );
            },
          );
      final stdout = results[0] as _BoundedUtf8Capture;
      final stderr = (results[1] as String).trim();
      final exitCode = results[2] as int;
      if (stdout.truncated) {
        return CoreServiceBoundaryHealth.unavailable(
          'Core Service health response exceeded the '
          '$_maxServiceHealthResponseBytes-byte limit.',
        );
      }
      if (exitCode != 0) {
        final detail = stderr.isEmpty
            ? 'no stderr output'
            : _boundedServiceHealthDiagnostic(stderr);
        return CoreServiceBoundaryHealth.unavailable(
          'Core Service health probe exited with exit code $exitCode: $detail',
        );
      }
      final text = stdout.text.trim();
      if (text.isEmpty) {
        return CoreServiceBoundaryHealth.unavailable(
          'Core Service health probe returned no response.',
        );
      }
      final Object? decoded;
      try {
        decoded = jsonDecode(text);
      } on Object catch (error) {
        return CoreServiceBoundaryHealth.unavailable(
          'Core Service health probe returned malformed JSON: '
          '${_ipcDiagnosticOrNull('$error') ?? 'parse failed'}',
        );
      }
      if (decoded is! Map) {
        return CoreServiceBoundaryHealth.unavailable(
          'Core Service health probe returned non-object JSON.',
        );
      }
      return CoreServiceBoundaryHealth.fromJson(
        Map<String, Object?>.from(decoded),
      );
    } on Object catch (error) {
      return CoreServiceBoundaryHealth.unavailable(
        'Authenticated Core Service health probe failed: '
        '${_ipcDiagnosticOrNull('$error') ?? 'unknown error'}',
      );
    }
  }

  Future<LocalCoreHealth> healthSummary() async {
    if (!isDesktop) return const LocalCoreHealth();
    final response = await _call({'command': 'health'});
    if (response == null) return const LocalCoreHealth();
    if (response['ok'] == false) {
      return LocalCoreHealth(
        coreServiceStatus: 'error',
        lastError: _ipcDiagnosticOrNull(response['error']),
      );
    }
    final engineStatus = _field(response, 'engineStatus', 'engine_status');
    final healthDiagnostics = <String>[];
    healthDiagnostics.addAll(
      _scanErrorList(_field(response, 'scanErrors', 'scan_errors')),
    );
    final aiStatus = _healthAiStatusField(
      _field(response, 'aiStatus', 'ai_status'),
      'ai_status',
      healthDiagnostics,
    );
    final aiModelRaw = _field(response, 'aiModel', 'ai_model');
    final coreServiceStatusError = _healthDiagnosticField(
      _field(response, 'coreServiceStatusError', 'core_service_status_error'),
      'core_service_status_error',
      healthDiagnostics,
    );
    if (coreServiceStatusError != null) {
      healthDiagnostics.add(coreServiceStatusError);
    }
    final guardStatusError = _healthDiagnosticField(
      _field(response, 'guardStatusError', 'guard_status_error'),
      'guard_status_error',
      healthDiagnostics,
    );
    if (guardStatusError != null) {
      healthDiagnostics.add(guardStatusError);
    }
    final enginePathsChecked = _ipcStringList(
      _field(response, 'enginePathsChecked', 'engine_paths_checked'),
      maxEntryLength: _maxIpcDiagnosticTextLength,
      diagnostics: healthDiagnostics,
      fieldName: 'engine_paths_checked',
    );
    final aiModelInfo = _healthAiModelInfo(aiModelRaw, healthDiagnostics);
    final nativeSelfTestPassed = _healthNullableBoolField(
      _field(response, 'nativeSelfTest', 'native_self_test'),
      fieldName: 'native_self_test',
      diagnostics: healthDiagnostics,
    );
    final nativeSelfTestError = _healthDiagnosticField(
      _field(response, 'nativeSelfTestError', 'native_self_test_error'),
      'native_self_test_error',
      healthDiagnostics,
    );
    final aiSelfTestPassed = _healthNullableBoolField(
      _field(response, 'aiSelfTest', 'ai_self_test'),
      fieldName: 'ai_self_test',
      diagnostics: healthDiagnostics,
    );
    final aiSelfTestError = _healthDiagnosticField(
      _field(response, 'aiSelfTestError', 'ai_self_test_error'),
      'ai_self_test_error',
      healthDiagnostics,
    );
    final ipcMode = _healthAllowedStringField(
      _field(response, 'ipc', 'ipc'),
      fallback: 'unknown',
      fieldName: 'ipc',
      allowedValues: const {'stdio'},
      diagnostics: healthDiagnostics,
    );
    final networkExposed = _healthNullableBoolField(
      _field(response, 'networkExposed', 'network_exposed'),
      fieldName: 'network_exposed',
      diagnostics: healthDiagnostics,
    );
    final nativeMlModelVersion = _healthOptionalStringField(
      _field(response, 'nativeMlModelVersion', 'native_ml_model_version'),
      'native_ml_model_version',
      healthDiagnostics,
    );
    final installPath = _healthOptionalStringField(
      _field(response, 'installPath', 'install_path'),
      'install_path',
      healthDiagnostics,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    final engineDirectory = _healthOptionalStringField(
      _field(response, 'engineDirectory', 'engine_directory'),
      'engine_directory',
      healthDiagnostics,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    final nativeSignaturesDirectory = _healthOptionalStringField(
      _field(response, 'signaturesDir', 'signatures_dir'),
      'signatures_dir',
      healthDiagnostics,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    final nativeRulesDirectory = _healthOptionalStringField(
      _field(response, 'rulesDir', 'rules_dir'),
      'rules_dir',
      healthDiagnostics,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    final nativeMlDirectory = _healthOptionalStringField(
      _field(response, 'mlDir', 'ml_dir'),
      'ml_dir',
      healthDiagnostics,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    final nativeTrustDirectory = _healthOptionalStringField(
      _field(response, 'trustDir', 'trust_dir'),
      'trust_dir',
      healthDiagnostics,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    final nativeConfigDirectory = _healthOptionalStringField(
      _field(response, 'configDir', 'config_dir'),
      'config_dir',
      healthDiagnostics,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    final programDataDirectory = _healthOptionalStringField(
      _field(response, 'programDataDir', 'program_data_dir'),
      'program_data_dir',
      healthDiagnostics,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    final programDataDirectoryError = _healthDiagnosticField(
      _field(response, 'programDataDirError', 'program_data_dir_error'),
      'program_data_dir_error',
      healthDiagnostics,
    );
    final nativeEngineError = _healthDiagnosticField(
      _field(response, 'nativeError', 'native_error'),
      'native_error',
      healthDiagnostics,
    );
    final lastError = _healthDiagnosticField(
      _field(response, 'lastError', 'last_error'),
      'last_error',
      healthDiagnostics,
    );
    return LocalCoreHealth(
      malwareEngineStatus: _healthMalwareEngineStatus(
        engineStatus,
        healthDiagnostics,
      ),
      aiStatus: aiStatus,
      aiModelInfo: aiModelInfo,
      yaraStatus: _healthAllowedStringField(
        _field(response, 'yaraStatus', 'yara_status'),
        fallback: 'rulesUnavailable',
        fieldName: 'yara_status',
        allowedValues: const {'compatDisabled', 'rulesUnavailable', 'ready'},
        diagnostics: healthDiagnostics,
      ),
      yaraRuleCount: _healthIntField(
        response,
        'yaraRuleCount',
        'yara_rule_count',
        healthDiagnostics,
      ),
      nativeEngineStatus: _healthAllowedStringField(
        _field(response, 'nativeEngineStatus', 'native_engine_status'),
        fallback: 'unavailable',
        fieldName: 'native_engine_status',
        allowedValues: const {'ready', 'error', 'unavailable'},
        diagnostics: healthDiagnostics,
      ),
      nativeSignatureCount: _healthIntField(
        response,
        'nativeSignatureCount',
        'native_signature_count',
        healthDiagnostics,
      ),
      nativeRuleCount: _healthIntField(
        response,
        'nativeRuleCount',
        'native_rule_count',
        healthDiagnostics,
      ),
      nativeMlStatus: _healthAllowedStringField(
        _field(response, 'nativeMlStatus', 'native_ml_status'),
        fallback: 'modelMissing',
        fieldName: 'native_ml_status',
        allowedValues: const {
          'loaded',
          'developmentModel',
          'modelMissing',
          'error',
        },
        diagnostics: healthDiagnostics,
      ),
      nativeMlModelVersion: nativeMlModelVersion,
      nativeMlProductionReady: _ipcBool(
        _field(
          response,
          'nativeMlProductionReady',
          'native_ml_production_ready',
        ),
        diagnostics: healthDiagnostics,
        fieldName: 'native_ml_production_ready',
      ),
      nativeEngineError: nativeEngineError,
      nativeSelfTestPassed: nativeSelfTestPassed,
      nativeSelfTestError: nativeSelfTestError,
      aiSelfTestPassed: aiSelfTestPassed,
      aiSelfTestError: aiSelfTestError,
      ipcMode: ipcMode,
      networkExposed: networkExposed,
      compatibilityEnginesEnabled: _ipcBool(
        _field(
          response,
          'compatibilityEnginesEnabled',
          'compatibility_engines_enabled',
        ),
        diagnostics: healthDiagnostics,
        fieldName: 'compatibility_engines_enabled',
      ),
      coreServiceStatus: _healthAllowedStringField(
        _field(response, 'coreServiceStatus', 'core_service_status'),
        fallback: 'unknown',
        fieldName: 'core_service_status',
        allowedValues: const {
          'running',
          'stopped',
          'missing',
          'installed',
          'unknown',
          'unsupported',
          'error',
        },
        diagnostics: healthDiagnostics,
      ),
      coreServiceStatusError: coreServiceStatusError,
      guardStatus: _healthAllowedStringField(
        _field(response, 'guardStatus', 'guard_status'),
        fallback: 'unknown',
        fieldName: 'guard_status',
        allowedValues: const {
          'running',
          'stopped',
          'missing',
          'installed',
          'unknown',
          'off',
        },
        diagnostics: healthDiagnostics,
      ),
      guardStatusError: guardStatusError,
      driverStatus: _healthAllowedStringField(
        _field(response, 'driverStatus', 'driver_status'),
        fallback: 'unknown',
        fieldName: 'driver_status',
        allowedValues: const {
          'running',
          'stopped',
          'missing',
          'installed',
          'unknown',
        },
        diagnostics: healthDiagnostics,
      ),
      processMonitorStatus: _healthAllowedStringField(
        _field(response, 'processMonitorStatus', 'process_monitor_status'),
        fallback: 'unknown',
        fieldName: 'process_monitor_status',
        allowedValues: const {
          'active',
          'notActive',
          'unavailable',
          'unknown',
          'error',
        },
        diagnostics: healthDiagnostics,
      ),
      processMonitorCapability: _healthAllowedStringField(
        _field(
          response,
          'processMonitorCapability',
          'process_monitor_capability',
        ),
        fallback: 'unknown',
        fieldName: 'process_monitor_capability',
        allowedValues: const {
          'userModeSnapshot',
          'userModePolling',
          'endpointSecurityWhenEntitled',
          'fanotifyOrInotifyWhenAvailable',
          'unavailable',
          'unknown',
        },
        diagnostics: healthDiagnostics,
      ),
      processMonitorStatusReason: _healthDiagnosticField(
        _field(
          response,
          'processMonitorStatusReason',
          'process_monitor_status_reason',
        ),
        'process_monitor_status_reason',
        healthDiagnostics,
      ),
      behaviorMonitorStatus: _healthAllowedStringField(
        _field(response, 'behaviorMonitorStatus', 'behavior_monitor_status'),
        fallback: 'unknown',
        fieldName: 'behavior_monitor_status',
        allowedValues: const {
          'active',
          'notActive',
          'unavailable',
          'unknown',
          'error',
        },
        diagnostics: healthDiagnostics,
      ),
      behaviorMonitorStatusReason: _healthDiagnosticField(
        _field(
          response,
          'behaviorMonitorStatusReason',
          'behavior_monitor_status_reason',
        ),
        'behavior_monitor_status_reason',
        healthDiagnostics,
      ),
      reputationStatus: _healthAllowedStringField(
        _field(response, 'reputationStatus', 'reputation_status'),
        fallback: 'unavailable',
        fieldName: 'reputation_status',
        allowedValues: const {
          'available',
          'unavailable',
          'disabled',
          'unknown',
          'error',
        },
        diagnostics: healthDiagnostics,
      ),
      reputationStatusReason: _healthDiagnosticField(
        _field(response, 'reputationStatusReason', 'reputation_status_reason'),
        'reputation_status_reason',
        healthDiagnostics,
      ),
      installPath: installPath,
      engineDirectory: engineDirectory,
      nativeSignaturesDirectory: nativeSignaturesDirectory,
      nativeRulesDirectory: nativeRulesDirectory,
      nativeMlDirectory: nativeMlDirectory,
      nativeTrustDirectory: nativeTrustDirectory,
      nativeConfigDirectory: nativeConfigDirectory,
      enginePathsChecked: enginePathsChecked,
      programDataDirectory: programDataDirectory,
      programDataDirectoryError: programDataDirectoryError,
      lastError: _healthLastErrorWithDiagnostics(lastError, healthDiagnostics),
    );
  }

  Future<ScanReport> scanFile(
    String path, {
    required ScanKind kind,
    required ScanActionMode actionMode,
    void Function(ScanProgress progress)? onProgress,
  }) async {
    return _scanCommand(
      {
        'command': 'scan_file',
        'path': path,
        'scan_kind': kind.name,
        'action_mode': actionMode.name,
      },
      kind: kind,
      actionMode: actionMode,
      onProgress: onProgress,
    );
  }

  Future<ScanReport> scanPaths(
    List<String> paths, {
    required ScanKind kind,
    required ScanActionMode actionMode,
    void Function(ScanProgress progress)? onProgress,
  }) async {
    return _scanCommand(
      {
        'command': kind == ScanKind.full
            ? 'full_scan'
            : 'quick_scan_selected_paths',
        'paths': paths,
        'scan_kind': kind.name,
        'action_mode': actionMode.name,
      },
      kind: kind,
      actionMode: actionMode,
      onProgress: onProgress,
    );
  }

  Future<List<QuarantineRecord>> listQuarantine() async {
    final response = await _call({'command': 'list_quarantine'});
    if (response?['ok'] != true) {
      final error = _ipcDiagnosticOrNull(response?['error']);
      throw StateError(error ?? 'Quarantine list request failed.');
    }
    _rejectListProtocolWarnings(response, responseName: 'Quarantine list');
    final records = response?['records'];
    if (records is! List) {
      throw StateError('Quarantine response did not include a records list.');
    }
    final parsed = <QuarantineRecord>[];
    for (var index = 0; index < records.length; index += 1) {
      final item = records[index];
      if (item is! Map) {
        throw StateError(
          'Quarantine response record $index was not an object.',
        );
      }
      final record = _quarantineRecordFromJson(Map<String, Object?>.from(item));
      if (record == null) {
        throw StateError('Quarantine response record $index was malformed.');
      }
      parsed.add(record);
    }
    return parsed;
  }

  QuarantineRecord? _quarantineRecordFromJson(Map<String, Object?> map) {
    final quarantineId = _recordId(
      _field(map, 'quarantineId', 'quarantine_id'),
    );
    final originalPath = _recordPathField(
      _field(map, 'originalPath', 'original_path'),
    );
    final quarantinePath = _recordPathField(
      _field(map, 'quarantinePath', 'quarantine_path'),
    );
    final sha256 = _normalizedSha256(map['sha256']);
    final quarantinedAtValue = _field(map, 'quarantinedAt', 'quarantined_at');
    final quarantinedAt = quarantinedAtValue == null
        ? null
        : _recordDateTimeOrNull(quarantinedAtValue);
    final statusValue = map['status'];
    final statusName = _ipcStringOrNull(statusValue);
    final status = statusName == null
        ? null
        : _enumByName(QuarantineItemStatus.values, statusName);
    final fileSizeValue = _field(map, 'fileSize', 'file_size');
    final fileSize = _recordIntField(map, 'fileSize', 'file_size');
    final detectionName = _recordStringField(
      map,
      'detectionName',
      'detection_name',
    );
    final engine = _recordStringField(map, 'engine', 'engine');
    final source = _recordStringField(map, 'source', 'source');
    final actionTaken = _recordStringField(map, 'actionTaken', 'action_taken');
    final userNoteValue = _field(map, 'userNote', 'user_note');
    final userNote = userNoteValue == null
        ? null
        : _ipcDiagnosticOrNull(userNoteValue);
    final blockedBeforeExecutionValue = _field(
      map,
      'blockedBeforeExecution',
      'blocked_before_execution',
    );
    final blockedBeforeExecution = _optionalRecordBool(
      blockedBeforeExecutionValue,
    );
    final processStartedValue = _field(
      map,
      'processStarted',
      'process_started',
    );
    final processStarted = _optionalRecordBool(processStartedValue);
    final processIdValue = _field(map, 'processId', 'process_id');
    final processId = processIdValue == null
        ? null
        : _parseNonNegativeInt(processIdValue);
    if (quarantineId == null ||
        originalPath == null ||
        quarantinePath == null ||
        sha256 == null ||
        quarantinedAt == null ||
        statusValue == null ||
        statusName == null ||
        status == null ||
        fileSizeValue == null ||
        fileSize == null ||
        detectionName == null ||
        engine == null ||
        source == null ||
        actionTaken == null ||
        (userNoteValue != null && userNote == null) ||
        blockedBeforeExecutionValue == null ||
        blockedBeforeExecution == null ||
        processStartedValue == null ||
        processStarted == null ||
        (processIdValue != null && processId == null) ||
        !_quarantineActionMatchesStatus(actionTaken, status) ||
        !_quarantineSourceEvidenceIsValid(
          source,
          blockedBeforeExecution,
          processStarted,
          processId,
        )) {
      return null;
    }
    return QuarantineRecord(
      quarantineId: quarantineId,
      originalPath: originalPath,
      quarantinePath: quarantinePath,
      sha256: sha256,
      fileSize: fileSize,
      detectionName: detectionName,
      engine: engine,
      quarantinedAt: quarantinedAt,
      status: status,
      userNote: userNote,
      source: source,
      blockedBeforeExecution: blockedBeforeExecution,
      processStarted: processStarted,
      actionTaken: actionTaken,
    );
  }

  Future<LocalCoreActionResult> quarantineThreat(ThreatResult threat) async {
    final response = await _call({
      'command': 'quarantine_file',
      'path': threat.path,
      'threat_name': threat.threatName,
      'engine': threat.engine,
    });
    return _actionResult(
      response,
      fallbackError: 'Quarantine request failed.',
      successEvidenceError: (response) => _quarantineActionEvidenceError(
        response,
        expectedStatus: QuarantineItemStatus.quarantined,
      ),
    );
  }

  Future<LocalCoreActionResult> quarantineFile(
    String path, {
    required String threatName,
    required String engine,
  }) async {
    final response = await _call({
      'command': 'quarantine_file',
      'path': path,
      'threat_name': threatName,
      'engine': engine,
    });
    return _actionResult(
      response,
      fallbackError: 'Quarantine request failed.',
      successEvidenceError: (response) => _quarantineActionEvidenceError(
        response,
        expectedStatus: QuarantineItemStatus.quarantined,
      ),
    );
  }

  Future<LocalCoreActionResult> addAllowlistEntry(String path) async {
    final response = await _call({
      'command': 'add_allowlist_entry',
      'path': path,
    });
    return _actionResult(
      response,
      fallbackError: 'Allowlist add request failed.',
      successEvidenceError: (response) =>
          _allowlistActionEvidenceError(response, expectedActive: true),
    );
  }

  Future<List<AllowlistEntry>> listAllowlist() async {
    final response = await _call({'command': 'list_allowlist'});
    if (response?['ok'] != true) {
      final error = _ipcDiagnosticOrNull(response?['error']);
      throw StateError(error ?? 'Allowlist list request failed.');
    }
    _rejectListProtocolWarnings(response, responseName: 'Allowlist list');
    final entries = response?['entries'];
    if (entries is! List) {
      throw StateError('Allowlist response did not include an entries list.');
    }
    final parsed = <AllowlistEntry>[];
    for (var index = 0; index < entries.length; index += 1) {
      final item = entries[index];
      if (item is! Map) {
        throw StateError('Allowlist response entry $index was not an object.');
      }
      final entry = _allowlistEntryFromJson(Map<String, Object?>.from(item));
      if (entry == null) {
        throw StateError('Allowlist response entry $index was malformed.');
      }
      parsed.add(entry);
    }
    return parsed;
  }

  void _rejectListProtocolWarnings(
    Map<String, Object?>? response, {
    required String responseName,
  }) {
    final protocolWarnings = response == null
        ? const <String>[]
        : _scanErrorList(_field(response, 'scanErrors', 'scan_errors'));
    if (protocolWarnings.isNotEmpty) {
      throw StateError(
        '$responseName response had protocol warnings: ${protocolWarnings.first}',
      );
    }
  }

  Future<LocalCoreActionResult> removeAllowlistEntry(String id) async {
    final response = await _call({
      'command': 'remove_allowlist_entry',
      'allowlist_id': id,
      'confirmed': true,
    });
    return _actionResult(
      response,
      fallbackError: 'Allowlist remove request failed.',
      successEvidenceError: (response) => _allowlistActionEvidenceError(
        response,
        expectedActive: false,
        expectedId: id,
      ),
    );
  }

  Future<LocalCoreActionResult> labelDetection(
    ThreatResult threat,
    String label, {
    String? note,
  }) async {
    final response = await _call({
      'command': 'label_detection',
      'path': threat.path,
      'user_label': label,
      'user_note': note,
      'previous_verdict': threat.riskScore.verdict.name,
    });
    return _actionResult(
      response,
      fallbackError: 'Detection label request failed.',
      successEvidenceError: (response) =>
          _pathActionEvidenceError(response, fieldName: 'path'),
    );
  }

  Future<LocalCoreActionResult> restoreQuarantineItem(
    String quarantineId,
  ) async {
    final response = await _call({
      'command': 'restore_quarantine_item',
      'quarantine_id': quarantineId,
      'confirmed': true,
    });
    return _actionResult(
      response,
      fallbackError: 'Quarantine restore request failed.',
      successEvidenceError: (response) => _quarantineActionEvidenceError(
        response,
        expectedStatus: QuarantineItemStatus.restored,
        expectedId: quarantineId,
      ),
    );
  }

  Future<LocalCoreActionResult> deleteQuarantineItem(
    String quarantineId,
  ) async {
    final response = await _call({
      'command': 'delete_quarantine_item',
      'quarantine_id': quarantineId,
      'confirmed': true,
    });
    return _actionResult(
      response,
      fallbackError: 'Quarantine delete request failed.',
      successEvidenceError: (response) => _quarantineActionEvidenceError(
        response,
        expectedStatus: QuarantineItemStatus.deleted,
        expectedId: quarantineId,
      ),
    );
  }

  Future<ProtectionSelfTestResult> runProtectionSelfTest() async {
    if (!isDesktop) {
      return const ProtectionSelfTestResult.failed(
        'Protection self-test is only available on desktop platforms.',
      );
    }
    final executable = _guardServiceExecutable();
    final executableProbe = executable == null
        ? null
        : _regularFileProbe(executable);
    if (executable == null || executableProbe!.isNotRegularFile) {
      return ProtectionSelfTestResult.failed(
        _missingRegularFileMessage(
          'Avorax Guard Service',
          executable,
          probe: executableProbe,
          guidance: 'Post-launch fallback cannot be self-tested.',
        ),
      );
    }
    final executablePath = File(executable).resolveSymbolicLinksSync();
    final launchBlocker = _executableLaunchBlocker(
      'Avorax Guard Service',
      executablePath,
      guidance: 'Post-launch fallback cannot be self-tested.',
    );
    if (launchBlocker != null) {
      return ProtectionSelfTestResult.failed(launchBlocker);
    }
    try {
      final timeout = protectionSelfTestTimeout ?? _protectionSelfTestTimeout;
      final process = await (processStarter ?? Process.start)(
        executablePath,
        guardExecutableArguments,
      );
      process.stdin.writeln(jsonEncode({'command': 'driver_self_test'}));
      await process.stdin.close();
      final stdoutFuture = _collectBoundedIpcText(process.stdout);
      final stderrFuture = _collectBoundedIpcText(process.stderr);
      final results =
          await Future.wait<Object>([
            stdoutFuture,
            stderrFuture,
            process.exitCode,
          ]).timeout(
            timeout,
            onTimeout: () async {
              final terminationStatus = await _ipcTimeoutTerminationStatus(
                process,
              );
              final reapStatus = await _ipcReapStatus(process);
              throw TimeoutException(
                'Protection self-test timed out after ${_formatDuration(timeout)}. $terminationStatus $reapStatus',
              );
            },
          );
      final stdout = (results[0] as String).trim();
      final stderr = results[1] as String;
      final exitCode = results[2] as int;
      return _protectionSelfTestResultFromOutput(
        stdout: stdout,
        stderr: stderr,
        exitCode: exitCode,
      );
    } on Object catch (error) {
      final details = _ipcDiagnosticOrNull('$error') ?? 'Self-test failed.';
      return ProtectionSelfTestResult.failed(
        'Protection self-test failed: $details',
      );
    }
  }

  ProtectionSelfTestResult _protectionSelfTestResultFromOutput({
    required String stdout,
    required String stderr,
    required int exitCode,
  }) {
    if (exitCode != 0) {
      final diagnostic = stderr.isEmpty ? null : _ipcDiagnosticOrNull(stderr);
      return ProtectionSelfTestResult.failed(
        diagnostic == null
            ? 'Protection self-test process exited with code $exitCode.'
            : 'Protection self-test process exited with code $exitCode: $diagnostic',
      );
    }
    if (stderr.isNotEmpty) {
      final diagnostic = _ipcDiagnosticOrNull(stderr);
      return ProtectionSelfTestResult.failed(
        diagnostic == null
            ? 'Protection self-test returned malformed stderr diagnostics.'
            : 'Protection self-test returned stderr diagnostics: $diagnostic',
      );
    }
    final lines = stdout
        .split(RegExp(r'\r?\n'))
        .map((line) => line.trim())
        .where((line) => line.isNotEmpty)
        .toList(growable: false);
    if (lines.length != 1) {
      return ProtectionSelfTestResult.failed(
        lines.isEmpty
            ? 'Protection self-test produced no output.'
            : 'Protection self-test returned multiple non-empty response lines.',
      );
    }

    Object? decoded;
    try {
      decoded = jsonDecode(lines.single);
    } on Object {
      return const ProtectionSelfTestResult.failed(
        'Protection self-test returned invalid response JSON.',
      );
    }
    final response = _actionEvidenceObject(decoded);
    if (response == null || !_hasExactSelfTestResponseFields(response)) {
      return const ProtectionSelfTestResult.failed(
        'Protection self-test returned a malformed response object.',
      );
    }
    final ok = response['ok'];
    final action = _strictSelfTestText(response['action'], maxLength: 64);
    final message = _protectionSelfTestMessage(response['message']);
    final createdAt = _strictSelfTestTimestamp(response['created_at']);
    if (ok is! bool || action == null || message == null || createdAt == null) {
      return const ProtectionSelfTestResult.failed(
        'Protection self-test response fields failed validation.',
      );
    }
    if (response['process_id'] != null ||
        response['process_path'] != null ||
        response['quarantine_id'] != null ||
        response['quarantine_path'] != null ||
        response['quarantine_record_path'] != null) {
      return const ProtectionSelfTestResult.failed(
        'Protection self-test response contained unrelated action evidence.',
      );
    }
    if (action == 'error') {
      if (ok) {
        return const ProtectionSelfTestResult.failed(
          'Protection self-test error response contradicted its success flag.',
        );
      }
      return ProtectionSelfTestResult.failed(
        'Protection self-test failed: $message',
      );
    }
    if (action != 'driverSelfTest') {
      return const ProtectionSelfTestResult.failed(
        'Protection self-test response had an unexpected action.',
      );
    }

    Object? reportDecoded;
    try {
      reportDecoded = jsonDecode(message);
    } on Object {
      return const ProtectionSelfTestResult.failed(
        'Protection self-test report JSON was invalid.',
      );
    }
    final report = _actionEvidenceObject(reportDecoded);
    if (report == null || !_hasExactSelfTestReportFields(report)) {
      return const ProtectionSelfTestResult.failed(
        'Protection self-test report shape was invalid.',
      );
    }
    final reportPassed = report['passed'];
    final overallResult = _strictSelfTestText(
      report['overall_result'],
      maxLength: 16,
    );
    final version = _strictSelfTestText(
      report['zentor_version'],
      maxLength: 128,
    );
    final timestamp = _strictSelfTestTimestamp(report['timestamp_utc']);
    final preExecutionAvailable = report['pre_execution_blocking_available'];
    if (reportPassed is! bool ||
        overallResult == null ||
        version == null ||
        timestamp == null ||
        preExecutionAvailable is! bool ||
        !_validSelfTestDriver(report['driver']) ||
        !_validSelfTestGuard(report['guard_service']) ||
        !_validSelfTestResults(report['tests']) ||
        !_validSelfTestAi(report['ai']) ||
        createdAt.difference(timestamp).inSeconds.abs() > 300) {
      return const ProtectionSelfTestResult.failed(
        'Protection self-test report fields failed validation.',
      );
    }
    final stepsValue = report['steps'];
    if (stepsValue is! List || stepsValue.isEmpty || stepsValue.length > 64) {
      return const ProtectionSelfTestResult.failed(
        'Protection self-test report had an invalid step list.',
      );
    }
    final steps = _parseProtectionSelfTestSteps(stepsValue);
    if (!steps.valid) {
      return ProtectionSelfTestResult.failed(steps.details);
    }
    if (reportPassed != steps.allPassed ||
        overallResult != (reportPassed ? 'pass' : 'fail') ||
        ok != reportPassed) {
      return ProtectionSelfTestResult.failed(
        'Protection self-test success evidence was contradictory.\n${steps.details}',
      );
    }
    return ProtectionSelfTestResult(
      passed: reportPassed,
      details: steps.details,
    );
  }

  bool _hasExactSelfTestResponseFields(Map<String, Object?> response) {
    const expected = <String>{
      'ok',
      'action',
      'message',
      'process_id',
      'process_path',
      'quarantine_id',
      'quarantine_path',
      'quarantine_record_path',
      'created_at',
    };
    return response.length == expected.length &&
        expected.every(response.containsKey);
  }

  bool _hasExactSelfTestReportFields(Map<String, Object?> report) {
    const expected = <String>{
      'zentor_version',
      'timestamp_utc',
      'driver',
      'guard_service',
      'tests',
      'ai',
      'overall_result',
      'passed',
      'pre_execution_blocking_available',
      'steps',
    };
    return report.length == expected.length &&
        expected.every(report.containsKey);
  }

  String? _protectionSelfTestMessage(Object? value) {
    if (value is! String ||
        value.isEmpty ||
        value.trim() != value ||
        value.length > _maxIpcStdoutLineLength ||
        RegExp(r'[\x00-\x1F\x7F]').hasMatch(value)) {
      return null;
    }
    return value;
  }

  String? _strictSelfTestText(Object? value, {required int maxLength}) {
    if (value is! String ||
        value.isEmpty ||
        value.length > maxLength ||
        value.trim() != value ||
        RegExp(r'[\x00-\x1F\x7F]').hasMatch(value)) {
      return null;
    }
    return value;
  }

  DateTime? _strictSelfTestTimestamp(Object? value) {
    final text = _strictSelfTestText(value, maxLength: 64);
    if (text == null) return null;
    final match = RegExp(
      r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,9})?(?:Z|\+00:00)$',
    ).firstMatch(text);
    if (match == null) return null;
    final parsed = DateTime.tryParse(text);
    if (parsed == null || !parsed.isUtc) return null;
    final expectedParts = <int>[
      for (var index = 1; index <= 6; index++) int.parse(match.group(index)!),
    ];
    final parsedParts = <int>[
      parsed.year,
      parsed.month,
      parsed.day,
      parsed.hour,
      parsed.minute,
      parsed.second,
    ];
    for (var index = 0; index < expectedParts.length; index++) {
      if (expectedParts[index] != parsedParts[index]) return null;
    }
    return parsed;
  }

  bool _validSelfTestDriver(Object? value) => _exactBooleanObject(value, const {
    'built',
    'installed',
    'running',
    'test_signed',
    'production_signed',
    'communication_port_ok',
  });

  bool _validSelfTestGuard(Object? value) => _exactBooleanObject(value, const {
    'running',
    'ipc_ok',
    'verdict_cache_ok',
  });

  bool _validSelfTestResults(Object? value) =>
      _exactBooleanObject(value, const {
        'eicar_scan_blocked',
        'eicar_quarantined',
        'known_bad_executable_blocked_before_launch',
        'known_bad_executable_quarantined',
        'unknown_unsigned_lockdown_blocked_before_launch',
        'unknown_unsigned_lockdown_policy_blocked',
        'unknown_unsigned_allowed_after_hash_approval',
        'known_good_executable_allowed',
        'normal_exe_blocked_only_as_unknown',
        'post_launch_fallback_verified',
        'quarantine_ui_record_created',
      });

  bool _validSelfTestAi(Object? value) {
    final ai = _actionEvidenceObject(value);
    if (ai == null) return false;
    const required = <String>{
      'model_loaded',
      'model_version',
      'production_ready',
      'can_auto_quarantine_ai_only',
    };
    final hasMetadataError = ai.containsKey('metadata_error');
    if (ai.length != required.length + (hasMetadataError ? 1 : 0) ||
        !required.every(ai.containsKey) ||
        ai['model_loaded'] is! bool ||
        ai['production_ready'] is! bool ||
        ai['can_auto_quarantine_ai_only'] is! bool ||
        _strictSelfTestText(ai['model_version'], maxLength: 128) == null) {
      return false;
    }
    return !hasMetadataError ||
        _strictSelfTestText(ai['metadata_error'], maxLength: 2048) != null;
  }

  bool _exactBooleanObject(Object? value, Set<String> fields) {
    final object = _actionEvidenceObject(value);
    return object != null &&
        object.length == fields.length &&
        fields.every(
          (field) => object.containsKey(field) && object[field] is bool,
        );
  }

  _ProtectionSelfTestSteps _parseProtectionSelfTestSteps(List<Object?> steps) {
    final rows = <String>[];
    final names = <String>{};
    var valid = true;
    var allPassed = true;
    for (var index = 0; index < steps.length; index++) {
      final stepNumber = index + 1;
      final step = _actionEvidenceObject(steps[index]);
      if (step == null ||
          step.length != 3 ||
          !step.containsKey('name') ||
          !step.containsKey('reason') ||
          !step.containsKey('passed')) {
        rows.add(
          'FAIL malformed self-test step $stepNumber: invalid step object',
        );
        valid = false;
        allPassed = false;
        continue;
      }
      final name = _strictSelfTestText(step['name'], maxLength: 128);
      if (name == null || !names.add(name)) {
        rows.add('FAIL malformed self-test step $stepNumber: malformed name');
        valid = false;
        allPassed = false;
        continue;
      }
      final reason = _strictSelfTestText(step['reason'], maxLength: 2048);
      if (reason == null) {
        rows.add('FAIL $name: malformed reason');
        valid = false;
        allPassed = false;
        continue;
      }
      final passed = step['passed'];
      if (passed is! bool) {
        rows.add('FAIL $name: malformed passed flag; $reason');
        valid = false;
        allPassed = false;
        continue;
      }
      allPassed = allPassed && passed;
      final status = passed ? 'PASS' : 'FAIL';
      rows.add('$status $name: $reason');
    }
    return _ProtectionSelfTestSteps(
      valid: valid,
      allPassed: allPassed,
      details: rows.join('\n'),
    );
  }

  Future<LocalCoreActionResult> configureGuardMode(ProtectionMode mode) async {
    final response = await _call({
      'command': 'configure_guard_mode',
      'protection_mode': mode.name,
    });
    return _actionResult(
      response,
      fallbackError: 'Guard mode config request failed.',
      successEvidenceError: (response) => _pathActionEvidenceError(
        response,
        fieldName: 'guard_mode_config_path',
      ),
    );
  }

  Future<LocalCoreActionResult> configureRansomwareGuard({
    required List<String> protectedRoots,
    required List<String> trustedProcesses,
  }) async {
    final response = await _call({
      'command': 'configure_ransomware_guard',
      'protected_roots': protectedRoots,
      'trusted_process_allowlist': trustedProcesses,
    });
    return _actionResult(
      response,
      fallbackError: 'Ransomware guard config request failed.',
      successEvidenceError: (response) => _pathActionEvidenceError(
        response,
        fieldName: 'ransomware_guard_config_path',
      ),
    );
  }

  Future<RealtimeWatcherState> startWatch(List<String> paths) async {
    final response = await _call({'command': 'start_watch', 'paths': paths});
    final protocolError = _watcherProtocolError(
      response,
      fallbackError: 'Start watch request failed.',
    );
    if (protocolError != null) {
      return RealtimeWatcherState(
        active: false,
        mode: 'off',
        watchedPaths: const [],
        error: protocolError,
      );
    }
    final watcher = response!['watcher'];
    if (watcher is Map) {
      return RealtimeWatcherState.fromJson(Map<String, Object?>.from(watcher));
    }
    return const RealtimeWatcherState(
      active: false,
      mode: 'off',
      error: 'Start watch response did not include watcher state.',
    );
  }

  Future<RealtimeWatcherState> stopWatch() async {
    final response = await _call({'command': 'stop_watch'});
    final protocolError = _watcherProtocolError(
      response,
      fallbackError: 'Stop watch request failed.',
    );
    if (protocolError != null) {
      return RealtimeWatcherState(
        active: false,
        mode: 'off',
        watchedPaths: const [],
        error: protocolError,
      );
    }
    final watcher = response!['watcher'];
    if (watcher is Map) {
      return RealtimeWatcherState.fromJson(Map<String, Object?>.from(watcher));
    }
    return const RealtimeWatcherState(
      active: false,
      mode: 'off',
      error: 'Stop watch response did not include watcher state.',
    );
  }

  Future<WatchPollScanResult> watchPollScan(
    List<String> paths, {
    Duration duration = const Duration(seconds: 4),
    Duration pollInterval = const Duration(milliseconds: 200),
    int maxEvents = 8,
  }) async {
    final response = await _call({
      'command': 'watch_poll_scan',
      'paths': paths,
      'action_mode': ScanActionMode.autoQuarantineConfirmedOnly.name,
      'scan_kind': ScanKind.custom.name,
      'duration_ms': duration.inMilliseconds,
      'poll_interval_ms': pollInterval.inMilliseconds,
      'max_events': maxEvents,
    });
    return _watchPollScanResultFromResponse(response);
  }

  Future<ProcessSnapshotReport> evaluateProcessSnapshot(
    List<ProcessObservation> observations, {
    ProcessMonitorPolicy policy = const ProcessMonitorPolicy(),
  }) async {
    final response = await _call({
      'command': 'evaluate_process_snapshot',
      'process_observations': observations
          .map((observation) => observation.toJson())
          .toList(growable: false),
      'process_monitor_policy': policy.toJson(),
    });
    return _processSnapshotReportFromResponse(response);
  }

  Future<String> startCoreService() async {
    if (!Platform.isWindows) {
      return 'Starting the Avorax Core Service is only supported on Windows.';
    }
    final result = await _runElevatedPowerShell(r'''
$service = Get-Service -Name 'avorax_core_service' -ErrorAction Stop
if ($service.Status -ne 'Running') {
  Start-Service -Name 'avorax_core_service' -ErrorAction Stop
}
''');
    if (result == null) return 'Avorax Core Service start was requested.';
    return 'Avorax Core Service start failed: $result';
  }

  Future<String> repairInstallation() async {
    if (!Platform.isWindows) {
      return 'Repairing the Avorax service registration is only supported on Windows.';
    }
    final executable = _installedLocalCoreExecutableForRepair();
    final executableProbe = executable == null
        ? null
        : _regularFileProbe(executable);
    if (executable == null || executableProbe!.isNotRegularFile) {
      return _missingRegularFileMessage(
        'Avorax Core Service',
        executable,
        probe: executableProbe,
        guidance:
            'Reinstall Avorax or set AVORAX_CORE_SERVICE to the installed executable.',
      );
    }
    final executablePath = File(executable).resolveSymbolicLinksSync();
    final devCheckoutBlocker = _developmentServiceRegistrationBlocker(
      executablePath,
      const ['core', 'zentor_local_core'],
    );
    if (devCheckoutBlocker != null) return devCheckoutBlocker;
    final launchBlocker = _executableLaunchBlocker(
      'Avorax Core Service',
      executablePath,
      guidance:
          'Reinstall Avorax or set AVORAX_CORE_SERVICE to the installed executable.',
    );
    if (launchBlocker != null) return launchBlocker;
    final escapedExecutable = executablePath.replaceAll("'", "''");
    final result = await _runElevatedPowerShell('''
\$exe = '$escapedExecutable'
\$service = \$null
try {
  \$service = Get-Service -Name 'avorax_core_service' -ErrorAction Stop
} catch {
  if (\$_.CategoryInfo.Category -ne 'ObjectNotFound') {
    throw
  }
}
if (\$null -eq \$service) {
  New-Service -Name 'avorax_core_service' -BinaryPathName "`"\$exe`" --service" -DisplayName 'Avorax Core Service' -Description 'Provides local scanning, native engine loading, quarantine, scan jobs, and local protection state for Avorax Anti-Virus.' -StartupType Automatic -ErrorAction Stop
}
Set-Service -Name 'avorax_core_service' -StartupType Automatic -ErrorAction Stop
Start-Service -Name 'avorax_core_service' -ErrorAction Stop
''');
    if (result == null) {
      return 'Avorax Core Service repair was requested.';
    }
    return 'Avorax Core Service repair failed: $result';
  }

  Future<String> openInstallReport() async {
    if (!Platform.isWindows) {
      return 'Install reports are only opened automatically on Windows.';
    }
    final List<String> candidates;
    try {
      candidates = _installReportCandidates();
    } on Object catch (error) {
      final details =
          _ipcDiagnosticOrNull('$error') ??
          'install report root validation failed.';
      return 'Unable to locate install report: $details';
    }
    File? report;
    final probeErrors = <String>[];
    for (final candidate in candidates) {
      final file = File(candidate);
      final probe = _regularFileProbe(candidate);
      if (probe.isRegularFile) {
        report = file;
        break;
      }
      if (probe.diagnostic != null) probeErrors.add(probe.diagnostic!);
    }
    if (report == null) {
      final details = probeErrors.isEmpty
          ? ''
          : ' Probe failures: ${probeErrors.take(3).join('; ')}';
      return 'No Avorax install report was found under ProgramData or the install directory.$details';
    }
    final launchBlocker = _installReportLaunchBlocker(report);
    if (launchBlocker != null) {
      return 'Unable to open install report: $launchBlocker';
    }
    try {
      final explorer = _windowsExplorerExecutable();
      await Process.start(explorer, _explorerSelectArguments(report));
      return 'Opened Avorax install report location.';
    } on Object catch (error) {
      final details =
          _ipcDiagnosticOrNull('$error') ?? 'Explorer launch failed.';
      return 'Unable to open install report: $details';
    }
  }

  Future<String?> cancelActiveScan() async {
    Object? cancelError;
    try {
      await _sendCancelScanRequest();
    } on Object catch (error) {
      cancelError = error;
    }
    await Future<void>.delayed(const Duration(milliseconds: 250));
    final killed = _activeScanProcess?.kill() ?? false;
    if (cancelError != null) {
      final fallback = killed
          ? 'process kill fallback was requested'
          : 'no active scan process was available for fallback';
      final details =
          _ipcDiagnosticOrNull('$cancelError') ?? 'Cancel IPC failed.';
      return 'Avorax local core cancel IPC failed; $fallback: $details';
    }
    return null;
  }

  Future<ScanReport> _scanCommand(
    Map<String, Object?> command, {
    required ScanKind kind,
    required ScanActionMode actionMode,
    void Function(ScanProgress progress)? onProgress,
  }) async {
    final response = await _call(command, onProgress: onProgress);
    if (response == null || response['ok'] == false) {
      final error = _ipcDiagnosticOrNull(response?['error']);
      final protocolErrors = response == null
          ? const <String>[]
          : _scanErrorList(_field(response, 'scanErrors', 'scan_errors'));
      final scanErrors = [?error, ...protocolErrors];
      return ScanReport(
        status: ScanStatus.engineUnavailable,
        kind: kind,
        actionMode: actionMode,
        filesScanned: 0,
        threatsFound: 0,
        skippedFiles: 0,
        elapsedMs: 0,
        threats: const [],
        scanErrors: scanErrors,
        message:
            error ??
            (protocolErrors.isEmpty
                ? 'Avorax local core is not available.'
                : protocolErrors.first),
      );
    }
    return _scanReportFromJson(response, kind: kind, actionMode: actionMode);
  }

  Future<Map<String, Object?>?> _call(
    Map<String, Object?> command, {
    void Function(ScanProgress progress)? onProgress,
  }) async {
    if (!isDesktop) return null;
    final executable = _localCoreExecutable();
    final executableProbe = executable == null
        ? null
        : _regularFileProbe(executable);
    if (executable == null || executableProbe!.isNotRegularFile) {
      return {
        'ok': false,
        'error': _missingRegularFileMessage(
          'Avorax Core Service',
          executable,
          probe: executableProbe,
        ),
      };
    }
    final executablePath = File(executable).absolute.path;
    final launchBlocker = _executableLaunchBlocker(
      'Avorax Core Service',
      executablePath,
    );
    if (launchBlocker != null) {
      return {'ok': false, 'error': launchBlocker};
    }
    try {
      final process = await (processStarter ?? Process.start)(
        executablePath,
        executableArguments,
      );
      if (command['command'] == 'scan_file' ||
          command['command'] == 'scan_folder' ||
          command['command'] == 'quick_scan_selected_paths' ||
          command['command'] == 'full_scan') {
        _activeScanProcess = process;
      }
      return await (() async {
        process.stdin.writeln(jsonEncode(command));
        await process.stdin.close();
        final stderrFuture = _collectBoundedIpcText(process.stderr);
        Map<String, Object?>? last;
        final protocolWarnings = <String>[];
        await for (final line in _boundedIpcStdoutLines(process.stdout)) {
          final trimmed = line.trim();
          if (trimmed.isEmpty) continue;
          Object? decoded;
          try {
            decoded = jsonDecode(trimmed);
          } on Object {
            _recordIpcProtocolWarning(
              protocolWarnings,
              'Avorax local core returned malformed JSON on stdout: $trimmed',
            );
            continue;
          }
          if (decoded is! Map) {
            _recordIpcProtocolWarning(
              protocolWarnings,
              'Avorax local core returned non-object JSON on stdout.',
            );
            continue;
          }
          final map = Map<String, Object?>.from(decoded);
          if (map['type'] == 'progress') {
            final raw = map['progress'];
            if (raw is Map) {
              final progressDiagnostics = <String>[];
              final progress = _scanProgressFromJson(
                Map<String, Object?>.from(raw),
                diagnostics: progressDiagnostics,
              );
              for (final diagnostic in progressDiagnostics) {
                _recordIpcProtocolWarning(protocolWarnings, diagnostic);
              }
              if (progress != null && onProgress != null) {
                onProgress(progress);
              }
            } else {
              _recordIpcProtocolWarning(
                protocolWarnings,
                'Avorax local core returned malformed progress JSON on stdout.',
              );
            }
          } else {
            last = map;
          }
        }
        final stderr = (await stderrFuture).trim();
        final exitCode = await process.exitCode;
        if (exitCode != 0) {
          final detail = stderr.isEmpty ? 'no stderr output' : stderr;
          return {
            'ok': false,
            'error':
                'Avorax local core exited with exit code $exitCode: $detail',
          };
        }
        if (last == null && protocolWarnings.isNotEmpty) {
          return {'ok': false, 'error': protocolWarnings.first};
        }
        if (last != null && protocolWarnings.isNotEmpty) {
          last = _responseWithIpcProtocolWarnings(last, protocolWarnings);
        }
        return last;
      })().timeout(
        ipcTimeout,
        onTimeout: () async {
          final terminationStatus = await _ipcTimeoutTerminationStatus(process);
          final reapStatus = await _ipcReapStatus(process);
          return {
            'ok': false,
            'error':
                'Avorax local core IPC timed out after ${_formatDuration(ipcTimeout)}. $terminationStatus $reapStatus',
          };
        },
      );
    } on Object catch (error) {
      final details = _ipcDiagnosticOrNull('$error') ?? 'IPC failed.';
      return {'ok': false, 'error': 'Avorax local core IPC failed: $details'};
    } finally {
      _activeScanProcess = null;
    }
  }

  String _formatDuration(Duration duration) {
    if (duration.inMilliseconds < 1000) {
      return '${duration.inMilliseconds}ms';
    }
    if (duration.inSeconds < 60) return '${duration.inSeconds}s';
    return '${duration.inMinutes}m';
  }

  String _ipcTerminationStatus(bool killed) =>
      killed ? 'Termination requested.' : 'Termination request failed.';

  Future<String> _ipcTimeoutTerminationStatus(Process process) async {
    if (Platform.isWindows) {
      final treeStatus = await _windowsProcessTreeTerminationStatus(
        process.pid,
      );
      if (treeStatus.startsWith('Process tree termination requested.')) {
        return 'Termination requested. $treeStatus';
      }
      return '${_ipcTerminationStatus(process.kill())} $treeStatus';
    }
    return _ipcTerminationStatus(process.kill());
  }

  Future<String> _windowsProcessTreeTerminationStatus(int pid) async {
    Process? taskkillProcess;
    try {
      final taskkill = _windowsTaskkillExecutable();
      taskkillProcess = await Process.start(taskkill, [
        '/PID',
        '$pid',
        '/T',
        '/F',
      ]);
      final stdoutFuture = _collectBoundedIpcText(taskkillProcess.stdout);
      final stderrFuture = _collectBoundedIpcText(taskkillProcess.stderr);
      final exitCode = await taskkillProcess.exitCode.timeout(
        _windowsProcessTreeKillTimeout,
      );
      final stdout = await stdoutFuture;
      final stderr = await stderrFuture;
      if (exitCode == 0) return 'Process tree termination requested.';
      final detail =
          _ipcDiagnosticOrNull(stderr.trim()) ??
          _ipcDiagnosticOrNull(stdout.trim()) ??
          'no diagnostic output';
      return 'Process tree termination failed with exit code $exitCode: $detail.';
    } on TimeoutException {
      taskkillProcess?.kill();
      return 'Process tree termination timed out.';
    } on Object catch (error) {
      return 'Process tree termination failed: '
          '${_ipcDiagnosticOrNull('$error') ?? 'unknown error'}.';
    }
  }

  Future<String> _ipcReapStatus(Process process) async {
    try {
      final exitCode = await process.exitCode.timeout(
        ipcProcessReapTimeout ?? _ipcProcessReapTimeout,
      );
      return 'Timed-out process exited with code $exitCode.';
    } on TimeoutException {
      final timeout = ipcProcessReapTimeout ?? _ipcProcessReapTimeout;
      return 'Timed-out process did not exit within '
          '${_formatDuration(timeout)} after termination request.';
    } on Object catch (error) {
      return 'Failed to observe timed-out process exit: '
          '${_ipcDiagnosticOrNull('$error') ?? 'unknown error'}.';
    }
  }

  void _recordIpcProtocolWarning(List<String> warnings, String warning) {
    if (warnings.length >= _maxIpcProtocolWarnings) return;
    warnings.add(_truncateIpcText(warning, _maxIpcDiagnosticTextLength));
  }

  Future<String> _collectBoundedIpcText(Stream<List<int>> stream) async {
    final buffer = StringBuffer();
    await for (final chunk in stream.transform(
      const Utf8Decoder(allowMalformed: true),
    )) {
      final remaining = _maxIpcDiagnosticTextLength - buffer.length;
      if (remaining <= 0) continue;
      buffer.write(
        chunk.length <= remaining ? chunk : chunk.substring(0, remaining),
      );
    }
    return buffer.toString();
  }

  Future<_BoundedUtf8Capture> _collectBoundedUtf8Text(
    Stream<List<int>> stream, {
    required int maxBytes,
  }) async {
    final bytes = <int>[];
    var truncated = false;
    await for (final chunk in stream) {
      final remaining = maxBytes - bytes.length;
      if (remaining <= 0) {
        truncated = true;
        continue;
      }
      if (chunk.length <= remaining) {
        bytes.addAll(chunk);
      } else {
        bytes.addAll(chunk.take(remaining));
        truncated = true;
      }
    }
    return _BoundedUtf8Capture(
      utf8.decode(bytes, allowMalformed: true),
      truncated: truncated,
    );
  }

  Future<_IpcJsonResponseCapture> _collectLastIpcJsonResponse(
    Stream<List<int>> stream,
  ) async {
    Map<String, Object?>? last;
    final protocolWarnings = <String>[];
    await for (final line in _boundedIpcStdoutLines(stream)) {
      final trimmed = line.trim();
      if (trimmed.isEmpty) continue;
      Object? decoded;
      try {
        decoded = jsonDecode(trimmed);
      } on Object {
        _recordIpcProtocolWarning(
          protocolWarnings,
          'Avorax local core returned malformed JSON on stdout: $trimmed',
        );
        continue;
      }
      if (decoded is! Map) {
        _recordIpcProtocolWarning(
          protocolWarnings,
          'Avorax local core returned non-object JSON on stdout.',
        );
        continue;
      }
      last = Map<String, Object?>.from(decoded);
    }
    return _IpcJsonResponseCapture(
      response: last,
      protocolWarnings: protocolWarnings,
    );
  }

  Stream<String> _boundedIpcStdoutLines(Stream<List<int>> stream) async* {
    var buffer = StringBuffer();
    var truncated = false;
    await for (final chunk in stream.transform(
      const Utf8Decoder(allowMalformed: true),
    )) {
      for (var index = 0; index < chunk.length; index += 1) {
        final char = chunk[index];
        if (char == '\n') {
          var line = buffer.toString();
          if (line.endsWith('\r')) {
            line = line.substring(0, line.length - 1);
          }
          yield truncated ? _truncatedIpcStdoutLine(line) : line;
          buffer = StringBuffer();
          truncated = false;
          continue;
        }
        if (buffer.length < _maxIpcStdoutLineLength) {
          buffer.write(char);
        } else {
          truncated = true;
        }
      }
    }
    if (buffer.length > 0 || truncated) {
      final line = buffer.toString();
      yield truncated ? _truncatedIpcStdoutLine(line) : line;
    }
  }

  String _truncatedIpcStdoutLine(String line) {
    if (_maxIpcStdoutLineLength <= _ipcStdoutLineTruncationSuffix.length) {
      return _ipcStdoutLineTruncationSuffix.substring(
        0,
        _maxIpcStdoutLineLength,
      );
    }
    final prefixLimit =
        _maxIpcStdoutLineLength - _ipcStdoutLineTruncationSuffix.length;
    final prefix = line.length <= prefixLimit
        ? line
        : line.substring(0, prefixLimit);
    return '$prefix$_ipcStdoutLineTruncationSuffix';
  }

  Map<String, Object?> _responseWithIpcProtocolWarnings(
    Map<String, Object?> response,
    List<String> warnings,
  ) {
    return {
      ...response,
      'scanErrors': [
        ..._scanErrorList(_field(response, 'scanErrors', 'scan_errors')),
        ...warnings,
      ],
    };
  }

  LocalCoreActionResult _actionResult(
    Map<String, Object?>? response, {
    required String fallbackError,
    required String? Function(Map<String, Object?> response)
    successEvidenceError,
  }) {
    if (response == null) {
      return LocalCoreActionResult.failed(
        'Avorax local core IPC returned no response. $fallbackError',
      );
    }
    final ok = response['ok'];
    final protocolWarnings = _scanErrorList(
      _field(response, 'scanErrors', 'scan_errors'),
    );
    if (ok == true) {
      if (protocolWarnings.isNotEmpty) {
        return LocalCoreActionResult.failed(
          'Avorax local core IPC returned action success with protocol warnings: ${protocolWarnings.first}',
        );
      }
      if (response.containsKey('error')) {
        final error = _ipcDiagnosticOrNull(response['error']);
        return LocalCoreActionResult.failed(
          error == null
              ? 'Avorax local core IPC returned action success with malformed error evidence.'
              : 'Avorax local core IPC returned action success with error evidence: $error',
        );
      }
      final evidenceError = successEvidenceError(response);
      if (evidenceError != null) {
        return LocalCoreActionResult.failed(
          'Avorax local core IPC returned action success without valid evidence: $evidenceError',
        );
      }
      return const LocalCoreActionResult.ok();
    }
    final error = _ipcDiagnosticOrNull(response['error']);
    if (ok != false) {
      return LocalCoreActionResult.failed(
        error != null
            ? 'Avorax local core IPC returned a malformed action response: $error'
            : 'Avorax local core IPC returned a malformed action response. $fallbackError',
      );
    }
    return LocalCoreActionResult.failed(error ?? fallbackError);
  }

  String? _quarantineActionEvidenceError(
    Map<String, Object?> response, {
    required QuarantineItemStatus expectedStatus,
    String? expectedId,
  }) {
    final recordJson = _actionEvidenceObject(response['record']);
    if (recordJson == null) {
      return 'the quarantine record was missing or malformed.';
    }
    final record = _quarantineRecordFromJson(recordJson);
    if (record == null) {
      return 'the quarantine record failed validation.';
    }
    if (record.status != expectedStatus) {
      return 'the quarantine record status did not match ${expectedStatus.name}.';
    }
    if (expectedId != null && record.quarantineId != expectedId) {
      return 'the quarantine record identifier did not match the request.';
    }
    return null;
  }

  String? _allowlistActionEvidenceError(
    Map<String, Object?> response, {
    required bool expectedActive,
    String? expectedId,
  }) {
    final entryJson = _actionEvidenceObject(response['entry']);
    if (entryJson == null) {
      return 'the allowlist entry was missing or malformed.';
    }
    final entry = _allowlistEntryFromJson(entryJson);
    if (entry == null) {
      return 'the allowlist entry failed validation.';
    }
    if (entry.active != expectedActive) {
      return 'the allowlist entry active state did not match the request.';
    }
    if (expectedId != null && entry.id != expectedId) {
      return 'the allowlist entry identifier did not match the request.';
    }
    return null;
  }

  String? _pathActionEvidenceError(
    Map<String, Object?> response, {
    required String fieldName,
  }) {
    if (!response.containsKey(fieldName)) {
      return 'the expected result path was missing.';
    }
    if (_recordPathField(response[fieldName]) == null) {
      return 'the expected result path was malformed.';
    }
    return null;
  }

  Map<String, Object?>? _actionEvidenceObject(Object? value) {
    if (value is! Map) return null;
    final result = <String, Object?>{};
    for (final entry in value.entries) {
      final key = entry.key;
      if (key is! String) return null;
      result[key] = entry.value;
    }
    return result;
  }

  String? _watcherProtocolError(
    Map<String, Object?>? response, {
    required String fallbackError,
  }) {
    if (response == null) {
      return 'Avorax local core IPC returned no watcher response. $fallbackError';
    }
    final ok = response['ok'];
    final protocolWarnings = _scanErrorList(
      _field(response, 'scanErrors', 'scan_errors'),
    );
    if (ok == true) {
      if (protocolWarnings.isNotEmpty) {
        return 'Avorax local core IPC returned watcher success with protocol warnings: ${protocolWarnings.first}';
      }
      return null;
    }
    final error = _ipcDiagnosticOrNull(response['error']);
    if (ok == false) {
      return error ?? fallbackError;
    }
    return error != null
        ? 'Avorax local core IPC returned a malformed watcher response: $error'
        : 'Avorax local core IPC returned a malformed watcher response. $fallbackError';
  }

  WatchPollScanResult _watchPollScanResultFromResponse(
    Map<String, Object?>? response,
  ) {
    if (response == null) {
      return const WatchPollScanResult(
        ok: false,
        watcher: RealtimeWatcherState(active: false, mode: 'unknown'),
        poll: WatchPollScanSummary(active: false, mode: 'unknown'),
        error: 'Avorax local core IPC returned no watch-poll response.',
      );
    }
    final diagnostics = <String>[
      ..._scanErrorList(_field(response, 'scanErrors', 'scan_errors')),
    ];
    final ok = response['ok'];
    if (ok == false) {
      final error =
          _ipcDiagnosticOrNull(response['error']) ??
          'Watch-poll scan request failed.';
      return WatchPollScanResult(
        ok: false,
        watcher: const RealtimeWatcherState(active: false, mode: 'unknown'),
        poll: WatchPollScanSummary(
          active: false,
          mode: 'unknown',
          scanErrors: diagnostics,
        ),
        error: error,
      );
    }
    if (ok != true) {
      diagnostics.add('local core watch-poll response had malformed ok');
    }

    RealtimeWatcherState watcher;
    final watcherRaw = response['watcher'];
    if (watcherRaw is Map) {
      watcher = RealtimeWatcherState.fromJson(
        Map<String, Object?>.from(watcherRaw),
      );
    } else {
      watcher = const RealtimeWatcherState(
        active: false,
        mode: 'unknown',
        error: 'Watch-poll response did not include watcher state.',
      );
    }

    final pollRaw = response['poll'];
    final poll = pollRaw is Map
        ? _watchPollSummaryFromJson(
            Map<String, Object?>.from(pollRaw),
            diagnostics,
          )
        : WatchPollScanSummary(
            active: false,
            mode: 'unknown',
            scanErrors: [
              ...diagnostics,
              'local core watch-poll response was missing poll summary',
            ],
          );
    final error =
        watcher.error ??
        _watchPollConsistencyError(watcher: watcher, poll: poll);
    return WatchPollScanResult(
      ok: ok == true && error == null,
      watcher: watcher,
      poll: poll,
      error: error,
    );
  }

  String? _watchPollConsistencyError({
    required RealtimeWatcherState watcher,
    required WatchPollScanSummary poll,
  }) {
    if (watcher.active != poll.active) {
      return 'Local Core watch-poll response had contradictory watcher and poll activity.';
    }
    if (poll.active) {
      if (watcher.mode != 'userModeBestEffort') {
        return 'Local Core watch-poll response had an invalid active watcher mode.';
      }
      if (watcher.watchedPaths.isEmpty) {
        return 'Local Core watch-poll response reported active without watched paths.';
      }
      if (poll.mode != 'finiteUserModePolling') {
        return 'Local Core watch-poll response had an invalid active poll mode.';
      }
      return null;
    }
    if (watcher.mode != 'stopped' && watcher.mode != 'off') {
      return 'Local Core watch-poll response had an invalid inactive watcher mode.';
    }
    if (poll.mode != 'stopped') {
      return 'Local Core watch-poll response had an invalid inactive poll mode.';
    }
    return null;
  }

  WatchPollScanSummary _watchPollSummaryFromJson(
    Map<String, Object?> json,
    List<String> responseDiagnostics,
  ) {
    final diagnostics = <String>[...responseDiagnostics];
    final active = _ipcBool(
      json['active'],
      diagnostics: diagnostics,
      fieldName: 'watch_poll.active',
    );
    final mode = _watchPollStringField(
      json,
      'mode',
      diagnostics,
      fallback: 'unknown',
    );
    final durationMs = _watchPollIntField(json, 'duration_ms', diagnostics);
    final pollIntervalMs = _watchPollIntField(
      json,
      'poll_interval_ms',
      diagnostics,
    );
    final maxEvents = _watchPollIntField(json, 'max_events', diagnostics);
    final initialFilesObserved = _watchPollIntField(
      json,
      'initial_files_observed',
      diagnostics,
    );
    final pollsCompleted = _watchPollIntField(
      json,
      'polls_completed',
      diagnostics,
    );
    final eventsObserved = _watchPollIntField(
      json,
      'events_observed',
      diagnostics,
    );
    final filesScanned = _watchPollIntField(json, 'files_scanned', diagnostics);
    final threatsFound = _watchPollIntField(json, 'threats_found', diagnostics);
    final quarantinedFiles = _watchPollIntField(
      json,
      'quarantined_files',
      diagnostics,
    );
    final limitations = _ipcStringList(
      json['limitations'],
      diagnostics: diagnostics,
      fieldName: 'watch_poll.limitations',
    );
    return WatchPollScanSummary(
      active: active,
      mode: mode,
      durationMs: durationMs,
      pollIntervalMs: pollIntervalMs,
      maxEvents: maxEvents,
      initialFilesObserved: initialFilesObserved,
      pollsCompleted: pollsCompleted,
      eventsObserved: eventsObserved,
      filesScanned: filesScanned,
      threatsFound: threatsFound,
      quarantinedFiles: quarantinedFiles,
      scanErrors: [
        ..._scanErrorList(_field(json, 'scanErrors', 'scan_errors')),
        ...diagnostics,
      ],
      limitations: limitations,
    );
  }

  String _watchPollStringField(
    Map<String, Object?> json,
    String field,
    List<String> diagnostics, {
    required String fallback,
  }) {
    final value = _ipcStringOrNull(json[field]);
    if (value != null) return value;
    diagnostics.add('local core watch-poll response had malformed $field');
    return fallback;
  }

  int _watchPollIntField(
    Map<String, Object?> json,
    String field,
    List<String> diagnostics,
  ) {
    final value = _parseNonNegativeInt(json[field]);
    if (value != null) return value;
    diagnostics.add('local core watch-poll response had malformed $field');
    return 0;
  }

  ProcessSnapshotReport _processSnapshotReportFromResponse(
    Map<String, Object?>? response,
  ) {
    if (response == null) {
      return const ProcessSnapshotReport(
        ok: false,
        status: 'unknown',
        capability: 'unknown',
        statusReason:
            'Avorax local core IPC returned no process snapshot response.',
      );
    }
    final diagnostics = <String>[
      ..._scanErrorList(_field(response, 'scanErrors', 'scan_errors')),
    ];
    final ok = response['ok'];
    if (ok == false) {
      final error =
          _ipcDiagnosticOrNull(response['error']) ??
          'Process snapshot request failed.';
      return ProcessSnapshotReport(
        ok: false,
        status: 'unknown',
        capability: 'unknown',
        statusReason: error,
        diagnostics: diagnostics,
      );
    }
    if (ok != true) {
      diagnostics.add('local core process snapshot response had malformed ok');
    }
    final status = _processSnapshotStringField(
      response,
      'status',
      diagnostics,
      fallback: 'unknown',
    );
    final capability = _processSnapshotStringField(
      response,
      'capability',
      diagnostics,
      fallback: 'unknown',
    );
    final statusReason = _processSnapshotStringField(
      response,
      'status_reason',
      diagnostics,
      fallback: 'Process snapshot status reason was unavailable.',
    );
    final observedProcesses = _processSnapshotIntField(
      response,
      'observed_processes',
      diagnostics,
    );
    final skippedProcesses = _processSnapshotIntField(
      response,
      'skipped_processes',
      diagnostics,
    );
    final findings = _processSnapshotFindings(
      response['findings'],
      diagnostics,
    );
    return ProcessSnapshotReport(
      ok: ok == true,
      status: status,
      capability: capability,
      statusReason: statusReason,
      observedProcesses: observedProcesses,
      skippedProcesses: skippedProcesses,
      findings: findings,
      diagnostics: diagnostics,
    );
  }

  String _processSnapshotStringField(
    Map<String, Object?> response,
    String field,
    List<String> diagnostics, {
    required String fallback,
  }) {
    final value = _ipcStringOrNull(response[field]);
    if (value != null) return value;
    diagnostics.add(
      'local core process snapshot response had malformed $field',
    );
    return fallback;
  }

  int _processSnapshotIntField(
    Map<String, Object?> response,
    String field,
    List<String> diagnostics,
  ) {
    final value = _parseNonNegativeInt(response[field]);
    if (value != null) return value;
    diagnostics.add(
      'local core process snapshot response had malformed $field',
    );
    return 0;
  }

  List<ProcessFinding> _processSnapshotFindings(
    Object? raw,
    List<String> diagnostics,
  ) {
    if (raw == null) return const [];
    if (raw is! List) {
      diagnostics.add(
        'local core process snapshot response had malformed findings',
      );
      return const [];
    }
    final findings = <ProcessFinding>[];
    for (var index = 0; index < raw.length && index < 64; index += 1) {
      final item = raw[index];
      if (item is! Map) {
        diagnostics.add(
          'local core process snapshot response dropped malformed finding $index',
        );
        continue;
      }
      final finding = _processFindingFromJson(
        Map<String, Object?>.from(item),
        index,
        diagnostics,
      );
      if (finding != null) findings.add(finding);
    }
    if (raw.length > 64) {
      diagnostics.add(
        'local core process snapshot response truncated findings',
      );
    }
    return findings;
  }

  ProcessFinding? _processFindingFromJson(
    Map<String, Object?> json,
    int index,
    List<String> diagnostics,
  ) {
    final pid = _parseNonNegativeInt(json['pid']);
    final imagePath = _ipcStringOrNull(
      _field(json, 'imagePath', 'image_path'),
      maxLength: _maxIpcDiagnosticTextLength,
    );
    final score = _boundedInt(json['score'], min: 0, max: 1000);
    final verdict = _ipcStringOrNull(json['verdict']);
    final reasons = _processSnapshotReasonList(
      json['reasons'],
      index,
      diagnostics,
    );
    if (pid == null || imagePath == null || score == null || verdict == null) {
      diagnostics.add(
        'local core process snapshot response dropped malformed finding $index',
      );
      return null;
    }
    return ProcessFinding(
      pid: pid,
      imagePath: imagePath,
      score: score,
      verdict: verdict,
      reasons: reasons,
    );
  }

  List<String> _processSnapshotReasonList(
    Object? raw,
    int findingIndex,
    List<String> diagnostics,
  ) {
    if (raw == null) return const [];
    if (raw is! List) {
      diagnostics.add(
        'local core process snapshot response had malformed finding $findingIndex reasons',
      );
      return const [];
    }
    final reasons = <String>[];
    for (var index = 0; index < raw.length && index < 16; index += 1) {
      final reason = _ipcDiagnosticOrNull(raw[index]);
      if (reason == null) {
        diagnostics.add(
          'local core process snapshot response dropped malformed finding $findingIndex reason $index',
        );
        continue;
      }
      reasons.add(reason);
    }
    if (raw.length > 16) {
      diagnostics.add(
        'local core process snapshot response truncated finding $findingIndex reasons',
      );
    }
    return reasons;
  }

  Future<void> _sendCancelScanRequest() async {
    if (!isDesktop) {
      throw StateError('Avorax local core scan cancellation is desktop-only.');
    }
    final executable = _localCoreExecutable();
    final executableProbe = executable == null
        ? null
        : _regularFileProbe(executable);
    if (executable == null || executableProbe!.isNotRegularFile) {
      throw StateError(
        _missingRegularFileMessage(
          'Avorax Core Service',
          executable,
          probe: executableProbe,
        ),
      );
    }
    final executablePath = File(executable).absolute.path;
    final launchBlocker = _executableLaunchBlocker(
      'Avorax Core Service',
      executablePath,
    );
    if (launchBlocker != null) throw StateError(launchBlocker);
    try {
      final timeout = cancelIpcTimeout ?? _cancelIpcTimeout;
      final process = await (processStarter ?? Process.start)(
        executablePath,
        executableArguments,
      );
      process.stdin.writeln(jsonEncode({'command': 'cancel_scan'}));
      await process.stdin.close();
      final results =
          await Future.wait<Object?>([
            _collectLastIpcJsonResponse(process.stdout),
            _collectBoundedIpcText(process.stderr),
            process.exitCode,
          ]).timeout(
            timeout,
            onTimeout: () async {
              final terminationStatus = await _ipcTimeoutTerminationStatus(
                process,
              );
              final reapStatus = await _ipcReapStatus(process);
              throw TimeoutException(
                'Cancel IPC timed out after ${_formatDuration(timeout)}. $terminationStatus $reapStatus',
              );
            },
          );
      final stdout = results[0] as _IpcJsonResponseCapture;
      final stderr = (results[1] as String).trim();
      final exitCode = results[2] as int;
      if (exitCode != 0) {
        final detail = stderr.isEmpty ? 'no stderr output' : stderr;
        throw StateError('Cancel IPC exited with exit code $exitCode: $detail');
      }
      final response = stdout.response;
      if (response == null) {
        final detail = stdout.protocolWarnings.isEmpty
            ? 'Cancel IPC returned no response.'
            : stdout.protocolWarnings.first;
        throw StateError(detail);
      }
      final ok = response['ok'];
      if (stdout.protocolWarnings.isNotEmpty) {
        throw StateError(
          'Cancel IPC returned response with protocol warnings: ${stdout.protocolWarnings.first}',
        );
      }
      if (ok == true) return;
      final error = _ipcDiagnosticOrNull(response['error']);
      if (ok == false) {
        throw StateError(error ?? 'Cancel IPC request failed.');
      }
      throw StateError(
        error == null
            ? 'Cancel IPC returned a malformed response.'
            : 'Cancel IPC returned a malformed response: $error',
      );
    } on Object catch (error) {
      final details = _ipcDiagnosticOrNull('$error') ?? 'Cancel IPC failed.';
      throw StateError('Avorax local core cancel IPC failed: $details');
    }
  }

  String? _localCoreExecutable() {
    if (executableOverride != null) return executableOverride;
    final override = _environmentPathOverride(
      'AVORAX_CORE_SERVICE',
      'ZENTOR_LOCAL_CORE',
    );
    if (override != null) {
      return override;
    }
    final primaryName = Platform.isWindows
        ? 'avorax_core_service.exe'
        : 'avorax_core_service';
    final legacyName = Platform.isWindows
        ? 'zentor_local_core.exe'
        : 'zentor_local_core';
    final executableParent = _requiredResolvedExecutableParentPath(
      'Avorax Core Service executable directory',
    );
    final candidates = [
      _joinPath([executableParent, primaryName]),
      _joinPath([executableParent, legacyName]),
      ..._developmentExecutableCandidates(const [
        'core',
        'zentor_local_core',
      ], legacyName),
    ];
    for (final candidate in candidates) {
      final file = File(candidate);
      if (_regularFileProbe(candidate).isRegularFile) return file.absolute.path;
    }
    return candidates.first;
  }

  String? _installedLocalCoreExecutableForRepair() {
    if (executableOverride != null) return executableOverride;
    final override = _environmentPathOverride(
      'AVORAX_CORE_SERVICE',
      'ZENTOR_LOCAL_CORE',
    );
    if (override != null) return override;
    final primaryName = Platform.isWindows
        ? 'avorax_core_service.exe'
        : 'avorax_core_service';
    final legacyName = Platform.isWindows
        ? 'zentor_local_core.exe'
        : 'zentor_local_core';
    final executableParent = _requiredResolvedExecutableParentPath(
      'Avorax Core Service executable directory',
    );
    final candidates = [
      _joinPath([executableParent, primaryName]),
      _joinPath([executableParent, legacyName]),
    ];
    for (final candidate in candidates) {
      final file = File(candidate);
      if (_regularFileProbe(candidate).isRegularFile) return file.absolute.path;
    }
    return candidates.first;
  }

  String? _developmentServiceRegistrationBlocker(
    String executablePath,
    List<String> crateSegments,
  ) {
    for (final root in _candidateDevelopmentRepoRoots()) {
      if (!_isDevelopmentRepoRoot(root, crateSegments)) continue;
      if (_localPathInside(root.path, executablePath)) {
        return 'Refusing to register a development checkout executable as the Windows Core Service. Build and install Avorax first, then repair the installed service from the installed app.';
      }
    }
    return null;
  }

  String? _guardServiceExecutable() {
    if (guardExecutableOverride != null) return guardExecutableOverride;
    final override = _environmentPathOverride(
      'AVORAX_GUARD_SERVICE',
      'ZENTOR_GUARD_SERVICE',
    );
    if (override != null) {
      return override;
    }
    final primaryName = Platform.isWindows
        ? 'avorax_guard_service.exe'
        : 'avorax_guard_service';
    final legacyName = Platform.isWindows
        ? 'zentor_guard_service.exe'
        : 'zentor_guard_service';
    final executableParent = _requiredResolvedExecutableParentPath(
      'Avorax Guard Service executable directory',
    );
    final candidates = [
      _joinPath([executableParent, primaryName]),
      _joinPath([executableParent, legacyName]),
      ..._developmentExecutableCandidates(const [
        'core',
        'zentor_guard_service',
      ], legacyName),
    ];
    for (final candidate in candidates) {
      final file = File(candidate);
      if (_regularFileProbe(candidate).isRegularFile) return file.absolute.path;
    }
    return candidates.first;
  }

  String? _environmentPathOverride(String primary, String legacy) =>
      _checkedEnvironmentExecutablePath(primary) ??
      _checkedEnvironmentExecutablePath(legacy);

  String? _nonEmptyEnvironmentPath(String name) {
    final value = Platform.environment[name]?.trim();
    return value == null || value.isEmpty ? null : value;
  }

  String? _checkedEnvironmentExecutablePath(String name) {
    final value = _nonEmptyEnvironmentPath(name);
    if (value == null) return null;
    _validateEnvironmentPathText(name, value);
    if (!_isAbsoluteLocalExecutablePath(value)) {
      throw StateError('$name must be an absolute local executable path.');
    }
    return value;
  }

  List<String> _developmentExecutableCandidates(
    List<String> crateSegments,
    String executableName,
  ) {
    final candidates = <String>[];
    final seen = <String>{};
    for (final root in _candidateDevelopmentRepoRoots()) {
      if (!_isDevelopmentRepoRoot(root, crateSegments)) continue;
      final candidate = _joinPath([
        root.path,
        ...crateSegments,
        'target',
        'release',
        executableName,
      ]);
      if (seen.add(candidate)) candidates.add(candidate);
    }
    return candidates;
  }

  List<Directory> _candidateDevelopmentRepoRoots() {
    final roots = <Directory>[];
    final seen = <String>{};
    var cursor = Directory.current.absolute;
    for (var depth = 0; depth < 3; depth++) {
      if (seen.add(cursor.path)) roots.add(cursor);
      final parent = cursor.parent;
      if (parent.path == cursor.path) break;
      cursor = parent;
    }
    return roots;
  }

  bool _isDevelopmentRepoRoot(Directory root, List<String> crateSegments) {
    final appMarker = _joinPath([
      root.path,
      'apps',
      'zentor_client',
      'pubspec.yaml',
    ]);
    final crateMarker = _joinPath([root.path, ...crateSegments, 'Cargo.toml']);
    return _regularFileProbe(appMarker).isRegularFile &&
        _regularFileProbe(crateMarker).isRegularFile;
  }

  String _joinPath(List<String> segments) {
    final separator = Platform.pathSeparator;
    var path = segments.first;
    for (final segment in segments.skip(1)) {
      path = path.endsWith(separator)
          ? '$path$segment'
          : '$path$separator$segment';
    }
    return path;
  }

  bool _isAbsoluteLocalExecutablePath(String path) {
    return _isAbsoluteLocalPath(path);
  }

  bool _isAbsoluteLocalPath(String path) {
    final normalized = path.trim();
    if (normalized.isEmpty) return false;
    if (Platform.isWindows) return !_isWindowsRemoteOrDevicePath(normalized);
    return normalized.startsWith('/') && !normalized.startsWith('//');
  }

  String? _executableLaunchBlocker(
    String displayName,
    String path, {
    String? guidance,
  }) {
    if (Platform.isWindows && _isWindowsRemoteOrDevicePath(path)) {
      final suffix = guidance == null ? '' : ' $guidance';
      return '$displayName executable path must be a local Windows drive path.$suffix';
    }
    final probe = _regularFileProbe(path);
    if (probe.isRegularFile) return null;
    return _missingRegularFileMessage(
      displayName,
      path,
      probe: probe,
      guidance: guidance,
    );
  }

  String? _installReportLaunchBlocker(File report) {
    try {
      final path = report.absolute.path;
      if (Platform.isWindows && _isWindowsRemoteOrDevicePath(path)) {
        return 'install report path must be a local Windows drive path.';
      }
      final probe = _regularFileProbe(path);
      if (!probe.isRegularFile) {
        final diagnostic = probe.diagnostic == null
            ? ''
            : ' Probe failed: ${probe.diagnostic}.';
        return 'install report is not a regular file.$diagnostic';
      }
      final allowedRoots = _installReportAllowedRoots();
      if (!allowedRoots.any((root) => _localPathInside(root, path))) {
        return 'install report is outside the Avorax report and install directories.';
      }
      return null;
    } on Object catch (error) {
      return _ipcDiagnosticOrNull('$error') ??
          'install report path validation failed.';
    }
  }

  List<String> _explorerSelectArguments(File report) => [
    '/select,',
    report.absolute.path,
  ];

  List<String> _installReportCandidates() {
    final candidates = <String>[];
    for (final root in _programDataRoots()) {
      _addUniqueLocalPath(
        candidates,
        _joinPath([root, 'Avorax', 'reports', 'install_report.json']),
      );
    }
    for (final root in _programFilesRoots()) {
      _addUniqueLocalPath(
        candidates,
        _joinPath([root, 'Avorax', 'install-manifest.json']),
      );
    }
    final executableParent = _resolvedExecutableParentPath();
    if (executableParent != null) {
      _addUniqueLocalPath(
        candidates,
        _joinPath([executableParent, 'install-manifest.json']),
      );
    }
    return candidates;
  }

  List<String> _installReportAllowedRoots() {
    final roots = <String>[];
    for (final root in _programDataRoots()) {
      _addUniqueLocalPath(roots, _joinPath([root, 'Avorax', 'reports']));
    }
    for (final root in _programFilesRoots()) {
      _addUniqueLocalPath(roots, _joinPath([root, 'Avorax']));
    }
    final executableParent = _resolvedExecutableParentPath();
    if (executableParent != null) {
      _addUniqueLocalPath(roots, executableParent);
    }
    return roots;
  }

  List<String> _programDataRoots() =>
      _environmentDirectoryRoots(['ProgramData', 'PROGRAMDATA']);

  List<String> _programFilesRoots() => _environmentDirectoryRoots([
    'ProgramFiles',
    'PROGRAMFILES',
    'ProgramW6432',
    'ProgramFiles(x86)',
  ]);

  List<String> _environmentDirectoryRoots(List<String> names) {
    final roots = <String>[];
    for (final name in names) {
      final root = _checkedEnvironmentDirectoryPath(name);
      if (root != null) _addUniqueLocalPath(roots, root);
    }
    return roots;
  }

  String? _checkedEnvironmentDirectoryPath(String name) {
    final value = _nonEmptyEnvironmentPath(name);
    if (value == null) return null;
    _validateEnvironmentPathText(name, value);
    if (!_isAbsoluteLocalPath(value)) {
      throw StateError('$name must be an absolute local directory path.');
    }
    return Directory(value).absolute.path;
  }

  void _validateEnvironmentPathText(String name, String value) {
    if (value.contains('\u0000')) {
      throw StateError('$name must not contain NUL.');
    }
    if (_hasParentTraversal(value)) {
      throw StateError('$name must not contain parent traversal.');
    }
  }

  String? _resolvedExecutableParentPath() {
    final parent = File(Platform.resolvedExecutable).parent.absolute.path;
    return _isAbsoluteLocalPath(parent) ? parent : null;
  }

  String _requiredResolvedExecutableParentPath(String purpose) {
    final parent = File(Platform.resolvedExecutable).parent.absolute.path;
    if (!_isAbsoluteLocalPath(parent)) {
      throw StateError('$purpose must be an absolute local path.');
    }
    return parent;
  }

  void _addUniqueLocalPath(List<String> paths, String path) {
    final key = Platform.isWindows ? path.toLowerCase() : path;
    final hasPath = paths.any(
      (existing) =>
          (Platform.isWindows ? existing.toLowerCase() : existing) == key,
    );
    if (!hasPath) paths.add(path);
  }

  bool _localPathInside(String parentPath, String childPath) {
    final parent = _normalizeLocalPath(parentPath);
    final child = _normalizeLocalPath(childPath);
    return child == parent ||
        child.startsWith('$parent${Platform.pathSeparator}');
  }

  String _normalizeLocalPath(String path) {
    final absolute = File(path).absolute.path;
    final parts = absolute
        .split(RegExp(r'[/\\]+'))
        .where((part) => part.isNotEmpty && part != '.')
        .toList(growable: false);
    if (parts.any((part) => part == '..')) {
      throw StateError('install report path contains traversal.');
    }
    final normalized = parts.join(Platform.pathSeparator);
    return Platform.isWindows ? normalized.toLowerCase() : normalized;
  }

  String _windowsExplorerExecutable() {
    final systemRoot = _windowsSystemRoot('Windows Explorer executable');
    final candidate = File(
      '$systemRoot${Platform.pathSeparator}explorer.exe',
    ).absolute.path;
    final launchBlocker = _executableLaunchBlocker(
      'Windows Explorer',
      candidate,
    );
    if (launchBlocker != null) throw StateError(launchBlocker);
    return candidate;
  }

  bool _isWindowsRemoteOrDevicePath(String path) {
    final normalized = path.replaceAll('/', r'\');
    if (normalized.startsWith(r'\\')) return true;
    return !RegExp(r'^[A-Za-z]:\\').hasMatch(normalized);
  }

  bool _hasParentTraversal(String path) {
    return path
        .replaceAll(r'\', '/')
        .split('/')
        .any((segment) => segment == '..');
  }

  String _windowsSystemRoot(String purpose) {
    final systemRoot =
        _checkedWindowsSystemRootEnvironmentPath('SystemRoot', purpose) ??
        _checkedWindowsSystemRootEnvironmentPath('WINDIR', purpose);
    if (systemRoot == null) {
      throw StateError('SystemRoot or WINDIR is required to locate $purpose.');
    }
    if (_isWindowsRemoteOrDevicePath(systemRoot)) {
      throw StateError('$purpose root must be a local Windows drive path.');
    }
    return Directory(systemRoot).absolute.path;
  }

  String? _checkedWindowsSystemRootEnvironmentPath(
    String name,
    String purpose,
  ) {
    final value = _nonEmptyEnvironmentPath(name);
    if (value == null) return null;
    if (value.contains('\u0000')) {
      throw StateError('$purpose root $name must not contain NUL.');
    }
    if (_hasParentTraversal(value)) {
      throw StateError(
        '$purpose root $name must not contain parent traversal.',
      );
    }
    return value;
  }

  _FileProbeResult _regularFileProbe(String path) {
    try {
      final type = FileSystemEntity.typeSync(path, followLinks: false);
      return _FileProbeResult(type == FileSystemEntityType.file);
    } on FileSystemException catch (error) {
      return _FileProbeResult(
        false,
        'Unable to inspect $path: ${_ipcDiagnosticOrNull(error.message) ?? 'probe failed'}',
      );
    } on ArgumentError catch (error) {
      final details = _ipcDiagnosticOrNull('$error') ?? 'probe failed';
      return _FileProbeResult(false, 'Unable to inspect $path: $details');
    }
  }

  String _missingRegularFileMessage(
    String displayName,
    String? path, {
    _FileProbeResult? probe,
    String? guidance,
  }) {
    final location = path == null ? '' : ' at $path';
    final diagnostic = probe?.diagnostic == null
        ? ''
        : ' Probe failed: ${probe!.diagnostic}.';
    final suffix = guidance == null ? '' : ' $guidance';
    return '$displayName executable was not found as a regular file$location.$diagnostic$suffix';
  }

  Future<String?> _runElevatedPowerShell(String script) async {
    final encoded = _powershellEncodedCommand(script);
    final powerShell = _windowsPowerShellExecutable();
    final quotedPowerShell = _powershellSingleQuoted(powerShell);
    final launcher =
        '\$process = Start-Process -FilePath $quotedPowerShell '
        "-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','$encoded') "
        '-Verb RunAs -Wait -PassThru; exit \$process.ExitCode';
    try {
      final timeout = elevatedPowerShellTimeout ?? _elevatedPowerShellTimeout;
      final process = await (processStarter ?? Process.start)(powerShell, [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-EncodedCommand',
        _powershellEncodedCommand(launcher),
      ]);
      final stdoutFuture = _collectBoundedIpcText(process.stdout);
      final stderrFuture = _collectBoundedIpcText(process.stderr);
      final int exitCode;
      try {
        exitCode = await process.exitCode.timeout(timeout);
      } on TimeoutException {
        final terminationStatus = await _ipcTimeoutTerminationStatus(process);
        final reapStatus = await _ipcReapStatus(process);
        final stdout = await _timedOutIpcText(stdoutFuture);
        final stderr = await _timedOutIpcText(stderrFuture);
        final detail = _powerShellLaunchDiagnostic(
          stdout: stdout,
          stderr: stderr,
        );
        return 'PowerShell timed out after ${_formatDuration(timeout)}. $terminationStatus $reapStatus: $detail';
      }
      final stdout = await stdoutFuture;
      final stderr = await stderrFuture;
      if (exitCode == 0) return null;
      final detail = _powerShellLaunchDiagnostic(
        stdout: stdout,
        stderr: stderr,
      );
      return detail == 'no diagnostic output'
          ? 'PowerShell exit code $exitCode'
          : detail;
    } on Object catch (error) {
      return _ipcDiagnosticOrNull('$error') ?? 'PowerShell launch failed.';
    }
  }

  Future<String> _timedOutIpcText(Future<String> output) async {
    try {
      return await output.timeout(
        ipcProcessReapTimeout ?? _ipcProcessReapTimeout,
      );
    } on TimeoutException {
      return 'stream collection did not finish after timeout cleanup';
    }
  }

  String _powerShellLaunchDiagnostic({
    required String stdout,
    required String stderr,
  }) {
    final stderrText = _ipcDiagnosticOrNull(stderr);
    if (stderrText != null) return stderrText;
    final stdoutText = _ipcDiagnosticOrNull(stdout);
    return stdoutText ?? 'no diagnostic output';
  }

  String _windowsPowerShellExecutable() {
    final systemRoot = _windowsSystemRoot(
      'PowerShell elevation launcher executable',
    );
    final candidate = File(
      '$systemRoot${Platform.pathSeparator}System32${Platform.pathSeparator}WindowsPowerShell${Platform.pathSeparator}v1.0${Platform.pathSeparator}powershell.exe',
    ).absolute.path;
    final launchBlocker = _executableLaunchBlocker(
      'PowerShell elevation launcher',
      candidate,
    );
    if (launchBlocker != null) throw StateError(launchBlocker);
    return candidate;
  }

  String _windowsTaskkillExecutable() {
    final systemRoot = _windowsSystemRoot(
      'Windows process tree termination executable',
    );
    final candidate = File(
      '$systemRoot${Platform.pathSeparator}System32${Platform.pathSeparator}taskkill.exe',
    ).absolute.path;
    final launchBlocker = _executableLaunchBlocker(
      'Windows process tree termination',
      candidate,
    );
    if (launchBlocker != null) throw StateError(launchBlocker);
    return candidate;
  }

  String _powershellSingleQuoted(String value) =>
      "'${value.replaceAll("'", "''")}'";

  String _powershellEncodedCommand(String script) {
    final bytes = <int>[];
    for (final codeUnit in script.codeUnits) {
      bytes
        ..add(codeUnit & 0xff)
        ..add((codeUnit >> 8) & 0xff);
    }
    return base64Encode(bytes);
  }

  ScanReport _scanReportFromJson(
    Map<String, Object?> json, {
    required ScanKind kind,
    required ScanActionMode actionMode,
  }) {
    final threats = json['threats'];
    final scanErrors = _scanErrorList(
      _field(json, 'scanErrors', 'scan_errors'),
    );
    final parsedThreats = <ThreatResult>[];
    if (threats is List) {
      for (var index = 0; index < threats.length; index += 1) {
        final item = threats[index];
        if (item is! Map) {
          scanErrors.add(
            'local core scan response dropped malformed threat row $index',
          );
          continue;
        }
        final threat = _threatFromJson(item, scanErrors);
        if (threat != null) parsedThreats.add(threat);
      }
    } else if (threats != null) {
      scanErrors.add('local core scan response had malformed threats list');
    }
    final parsedKind = _scanReportKindField(json['kind'], kind, scanErrors);
    final parsedActionMode = _scanReportActionModeField(
      _field(json, 'actionMode', 'action_mode'),
      actionMode,
      scanErrors,
    );
    final filesScanned = _scanIntField(
      json,
      'filesScanned',
      'files_scanned',
      scanErrors,
    );
    final foldersScanned = _scanIntField(
      json,
      'foldersScanned',
      'folders_scanned',
      scanErrors,
    );
    final bytesScanned = _scanIntField(
      json,
      'bytesScanned',
      'bytes_scanned',
      scanErrors,
    );
    final totalFilesEstimated = _optionalScanIntField(
      json,
      'totalFilesEstimated',
      'total_files_estimated',
      scanErrors,
    );
    final totalBytesEstimated = _optionalScanIntField(
      json,
      'totalBytesEstimated',
      'total_bytes_estimated',
      scanErrors,
    );
    final threatsFound = _scanIntField(
      json,
      'threatsFound',
      'threats_found',
      scanErrors,
    );
    final suspiciousFound = _scanIntField(
      json,
      'suspiciousFound',
      'suspicious_found',
      scanErrors,
    );
    final quarantinedFiles = _scanIntField(
      json,
      'quarantinedFiles',
      'quarantined_files',
      scanErrors,
    );
    final skippedFiles = _scanIntField(
      json,
      'skippedFiles',
      'skipped_files',
      scanErrors,
    );
    final permissionDeniedCount = _scanIntField(
      json,
      'permissionDeniedCount',
      'permission_denied_count',
      scanErrors,
    );
    final elapsedMs = _scanIntField(
      json,
      'elapsedMs',
      'elapsed_ms',
      scanErrors,
    );
    final currentPath = _scanReportCurrentPathField(
      _field(json, 'currentPath', 'current_path'),
      scanErrors,
    );
    final message = _scanReportMessageField(json['message'], scanErrors);
    final progress = _scanProgressField(json['progress'], scanErrors);
    final status = _scanReportStatusWithErrorEvidence(
      _scanReportStatusField(json['status'], scanErrors),
      scanErrors,
    );
    return ScanReport(
      status: status,
      kind: parsedKind,
      actionMode: parsedActionMode,
      filesScanned: filesScanned,
      foldersScanned: foldersScanned,
      bytesScanned: bytesScanned,
      totalFilesEstimated: totalFilesEstimated,
      totalBytesEstimated: totalBytesEstimated,
      threatsFound: threatsFound,
      suspiciousFound: suspiciousFound,
      quarantinedFiles: quarantinedFiles,
      skippedFiles: skippedFiles,
      permissionDeniedCount: permissionDeniedCount,
      elapsedMs: elapsedMs,
      currentPath: currentPath,
      message: message,
      scanErrors: scanErrors,
      progress: progress,
      threats: parsedThreats,
    );
  }

  String? _scanReportCurrentPathField(Object? raw, List<String> scanErrors) {
    if (raw == null) return null;
    final parsed = _ipcStringOrNull(
      raw,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    if (parsed != null) return parsed;
    scanErrors.add('local core scan response had malformed current_path');
    return null;
  }

  String? _scanReportMessageField(Object? raw, List<String> scanErrors) {
    if (raw == null) return null;
    final parsed = _ipcDiagnosticOrNull(raw);
    if (parsed != null) return parsed;
    scanErrors.add('local core scan response had malformed message');
    return null;
  }

  ScanStatus _scanReportStatusField(Object? raw, List<String> scanErrors) {
    if (raw == null) {
      scanErrors.add('local core scan response was missing status');
      return ScanStatus.engineUnavailable;
    }
    final statusName = _ipcStringOrNull(raw);
    if (statusName == null) {
      scanErrors.add('local core scan response had malformed status');
      return ScanStatus.engineUnavailable;
    }
    final status = _scanStatusOrNull(statusName);
    if (status != null) return status;
    scanErrors.add('local core scan response had malformed status');
    return ScanStatus.failed;
  }

  ScanStatus _scanReportStatusWithErrorEvidence(
    ScanStatus status,
    List<String> scanErrors,
  ) {
    if (status == ScanStatus.clean && scanErrors.isNotEmpty) {
      return ScanStatus.completedWithErrors;
    }
    return status;
  }

  ScanKind _scanReportKindField(
    Object? raw,
    ScanKind fallback,
    List<String> scanErrors,
  ) {
    if (raw == null) {
      scanErrors.add('local core scan response was missing kind');
      return fallback;
    }
    final parsed = _enumByName(ScanKind.values, _ipcStringOrNull(raw));
    if (parsed != null) return parsed;
    scanErrors.add('local core scan response had malformed kind');
    return fallback;
  }

  ScanActionMode _scanReportActionModeField(
    Object? raw,
    ScanActionMode fallback,
    List<String> scanErrors,
  ) {
    if (raw == null) {
      scanErrors.add('local core scan response was missing action_mode');
      return fallback;
    }
    final parsed = _enumByName(ScanActionMode.values, _ipcStringOrNull(raw));
    if (parsed != null) return parsed;
    scanErrors.add('local core scan response had malformed action_mode');
    return fallback;
  }

  List<String> _scanErrorList(Object? value) {
    if (value == null) return <String>[];
    if (value is! List) {
      return ['local core scan response had malformed scan_errors list'];
    }
    final result = <String>[];
    var malformedItems = 0;
    var inspectedItems = 0;
    for (final item in value) {
      if (inspectedItems >= _maxIpcStringListEntries) {
        result.add('local core scan response truncated scan_errors list');
        break;
      }
      inspectedItems++;
      final parsed = _ipcDiagnosticOrNull(item);
      if (parsed == null) {
        malformedItems++;
        continue;
      }
      result.add(parsed);
    }
    if (malformedItems > 0) {
      result.add(
        'local core scan response dropped $malformedItems malformed scan_errors entries',
      );
    }
    return result;
  }

  Object? _field(Map<String, Object?> json, String camel, String snake) =>
      json[camel] ?? json[snake];

  String? _ipcStringOrNull(
    Object? value, {
    int maxLength = _maxIpcStatusTextLength,
  }) {
    if (value is! String) return null;
    final trimmed = value.trim();
    if (trimmed.isEmpty) return null;
    return _truncateIpcText(trimmed, maxLength);
  }

  String? _ipcDiagnosticOrNull(Object? value) {
    if (value is! String) return null;
    final normalized = value
        .replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ')
        .trim();
    if (normalized.isEmpty) return null;
    return _truncateIpcText(normalized, _maxIpcDiagnosticTextLength);
  }

  bool _ipcBool(
    Object? value, {
    List<String>? diagnostics,
    String fieldName = 'boolean field',
  }) {
    if (value is bool) return value;
    if (value != null) {
      diagnostics?.add(
        'local core health response had malformed $fieldName boolean',
      );
    }
    return false;
  }

  List<String> _ipcStringList(
    Object? value, {
    int maxEntries = _maxIpcStringListEntries,
    int maxEntryLength = _maxIpcStatusTextLength,
    List<String>? diagnostics,
    String fieldName = 'string list',
  }) {
    if (value == null) return const [];
    if (value is! List) {
      diagnostics?.add(
        'local core health response had malformed $fieldName list',
      );
      return const [];
    }
    final result = <String>[];
    var malformedItems = 0;
    var inspectedItems = 0;
    for (final item in value) {
      if (inspectedItems >= maxEntries) {
        diagnostics?.add(
          'local core health response truncated $fieldName list',
        );
        break;
      }
      inspectedItems++;
      final parsed = _ipcStringOrNull(item, maxLength: maxEntryLength);
      if (parsed == null) {
        malformedItems++;
        continue;
      }
      result.add(parsed);
    }
    if (malformedItems > 0) {
      diagnostics?.add(
        'local core health response dropped $malformedItems '
        'malformed $fieldName entries',
      );
    }
    return result;
  }

  String? _healthLastErrorWithDiagnostics(
    String? lastError,
    List<String> diagnostics,
  ) {
    if (diagnostics.isEmpty) return lastError;
    return _ipcDiagnosticOrNull([?lastError, ...diagnostics].join(' '));
  }

  String? _healthDiagnosticField(
    Object? raw,
    String fieldName,
    List<String> diagnostics,
  ) => _healthOptionalStringField(
    raw,
    fieldName,
    diagnostics,
    maxLength: _maxIpcDiagnosticTextLength,
  );

  String? _healthOptionalStringField(
    Object? raw,
    String fieldName,
    List<String> diagnostics, {
    int maxLength = _maxIpcStatusTextLength,
  }) {
    if (raw == null) return null;
    final parsed = _ipcStringOrNull(raw, maxLength: maxLength);
    if (parsed != null) return parsed;
    diagnostics.add('local core health response had malformed $fieldName');
    return null;
  }

  String _healthStringField(
    Object? raw, {
    required String fallback,
    required String fieldName,
    required List<String> diagnostics,
  }) {
    if (raw == null) {
      diagnostics.add('local core health response was missing $fieldName');
      return fallback;
    }
    final parsed = _ipcStringOrNull(raw);
    if (parsed != null) return parsed;
    diagnostics.add('local core health response had malformed $fieldName');
    return fallback;
  }

  String _healthAllowedStringField(
    Object? raw, {
    required String fallback,
    required String fieldName,
    required Set<String> allowedValues,
    required List<String> diagnostics,
  }) {
    if (raw == null) {
      diagnostics.add('local core health response was missing $fieldName');
      return fallback;
    }
    final parsed = _ipcStringOrNull(raw);
    if (parsed != null && allowedValues.contains(parsed)) return parsed;
    diagnostics.add('local core health response had malformed $fieldName');
    return fallback;
  }

  bool? _healthNullableBoolField(
    Object? raw, {
    required String fieldName,
    required List<String> diagnostics,
  }) {
    if (raw == null) {
      diagnostics.add('local core health response was missing $fieldName');
      return null;
    }
    if (raw is bool) return raw;
    diagnostics.add(
      'local core health response had malformed $fieldName boolean',
    );
    return null;
  }

  int _healthIntField(
    Map<String, Object?> json,
    String camel,
    String snake,
    List<String> diagnostics,
  ) {
    final value = _field(json, camel, snake);
    if (value == null) {
      diagnostics.add('local core health response was missing $snake');
      return 0;
    }
    final parsed = _parseNonNegativeInt(value);
    if (parsed != null) return parsed;
    diagnostics.add('local core health response had malformed $snake');
    return 0;
  }

  MalwareEngineStatus _healthMalwareEngineStatus(
    Object? raw,
    List<String> diagnostics,
  ) {
    if (raw == null) {
      diagnostics.add('local core health response was missing engine_status');
      return MalwareEngineStatus.unavailable;
    }
    final status = _ipcStringOrNull(raw);
    if (status == null) {
      diagnostics.add('local core health response had malformed engine_status');
      return MalwareEngineStatus.unavailable;
    }
    switch (status) {
      case 'available':
        return MalwareEngineStatus.available;
      case 'signatures_outdated':
        return MalwareEngineStatus.signaturesOutdated;
      case 'error':
        return MalwareEngineStatus.error;
    }
    diagnostics.add('local core health response had malformed engine_status');
    return MalwareEngineStatus.unavailable;
  }

  AiModelInfo _healthAiModelInfo(Object? raw, List<String> diagnostics) {
    if (raw == null) {
      diagnostics.add('local core health response was missing ai_model');
      return const AiModelInfo();
    }
    if (raw is! Map) {
      diagnostics.add('local core health response had malformed ai_model');
      return const AiModelInfo();
    }
    return _aiModelInfoFromJson(Map<String, Object?>.from(raw), diagnostics);
  }

  String _truncateIpcText(String value, int maxLength) {
    if (value.length <= maxLength) return value;
    return value.substring(0, maxLength);
  }

  int _scanIntField(
    Map<String, Object?> json,
    String camel,
    String snake,
    List<String> scanErrors,
  ) {
    final value = _field(json, camel, snake);
    if (value == null) {
      scanErrors.add(
        'local core scan response was missing numeric field $snake',
      );
      return 0;
    }
    final parsed = _parseNonNegativeInt(value);
    if (parsed != null) return parsed;
    scanErrors.add(
      'local core scan response had malformed numeric field $snake',
    );
    return 0;
  }

  int? _optionalScanIntField(
    Map<String, Object?> json,
    String camel,
    String snake,
    List<String> scanErrors,
  ) {
    final value = _field(json, camel, snake);
    if (value == null) return null;
    final parsed = _parseNonNegativeInt(value);
    if (parsed != null) return parsed;
    scanErrors.add(
      'local core scan response had malformed numeric field $snake',
    );
    return null;
  }

  int? _parseNonNegativeInt(Object? value) {
    if (value is int && value >= 0) return value;
    return null;
  }

  ScanProgress? _scanProgressField(Object? value, List<String> scanErrors) {
    if (value == null) return null;
    if (value is! Map) {
      scanErrors.add('local core scan response had malformed progress object');
      return null;
    }
    return _scanProgressFromJson(
      Map<String, Object?>.from(value),
      diagnostics: scanErrors,
    );
  }

  ScanProgress? _scanProgressFromJson(
    Map<String, Object?> json, {
    List<String>? diagnostics,
  }) {
    final rawScanType = _field(json, 'scanType', 'scan_type');
    final rawStatus = json['status'];
    final rawJobId = _field(json, 'jobId', 'job_id');
    final rawCurrentPath = _field(json, 'currentPath', 'current_path');
    final jobId = _progressJobIdField(rawJobId, diagnostics);
    final scanType = _progressScanTypeField(rawScanType, diagnostics);
    final status = _progressStatusField(rawStatus, diagnostics);
    final filesScanned = _progressIntField(
      json,
      'filesScanned',
      'files_scanned',
      diagnostics,
    );
    final foldersScanned = _progressIntField(
      json,
      'foldersScanned',
      'folders_scanned',
      diagnostics,
    );
    final bytesScanned = _progressIntField(
      json,
      'bytesScanned',
      'bytes_scanned',
      diagnostics,
    );
    final threatsFound = _progressIntField(
      json,
      'threatsFound',
      'threats_found',
      diagnostics,
    );
    final suspiciousFound = _progressIntField(
      json,
      'suspiciousFound',
      'suspicious_found',
      diagnostics,
    );
    final skippedFiles = _progressIntField(
      json,
      'skippedFiles',
      'skipped_files',
      diagnostics,
    );
    final permissionDeniedCount = _progressIntField(
      json,
      'permissionDeniedCount',
      'permission_denied_count',
      diagnostics,
    );
    final startedAt = _progressDateTimeField(
      json,
      'startedAt',
      'started_at',
      diagnostics,
    );
    final updatedAt = _progressDateTimeField(
      json,
      'updatedAt',
      'updated_at',
      diagnostics,
    );
    final elapsedSeconds = _progressIntField(
      json,
      'elapsedSeconds',
      'elapsed_seconds',
      diagnostics,
    );
    if (jobId == null ||
        scanType == null ||
        status == null ||
        filesScanned == null ||
        foldersScanned == null ||
        bytesScanned == null ||
        threatsFound == null ||
        suspiciousFound == null ||
        skippedFiles == null ||
        permissionDeniedCount == null ||
        startedAt == null ||
        updatedAt == null ||
        elapsedSeconds == null) {
      return null;
    }
    return ScanProgress(
      jobId: jobId,
      scanType: scanType,
      status: status,
      currentPath: _progressCurrentPathField(rawCurrentPath, diagnostics),
      filesScanned: filesScanned,
      foldersScanned: foldersScanned,
      bytesScanned: bytesScanned,
      totalFilesEstimated: _progressOptionalIntField(
        json,
        'totalFilesEstimated',
        'total_files_estimated',
        diagnostics,
      ),
      totalBytesEstimated: _progressOptionalIntField(
        json,
        'totalBytesEstimated',
        'total_bytes_estimated',
        diagnostics,
      ),
      threatsFound: threatsFound,
      suspiciousFound: suspiciousFound,
      skippedFiles: skippedFiles,
      permissionDeniedCount: permissionDeniedCount,
      startedAt: startedAt,
      updatedAt: updatedAt,
      elapsedSeconds: elapsedSeconds,
      estimatedRemainingSeconds: _progressOptionalIntField(
        json,
        'estimatedRemainingSeconds',
        'estimated_remaining_seconds',
        diagnostics,
      ),
      progressPercent: _progressPercentField(
        json,
        'progressPercent',
        'progress_percent',
        diagnostics,
      ),
    );
  }

  ScanKind? _progressScanTypeField(Object? raw, List<String>? diagnostics) {
    if (raw == null) {
      diagnostics?.add('local core scan progress was missing scan_type');
      return null;
    }
    final scanTypeName = _ipcStringOrNull(raw);
    final scanType = _enumByName(ScanKind.values, scanTypeName);
    if (scanType != null) return scanType;
    diagnostics?.add('local core scan progress had malformed scan_type');
    return null;
  }

  ScanJobStatus? _progressStatusField(Object? raw, List<String>? diagnostics) {
    if (raw == null) {
      diagnostics?.add('local core scan progress was missing status');
      return null;
    }
    final statusName = _ipcStringOrNull(raw);
    final status = _enumByName(ScanJobStatus.values, statusName);
    if (status != null) return status;
    diagnostics?.add('local core scan progress had malformed status');
    return null;
  }

  String? _progressJobIdField(Object? raw, List<String>? diagnostics) {
    if (raw == null) {
      diagnostics?.add('local core scan progress was missing job_id');
      return null;
    }
    final parsed = _ipcStringOrNull(raw);
    if (parsed != null) return parsed;
    diagnostics?.add('local core scan progress had malformed job_id');
    return null;
  }

  String? _progressCurrentPathField(Object? raw, List<String>? diagnostics) {
    if (raw == null) return null;
    final parsed = _ipcStringOrNull(
      raw,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    if (parsed != null) return parsed;
    diagnostics?.add('local core scan progress had malformed current_path');
    return null;
  }

  DateTime? _progressDateTimeField(
    Map<String, Object?> json,
    String camel,
    String snake,
    List<String>? diagnostics,
  ) {
    final raw = _field(json, camel, snake);
    if (raw == null) {
      diagnostics?.add('local core scan progress was missing $snake timestamp');
      return null;
    }
    final text = _ipcStringOrNull(raw, maxLength: _maxIpcTimestampTextLength);
    final parsed = text == null ? null : DateTime.tryParse(text);
    if (parsed != null) return parsed;
    diagnostics?.add('local core scan progress had malformed $snake timestamp');
    return null;
  }

  int? _progressIntField(
    Map<String, Object?> json,
    String camel,
    String snake,
    List<String>? diagnostics,
  ) {
    final raw = _field(json, camel, snake);
    if (raw == null) {
      diagnostics?.add(
        'local core scan progress was missing numeric field $snake',
      );
      return null;
    }
    final parsed = _parseNonNegativeInt(raw);
    if (parsed == null) {
      diagnostics?.add(
        'local core scan progress had malformed numeric field $snake',
      );
    }
    return parsed;
  }

  int? _progressOptionalIntField(
    Map<String, Object?> json,
    String camel,
    String snake,
    List<String>? diagnostics,
  ) {
    final raw = _field(json, camel, snake);
    if (raw == null) return null;
    final parsed = _parseNonNegativeInt(raw);
    if (parsed == null) {
      diagnostics?.add(
        'local core scan progress had malformed numeric field $snake',
      );
    }
    return parsed;
  }

  double? _progressPercentField(
    Map<String, Object?> json,
    String camel,
    String snake,
    List<String>? diagnostics,
  ) {
    final raw = _field(json, camel, snake);
    if (raw == null) return null;
    final parsed = _parseProgressPercent(raw);
    if (parsed != null) return parsed;
    if (raw is num && raw.toDouble().isFinite) {
      diagnostics?.add(
        'local core scan progress had out-of-range percentage field $snake',
      );
    } else {
      diagnostics?.add(
        'local core scan progress had malformed numeric field $snake',
      );
    }
    return null;
  }

  double? _parseProgressPercent(Object? value) {
    if (value is! num) return null;
    final percent = value.toDouble();
    if (!percent.isFinite) return null;
    if (percent < 0 || percent > 100) return null;
    return percent;
  }

  ThreatResult? _threatFromJson(
    Map<dynamic, dynamic> raw,
    List<String> scanErrors,
  ) {
    final json = Map<String, Object?>.from(raw);
    final id = _requiredThreatString(json, 'id', 'id', scanErrors);
    final path = _requiredThreatString(json, 'path', 'path', scanErrors);
    final sha256 = _requiredThreatSha256(json, scanErrors);
    final threatName = _requiredThreatString(
      json,
      'threatName',
      'threat_name',
      scanErrors,
    );
    final engine = _requiredThreatString(json, 'engine', 'engine', scanErrors);
    final detectedAt = _threatDateTimeField(
      json,
      'detectedAt',
      'detected_at',
      scanErrors,
    );
    final sizeBytes = _threatIntField(
      json,
      'sizeBytes',
      'size_bytes',
      scanErrors,
    );
    final detectionType = _threatEnumField(
      _field(json, 'detectionType', 'detection_type'),
      DetectionType.values,
      'detection_type',
      scanErrors,
    );
    final threatCategory = _threatEnumField(
      _field(json, 'threatCategory', 'threat_category'),
      ThreatCategory.values,
      'threat_category',
      scanErrors,
    );
    final confidence = _threatEnumField(
      json['confidence'],
      ThreatConfidence.values,
      'confidence',
      scanErrors,
    );
    final recommendedAction = _threatEnumField(
      _field(json, 'recommendedAction', 'recommended_action'),
      RecommendedAction.values,
      'recommended_action',
      scanErrors,
    );
    final status = _threatEnumField(
      json['status'],
      ThreatResultStatus.values,
      'status',
      scanErrors,
    );
    final riskScore = _riskScoreFromJson(
      _field(json, 'riskScore', 'risk_score'),
      scanErrors: scanErrors,
    );
    final reasonSummary = _requiredThreatDiagnosticField(
      _field(json, 'reasonSummary', 'reason_summary'),
      'reason_summary',
      scanErrors,
    );
    final quarantineId = _optionalThreatRecordIdField(
      _field(json, 'quarantineId', 'quarantine_id'),
      'quarantine_id',
      scanErrors,
    );
    final quarantinePath = _optionalThreatPathField(
      _field(json, 'quarantinePath', 'quarantine_path'),
      'quarantine_path',
      scanErrors,
    );
    final quarantineActionTaken = _optionalThreatStringField(
      _field(json, 'quarantineActionTaken', 'quarantine_action_taken'),
      'quarantine_action_taken',
      scanErrors,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    if (id == null ||
        path == null ||
        sha256 == null ||
        threatName == null ||
        engine == null ||
        detectedAt == null ||
        sizeBytes == null ||
        detectionType == null ||
        threatCategory == null ||
        confidence == null ||
        recommendedAction == null ||
        status == null ||
        riskScore == null ||
        reasonSummary == null) {
      return null;
    }
    final fileName =
        _optionalThreatStringField(
          _field(json, 'fileName', 'file_name'),
          'file_name',
          scanErrors,
        ) ??
        Uri.file(path).pathSegments.last;
    return ThreatResult(
      id: id,
      path: path,
      fileName: fileName,
      sha256: sha256,
      sizeBytes: sizeBytes,
      detectionType: detectionType,
      threatCategory: threatCategory,
      threatName: threatName,
      confidence: confidence,
      engine: engine,
      detectedAt: detectedAt,
      recommendedAction: recommendedAction,
      status: status,
      riskScore: riskScore,
      reasonSummary: reasonSummary,
      quarantineId: quarantineId,
      quarantinePath: quarantinePath,
      quarantineActionTaken: quarantineActionTaken,
    );
  }

  String? _requiredThreatString(
    Map<String, Object?> json,
    String camel,
    String snake,
    List<String> scanErrors,
  ) {
    final value = _field(json, camel, snake);
    if (value is String && value.trim().isNotEmpty) return value;
    scanErrors.add('local core scan response dropped malformed threat: $snake');
    return null;
  }

  String? _requiredThreatSha256(
    Map<String, Object?> json,
    List<String> scanErrors,
  ) {
    final value = _normalizedSha256(json['sha256']);
    if (value != null) return value;
    scanErrors.add('local core scan response dropped malformed threat: sha256');
    return null;
  }

  String? _optionalThreatStringField(
    Object? raw,
    String fieldName,
    List<String> scanErrors, {
    int maxLength = _maxIpcDiagnosticTextLength,
  }) {
    if (raw == null) return null;
    final parsed = _ipcStringOrNull(raw, maxLength: maxLength);
    if (parsed != null) return parsed;
    scanErrors.add('local core scan response had malformed threat $fieldName');
    return null;
  }

  String? _optionalThreatDiagnosticField(
    Object? raw,
    String fieldName,
    List<String> scanErrors,
  ) => _optionalThreatStringField(
    raw,
    fieldName,
    scanErrors,
    maxLength: _maxIpcDiagnosticTextLength,
  );

  String? _optionalThreatRecordIdField(
    Object? raw,
    String fieldName,
    List<String> scanErrors,
  ) {
    if (raw == null) return null;
    final parsed = _recordId(raw);
    if (parsed != null) return parsed;
    scanErrors.add('local core scan response had malformed threat $fieldName');
    return null;
  }

  String? _optionalThreatPathField(
    Object? raw,
    String fieldName,
    List<String> scanErrors,
  ) {
    if (raw == null) return null;
    final parsed = _recordPathField(raw);
    if (parsed != null) return parsed;
    scanErrors.add('local core scan response had malformed threat $fieldName');
    return null;
  }

  String? _requiredThreatDiagnosticField(
    Object? raw,
    String fieldName,
    List<String> scanErrors,
  ) {
    if (raw == null) {
      scanErrors.add('local core scan response was missing threat $fieldName');
      return null;
    }
    return _optionalThreatDiagnosticField(raw, fieldName, scanErrors);
  }

  int? _threatIntField(
    Map<String, Object?> json,
    String camel,
    String snake,
    List<String> scanErrors,
  ) {
    final value = _field(json, camel, snake);
    if (value == null) {
      scanErrors.add(
        'local core scan response was missing threat numeric field $snake',
      );
      return null;
    }
    final parsed = _parseNonNegativeInt(value);
    if (parsed != null) return parsed;
    scanErrors.add(
      'local core scan response had malformed threat numeric field $snake',
    );
    return null;
  }

  T? _threatEnumField<T extends Enum>(
    Object? raw,
    List<T> values,
    String fieldName,
    List<String> scanErrors,
  ) {
    if (raw == null) {
      scanErrors.add('local core scan response was missing threat $fieldName');
      return null;
    }
    final parsed = _enumByName(values, _ipcStringOrNull(raw));
    if (parsed != null) return parsed;
    scanErrors.add('local core scan response had malformed threat $fieldName');
    return null;
  }

  DateTime? _threatDateTimeField(
    Map<String, Object?> json,
    String camel,
    String snake,
    List<String> scanErrors,
  ) {
    final value = _field(json, camel, snake);
    if (value == null) {
      scanErrors.add(
        'local core scan response was missing threat timestamp $snake',
      );
      return null;
    }
    final text = _ipcStringOrNull(value, maxLength: _maxIpcTimestampTextLength);
    if (text == null) {
      scanErrors.add(
        'local core scan response had malformed threat timestamp $snake',
      );
      return null;
    }
    final parsed = DateTime.tryParse(text);
    if (parsed == null) {
      scanErrors.add(
        'local core scan response had malformed threat timestamp $snake',
      );
      return null;
    }
    return parsed;
  }

  bool _isSha256(String value) => RegExp(r'^[a-fA-F0-9]{64}$').hasMatch(value);

  String? _normalizedSha256(Object? value) {
    if (value is! String) return null;
    final trimmed = value.trim();
    final raw = trimmed.toLowerCase().startsWith('sha256:')
        ? trimmed.substring('sha256:'.length)
        : trimmed;
    if (_isSha256(raw)) return raw.toLowerCase();
    return null;
  }

  String? _recordPathField(Object? value) {
    final parsed = _ipcStringOrNull(
      value,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    if (parsed == null || parsed.contains('\u0000')) return null;
    if (!_isAbsoluteLocalPath(parsed)) return null;
    return parsed;
  }

  String? _recordId(Object? value) {
    if (value is! String) return null;
    if (value.trim() != value) return null;
    if (!RegExp(r'^[A-Za-z0-9_-]{1,128}$').hasMatch(value)) return null;
    return value;
  }

  AllowlistEntry? _allowlistEntryFromJson(Map<String, Object?> json) {
    final rawType = _field(json, 'entryType', 'entry_type') ?? json['type'];
    final typeName = _ipcStringOrNull(rawType);
    final id = _recordId(json['id']);
    final type = typeName == null
        ? null
        : _enumByName(AllowlistEntryType.values, typeName);
    final path = _allowlistPathField(json['path'], type);
    final sha256 = json['sha256'] == null
        ? null
        : _normalizedSha256(json['sha256']);
    final createdAtValue = _field(json, 'createdAt', 'created_at');
    final createdAt = createdAtValue == null
        ? null
        : _recordDateTimeOrNull(createdAtValue);
    final active = _optionalRecordBool(json['active']);
    final reasonValue = json['reason'];
    final reason = reasonValue == null
        ? null
        : _ipcDiagnosticOrNull(reasonValue);
    final reasonText = reason;
    final createdBy = _recordStringField(json, 'createdBy', 'created_by');
    if (id == null ||
        path == null ||
        rawType == null ||
        typeName == null ||
        type == null ||
        (sha256 == null && json['sha256'] != null) ||
        (_allowlistTypeRequiresSha256(type) && sha256 == null) ||
        !_allowlistHashEntryHasSha256Evidence(type, path, sha256) ||
        createdAt == null ||
        json['active'] == null ||
        reasonValue == null ||
        reasonText == null ||
        createdBy == null ||
        active == null) {
      return null;
    }
    return AllowlistEntry(
      id: id,
      type: type,
      path: path,
      sha256: sha256,
      reason: reasonText,
      createdAt: createdAt,
      createdBy: createdBy,
      active: active,
    );
  }

  bool _allowlistTypeRequiresSha256(AllowlistEntryType type) => switch (type) {
    AllowlistEntryType.file ||
    AllowlistEntryType.app ||
    AllowlistEntryType.executable => true,
    AllowlistEntryType.folder || AllowlistEntryType.hash => false,
  };

  String? _allowlistPathField(Object? value, AllowlistEntryType? type) {
    if (type == null) return null;
    final parsed = _ipcStringOrNull(
      value,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    if (parsed == null || parsed.contains('\u0000')) return null;
    return switch (type) {
      AllowlistEntryType.hash => parsed,
      AllowlistEntryType.file ||
      AllowlistEntryType.folder ||
      AllowlistEntryType.app ||
      AllowlistEntryType.executable =>
        _isAbsoluteLocalPath(parsed) ? parsed : null,
    };
  }

  bool _allowlistHashEntryHasSha256Evidence(
    AllowlistEntryType type,
    String path,
    String? sha256,
  ) {
    if (type != AllowlistEntryType.hash) return true;
    return sha256 != null || _normalizedSha256(path) != null;
  }

  DateTime? _recordDateTimeOrNull(Object? value) {
    final text = _ipcStringOrNull(value, maxLength: _maxIpcTimestampTextLength);
    if (text == null) return null;
    return DateTime.tryParse(text);
  }

  int? _recordIntField(Map<String, Object?> json, String camel, String snake) {
    final value = _field(json, camel, snake);
    if (value == null) return null;
    return _parseNonNegativeInt(value);
  }

  String? _recordStringField(
    Map<String, Object?> json,
    String camel,
    String snake,
  ) {
    final value = _field(json, camel, snake);
    if (value == null) return null;
    return _ipcStringOrNull(value, maxLength: _maxIpcDiagnosticTextLength);
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

  bool _quarantineSourceEvidenceIsValid(
    String source,
    bool blockedBeforeExecution,
    bool processStarted,
    int? processId,
  ) {
    if (source != 'scanner') return false;
    return !blockedBeforeExecution && !processStarted && processId == null;
  }

  bool? _optionalRecordBool(Object? value) {
    if (value == null) return null;
    if (value is bool) return value;
    return null;
  }

  RiskScore? _riskScoreFromJson(Object? raw, {List<String>? scanErrors}) {
    if (raw == null) {
      scanErrors?.add('local core scan response was missing risk_score object');
      return null;
    }
    if (raw is! Map) {
      scanErrors?.add(
        'local core scan response had malformed risk_score object',
      );
      return null;
    }
    final json = Map<String, Object?>.from(raw);
    final reasons = json['reasons'];
    final engines = _field(json, 'enginesUsed', 'engines_used');
    final parsedReasons = <RiskReason>[];
    if (reasons is List) {
      for (var index = 0; index < reasons.length; index += 1) {
        if (parsedReasons.length >= _maxRiskReasons) {
          scanErrors?.add(
            'local core scan response truncated risk reasons list',
          );
          break;
        }
        final item = reasons[index];
        if (item is! Map) {
          scanErrors?.add(
            'local core scan response dropped malformed risk reason $index',
          );
          continue;
        }
        final reason = Map<String, Object?>.from(item);
        final id = _riskReasonStringField(
          reason['id'],
          'id',
          index,
          scanErrors,
        );
        final title = _riskReasonStringField(
          reason['title'],
          'title',
          index,
          scanErrors,
        );
        final detail =
            _optionalRiskReasonDiagnosticField(
              reason['detail'],
              'detail',
              index,
              scanErrors,
            ) ??
            '';
        final weight = _riskReasonIntField(
          reason['weight'],
          'weight',
          index,
          scanErrors,
        );
        final severity = _riskReasonEnumField(
          reason['severity'],
          RiskSeverity.values,
          'severity',
          index,
          scanErrors,
        );
        final source = _riskReasonEnumField(
          reason['source'],
          RiskReasonSource.values,
          'source',
          index,
          scanErrors,
        );
        if (id == null ||
            title == null ||
            weight == null ||
            severity == null ||
            source == null) {
          continue;
        }
        parsedReasons.add(
          RiskReason(
            id: id,
            title: title,
            detail: detail,
            weight: weight,
            severity: severity,
            source: source,
          ),
        );
      }
    } else if (reasons != null) {
      scanErrors?.add(
        'local core scan response had malformed risk reasons list',
      );
    }
    final parsedEngines = <DetectionType>[];
    if (engines is List) {
      for (var index = 0; index < engines.length; index += 1) {
        if (parsedEngines.length >= _maxRiskEngines) {
          scanErrors?.add(
            'local core scan response truncated risk engines list',
          );
          break;
        }
        final item = engines[index];
        final engine = _ipcStringOrNull(item);
        if (engine == null) {
          scanErrors?.add(
            'local core scan response dropped malformed risk engine $index',
          );
          continue;
        }
        final detectionType = _engineToDetectionType(engine);
        if (detectionType != DetectionType.unknown) {
          parsedEngines.add(detectionType);
        } else {
          scanErrors?.add(
            'local core scan response dropped unknown risk engine $index',
          );
        }
      }
    } else if (engines != null) {
      scanErrors?.add(
        'local core scan response had malformed risk engines list',
      );
    }
    final score = _boundedInt(json['score'], min: 0, max: 100);
    if (json['score'] == null) {
      scanErrors?.add('local core scan response was missing risk score');
    } else if (score == null) {
      scanErrors?.add('local core scan response had malformed risk score');
    }
    final verdict = _riskScoreEnumField(
      json['verdict'],
      RiskVerdict.values,
      'verdict',
      scanErrors,
    );
    final confidence = _riskScoreEnumField(
      json['confidence'],
      ThreatConfidence.values,
      'confidence',
      scanErrors,
    );
    final recommendedAction = _riskScoreEnumField(
      _field(json, 'recommendedAction', 'recommended_action'),
      RecommendedAction.values,
      'recommended_action',
      scanErrors,
    );
    if (score == null ||
        verdict == null ||
        confidence == null ||
        recommendedAction == null) {
      return null;
    }
    return RiskScore(
      score: score,
      verdict: verdict,
      confidence: confidence,
      reasons: parsedReasons,
      recommendedAction: recommendedAction,
      enginesUsed: parsedEngines,
    );
  }

  String? _riskReasonStringField(
    Object? raw,
    String fieldName,
    int index,
    List<String>? scanErrors,
  ) {
    if (raw == null) {
      scanErrors?.add(
        'local core scan response was missing risk reason $index $fieldName',
      );
      return null;
    }
    final parsed = _ipcStringOrNull(
      raw,
      maxLength: _maxIpcDiagnosticTextLength,
    );
    if (parsed != null) return parsed;
    scanErrors?.add(
      'local core scan response had malformed risk reason $index $fieldName',
    );
    return null;
  }

  String? _optionalRiskReasonDiagnosticField(
    Object? raw,
    String fieldName,
    int index,
    List<String>? scanErrors,
  ) {
    if (raw == null) return null;
    final parsed = _ipcDiagnosticOrNull(raw);
    if (parsed != null) return parsed;
    scanErrors?.add(
      'local core scan response had malformed risk reason $index $fieldName',
    );
    return null;
  }

  int? _riskReasonIntField(
    Object? raw,
    String fieldName,
    int index,
    List<String>? scanErrors,
  ) {
    if (raw == null) {
      scanErrors?.add(
        'local core scan response was missing risk reason $index $fieldName',
      );
      return null;
    }
    final parsed = _boundedInt(raw, min: 0, max: 100);
    if (parsed != null) return parsed;
    scanErrors?.add(
      'local core scan response had malformed risk reason $index $fieldName',
    );
    return null;
  }

  T? _riskReasonEnumField<T extends Enum>(
    Object? raw,
    List<T> values,
    String fieldName,
    int index,
    List<String>? scanErrors,
  ) {
    if (raw == null) {
      scanErrors?.add(
        'local core scan response was missing risk reason $index $fieldName',
      );
      return null;
    }
    final parsed = _enumByName(values, _ipcStringOrNull(raw));
    if (parsed != null) return parsed;
    scanErrors?.add(
      'local core scan response had malformed risk reason $index $fieldName',
    );
    return null;
  }

  T? _riskScoreEnumField<T extends Enum>(
    Object? raw,
    List<T> values,
    String fieldName,
    List<String>? scanErrors,
  ) {
    if (raw == null) {
      scanErrors?.add(
        'local core scan response was missing risk_score $fieldName',
      );
      return null;
    }
    final parsed = _enumByName(values, _ipcStringOrNull(raw));
    if (parsed != null) return parsed;
    scanErrors?.add(
      'local core scan response had malformed risk_score $fieldName',
    );
    return null;
  }

  int? _boundedInt(Object? value, {required int min, required int max}) {
    final parsed = _parseNonNegativeInt(value);
    if (parsed == null || parsed < min || parsed > max) return null;
    return parsed;
  }

  DetectionType _engineToDetectionType(String value) => switch (value) {
    'signature' => DetectionType.signature,
    'yara' => DetectionType.yara,
    'heuristic' => DetectionType.heuristic,
    'localAi' => DetectionType.localAi,
    'behavior' => DetectionType.behavior,
    'ransomwareGuard' => DetectionType.ransomwareGuard,
    _ => DetectionType.unknown,
  };

  AiModelInfo _aiModelInfoFromJson(
    Map<String, Object?> json,
    List<String> diagnostics,
  ) {
    return AiModelInfo(
      status: _aiModelStatusField(json['status'], diagnostics),
      modelVersion: _healthStringField(
        _field(json, 'modelVersion', 'model_version'),
        fallback: 'unavailable',
        fieldName: 'ai_model.model_version',
        diagnostics: diagnostics,
      ),
      featureSchemaVersion: _healthStringField(
        _field(json, 'featureSchemaVersion', 'feature_schema_version'),
        fallback: 'unavailable',
        fieldName: 'ai_model.feature_schema_version',
        diagnostics: diagnostics,
      ),
      productionReady: _ipcBool(
        _field(json, 'productionReady', 'production_ready'),
        diagnostics: diagnostics,
        fieldName: 'ai_model.production_ready',
      ),
      message:
          _healthDiagnosticField(
            json['message'],
            'ai_model.message',
            diagnostics,
          ) ??
          '',
    );
  }

  AiModelStatus _healthAiStatusField(
    Object? raw,
    String fieldName,
    List<String> diagnostics,
  ) {
    if (raw == null) {
      diagnostics.add('local core health response was missing $fieldName');
      return AiModelStatus.modelMissing;
    }
    final status = _enumByName(AiModelStatus.values, _ipcStringOrNull(raw));
    if (status != null) return status;
    diagnostics.add('local core health response had malformed $fieldName');
    return AiModelStatus.modelMissing;
  }

  AiModelStatus _aiModelStatusField(Object? raw, List<String> diagnostics) {
    if (raw == null) {
      diagnostics.add('local core health response was missing ai_model.status');
      return AiModelStatus.modelMissing;
    }
    final status = _enumByName(AiModelStatus.values, _ipcStringOrNull(raw));
    if (status != null) return status;
    diagnostics.add('local core health response had malformed ai_model.status');
    return AiModelStatus.modelMissing;
  }

  ScanStatus? _scanStatusOrNull(String status) => switch (status) {
    'clean' => ScanStatus.clean,
    'threatsFound' => ScanStatus.infected,
    'completedWithErrors' => ScanStatus.completedWithErrors,
    'engineUnavailable' => ScanStatus.engineUnavailable,
    'cancelled' => ScanStatus.cancelled,
    'failed' => ScanStatus.failed,
    _ => null,
  };

  T? _enumByName<T extends Enum>(List<T> values, String? name) {
    if (name == null) return null;
    for (final value in values) {
      if (value.name == name) return value;
    }
    return null;
  }
}

class _IpcJsonResponseCapture {
  const _IpcJsonResponseCapture({
    required this.response,
    required this.protocolWarnings,
  });

  final Map<String, Object?>? response;
  final List<String> protocolWarnings;
}

class ProcessObservation {
  const ProcessObservation({
    required this.pid,
    required this.imagePath,
    this.parentPid,
    this.commandLine,
    this.commandLineTruncated = false,
    this.signerTrusted,
  });

  final int pid;
  final int? parentPid;
  final String imagePath;
  final String? commandLine;
  final bool commandLineTruncated;
  final bool? signerTrusted;

  Map<String, Object?> toJson() => {
    'pid': pid,
    if (parentPid != null) 'parent_pid': parentPid,
    'image_path': imagePath,
    if (commandLine != null) 'command_line': commandLine,
    if (commandLineTruncated) 'command_line_truncated': true,
    if (signerTrusted != null) 'signer_trusted': signerTrusted,
  };
}

class ProcessMonitorPolicy {
  const ProcessMonitorPolicy({
    this.suspiciousThreshold = 40,
    this.allowedImagePaths = const [],
  });

  final int suspiciousThreshold;
  final List<String> allowedImagePaths;

  Map<String, Object?> toJson() => {
    'suspicious_threshold': suspiciousThreshold,
    if (allowedImagePaths.isNotEmpty) 'allowed_image_paths': allowedImagePaths,
  };
}

class ProcessSnapshotReport {
  const ProcessSnapshotReport({
    required this.ok,
    required this.status,
    required this.capability,
    required this.statusReason,
    this.observedProcesses = 0,
    this.skippedProcesses = 0,
    this.findings = const [],
    this.diagnostics = const [],
  });

  final bool ok;
  final String status;
  final String capability;
  final String statusReason;
  final int observedProcesses;
  final int skippedProcesses;
  final List<ProcessFinding> findings;
  final List<String> diagnostics;
}

class ProcessFinding {
  const ProcessFinding({
    required this.pid,
    required this.imagePath,
    required this.score,
    required this.verdict,
    this.reasons = const [],
  });

  final int pid;
  final String imagePath;
  final int score;
  final String verdict;
  final List<String> reasons;
}

class WatchPollScanResult {
  const WatchPollScanResult({
    required this.ok,
    required this.watcher,
    required this.poll,
    this.error,
  });

  final bool ok;
  final RealtimeWatcherState watcher;
  final WatchPollScanSummary poll;
  final String? error;
}

class WatchPollScanSummary {
  const WatchPollScanSummary({
    required this.active,
    required this.mode,
    this.durationMs = 0,
    this.pollIntervalMs = 0,
    this.maxEvents = 0,
    this.initialFilesObserved = 0,
    this.pollsCompleted = 0,
    this.eventsObserved = 0,
    this.filesScanned = 0,
    this.threatsFound = 0,
    this.quarantinedFiles = 0,
    this.scanErrors = const [],
    this.limitations = const [],
  });

  final bool active;
  final String mode;
  final int durationMs;
  final int pollIntervalMs;
  final int maxEvents;
  final int initialFilesObserved;
  final int pollsCompleted;
  final int eventsObserved;
  final int filesScanned;
  final int threatsFound;
  final int quarantinedFiles;
  final List<String> scanErrors;
  final List<String> limitations;
}

class ProtectionSelfTestResult {
  const ProtectionSelfTestResult({required this.passed, required this.details});

  const ProtectionSelfTestResult.failed(this.details) : passed = false;

  final bool passed;
  final String details;
}

class _ProtectionSelfTestSteps {
  const _ProtectionSelfTestSteps({
    required this.valid,
    required this.allPassed,
    required this.details,
  });

  final bool valid;
  final bool allPassed;
  final String details;
}

class LocalCoreActionResult {
  const LocalCoreActionResult._({required this.ok, this.error});

  const LocalCoreActionResult.ok() : this._(ok: true);

  const LocalCoreActionResult.failed(String error)
    : this._(ok: false, error: error);

  final bool ok;
  final String? error;
}

class RealtimeWatcherState {
  const RealtimeWatcherState({
    required this.active,
    required this.mode,
    this.watchedPaths = const [],
    this.limitations = const [],
    this.error,
  });

  factory RealtimeWatcherState.fromJson(Map<String, Object?> json) {
    final rawPaths = json['watchedPaths'] ?? json['watched_paths'];
    final rawLimitations = json['limitations'];
    final diagnostics = <String>[];
    final pathDiagnostics = <String>[];
    final limitationDiagnostics = <String>[];
    final limitations = [
      ..._watcherStringList(
        rawLimitations,
        fieldName: 'limitations',
        diagnostics: limitationDiagnostics,
      ),
      ...limitationDiagnostics,
    ];
    final active = _watcherBool(
      json['active'],
      fieldName: 'active',
      diagnostics: diagnostics,
    );
    final watchedPaths = _watcherStringList(
      rawPaths,
      fieldName: 'watched_paths',
      diagnostics: pathDiagnostics,
    );
    diagnostics.addAll(pathDiagnostics);
    if (active && watchedPaths.isEmpty && pathDiagnostics.isEmpty) {
      const diagnostic =
          'Watcher response reported active without watched paths.';
      diagnostics.add(diagnostic);
      limitations.add(diagnostic);
    }
    return RealtimeWatcherState(
      active: active,
      mode: _watcherMode(json['mode'], diagnostics: diagnostics),
      watchedPaths: watchedPaths,
      limitations: limitations,
      error: _watcherErrorWithDiagnostics(
        _watcherStringOrNull(json['error'], maxLength: 2048),
        [...diagnostics, ...limitationDiagnostics],
      ),
    );
  }

  final bool active;
  final String mode;
  final List<String> watchedPaths;
  final List<String> limitations;
  final String? error;

  static bool _watcherBool(
    Object? value, {
    required String fieldName,
    required List<String> diagnostics,
  }) {
    if (value is bool) return value;
    if (value != null) {
      diagnostics.add('Watcher response had malformed $fieldName boolean.');
    }
    return false;
  }

  static String _watcherMode(
    Object? value, {
    required List<String> diagnostics,
  }) {
    final mode = _watcherStringOrNull(value);
    if (mode == null) {
      diagnostics.add('Watcher response was missing or malformed mode.');
      return 'unknown';
    }
    if (mode == 'userModeBestEffort' || mode == 'stopped' || mode == 'off') {
      return mode;
    }
    diagnostics.add('Watcher response had unsupported mode.');
    return 'unknown';
  }

  static String? _watcherStringOrNull(Object? value, {int maxLength = 256}) {
    if (value is! String) return null;
    final trimmed = value.trim();
    if (trimmed.isEmpty) return null;
    if (trimmed.length <= maxLength) return trimmed;
    return trimmed.substring(0, maxLength);
  }

  static List<String> _watcherStringList(
    Object? value, {
    required String fieldName,
    required List<String> diagnostics,
  }) {
    if (value == null) return const [];
    if (value is! List) {
      diagnostics.add('Watcher response had malformed $fieldName list.');
      return const [];
    }
    final result = <String>[];
    var malformedItems = 0;
    var inspectedItems = 0;
    for (final item in value) {
      if (inspectedItems >= 64) {
        diagnostics.add('Watcher response truncated $fieldName list.');
        break;
      }
      inspectedItems++;
      final parsed = _watcherStringOrNull(item, maxLength: 2048);
      if (parsed == null) {
        malformedItems++;
        continue;
      }
      result.add(parsed);
    }
    if (malformedItems > 0) {
      diagnostics.add(
        'Watcher response dropped $malformedItems malformed $fieldName entries.',
      );
    }
    return result;
  }

  static String? _watcherErrorWithDiagnostics(
    String? error,
    List<String> diagnostics,
  ) {
    final parts = [?error, ...diagnostics];
    if (parts.isEmpty) return null;
    return _watcherStringOrNull(parts.join(' '), maxLength: 2048);
  }
}

class _FileProbeResult {
  const _FileProbeResult(this.isRegularFile, [this.diagnostic]);

  final bool isRegularFile;
  final String? diagnostic;

  bool get isNotRegularFile => !isRegularFile;
}

class _BoundedUtf8Capture {
  const _BoundedUtf8Capture(this.text, {required this.truncated});

  final String text;
  final bool truncated;
}

enum CoreServiceBoundaryStatus {
  notChecked,
  unsupported,
  unavailable,
  degraded,
  ready,
}

class CoreServiceBoundaryHealth {
  const CoreServiceBoundaryHealth({
    this.status = CoreServiceBoundaryStatus.notChecked,
    this.protocolVersion = 0,
    this.transport = 'unknown',
    this.networkExposed,
    this.commandScope = 'unknown',
    this.clientAuthenticated = false,
    this.serverAuthenticated = false,
    this.serverPid = 0,
    this.servicePid = 0,
    this.serviceReady = false,
    this.engineReady = false,
    this.nativeSignatureCount = 0,
    this.nativeRuleCount = 0,
    this.nativeMlProductionReady = false,
    this.limitations = const [],
    this.diagnostic,
  });

  factory CoreServiceBoundaryHealth.unavailable(String diagnostic) =>
      CoreServiceBoundaryHealth(
        status: CoreServiceBoundaryStatus.unavailable,
        diagnostic: _boundedServiceHealthDiagnostic(diagnostic),
      );

  factory CoreServiceBoundaryHealth.fromJson(Map<String, Object?> json) {
    const expectedFields = <String>{
      'ok',
      'protocolVersion',
      'transport',
      'networkExposed',
      'commandScope',
      'clientAuthenticated',
      'serverAuthenticated',
      'serverPid',
      'servicePid',
      'serviceReady',
      'engineReady',
      'nativeSignatureCount',
      'nativeRuleCount',
      'nativeMlProductionReady',
      'limitations',
    };
    final actualFields = json.keys.toSet();
    final missing = expectedFields.difference(actualFields).toList()..sort();
    final unknown = actualFields.difference(expectedFields).toList()..sort();
    if (missing.isNotEmpty || unknown.isNotEmpty) {
      throw FormatException(
        'Core Service health schema mismatch '
        '(missing: ${missing.join(', ')}; unknown: ${unknown.join(', ')}).',
      );
    }

    T requiredField<T>(String name) {
      final value = json[name];
      if (value is! T) {
        throw FormatException('Core Service health field $name was malformed.');
      }
      return value;
    }

    int boundedCount(String name, {int maximum = 10000000}) {
      final value = requiredField<int>(name);
      if (value < 0 || value > maximum) {
        throw FormatException(
          'Core Service health field $name was outside its safe bounds.',
        );
      }
      return value;
    }

    final ok = requiredField<bool>('ok');
    final protocolVersion = requiredField<int>('protocolVersion');
    final transport = requiredField<String>('transport');
    final networkExposed = requiredField<bool>('networkExposed');
    final commandScope = requiredField<String>('commandScope');
    final clientAuthenticated = requiredField<bool>('clientAuthenticated');
    final serverAuthenticated = requiredField<bool>('serverAuthenticated');
    final serverPid = boundedCount('serverPid', maximum: 0xffffffff);
    final servicePid = boundedCount('servicePid', maximum: 0xffffffff);
    final serviceReady = requiredField<bool>('serviceReady');
    final engineReady = requiredField<bool>('engineReady');
    final nativeSignatureCount = boundedCount('nativeSignatureCount');
    final nativeRuleCount = boundedCount('nativeRuleCount');
    final nativeMlProductionReady = requiredField<bool>(
      'nativeMlProductionReady',
    );
    final rawLimitations = requiredField<List<Object?>>('limitations');
    if (protocolVersion != 1 ||
        transport != 'windowsNamedPipe' ||
        networkExposed ||
        commandScope != 'healthOnly' ||
        !clientAuthenticated ||
        !serverAuthenticated ||
        serverPid == 0 ||
        servicePid == 0 ||
        serverPid != servicePid ||
        !serviceReady ||
        ok != engineReady) {
      throw const FormatException(
        'Core Service health response failed authenticated boundary validation.',
      );
    }
    if (rawLimitations.isEmpty || rawLimitations.length > 16) {
      throw const FormatException(
        'Core Service health limitations were outside their safe bounds.',
      );
    }
    final limitations = <String>[];
    for (final raw in rawLimitations) {
      if (raw is! String ||
          raw.trim().isEmpty ||
          raw.length > 256 ||
          RegExp(r'[\u0000-\u001f\u007f]').hasMatch(raw)) {
        throw const FormatException(
          'Core Service health limitation was malformed.',
        );
      }
      limitations.add(raw);
    }

    return CoreServiceBoundaryHealth(
      status: engineReady
          ? CoreServiceBoundaryStatus.ready
          : CoreServiceBoundaryStatus.degraded,
      protocolVersion: protocolVersion,
      transport: transport,
      networkExposed: networkExposed,
      commandScope: commandScope,
      clientAuthenticated: clientAuthenticated,
      serverAuthenticated: serverAuthenticated,
      serverPid: serverPid,
      servicePid: servicePid,
      serviceReady: serviceReady,
      engineReady: engineReady,
      nativeSignatureCount: nativeSignatureCount,
      nativeRuleCount: nativeRuleCount,
      nativeMlProductionReady: nativeMlProductionReady,
      limitations: List.unmodifiable(limitations),
    );
  }

  final CoreServiceBoundaryStatus status;
  final int protocolVersion;
  final String transport;
  final bool? networkExposed;
  final String commandScope;
  final bool clientAuthenticated;
  final bool serverAuthenticated;
  final int serverPid;
  final int servicePid;
  final bool serviceReady;
  final bool engineReady;
  final int nativeSignatureCount;
  final int nativeRuleCount;
  final bool nativeMlProductionReady;
  final List<String> limitations;
  final String? diagnostic;

  bool get authenticatedBoundaryVerified =>
      (status == CoreServiceBoundaryStatus.ready ||
          status == CoreServiceBoundaryStatus.degraded) &&
      protocolVersion == 1 &&
      transport == 'windowsNamedPipe' &&
      networkExposed == false &&
      commandScope == 'healthOnly' &&
      clientAuthenticated &&
      serverAuthenticated &&
      serverPid > 0 &&
      serverPid == servicePid &&
      serviceReady;

  bool get fullProtectionReady => authenticatedBoundaryVerified && engineReady;
}

String _boundedServiceHealthDiagnostic(String value) {
  final normalized = value
      .replaceAll(RegExp(r'[\u0000-\u001f\u007f]'), ' ')
      .replaceAll(RegExp(r'\s+'), ' ')
      .trim();
  if (normalized.isEmpty) return 'Core Service health evidence is unavailable.';
  if (normalized.length <= 2048) return normalized;
  return '${normalized.substring(0, 2034)}...[truncated]';
}

class LocalCoreHealth {
  const LocalCoreHealth({
    this.malwareEngineStatus = MalwareEngineStatus.unavailable,
    this.aiStatus = AiModelStatus.modelMissing,
    this.aiModelInfo = const AiModelInfo(),
    this.yaraStatus = 'rulesUnavailable',
    this.yaraRuleCount = 0,
    this.nativeEngineStatus = 'unavailable',
    this.nativeSignatureCount = 0,
    this.nativeRuleCount = 0,
    this.nativeMlStatus = 'modelMissing',
    this.nativeMlModelVersion,
    this.nativeMlProductionReady = false,
    this.nativeEngineError,
    this.nativeSelfTestPassed,
    this.nativeSelfTestError,
    this.aiSelfTestPassed,
    this.aiSelfTestError,
    this.ipcMode = 'unknown',
    this.networkExposed,
    this.compatibilityEnginesEnabled = false,
    this.coreServiceStatus = 'unknown',
    this.coreServiceStatusError,
    this.guardStatus = 'unknown',
    this.guardStatusError,
    this.driverStatus = 'unknown',
    this.processMonitorStatus = 'unknown',
    this.processMonitorCapability = 'unknown',
    this.processMonitorStatusReason,
    this.behaviorMonitorStatus = 'unknown',
    this.behaviorMonitorStatusReason,
    this.reputationStatus = 'unavailable',
    this.reputationStatusReason,
    this.installPath,
    this.engineDirectory,
    this.nativeSignaturesDirectory,
    this.nativeRulesDirectory,
    this.nativeMlDirectory,
    this.nativeTrustDirectory,
    this.nativeConfigDirectory,
    this.enginePathsChecked = const [],
    this.programDataDirectory,
    this.programDataDirectoryError,
    this.lastError,
  });

  final MalwareEngineStatus malwareEngineStatus;
  final AiModelStatus aiStatus;
  final AiModelInfo aiModelInfo;
  final String yaraStatus;
  final int yaraRuleCount;
  final String nativeEngineStatus;
  final int nativeSignatureCount;
  final int nativeRuleCount;
  final String nativeMlStatus;
  final String? nativeMlModelVersion;
  final bool nativeMlProductionReady;
  final String? nativeEngineError;
  final bool? nativeSelfTestPassed;
  final String? nativeSelfTestError;
  final bool? aiSelfTestPassed;
  final String? aiSelfTestError;
  final String ipcMode;
  final bool? networkExposed;
  final bool compatibilityEnginesEnabled;
  final String coreServiceStatus;
  final String? coreServiceStatusError;
  final String guardStatus;
  final String? guardStatusError;
  final String driverStatus;
  final String processMonitorStatus;
  final String processMonitorCapability;
  final String? processMonitorStatusReason;
  final String behaviorMonitorStatus;
  final String? behaviorMonitorStatusReason;
  final String reputationStatus;
  final String? reputationStatusReason;
  final String? installPath;
  final String? engineDirectory;
  final String? nativeSignaturesDirectory;
  final String? nativeRulesDirectory;
  final String? nativeMlDirectory;
  final String? nativeTrustDirectory;
  final String? nativeConfigDirectory;
  final List<String> enginePathsChecked;
  final String? programDataDirectory;
  final String? programDataDirectoryError;
  final String? lastError;
}
