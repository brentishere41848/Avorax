import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:zentor_protocol/zentor_protocol.dart';

class LocalCoreClient {
  const LocalCoreClient({
    this.executableOverride,
    this.executableArguments = const [],
    this.ipcTimeout = const Duration(minutes: 30),
  });

  final String? executableOverride;
  final List<String> executableArguments;
  final Duration ipcTimeout;

  static Process? _activeScanProcess;

  bool get isDesktop =>
      Platform.isWindows || Platform.isMacOS || Platform.isLinux;

  Future<MalwareEngineStatus> health() async {
    return (await healthSummary()).malwareEngineStatus;
  }

  Future<LocalCoreHealth> healthSummary() async {
    if (!isDesktop) return const LocalCoreHealth();
    final response = await _call({'command': 'health'});
    if (response == null) return const LocalCoreHealth();
    if (response['ok'] == false) {
      return LocalCoreHealth(
        coreServiceStatus: 'error',
        lastError: response['error']?.toString(),
      );
    }
    final engine = response['engine_status'];
    final aiModelRaw = response['ai_model'];
    return LocalCoreHealth(
      malwareEngineStatus: switch (engine) {
        'available' => MalwareEngineStatus.available,
        'signatures_outdated' => MalwareEngineStatus.signaturesOutdated,
        'error' => MalwareEngineStatus.error,
        _ => MalwareEngineStatus.unavailable,
      },
      aiModelInfo: aiModelRaw is Map
          ? _aiModelInfoFromJson(Map<String, Object?>.from(aiModelRaw))
          : const AiModelInfo(),
      yaraStatus: response['yara_status'] as String? ?? 'rulesUnavailable',
      yaraRuleCount: response['yara_rule_count'] as int? ?? 0,
      nativeEngineStatus:
          response['native_engine_status'] as String? ?? 'unavailable',
      nativeSignatureCount: response['native_signature_count'] as int? ?? 0,
      nativeRuleCount: response['native_rule_count'] as int? ?? 0,
      nativeMlStatus: response['native_ml_status'] as String? ?? 'modelMissing',
      nativeMlModelVersion: response['native_ml_model_version'] as String?,
      compatibilityEnginesEnabled:
          response['compatibility_engines_enabled'] as bool? ?? false,
      coreServiceStatus:
          response['core_service_status'] as String? ?? 'unknown',
      guardStatus: response['guard_status'] as String? ?? 'off',
      driverStatus: response['driver_status'] as String? ?? 'missing',
      installPath: response['install_path']?.toString(),
      engineDirectory: response['engine_directory']?.toString(),
      enginePathsChecked:
          (response['engine_paths_checked'] as List?)
              ?.map((item) => item.toString())
              .toList() ??
          const [],
      programDataDirectory: response['program_data_dir']?.toString(),
      lastError: response['last_error']?.toString(),
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
    final records = response?['records'];
    if (records is! List) return const [];
    return records.whereType<Map>().map((item) {
      final map = Map<String, Object?>.from(item);
      return QuarantineRecord(
        quarantineId: map['quarantine_id'] as String? ?? '',
        originalPath: map['original_path'] as String? ?? '',
        quarantinePath: map['quarantine_path'] as String? ?? '',
        sha256: map['sha256'] as String? ?? '',
        fileSize: map['file_size'] as int? ?? 0,
        detectionName: map['detection_name'] as String? ?? '',
        engine: map['engine'] as String? ?? '',
        quarantinedAt:
            DateTime.tryParse(map['quarantined_at'] as String? ?? '') ??
            DateTime.fromMillisecondsSinceEpoch(0),
        status: QuarantineItemStatus.values.firstWhere(
          (status) => status.name == (map['status'] as String? ?? ''),
          orElse: () => QuarantineItemStatus.quarantined,
        ),
        userNote: map['user_note'] as String?,
        source: map['source'] as String? ?? 'scanner',
        blockedBeforeExecution:
            map['blocked_before_execution'] as bool? ?? false,
        processStarted: map['process_started'] as bool? ?? false,
        actionTaken: map['action_taken'] as String? ?? 'quarantined',
      );
    }).toList();
  }

  Future<bool> quarantineThreat(ThreatResult threat) async {
    final response = await _call({
      'command': 'quarantine_file',
      'path': threat.path,
      'threat_name': threat.threatName,
      'engine': threat.engine,
    });
    return response?['ok'] == true;
  }

  Future<bool> addAllowlistEntry(String path) async {
    final response = await _call({
      'command': 'add_allowlist_entry',
      'path': path,
    });
    return response?['ok'] == true;
  }

  Future<bool> labelDetection(
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
    return response?['ok'] == true;
  }

  Future<bool> restoreQuarantineItem(String quarantineId) async {
    final response = await _call({
      'command': 'restore_quarantine_item',
      'quarantine_id': quarantineId,
      'confirmed': true,
    });
    return response?['ok'] == true;
  }

  Future<bool> deleteQuarantineItem(String quarantineId) async {
    final response = await _call({
      'command': 'delete_quarantine_item',
      'quarantine_id': quarantineId,
      'confirmed': true,
    });
    return response?['ok'] == true;
  }

  Future<String> runProtectionSelfTest() async {
    if (!isDesktop) {
      return 'Protection self-test is only available on desktop platforms.';
    }
    final executable = _guardServiceExecutable();
    if (executable == null || !File(executable).existsSync()) {
      return 'Avorax Guard Service executable was not found. Post-launch fallback cannot be self-tested.';
    }
    try {
      final process = await Process.start(executable, []);
      process.stdin.writeln(jsonEncode({'command': 'driver_self_test'}));
      await process.stdin.close();
      final stdoutFuture = process.stdout.transform(utf8.decoder).join();
      final stderrFuture = process.stderr.transform(utf8.decoder).join();
      final results = await Future.wait<Object>([
        stdoutFuture,
        stderrFuture,
        process.exitCode,
      ]).timeout(const Duration(seconds: 30));
      final stdout = (results[0] as String).trim();
      final stderr = (results[1] as String).trim();
      final lines = stdout
          .split(RegExp(r'\r?\n'))
          .map((line) => line.trim())
          .where((line) => line.isNotEmpty)
          .toList();
      if (lines.isEmpty) {
        return stderr.isEmpty
            ? 'Protection self-test produced no output.'
            : 'Protection self-test produced no output. stderr: $stderr';
      }
      final lastLine = lines.last;
      final decoded = jsonDecode(lastLine);
      if (decoded is! Map) return lastLine;
      final message = decoded['message'];
      if (message is String && message.trim().startsWith('{')) {
        final report = jsonDecode(message);
        if (report is Map) {
          final steps = report['steps'];
          if (steps is List) {
            return steps
                .whereType<Map>()
                .map((step) {
                  final passed = step['passed'] == true ? 'PASS' : 'FAIL';
                  return '$passed ${step['name']}: ${step['reason']}';
                })
                .join('\n');
          }
        }
      }
      return message is String ? message : lastLine;
    } on Object catch (error) {
      return 'Protection self-test failed: $error';
    }
  }

  Future<bool> configureGuardMode(ProtectionMode mode) async {
    final response = await _call({
      'command': 'configure_guard_mode',
      'protection_mode': mode.name,
    });
    return response?['ok'] == true;
  }

  Future<bool> configureRansomwareGuard({
    required List<String> protectedRoots,
    required List<String> trustedProcesses,
  }) async {
    final response = await _call({
      'command': 'configure_ransomware_guard',
      'protected_roots': protectedRoots,
      'trusted_process_allowlist': trustedProcesses,
    });
    return response?['ok'] == true;
  }

  Future<RealtimeWatcherState> startWatch(List<String> paths) async {
    final response = await _call({'command': 'start_watch', 'paths': paths});
    if (response == null || response['ok'] == false) {
      return RealtimeWatcherState(
        active: false,
        mode: 'off',
        watchedPaths: const [],
        error: response?['error']?.toString(),
      );
    }
    final watcher = response['watcher'];
    if (watcher is Map) {
      return RealtimeWatcherState.fromJson(Map<String, Object?>.from(watcher));
    }
    return const RealtimeWatcherState(active: false, mode: 'off');
  }

  Future<RealtimeWatcherState> stopWatch() async {
    final response = await _call({'command': 'stop_watch'});
    final watcher = response?['watcher'];
    if (watcher is Map) {
      return RealtimeWatcherState.fromJson(Map<String, Object?>.from(watcher));
    }
    return const RealtimeWatcherState(active: false, mode: 'off');
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
    final executable = _localCoreExecutable();
    if (executable == null || !File(executable).existsSync()) {
      return 'Avorax Core Service executable was not found. Reinstall Avorax or set AVORAX_CORE_SERVICE to the installed executable.';
    }
    final escapedExecutable = executable.replaceAll("'", "''");
    final result = await _runElevatedPowerShell('''
\$exe = '$escapedExecutable'
\$service = Get-Service -Name 'avorax_core_service' -ErrorAction SilentlyContinue
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
    final candidates = [
      r'C:\ProgramData\Avorax\reports\install_report.json',
      r'C:\Program Files\Avorax\install-manifest.json',
      '${File(Platform.resolvedExecutable).parent.path}${Platform.pathSeparator}install-manifest.json',
    ];
    File? report;
    for (final candidate in candidates) {
      final file = File(candidate);
      if (file.existsSync()) {
        report = file;
        break;
      }
    }
    if (report == null) {
      return 'No Avorax install report was found under ProgramData or the install directory.';
    }
    try {
      await Process.start('explorer.exe', ['/select,${report.path}']);
      return 'Opened Avorax install report location.';
    } on Object catch (error) {
      return 'Unable to open install report: $error';
    }
  }

  Future<void> cancelActiveScan() async {
    _activeScanProcess?.kill();
  }

  Future<ScanReport> _scanCommand(
    Map<String, Object?> command, {
    required ScanKind kind,
    required ScanActionMode actionMode,
    void Function(ScanProgress progress)? onProgress,
  }) async {
    final response = await _call(command, onProgress: onProgress);
    if (response == null || response['ok'] == false) {
      return ScanReport(
        status: ScanStatus.engineUnavailable,
        kind: kind,
        actionMode: actionMode,
        filesScanned: 0,
        threatsFound: 0,
        skippedFiles: 0,
        elapsedMs: 0,
        threats: const [],
        message:
            response?['error'] as String? ??
            'Avorax local core is not available.',
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
    if (executable == null || !File(executable).existsSync()) {
      return {
        'ok': false,
        'error': 'Avorax Core Service executable was not found at $executable.',
      };
    }
    try {
      final process = await Process.start(executable, executableArguments);
      if (command['command'] == 'scan_file' ||
          command['command'] == 'scan_folder' ||
          command['command'] == 'quick_scan_selected_paths' ||
          command['command'] == 'full_scan') {
        _activeScanProcess = process;
      }
      return await (() async {
        process.stdin.writeln(jsonEncode(command));
        await process.stdin.close();
        final stderrFuture = process.stderr.transform(utf8.decoder).join();
        Map<String, Object?>? last;
        String? malformedLine;
        await for (final line
            in process.stdout
                .transform(utf8.decoder)
                .transform(const LineSplitter())) {
          final trimmed = line.trim();
          if (trimmed.isEmpty) continue;
          Object? decoded;
          try {
            decoded = jsonDecode(trimmed);
          } on Object {
            malformedLine ??= trimmed;
            continue;
          }
          if (decoded is! Map) continue;
          final map = Map<String, Object?>.from(decoded);
          if (map['type'] == 'progress' && onProgress != null) {
            final raw = map['progress'];
            if (raw is Map) {
              onProgress(_scanProgressFromJson(Map<String, Object?>.from(raw)));
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
        if (last == null && malformedLine != null) {
          return {
            'ok': false,
            'error':
                'Avorax local core returned malformed JSON: $malformedLine',
          };
        }
        return last;
      })().timeout(
        ipcTimeout,
        onTimeout: () {
          process.kill();
          return {
            'ok': false,
            'error':
                'Avorax local core IPC timed out after ${_formatDuration(ipcTimeout)}.',
          };
        },
      );
    } on Object catch (error) {
      return {'ok': false, 'error': 'Avorax local core IPC failed: $error'};
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

  String? _localCoreExecutable() {
    if (executableOverride != null) return executableOverride;
    final override =
        Platform.environment['AVORAX_CORE_SERVICE'] ??
        Platform.environment['ZENTOR_LOCAL_CORE'];
    if (override != null &&
        override.isNotEmpty &&
        File(override).existsSync()) {
      return override;
    }
    final primaryName = Platform.isWindows
        ? 'avorax_core_service.exe'
        : 'avorax_core_service';
    final legacyName = Platform.isWindows
        ? 'zentor_local_core.exe'
        : 'zentor_local_core';
    final candidates = [
      '${File(Platform.resolvedExecutable).parent.path}${Platform.pathSeparator}$primaryName',
      '${File(Platform.resolvedExecutable).parent.path}${Platform.pathSeparator}$legacyName',
      '${Directory.current.path}${Platform.pathSeparator}$primaryName',
      '${Directory.current.path}${Platform.pathSeparator}$legacyName',
      'core${Platform.pathSeparator}zentor_local_core${Platform.pathSeparator}target${Platform.pathSeparator}release${Platform.pathSeparator}$legacyName',
      '..${Platform.pathSeparator}..${Platform.pathSeparator}core${Platform.pathSeparator}zentor_local_core${Platform.pathSeparator}target${Platform.pathSeparator}release${Platform.pathSeparator}$legacyName',
    ];
    for (final candidate in candidates) {
      final file = File(candidate);
      if (file.existsSync()) return file.absolute.path;
    }
    return candidates.first;
  }

  String? _guardServiceExecutable() {
    final override =
        Platform.environment['AVORAX_GUARD_SERVICE'] ??
        Platform.environment['ZENTOR_GUARD_SERVICE'];
    if (override != null &&
        override.isNotEmpty &&
        File(override).existsSync()) {
      return override;
    }
    final primaryName = Platform.isWindows
        ? 'avorax_guard_service.exe'
        : 'avorax_guard_service';
    final legacyName = Platform.isWindows
        ? 'zentor_guard_service.exe'
        : 'zentor_guard_service';
    final candidates = [
      '${File(Platform.resolvedExecutable).parent.path}${Platform.pathSeparator}$primaryName',
      '${File(Platform.resolvedExecutable).parent.path}${Platform.pathSeparator}$legacyName',
      '${Directory.current.path}${Platform.pathSeparator}$primaryName',
      '${Directory.current.path}${Platform.pathSeparator}$legacyName',
      'core${Platform.pathSeparator}zentor_guard_service${Platform.pathSeparator}target${Platform.pathSeparator}release${Platform.pathSeparator}$legacyName',
      '..${Platform.pathSeparator}..${Platform.pathSeparator}core${Platform.pathSeparator}zentor_guard_service${Platform.pathSeparator}target${Platform.pathSeparator}release${Platform.pathSeparator}$legacyName',
    ];
    for (final candidate in candidates) {
      final file = File(candidate);
      if (file.existsSync()) return file.absolute.path;
    }
    return candidates.first;
  }

  Future<String?> _runElevatedPowerShell(String script) async {
    final encoded = _powershellEncodedCommand(script);
    final launcher =
        r"$process = Start-Process -FilePath 'powershell.exe' "
        "-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','$encoded') "
        r"-Verb RunAs -Wait -PassThru; exit $process.ExitCode";
    try {
      final process = await Process.start('powershell.exe', [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        launcher,
      ]);
      final stderr = await process.stderr.transform(utf8.decoder).join();
      final exitCode = await process.exitCode.timeout(
        const Duration(minutes: 2),
      );
      if (exitCode == 0) return null;
      final trimmed = stderr.trim();
      return trimmed.isEmpty ? 'PowerShell exit code $exitCode' : trimmed;
    } on Object catch (error) {
      return '$error';
    }
  }

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
    final statusName = json['status'] as String? ?? 'engineUnavailable';
    return ScanReport(
      status: _scanStatus(statusName),
      kind: _enumByName(ScanKind.values, json['kind'] as String?) ?? kind,
      actionMode:
          _enumByName(ScanActionMode.values, json['action_mode'] as String?) ??
          actionMode,
      filesScanned: json['files_scanned'] as int? ?? 0,
      foldersScanned: json['folders_scanned'] as int? ?? 0,
      bytesScanned: json['bytes_scanned'] as int? ?? 0,
      totalFilesEstimated: json['total_files_estimated'] as int?,
      totalBytesEstimated: json['total_bytes_estimated'] as int?,
      threatsFound: json['threats_found'] as int? ?? 0,
      suspiciousFound: json['suspicious_found'] as int? ?? 0,
      quarantinedFiles: json['quarantined_files'] as int? ?? 0,
      skippedFiles: json['skipped_files'] as int? ?? 0,
      permissionDeniedCount: json['permission_denied_count'] as int? ?? 0,
      elapsedMs: json['elapsed_ms'] as int? ?? 0,
      currentPath: json['current_path'] as String?,
      message: json['message'] as String?,
      progress: json['progress'] is Map
          ? _scanProgressFromJson(
              Map<String, Object?>.from(json['progress'] as Map),
            )
          : null,
      threats: threats is List
          ? threats.whereType<Map>().map(_threatFromJson).toList()
          : const [],
    );
  }

  ScanProgress _scanProgressFromJson(Map<String, Object?> json) {
    return ScanProgress(
      jobId: json['job_id'] as String? ?? '',
      scanType:
          _enumByName(ScanKind.values, json['scan_type'] as String?) ??
          ScanKind.custom,
      status:
          _enumByName(ScanJobStatus.values, json['status'] as String?) ??
          ScanJobStatus.running,
      currentPath: json['current_path'] as String?,
      filesScanned: json['files_scanned'] as int? ?? 0,
      foldersScanned: json['folders_scanned'] as int? ?? 0,
      bytesScanned: json['bytes_scanned'] as int? ?? 0,
      totalFilesEstimated: json['total_files_estimated'] as int?,
      totalBytesEstimated: json['total_bytes_estimated'] as int?,
      threatsFound: json['threats_found'] as int? ?? 0,
      suspiciousFound: json['suspicious_found'] as int? ?? 0,
      skippedFiles: json['skipped_files'] as int? ?? 0,
      permissionDeniedCount: json['permission_denied_count'] as int? ?? 0,
      startedAt:
          DateTime.tryParse(json['started_at'] as String? ?? '') ??
          DateTime.now().toUtc(),
      updatedAt:
          DateTime.tryParse(json['updated_at'] as String? ?? '') ??
          DateTime.now().toUtc(),
      elapsedSeconds: json['elapsed_seconds'] as int? ?? 0,
      estimatedRemainingSeconds: json['estimated_remaining_seconds'] as int?,
      progressPercent: (json['progress_percent'] as num?)?.toDouble(),
    );
  }

  ThreatResult _threatFromJson(Map<dynamic, dynamic> raw) {
    final json = Map<String, Object?>.from(raw);
    return ThreatResult(
      id: json['id'] as String? ?? '',
      path: json['path'] as String? ?? '',
      fileName: json['file_name'] as String? ?? '',
      sha256: json['sha256'] as String? ?? '',
      sizeBytes: json['size_bytes'] as int? ?? 0,
      detectionType:
          _enumByName(
            DetectionType.values,
            json['detection_type'] as String?,
          ) ??
          DetectionType.unknown,
      threatCategory:
          _enumByName(
            ThreatCategory.values,
            json['threat_category'] as String?,
          ) ??
          ThreatCategory.unknown,
      threatName: json['threat_name'] as String? ?? 'Suspicious file',
      confidence:
          _enumByName(ThreatConfidence.values, json['confidence'] as String?) ??
          ThreatConfidence.low,
      engine: json['engine'] as String? ?? 'zentor',
      detectedAt:
          DateTime.tryParse(json['detected_at'] as String? ?? '') ??
          DateTime.now().toUtc(),
      recommendedAction:
          _enumByName(
            RecommendedAction.values,
            json['recommended_action'] as String?,
          ) ??
          RecommendedAction.review,
      status:
          _enumByName(ThreatResultStatus.values, json['status'] as String?) ??
          ThreatResultStatus.detected,
      riskScore: _riskScoreFromJson(json['risk_score']),
      reasonSummary: json['reason_summary'] as String? ?? '',
    );
  }

  RiskScore _riskScoreFromJson(Object? raw) {
    if (raw is! Map) {
      return const RiskScore(
        score: 0,
        verdict: RiskVerdict.unknown,
        confidence: ThreatConfidence.low,
        reasons: [],
        recommendedAction: RecommendedAction.review,
        enginesUsed: [],
      );
    }
    final json = Map<String, Object?>.from(raw);
    final reasons = json['reasons'];
    final engines = json['engines_used'];
    return RiskScore(
      score: json['score'] as int? ?? 0,
      verdict:
          _enumByName(RiskVerdict.values, json['verdict'] as String?) ??
          RiskVerdict.unknown,
      confidence:
          _enumByName(ThreatConfidence.values, json['confidence'] as String?) ??
          ThreatConfidence.low,
      reasons: reasons is List
          ? reasons.whereType<Map>().map((item) {
              final reason = Map<String, Object?>.from(item);
              return RiskReason(
                id: reason['id'] as String? ?? '',
                title: reason['title'] as String? ?? '',
                detail: reason['detail'] as String? ?? '',
                weight: reason['weight'] as int? ?? 0,
                severity:
                    _enumByName(
                      RiskSeverity.values,
                      reason['severity'] as String?,
                    ) ??
                    RiskSeverity.info,
                source:
                    _enumByName(
                      RiskReasonSource.values,
                      reason['source'] as String?,
                    ) ??
                    RiskReasonSource.heuristic,
              );
            }).toList()
          : const [],
      recommendedAction:
          _enumByName(
            RecommendedAction.values,
            json['recommended_action'] as String?,
          ) ??
          RecommendedAction.review,
      enginesUsed: engines is List
          ? engines
                .whereType<String>()
                .map(_engineToDetectionType)
                .where((engine) => engine != DetectionType.unknown)
                .toList()
          : const [],
    );
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

  AiModelInfo _aiModelInfoFromJson(Map<String, Object?> json) {
    return AiModelInfo(
      status:
          _enumByName(AiModelStatus.values, json['status'] as String?) ??
          AiModelStatus.modelMissing,
      modelVersion: json['model_version'] as String? ?? 'unavailable',
      featureSchemaVersion:
          json['feature_schema_version'] as String? ?? '1.0.0',
      productionReady: json['production_ready'] as bool? ?? false,
      message: json['message'] as String? ?? '',
    );
  }

  ScanStatus _scanStatus(String status) => switch (status) {
    'clean' => ScanStatus.clean,
    'threatsFound' => ScanStatus.infected,
    'completedWithErrors' => ScanStatus.completedWithErrors,
    'engineUnavailable' => ScanStatus.engineUnavailable,
    'cancelled' => ScanStatus.cancelled,
    'failed' => ScanStatus.failed,
    _ => ScanStatus.failed,
  };

  T? _enumByName<T extends Enum>(List<T> values, String? name) {
    if (name == null) return null;
    for (final value in values) {
      if (value.name == name) return value;
    }
    return null;
  }
}

class RealtimeWatcherState {
  const RealtimeWatcherState({
    required this.active,
    required this.mode,
    this.watchedPaths = const [],
    this.error,
  });

  factory RealtimeWatcherState.fromJson(Map<String, Object?> json) {
    final rawPaths = json['watched_paths'] ?? json['watchedPaths'];
    return RealtimeWatcherState(
      active: json['active'] as bool? ?? false,
      mode: json['mode']?.toString() ?? 'off',
      watchedPaths: rawPaths is List
          ? rawPaths.map((item) => item.toString()).toList()
          : const [],
      error: json['error']?.toString(),
    );
  }

  final bool active;
  final String mode;
  final List<String> watchedPaths;
  final String? error;
}

class LocalCoreHealth {
  const LocalCoreHealth({
    this.malwareEngineStatus = MalwareEngineStatus.unavailable,
    this.aiModelInfo = const AiModelInfo(),
    this.yaraStatus = 'rulesUnavailable',
    this.yaraRuleCount = 0,
    this.nativeEngineStatus = 'unavailable',
    this.nativeSignatureCount = 0,
    this.nativeRuleCount = 0,
    this.nativeMlStatus = 'modelMissing',
    this.nativeMlModelVersion,
    this.compatibilityEnginesEnabled = false,
    this.coreServiceStatus = 'unknown',
    this.guardStatus = 'off',
    this.driverStatus = 'missing',
    this.installPath,
    this.engineDirectory,
    this.enginePathsChecked = const [],
    this.programDataDirectory,
    this.lastError,
  });

  final MalwareEngineStatus malwareEngineStatus;
  final AiModelInfo aiModelInfo;
  final String yaraStatus;
  final int yaraRuleCount;
  final String nativeEngineStatus;
  final int nativeSignatureCount;
  final int nativeRuleCount;
  final String nativeMlStatus;
  final String? nativeMlModelVersion;
  final bool compatibilityEnginesEnabled;
  final String coreServiceStatus;
  final String guardStatus;
  final String driverStatus;
  final String? installPath;
  final String? engineDirectory;
  final List<String> enginePathsChecked;
  final String? programDataDirectory;
  final String? lastError;
}
