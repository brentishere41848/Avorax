import 'dart:async';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zentor_protocol/zentor_protocol.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/config/config_repository.dart';
import '../core/apps/app_detector.dart';
import '../core/files/file_selection_service.dart';
import '../core/local_core/local_core_client.dart';
import '../core/logging/local_event_repository.dart';
import '../core/network/api_result.dart';
import '../core/network/zentor_api_client.dart';
import '../core/platform/platform_info_service.dart';
import '../core/scanning/scan_target_service.dart';
import '../core/security/device_hash_service.dart';
import '../core/security/hash_service.dart';
import '../core/updates/update_service.dart';

final sharedPreferencesProvider = Provider<SharedPreferences>((ref) {
  throw StateError('SharedPreferences must be overridden at startup.');
});

final configRepositoryProvider = Provider<ConfigRepository>(
  (ref) => ConfigRepository(ref.watch(sharedPreferencesProvider)),
);

final localEventRepositoryProvider = Provider<LocalEventRepository>(
  (ref) => LocalEventRepository(ref.watch(sharedPreferencesProvider)),
);

final apiClientProvider = Provider<ZentorApiClient>((ref) => ZentorApiClient());
final hashServiceProvider = Provider<HashService>((ref) => HashService());
final appDetectorProvider = Provider<AppDetector>((ref) => AppDetector());
final fileSelectionServiceProvider = Provider<FileSelectionService>(
  (ref) => const FileSelectionService(),
);
final localCoreClientProvider = Provider<LocalCoreClient>(
  (ref) => const LocalCoreClient(),
);
final scanTargetServiceProvider = Provider<ScanTargetService>(
  (ref) => const ScanTargetService(),
);
final deviceHashServiceProvider = Provider<DeviceHashService>(
  (ref) => DeviceHashService(),
);
final platformInfoServiceProvider = Provider<PlatformInfoService>(
  (ref) => PlatformInfoService(ref.watch(deviceHashServiceProvider)),
);
final updateServiceProvider = Provider<ZentorUpdateService>(
  (ref) => ZentorUpdateService(),
);

const int _maxUiDiagnosticChars = 2048;

String _boundedUiDiagnostic(
  Object error, {
  String fallback = 'Operation failed.',
}) {
  final normalized = '$error'
      .replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ')
      .trim();
  if (normalized.isEmpty) return fallback;
  if (normalized.length <= _maxUiDiagnosticChars) return normalized;
  return '${normalized.substring(0, _maxUiDiagnosticChars - 3)}...';
}

String _boundedUpdateUiError(Object error) =>
    _boundedUiDiagnostic(error, fallback: 'Update operation failed.');

String _boundedQuarantinePath(String path) =>
    _boundedUiDiagnostic(path, fallback: 'quarantine path unavailable');

String _boundedExportPath(String path) =>
    _boundedUiDiagnostic(path, fallback: 'export path unavailable');

String _scanEventDetails(ScanReport report, {String? coverageWarning}) {
  final parts = <String>[
    'status=${report.status.label}',
    'kind=${report.kind.label}',
    'action=${report.actionMode.label}',
    'files=${report.filesScanned}',
    'threats=${report.threatsFound}',
    'suspicious=${report.suspiciousFound}',
    'quarantined=${report.quarantinedFiles}',
  ];
  final warning = coverageWarning ?? report.message;
  if (warning != null && warning.trim().isNotEmpty) {
    parts.add('message=${_boundedUiDiagnostic(warning)}');
  }
  final threatSummary = _threatEventSummary(report.threats);
  if (threatSummary.isNotEmpty) {
    parts.add(threatSummary);
  }
  final quarantineSummary = _quarantineThreatEventSummary(report.threats);
  if (quarantineSummary.isNotEmpty) {
    parts.add(quarantineSummary);
  }
  return _boundedUiDiagnostic(parts.join(' | '));
}

String _threatEventSummary(List<ThreatResult> threats) {
  if (threats.isEmpty) return '';
  final categories = <String, int>{};
  final verdicts = <String, int>{};
  final statuses = <String, int>{};
  for (final threat in threats) {
    categories.update(
      threat.threatCategory.label,
      (count) => count + 1,
      ifAbsent: () => 1,
    );
    verdicts.update(
      threat.riskScore.verdict.label,
      (count) => count + 1,
      ifAbsent: () => 1,
    );
    statuses.update(
      threat.status.label,
      (count) => count + 1,
      ifAbsent: () => 1,
    );
  }
  return [
    'categories=${_eventCountSummary(categories)}',
    'verdicts=${_eventCountSummary(verdicts)}',
    'statuses=${_eventCountSummary(statuses)}',
  ].join(' | ');
}

String _quarantineThreatEventSummary(List<ThreatResult> threats) {
  final records = threats
      .where((threat) => threat.status == ThreatResultStatus.quarantined)
      .map((threat) {
        final id = threat.quarantineId?.trim();
        final action = threat.quarantineActionTaken?.trim();
        if (id == null || id.isEmpty) return '';
        if (action == null || action.isEmpty) return id;
        return '$id:$action';
      })
      .where((value) => value.isNotEmpty)
      .take(5)
      .join(', ');
  return records.isEmpty ? '' : 'quarantineRecords=$records';
}

String _quarantinedThreatEventDetails(ThreatResult threat) {
  final parts = <String>[threat.path];
  final id = threat.quarantineId?.trim();
  final quarantinePath = threat.quarantinePath?.trim();
  final action = threat.quarantineActionTaken?.trim();
  if (id != null && id.isNotEmpty) {
    parts.add('quarantine_id=$id');
  }
  if (quarantinePath != null && quarantinePath.isNotEmpty) {
    parts.add('quarantine_path=${_boundedQuarantinePath(quarantinePath)}');
  }
  if (action != null && action.isNotEmpty) {
    parts.add('quarantine_action=$action');
  }
  return _boundedUiDiagnostic(parts.join('\n'));
}

String _eventCountSummary(Map<String, int> counts) {
  final entries = counts.entries.toList()
    ..sort((a, b) {
      final countOrder = b.value.compareTo(a.value);
      if (countOrder != 0) return countOrder;
      return a.key.compareTo(b.key);
    });
  return entries
      .take(5)
      .map(
        (entry) =>
            entry.value == 1 ? entry.key : '${entry.key} x${entry.value}',
      )
      .join(', ');
}

final _runtimePathListControlPattern = RegExp(r'[\x00-\x1F\x7F]');

typedef ScheduledQuickScanTimerFactory =
    Timer Function(Duration duration, void Function(Timer timer) callback);

typedef ProcessSnapshotTimerFactory =
    Timer Function(Duration duration, void Function(Timer timer) callback);

typedef WatchPollTimerFactory =
    Timer Function(Duration duration, void Function(Timer timer) callback);

typedef FileSystemTypeProbe =
    FileSystemEntityType Function(String path, {bool followLinks});

const Duration _processSnapshotLoopInterval = Duration(minutes: 2);
const Duration _watchPollLoopInterval = Duration(minutes: 1);
const Duration _watchPollScanDuration = Duration(seconds: 4);
const Duration _watchPollScanPollInterval = Duration(milliseconds: 200);
const int _watchPollScanMaxEvents = 8;

Timer _defaultScheduledQuickScanTimerFactory(
  Duration duration,
  void Function(Timer timer) callback,
) => Timer.periodic(duration, callback);

Timer _defaultProcessSnapshotTimerFactory(
  Duration duration,
  void Function(Timer timer) callback,
) => Timer.periodic(duration, callback);

Timer _defaultWatchPollTimerFactory(
  Duration duration,
  void Function(Timer timer) callback,
) => Timer.periodic(duration, callback);

FileSystemEntityType _defaultFileSystemTypeProbe(
  String path, {
  bool followLinks = true,
}) => FileSystemEntity.typeSync(path, followLinks: followLinks);

final scheduledQuickScanTimerFactoryProvider =
    Provider<ScheduledQuickScanTimerFactory>(
      (ref) => _defaultScheduledQuickScanTimerFactory,
    );

final processSnapshotTimerFactoryProvider =
    Provider<ProcessSnapshotTimerFactory>(
      (ref) => _defaultProcessSnapshotTimerFactory,
    );

final watchPollTimerFactoryProvider = Provider<WatchPollTimerFactory>(
  (ref) => _defaultWatchPollTimerFactory,
);

final zentorControllerProvider =
    StateNotifierProvider<ZentorController, ZentorState>((ref) {
      return ZentorController(
        configRepository: ref.watch(configRepositoryProvider),
        eventRepository: ref.watch(localEventRepositoryProvider),
        apiClient: ref.watch(apiClientProvider),
        hashService: ref.watch(hashServiceProvider),
        appDetector: ref.watch(appDetectorProvider),
        fileSelectionService: ref.watch(fileSelectionServiceProvider),
        localCoreClient: ref.watch(localCoreClientProvider),
        scanTargetService: ref.watch(scanTargetServiceProvider),
        updateService: ref.watch(updateServiceProvider),
        scheduledQuickScanTimerFactory: ref.watch(
          scheduledQuickScanTimerFactoryProvider,
        ),
        processSnapshotTimerFactory: ref.watch(
          processSnapshotTimerFactoryProvider,
        ),
        watchPollTimerFactory: ref.watch(watchPollTimerFactoryProvider),
      )..load();
    });

final deviceSummaryProvider = FutureProvider<DeviceIntegritySummary>((ref) {
  return ref.watch(platformInfoServiceProvider).load();
});

class ZentorState {
  const ZentorState({
    this.config = const ZentorConfig(),
    this.cloudStatus = CloudStatus.disabled,
    this.protectionStatus = ProtectionStatus.idle,
    this.appDetectionStatus = AppDetectionStatus.idle,
    this.appVerificationStatus = AppVerificationStatus.notConfigured,
    this.malwareEngineStatus = MalwareEngineStatus.checking,
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
    this.coreServiceBoundaryHealth = const CoreServiceBoundaryHealth(),
    this.guardStatus = 'unknown',
    this.guardStatusError,
    this.driverStatus = 'unknown',
    this.processMonitorStatus = 'unknown',
    this.processMonitorCapability = 'unknown',
    this.processMonitorStatusReason,
    this.behaviorMonitorStatus = 'unknown',
    this.behaviorMonitorStatusReason,
    this.processSnapshotLoopStatus = 'off',
    this.processSnapshotLoopStatusReason,
    this.watchPollLoopStatus = 'off',
    this.watchPollLoopStatusReason,
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
    this.lastEngineError,
    this.realtimeWatcherMode = 'off',
    this.realtimeWatchedPaths = const [],
    this.realtimeWatcherLimitations = const [],
    this.scanStatus = ScanStatus.idle,
    this.scanActionMode = ScanActionMode.detectOnly,
    this.scanProgress,
    this.lastScanReport,
    this.protectionRun,
    this.heartbeat = const HeartbeatStatus(),
    this.events = const [],
    this.detectedApps = const [],
    this.quarantine = const [],
    this.allowlist = const [],
    this.loading = false,
    this.onboardingCompletionInFlight = false,
    this.protectionOperationInFlight = false,
    this.quarantineActionInFlight = false,
    this.quarantineRefreshInFlight = false,
    this.allowlistActionInFlight = false,
    this.allowlistRefreshInFlight = false,
    this.appDetectionInFlight = false,
    this.malwareEngineHealthCheckInFlight = false,
    this.cloudHealthCheckInFlight = false,
    this.securitySettingsActionInFlight = false,
    this.protectionSelfTestInFlight = false,
    this.serviceActionInFlight = false,
    this.detectionFeedbackInFlight = false,
    this.threatIgnoreActionInFlight = false,
    this.configurationResetInFlight = false,
    this.developerCloudOverrideInFlight = false,
    this.logExportInFlight = false,
    this.supportBundleExportInFlight = false,
    this.protectedAppActionInFlight = false,
    this.scanStartInFlight = false,
    this.scanTargetSelectionInFlight = false,
    this.scanCancelInFlight = false,
    this.updateOperationInFlight = false,
    this.errorMessage,
    this.hashProgress,
    this.currentScanPath,
    this.protectionSelfTestResult,
    this.updateStatus = UpdateStatus.notChecked,
    this.currentAppVersion = 'Unknown',
    this.updatePackageMutationSupported = true,
    this.updateInfo,
    this.updateError,
  });

  final ZentorConfig config;
  final CloudStatus cloudStatus;
  final ProtectionStatus protectionStatus;
  final AppDetectionStatus appDetectionStatus;
  final AppVerificationStatus appVerificationStatus;
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
  final CoreServiceBoundaryHealth coreServiceBoundaryHealth;
  final String guardStatus;
  final String? guardStatusError;
  final String driverStatus;
  final String processMonitorStatus;
  final String processMonitorCapability;
  final String? processMonitorStatusReason;
  final String behaviorMonitorStatus;
  final String? behaviorMonitorStatusReason;
  final String processSnapshotLoopStatus;
  final String? processSnapshotLoopStatusReason;
  final String watchPollLoopStatus;
  final String? watchPollLoopStatusReason;
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
  final String? lastEngineError;
  final String realtimeWatcherMode;
  final List<String> realtimeWatchedPaths;
  final List<String> realtimeWatcherLimitations;
  final ScanStatus scanStatus;
  final ScanActionMode scanActionMode;
  final ScanProgress? scanProgress;
  final ScanReport? lastScanReport;
  final ProtectionRun? protectionRun;
  final HeartbeatStatus heartbeat;
  final List<LocalEvent> events;
  final List<DetectedApp> detectedApps;
  final List<QuarantineRecord> quarantine;
  final List<AllowlistEntry> allowlist;
  final bool loading;
  final bool onboardingCompletionInFlight;
  final bool protectionOperationInFlight;
  final bool quarantineActionInFlight;
  final bool quarantineRefreshInFlight;
  final bool allowlistActionInFlight;
  final bool allowlistRefreshInFlight;
  final bool appDetectionInFlight;
  final bool malwareEngineHealthCheckInFlight;
  final bool cloudHealthCheckInFlight;
  final bool securitySettingsActionInFlight;
  final bool protectionSelfTestInFlight;
  final bool serviceActionInFlight;
  final bool detectionFeedbackInFlight;
  final bool threatIgnoreActionInFlight;
  final bool configurationResetInFlight;
  final bool developerCloudOverrideInFlight;
  final bool logExportInFlight;
  final bool supportBundleExportInFlight;
  final bool protectedAppActionInFlight;
  final bool scanStartInFlight;
  final bool scanTargetSelectionInFlight;
  final bool scanCancelInFlight;
  final bool updateOperationInFlight;
  final String? errorMessage;
  final double? hashProgress;
  final String? currentScanPath;
  final String? protectionSelfTestResult;
  final UpdateStatus updateStatus;
  final String currentAppVersion;
  final bool updatePackageMutationSupported;
  final UpdateInfo? updateInfo;
  final String? updateError;

  ZentorState copyWith({
    ZentorConfig? config,
    CloudStatus? cloudStatus,
    ProtectionStatus? protectionStatus,
    AppDetectionStatus? appDetectionStatus,
    AppVerificationStatus? appVerificationStatus,
    MalwareEngineStatus? malwareEngineStatus,
    AiModelStatus? aiStatus,
    AiModelInfo? aiModelInfo,
    String? yaraStatus,
    int? yaraRuleCount,
    String? nativeEngineStatus,
    int? nativeSignatureCount,
    int? nativeRuleCount,
    String? nativeMlStatus,
    String? nativeMlModelVersion,
    bool clearNativeMlModelVersion = false,
    bool? nativeMlProductionReady,
    String? nativeEngineError,
    bool clearNativeEngineError = false,
    bool? nativeSelfTestPassed,
    bool clearNativeSelfTestPassed = false,
    String? nativeSelfTestError,
    bool clearNativeSelfTestError = false,
    bool? aiSelfTestPassed,
    bool clearAiSelfTestPassed = false,
    String? aiSelfTestError,
    bool clearAiSelfTestError = false,
    String? ipcMode,
    bool? networkExposed,
    bool clearNetworkExposed = false,
    bool? compatibilityEnginesEnabled,
    String? coreServiceStatus,
    String? coreServiceStatusError,
    bool clearCoreServiceStatusError = false,
    CoreServiceBoundaryHealth? coreServiceBoundaryHealth,
    String? guardStatus,
    String? guardStatusError,
    bool clearGuardStatusError = false,
    String? driverStatus,
    String? processMonitorStatus,
    String? processMonitorCapability,
    String? processMonitorStatusReason,
    bool clearProcessMonitorStatusReason = false,
    String? behaviorMonitorStatus,
    String? behaviorMonitorStatusReason,
    bool clearBehaviorMonitorStatusReason = false,
    String? processSnapshotLoopStatus,
    String? processSnapshotLoopStatusReason,
    String? watchPollLoopStatus,
    String? watchPollLoopStatusReason,
    String? reputationStatus,
    String? reputationStatusReason,
    bool clearReputationStatusReason = false,
    String? installPath,
    bool clearInstallPath = false,
    String? engineDirectory,
    bool clearEngineDirectory = false,
    String? nativeSignaturesDirectory,
    String? nativeRulesDirectory,
    String? nativeMlDirectory,
    String? nativeTrustDirectory,
    String? nativeConfigDirectory,
    bool clearNativeSignaturesDirectory = false,
    bool clearNativeRulesDirectory = false,
    bool clearNativeMlDirectory = false,
    bool clearNativeTrustDirectory = false,
    bool clearNativeConfigDirectory = false,
    List<String>? enginePathsChecked,
    String? programDataDirectory,
    bool clearProgramDataDirectory = false,
    String? programDataDirectoryError,
    bool clearProgramDataDirectoryError = false,
    String? lastEngineError,
    bool clearLastEngineError = false,
    String? realtimeWatcherMode,
    List<String>? realtimeWatchedPaths,
    List<String>? realtimeWatcherLimitations,
    ScanStatus? scanStatus,
    ScanActionMode? scanActionMode,
    ScanProgress? scanProgress,
    bool clearScanProgress = false,
    ScanReport? lastScanReport,
    bool clearLastScanReport = false,
    ProtectionRun? protectionRun,
    bool clearProtectionRun = false,
    HeartbeatStatus? heartbeat,
    List<LocalEvent>? events,
    List<DetectedApp>? detectedApps,
    List<QuarantineRecord>? quarantine,
    List<AllowlistEntry>? allowlist,
    bool? loading,
    bool? onboardingCompletionInFlight,
    bool? protectionOperationInFlight,
    bool? quarantineActionInFlight,
    bool? quarantineRefreshInFlight,
    bool? allowlistActionInFlight,
    bool? allowlistRefreshInFlight,
    bool? appDetectionInFlight,
    bool? malwareEngineHealthCheckInFlight,
    bool? cloudHealthCheckInFlight,
    bool? securitySettingsActionInFlight,
    bool? protectionSelfTestInFlight,
    bool? serviceActionInFlight,
    bool? detectionFeedbackInFlight,
    bool? threatIgnoreActionInFlight,
    bool? configurationResetInFlight,
    bool? developerCloudOverrideInFlight,
    bool? logExportInFlight,
    bool? supportBundleExportInFlight,
    bool? protectedAppActionInFlight,
    bool? scanStartInFlight,
    bool? scanTargetSelectionInFlight,
    bool? scanCancelInFlight,
    bool? updateOperationInFlight,
    String? errorMessage,
    bool clearError = false,
    double? hashProgress,
    bool clearHashProgress = false,
    String? currentScanPath,
    bool clearCurrentScanPath = false,
    String? protectionSelfTestResult,
    bool clearProtectionSelfTestResult = false,
    UpdateStatus? updateStatus,
    String? currentAppVersion,
    bool? updatePackageMutationSupported,
    UpdateInfo? updateInfo,
    bool clearUpdateInfo = false,
    String? updateError,
    bool clearUpdateError = false,
  }) {
    return ZentorState(
      config: config ?? this.config,
      cloudStatus: cloudStatus ?? this.cloudStatus,
      protectionStatus: protectionStatus ?? this.protectionStatus,
      appDetectionStatus: appDetectionStatus ?? this.appDetectionStatus,
      appVerificationStatus:
          appVerificationStatus ?? this.appVerificationStatus,
      malwareEngineStatus: malwareEngineStatus ?? this.malwareEngineStatus,
      aiStatus: aiStatus ?? this.aiStatus,
      aiModelInfo: aiModelInfo ?? this.aiModelInfo,
      yaraStatus: yaraStatus ?? this.yaraStatus,
      yaraRuleCount: yaraRuleCount ?? this.yaraRuleCount,
      nativeEngineStatus: nativeEngineStatus ?? this.nativeEngineStatus,
      nativeSignatureCount: nativeSignatureCount ?? this.nativeSignatureCount,
      nativeRuleCount: nativeRuleCount ?? this.nativeRuleCount,
      nativeMlStatus: nativeMlStatus ?? this.nativeMlStatus,
      nativeMlModelVersion: clearNativeMlModelVersion
          ? null
          : nativeMlModelVersion ?? this.nativeMlModelVersion,
      nativeMlProductionReady:
          nativeMlProductionReady ?? this.nativeMlProductionReady,
      nativeEngineError: clearNativeEngineError
          ? null
          : nativeEngineError ?? this.nativeEngineError,
      nativeSelfTestPassed: clearNativeSelfTestPassed
          ? null
          : nativeSelfTestPassed ?? this.nativeSelfTestPassed,
      nativeSelfTestError: clearNativeSelfTestError
          ? null
          : nativeSelfTestError ?? this.nativeSelfTestError,
      aiSelfTestPassed: clearAiSelfTestPassed
          ? null
          : aiSelfTestPassed ?? this.aiSelfTestPassed,
      aiSelfTestError: clearAiSelfTestError
          ? null
          : aiSelfTestError ?? this.aiSelfTestError,
      ipcMode: ipcMode ?? this.ipcMode,
      networkExposed: clearNetworkExposed
          ? null
          : networkExposed ?? this.networkExposed,
      compatibilityEnginesEnabled:
          compatibilityEnginesEnabled ?? this.compatibilityEnginesEnabled,
      coreServiceStatus: coreServiceStatus ?? this.coreServiceStatus,
      coreServiceStatusError: clearCoreServiceStatusError
          ? null
          : coreServiceStatusError ?? this.coreServiceStatusError,
      coreServiceBoundaryHealth:
          coreServiceBoundaryHealth ?? this.coreServiceBoundaryHealth,
      guardStatus: guardStatus ?? this.guardStatus,
      guardStatusError: clearGuardStatusError
          ? null
          : guardStatusError ?? this.guardStatusError,
      driverStatus: driverStatus ?? this.driverStatus,
      processMonitorStatus: processMonitorStatus ?? this.processMonitorStatus,
      processMonitorCapability:
          processMonitorCapability ?? this.processMonitorCapability,
      processMonitorStatusReason: clearProcessMonitorStatusReason
          ? null
          : processMonitorStatusReason ?? this.processMonitorStatusReason,
      behaviorMonitorStatus:
          behaviorMonitorStatus ?? this.behaviorMonitorStatus,
      behaviorMonitorStatusReason: clearBehaviorMonitorStatusReason
          ? null
          : behaviorMonitorStatusReason ?? this.behaviorMonitorStatusReason,
      processSnapshotLoopStatus:
          processSnapshotLoopStatus ?? this.processSnapshotLoopStatus,
      processSnapshotLoopStatusReason:
          processSnapshotLoopStatusReason ??
          this.processSnapshotLoopStatusReason,
      watchPollLoopStatus: watchPollLoopStatus ?? this.watchPollLoopStatus,
      watchPollLoopStatusReason:
          watchPollLoopStatusReason ?? this.watchPollLoopStatusReason,
      reputationStatus: reputationStatus ?? this.reputationStatus,
      reputationStatusReason: clearReputationStatusReason
          ? null
          : reputationStatusReason ?? this.reputationStatusReason,
      installPath: clearInstallPath ? null : installPath ?? this.installPath,
      engineDirectory: clearEngineDirectory
          ? null
          : engineDirectory ?? this.engineDirectory,
      nativeSignaturesDirectory: clearNativeSignaturesDirectory
          ? null
          : nativeSignaturesDirectory ?? this.nativeSignaturesDirectory,
      nativeRulesDirectory: clearNativeRulesDirectory
          ? null
          : nativeRulesDirectory ?? this.nativeRulesDirectory,
      nativeMlDirectory: clearNativeMlDirectory
          ? null
          : nativeMlDirectory ?? this.nativeMlDirectory,
      nativeTrustDirectory: clearNativeTrustDirectory
          ? null
          : nativeTrustDirectory ?? this.nativeTrustDirectory,
      nativeConfigDirectory: clearNativeConfigDirectory
          ? null
          : nativeConfigDirectory ?? this.nativeConfigDirectory,
      enginePathsChecked: enginePathsChecked ?? this.enginePathsChecked,
      programDataDirectory: clearProgramDataDirectory
          ? null
          : programDataDirectory ?? this.programDataDirectory,
      programDataDirectoryError: clearProgramDataDirectoryError
          ? null
          : programDataDirectoryError ?? this.programDataDirectoryError,
      lastEngineError: clearLastEngineError
          ? null
          : lastEngineError ?? this.lastEngineError,
      realtimeWatcherMode: realtimeWatcherMode ?? this.realtimeWatcherMode,
      realtimeWatchedPaths: realtimeWatchedPaths ?? this.realtimeWatchedPaths,
      realtimeWatcherLimitations:
          realtimeWatcherLimitations ?? this.realtimeWatcherLimitations,
      scanStatus: scanStatus ?? this.scanStatus,
      scanActionMode: scanActionMode ?? this.scanActionMode,
      scanProgress: clearScanProgress
          ? null
          : scanProgress ?? this.scanProgress,
      lastScanReport: clearLastScanReport
          ? null
          : lastScanReport ?? this.lastScanReport,
      protectionRun: clearProtectionRun
          ? null
          : protectionRun ?? this.protectionRun,
      heartbeat: heartbeat ?? this.heartbeat,
      events: events ?? this.events,
      detectedApps: detectedApps ?? this.detectedApps,
      quarantine: quarantine ?? this.quarantine,
      allowlist: allowlist ?? this.allowlist,
      loading: loading ?? this.loading,
      onboardingCompletionInFlight:
          onboardingCompletionInFlight ?? this.onboardingCompletionInFlight,
      protectionOperationInFlight:
          protectionOperationInFlight ?? this.protectionOperationInFlight,
      quarantineActionInFlight:
          quarantineActionInFlight ?? this.quarantineActionInFlight,
      quarantineRefreshInFlight:
          quarantineRefreshInFlight ?? this.quarantineRefreshInFlight,
      allowlistActionInFlight:
          allowlistActionInFlight ?? this.allowlistActionInFlight,
      allowlistRefreshInFlight:
          allowlistRefreshInFlight ?? this.allowlistRefreshInFlight,
      appDetectionInFlight: appDetectionInFlight ?? this.appDetectionInFlight,
      malwareEngineHealthCheckInFlight:
          malwareEngineHealthCheckInFlight ??
          this.malwareEngineHealthCheckInFlight,
      cloudHealthCheckInFlight:
          cloudHealthCheckInFlight ?? this.cloudHealthCheckInFlight,
      securitySettingsActionInFlight:
          securitySettingsActionInFlight ?? this.securitySettingsActionInFlight,
      protectionSelfTestInFlight:
          protectionSelfTestInFlight ?? this.protectionSelfTestInFlight,
      serviceActionInFlight:
          serviceActionInFlight ?? this.serviceActionInFlight,
      detectionFeedbackInFlight:
          detectionFeedbackInFlight ?? this.detectionFeedbackInFlight,
      threatIgnoreActionInFlight:
          threatIgnoreActionInFlight ?? this.threatIgnoreActionInFlight,
      configurationResetInFlight:
          configurationResetInFlight ?? this.configurationResetInFlight,
      developerCloudOverrideInFlight:
          developerCloudOverrideInFlight ?? this.developerCloudOverrideInFlight,
      logExportInFlight: logExportInFlight ?? this.logExportInFlight,
      supportBundleExportInFlight:
          supportBundleExportInFlight ?? this.supportBundleExportInFlight,
      protectedAppActionInFlight:
          protectedAppActionInFlight ?? this.protectedAppActionInFlight,
      scanStartInFlight: scanStartInFlight ?? this.scanStartInFlight,
      scanTargetSelectionInFlight:
          scanTargetSelectionInFlight ?? this.scanTargetSelectionInFlight,
      scanCancelInFlight: scanCancelInFlight ?? this.scanCancelInFlight,
      updateOperationInFlight:
          updateOperationInFlight ?? this.updateOperationInFlight,
      errorMessage: clearError ? null : errorMessage ?? this.errorMessage,
      hashProgress: clearHashProgress
          ? null
          : hashProgress ?? this.hashProgress,
      currentScanPath: clearCurrentScanPath
          ? null
          : currentScanPath ?? this.currentScanPath,
      protectionSelfTestResult: clearProtectionSelfTestResult
          ? null
          : protectionSelfTestResult ?? this.protectionSelfTestResult,
      updateStatus: updateStatus ?? this.updateStatus,
      currentAppVersion: currentAppVersion ?? this.currentAppVersion,
      updatePackageMutationSupported:
          updatePackageMutationSupported ?? this.updatePackageMutationSupported,
      updateInfo: clearUpdateInfo ? null : updateInfo ?? this.updateInfo,
      updateError: clearUpdateError ? null : updateError ?? this.updateError,
    );
  }
}

class ZentorController extends StateNotifier<ZentorState> {
  ZentorController({
    required ConfigRepository configRepository,
    required LocalEventRepository eventRepository,
    required ZentorApiClient apiClient,
    required HashService hashService,
    required AppDetector appDetector,
    FileSelectionService fileSelectionService = const FileSelectionService(),
    required LocalCoreClient localCoreClient,
    required ScanTargetService scanTargetService,
    required ZentorUpdateService updateService,
    ScheduledQuickScanTimerFactory scheduledQuickScanTimerFactory =
        _defaultScheduledQuickScanTimerFactory,
    ProcessSnapshotTimerFactory processSnapshotTimerFactory =
        _defaultProcessSnapshotTimerFactory,
    WatchPollTimerFactory watchPollTimerFactory = _defaultWatchPollTimerFactory,
    FileSystemTypeProbe fileSystemTypeProbe = _defaultFileSystemTypeProbe,
  }) : this._(
         configRepository,
         eventRepository,
         apiClient,
         hashService,
         appDetector,
         fileSelectionService,
         localCoreClient,
         scanTargetService,
         updateService,
         scheduledQuickScanTimerFactory,
         processSnapshotTimerFactory,
         watchPollTimerFactory,
         fileSystemTypeProbe,
       );

  ZentorController._(
    this._configRepository,
    this._eventRepository,
    this._apiClient,
    this._hashService,
    this._appDetector,
    this._fileSelectionService,
    this._localCoreClient,
    this._scanTargetService,
    ZentorUpdateService updateService,
    this._scheduledQuickScanTimerFactory,
    this._processSnapshotTimerFactory,
    this._watchPollTimerFactory,
    this._fileSystemTypeProbe,
  ) : _updateService = updateService,
      super(
        ZentorState(
          updatePackageMutationSupported:
              updateService.packageMutationSupported,
        ),
      );

  final ConfigRepository _configRepository;
  final LocalEventRepository _eventRepository;
  final ZentorApiClient _apiClient;
  final HashService _hashService;
  final AppDetector _appDetector;
  final FileSelectionService _fileSelectionService;
  final LocalCoreClient _localCoreClient;
  final ScanTargetService _scanTargetService;
  final ZentorUpdateService _updateService;
  final ScheduledQuickScanTimerFactory _scheduledQuickScanTimerFactory;
  final ProcessSnapshotTimerFactory _processSnapshotTimerFactory;
  final WatchPollTimerFactory _watchPollTimerFactory;
  final FileSystemTypeProbe _fileSystemTypeProbe;
  bool _updateOperationInFlight = false;
  bool _scanCancelled = false;
  bool _onboardingCompletionInFlight = false;
  bool _cloudHealthCheckInFlight = false;
  bool _appDetectionInFlight = false;
  bool _logExportInFlight = false;
  bool _supportBundleExportInFlight = false;
  bool _developerCloudOverrideInFlight = false;
  bool _configurationResetInFlight = false;
  bool _protectionOperationInFlight = false;
  bool _protectionSelfTestInFlight = false;
  bool _securitySettingsActionInFlight = false;
  bool _serviceActionInFlight = false;
  bool _protectedAppActionInFlight = false;
  bool _quarantineActionInFlight = false;
  bool _allowlistActionInFlight = false;
  bool _detectionFeedbackInFlight = false;
  bool _threatIgnoreActionInFlight = false;
  bool _scanStartInFlight = false;
  bool _scanTargetSelectionInFlight = false;
  bool _scanCancelInFlight = false;
  bool _malwareEngineHealthCheckInFlight = false;
  bool _quarantineRefreshInFlight = false;
  bool _quarantineRefreshPending = false;
  bool _allowlistRefreshInFlight = false;
  bool _allowlistRefreshPending = false;
  bool _processSnapshotEvaluationInFlight = false;
  bool _watchPollEvaluationInFlight = false;
  String? _lastProcessSnapshotLoopRoutineEventKey;
  String? _lastWatchPollLoopRoutineEventKey;
  Timer? _scheduledQuickScanTimer;
  Timer? _processSnapshotTimer;
  Timer? _watchPollTimer;
  List<String> _watchPollPaths = const [];

  void load() {
    final config = _configRepository.load();
    final configRecoveryReason = _configRepository.lastLoadRecoveryReason;
    state = state.copyWith(
      config: config,
      events: _eventRepository.load(),
      cloudStatus: CloudStatus.disabled,
      protectionStatus: config.realtimeProtectionEnabled
          ? ProtectionStatus.starting
          : ProtectionStatus.idle,
      appVerificationStatus: _verificationStatusFor(config.protectedAppConfig),
      errorMessage: configRecoveryReason,
    );
    logEvent('app_started', 'App started', category: 'app', severity: 'info');
    if (configRecoveryReason != null) {
      logEvent(
        'configuration_recovered',
        'Configuration recovered from invalid persisted data',
        details: configRecoveryReason,
        category: 'app',
        severity: 'warning',
      );
    }
    logEvent(
      'local_scanner_initialized',
      'Local scanner initialized',
      category: 'app',
      severity: 'info',
    );
    _runStartupTask('app_detection', 'App detection', unawaitedDetectApps);
    _runStartupTask(
      'malware_engine_health',
      'Malware engine health check',
      unawaitedCheckMalwareEngine,
    );
    _runStartupTask(
      'quarantine_refresh',
      'Quarantine refresh',
      unawaitedRefreshQuarantine,
    );
    _runStartupTask(
      'update_check',
      'Update check',
      () => unawaitedCheckForUpdates(silent: true),
    );
    _configureScheduledQuickScanAtStartup(config);
    if (config.realtimeProtectionEnabled) {
      _runStartupTask(
        'protection_restore',
        'Saved protection restore',
        _restoreProtectionAfterStartup,
      );
    }
  }

  void _configureScheduledQuickScanAtStartup(ZentorConfig config) {
    try {
      _configureScheduledQuickScan(config);
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      logEvent(
        'scheduled_quick_scan_startup_failed',
        'Scheduled quick scan startup failed',
        details: details,
        category: 'scan',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Scheduled quick scan startup failed: $details',
      );
    }
  }

  void _runStartupTask(
    String type,
    String label,
    Future<void> Function() task,
  ) {
    unawaited(
      task().catchError((Object error) async {
        if (!mounted) return;
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          '${type}_startup_failed',
          '$label startup task failed',
          details: details,
          category: 'app',
          severity: 'error',
        );
        if (!mounted) return;
        state = state.copyWith(
          errorMessage: '$label startup task failed: $details',
        );
      }),
    );
  }

  @override
  void dispose() {
    _scheduledQuickScanTimer?.cancel();
    _stopWatchPollLoop();
    _stopProcessSnapshotLoop();
    super.dispose();
  }

  Future<void> _restoreProtectionAfterStartup() async {
    await logEvent(
      'protection_restore_requested',
      'Restoring saved protection state',
      category: 'protection',
      severity: 'warning',
    );
    await startProtection(
      persistPreference: false,
      confirmed: true,
      restoringSavedPreference: true,
    );
  }

  Future<void> logEvent(
    String type,
    String message, {
    String? details,
    String category = 'app',
    String severity = 'info',
  }) async {
    try {
      await _eventRepository.add(
        type,
        message,
        details: details,
        category: category,
        severity: severity,
      );
      if (!mounted) return;
      state = state.copyWith(events: _eventRepository.load());
    } on Object catch (error) {
      if (!mounted) return;
      final details = _boundedUiDiagnostic(error);
      state = state.copyWith(
        errorMessage: 'Unable to record local event: $details',
      );
    }
  }

  Future<bool> completeOnboarding() async {
    if (_onboardingCompletionInFlight) {
      const message = 'Onboarding completion is already in progress.';
      await logEvent(
        'onboarding_completion_busy',
        'Onboarding completion already in progress',
        details: message,
        category: 'app',
        severity: 'warning',
      );
      state = state.copyWith(
        onboardingCompletionInFlight:
            _onboardingCompletionInFlight || state.onboardingCompletionInFlight,
        errorMessage: message,
      );
      return false;
    }
    _onboardingCompletionInFlight = true;
    state = state.copyWith(onboardingCompletionInFlight: true);
    try {
      final updated = state.config.copyWith(onboardingComplete: true);
      await _configRepository.save(updated);
      state = state.copyWith(config: updated, clearError: true);
      return true;
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'onboarding_save_failed',
        'Onboarding completion save failed',
        details: details,
        category: 'app',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Unable to save onboarding status: $details',
      );
      return false;
    } finally {
      _onboardingCompletionInFlight = false;
      if (mounted) {
        state = state.copyWith(onboardingCompletionInFlight: false);
      }
    }
  }

  Future<void> unawaitedCheckCloud() async {
    if (_cloudHealthCheckInFlight) {
      const message = 'Cloud health check is already in progress.';
      await logEvent(
        'cloud_health_check_ignored',
        'Cloud health check ignored',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      if (!mounted) return;
      state = state.copyWith(
        cloudHealthCheckInFlight:
            _cloudHealthCheckInFlight || state.cloudHealthCheckInFlight,
        errorMessage: message,
      );
      return;
    }
    _cloudHealthCheckInFlight = true;
    try {
      if (!mounted) return;
      state = state.copyWith(cloudHealthCheckInFlight: true);
      await logEvent(
        'cloud_health_check_started',
        'Cloud health check started',
        category: 'settings',
        severity: 'info',
      );
      if (!mounted) return;
      state = state.copyWith(
        cloudStatus: CloudStatus.checking,
        clearError: true,
      );
      final result = await _apiClient.healthCheck(state.config);
      if (!mounted) return;
      switch (result) {
        case ApiSuccess<void>():
          await logEvent(
            'cloud_online',
            'Cloud online',
            category: 'settings',
            severity: 'info',
          );
          state = state.copyWith(cloudStatus: CloudStatus.online);
        case ApiFailure<void>(:final message):
          await logEvent(
            'cloud_offline',
            'Cloud offline',
            details: message,
            category: 'settings',
            severity: 'warning',
          );
          state = state.copyWith(cloudStatus: CloudStatus.offline);
      }
    } on Object catch (error) {
      if (!mounted) return;
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'cloud_offline',
        'Cloud offline',
        details: details,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        cloudStatus: CloudStatus.offline,
        errorMessage: 'Unable to check Avorax Cloud: $details',
      );
    } finally {
      _cloudHealthCheckInFlight = false;
      if (mounted) {
        state = state.copyWith(cloudHealthCheckInFlight: false);
      }
    }
  }

  Future<void> testCloudConnection() => unawaitedCheckCloud();

  Future<void> unawaitedCheckForUpdates({bool silent = false}) async {
    if (!mounted) return;
    if (_updateOperationInFlight ||
        _isUpdateOperationBusy(state.updateStatus)) {
      if (!silent) {
        final message = _updateBusyMessage();
        state = state.copyWith(
          updateOperationInFlight:
              _updateOperationInFlight || state.updateOperationInFlight,
          errorMessage: message,
          updateError: message,
        );
        await logEvent(
          'update_action_busy',
          'Update action already in progress',
          details: message,
          category: 'update',
          severity: 'warning',
        );
      }
      return;
    }
    _updateOperationInFlight = true;
    state = state.copyWith(updateOperationInFlight: true);
    try {
      if (!silent) {
        await logEvent(
          'update_check_started',
          'Update check started',
          category: 'update',
          severity: 'info',
        );
      }
      state = state.copyWith(
        updateStatus: UpdateStatus.checking,
        clearUpdateError: true,
      );
      final UpdateCheckResult result;
      try {
        result = await _updateService.checkForUpdate();
      } catch (error) {
        if (!mounted) return;
        final details = _boundedUpdateUiError(error);
        state = state.copyWith(
          updateStatus: UpdateStatus.failed,
          errorMessage: 'Avorax could not check for updates: $details',
          updateError: details,
        );
        await logEvent(
          'update_check_failed',
          'Update check failed',
          details: details,
          category: 'update',
          severity: 'error',
        );
        return;
      }
      if (!mounted) return;
      state = state.copyWith(
        updateStatus: result.status,
        currentAppVersion: result.currentVersion,
        updateInfo: result.update,
        clearUpdateInfo: result.update == null,
        updateError: result.error,
        clearUpdateError: result.error == null,
      );
      if (result.status == UpdateStatus.updateAvailable &&
          result.update != null) {
        await logEvent(
          'update_available',
          'Update available',
          details: 'Avorax ${result.update!.latestVersion}',
          category: 'update',
          severity: 'warning',
        );
      } else if (!silent && result.status == UpdateStatus.upToDate) {
        await logEvent(
          'update_check_completed',
          'Avorax is up to date',
          category: 'update',
          severity: 'info',
        );
      } else if (result.status == UpdateStatus.failed) {
        await logEvent(
          'update_check_failed',
          'Update check failed',
          details: result.error,
          category: 'update',
          severity: 'error',
        );
      }
    } finally {
      _updateOperationInFlight = false;
      if (mounted) {
        state = state.copyWith(updateOperationInFlight: false);
      }
    }
  }

  Future<void> installUpdateInApp({bool confirmed = false}) async {
    if (_updateOperationInFlight ||
        _isUpdateOperationBusy(state.updateStatus)) {
      final message = _updateBusyMessage();
      state = state.copyWith(
        updateOperationInFlight:
            _updateOperationInFlight || state.updateOperationInFlight,
        errorMessage: message,
        updateError: message,
      );
      await logEvent(
        'update_action_busy',
        'Update action already in progress',
        details: message,
        category: 'update',
        severity: 'warning',
      );
      return;
    }
    if (!_updateService.packageMutationSupported) {
      const message =
          'In-app update package verification and installation are unavailable on this platform. Install the matching package from the official Avorax release manually.';
      state = state.copyWith(errorMessage: message, updateError: message);
      await logEvent(
        'update_install_platform_unsupported',
        'In-app update installation unavailable',
        details: message,
        category: 'update',
        severity: 'warning',
      );
      return;
    }
    if (!confirmed) {
      const message =
          'Update installation requires explicit confirmation before Avorax Update Service can apply a package.';
      state = state.copyWith(errorMessage: message, updateError: message);
      await logEvent(
        'update_install_confirmation_required',
        'Update install confirmation required',
        details: message,
        category: 'update',
        severity: 'warning',
      );
      return;
    }
    final update = state.updateInfo;
    if (update == null) {
      await unawaitedCheckForUpdates();
      return;
    }
    if (await _rejectUpdateMutationDuringActiveWork(
      'Update installation cannot run',
    )) {
      return;
    }
    UpdateInfo? downloadedForInstall;
    var packageVerified = false;
    _updateOperationInFlight = true;
    state = state.copyWith(updateOperationInFlight: true);
    try {
      state = state.copyWith(
        updateStatus: UpdateStatus.downloading,
        clearError: true,
        clearUpdateError: true,
      );
      final downloaded = await _updateService.downloadUpdatePackage(update);
      downloadedForInstall = downloaded;
      state = state.copyWith(
        updateStatus: UpdateStatus.verifying,
        updateInfo: downloaded,
      );
      await _updateService.verifyDownloadedPackage(downloaded);
      packageVerified = true;
      state = state.copyWith(
        updateStatus: UpdateStatus.installing,
        updateInfo: downloaded,
      );
      await logEvent(
        'update_install_started',
        'Update install started',
        details: downloaded.packageName,
        category: 'update',
        severity: 'warning',
      );
      await _updateService.installDownloadedPackage(downloaded);
      state = state.copyWith(
        updateStatus: UpdateStatus.readyToRestart,
        updateInfo: downloaded,
        clearUpdateError: true,
      );
      await logEvent(
        'update_install_ready',
        'Update installed; restart Avorax to finish',
        details: downloaded.packageName,
        category: 'update',
        severity: 'warning',
      );
    } on Object catch (error) {
      final failedUpdateInfo = packageVerified
          ? downloadedForInstall
          : update.withoutLocalPackagePath();
      final details = _boundedUpdateUiError(error);
      state = state.copyWith(
        updateStatus: UpdateStatus.updateAvailable,
        updateInfo: failedUpdateInfo,
        errorMessage: 'Avorax could not start the in-app update: $details',
        updateError: details,
      );
      await logEvent(
        'update_install_failed',
        'Update install failed',
        details: details,
        category: 'update',
        severity: 'error',
      );
    } finally {
      _updateOperationInFlight = false;
      if (mounted) {
        state = state.copyWith(updateOperationInFlight: false);
      }
    }
  }

  Future<void> rollbackUpdateInApp({bool confirmed = false}) async {
    if (_updateOperationInFlight ||
        _isUpdateOperationBusy(state.updateStatus)) {
      final message = _updateBusyMessage();
      state = state.copyWith(
        updateOperationInFlight:
            _updateOperationInFlight || state.updateOperationInFlight,
        errorMessage: message,
        updateError: message,
      );
      await logEvent(
        'update_action_busy',
        'Update action already in progress',
        details: message,
        category: 'update',
        severity: 'warning',
      );
      return;
    }
    if (!_updateService.packageMutationSupported) {
      const message =
          'In-app update rollback is unavailable on this platform. Install the matching package from the official Avorax release manually.';
      state = state.copyWith(errorMessage: message, updateError: message);
      await logEvent(
        'update_rollback_platform_unsupported',
        'In-app update rollback unavailable',
        details: message,
        category: 'update',
        severity: 'warning',
      );
      return;
    }
    if (state.updateInfo?.rollbackSupported != true) {
      const message = 'Rollback is not available for the current update.';
      state = state.copyWith(
        updateStatus: UpdateStatus.failed,
        errorMessage: message,
        updateError: message,
      );
      await logEvent(
        'update_rollback_unavailable',
        'Update rollback unavailable',
        details: message,
        category: 'update',
        severity: 'warning',
      );
      return;
    }
    if (!confirmed) {
      const message =
          'Update rollback requires explicit confirmation before Avorax Update Service can restore the previous version.';
      state = state.copyWith(errorMessage: message, updateError: message);
      await logEvent(
        'update_rollback_confirmation_required',
        'Update rollback confirmation required',
        details: message,
        category: 'update',
        severity: 'warning',
      );
      return;
    }
    if (await _rejectUpdateMutationDuringActiveWork(
      'Update rollback cannot run',
    )) {
      return;
    }
    _updateOperationInFlight = true;
    state = state.copyWith(updateOperationInFlight: true);
    try {
      state = state.copyWith(
        updateStatus: UpdateStatus.rollingBack,
        clearError: true,
        clearUpdateError: true,
      );
      await logEvent(
        'update_rollback_started',
        'Update rollback started',
        category: 'update',
        severity: 'warning',
      );
      await _updateService.rollbackPreviousVersion();
      state = state.copyWith(
        updateStatus: UpdateStatus.readyToRestart,
        clearUpdateError: true,
      );
      await logEvent(
        'update_rollback_ready',
        'Rollback applied; restart Avorax to finish',
        category: 'update',
        severity: 'warning',
      );
    } on Object catch (error) {
      final details = _boundedUpdateUiError(error);
      state = state.copyWith(
        updateStatus: UpdateStatus.failed,
        errorMessage: 'Avorax could not roll back the update: $details',
        updateError: details,
      );
      await logEvent(
        'update_rollback_failed',
        'Update rollback failed',
        details: details,
        category: 'update',
        severity: 'error',
      );
    } finally {
      _updateOperationInFlight = false;
      if (mounted) {
        state = state.copyWith(updateOperationInFlight: false);
      }
    }
  }

  bool _isUpdateOperationBusy(UpdateStatus status) =>
      status == UpdateStatus.checking || _isUpdateMutationStatusBusy(status);

  bool _isUpdateMutationStatusBusy(UpdateStatus status) => {
    UpdateStatus.downloading,
    UpdateStatus.verifying,
    UpdateStatus.installing,
    UpdateStatus.rollingBack,
  }.contains(status);

  String _updateBusyMessage() {
    final status = state.updateStatus;
    if (_isUpdateOperationBusy(status)) {
      return 'Update action is already in progress: ${status.label}.';
    }
    return 'Update action is already in progress.';
  }

  Future<bool> _rejectUpdateMutationDuringActiveWork(String prefix) async {
    final busyReason = _updateMutationBusyReason(prefix);
    if (busyReason == null) return false;
    await logEvent(
      'update_action_busy',
      'Update action already in progress',
      details: busyReason,
      category: 'update',
      severity: 'warning',
    );
    state = state.copyWith(
      protectionOperationInFlight:
          _protectionOperationInFlight || state.protectionOperationInFlight,
      protectionSelfTestInFlight:
          _protectionSelfTestInFlight || state.protectionSelfTestInFlight,
      securitySettingsActionInFlight:
          _securitySettingsActionInFlight ||
          state.securitySettingsActionInFlight,
      configurationResetInFlight:
          _configurationResetInFlight || state.configurationResetInFlight,
      quarantineActionInFlight:
          _quarantineActionInFlight || state.quarantineActionInFlight,
      allowlistActionInFlight:
          _allowlistActionInFlight || state.allowlistActionInFlight,
      detectionFeedbackInFlight:
          _detectionFeedbackInFlight || state.detectionFeedbackInFlight,
      serviceActionInFlight:
          _serviceActionInFlight || state.serviceActionInFlight,
      developerCloudOverrideInFlight:
          _developerCloudOverrideInFlight ||
          state.developerCloudOverrideInFlight,
      protectedAppActionInFlight:
          _protectedAppActionInFlight || state.protectedAppActionInFlight,
      scanStartInFlight: _scanStartInFlight || state.scanStartInFlight,
      scanTargetSelectionInFlight:
          _scanTargetSelectionInFlight || state.scanTargetSelectionInFlight,
      scanCancelInFlight: _scanCancelInFlight || state.scanCancelInFlight,
      errorMessage: busyReason,
      updateError: busyReason,
    );
    return true;
  }

  String? _updateMutationBusyReason(String prefix) {
    if (_protectionOperationInFlight ||
        state.protectionOperationInFlight ||
        _protectionSelfTestInFlight ||
        state.protectionSelfTestInFlight ||
        _configurationResetRequiresProtectionStop()) {
      return '$prefix while protection is enabled, changing, or self-test is running.';
    }
    final scanBusyReason = _scanBusyReasonForConfigurationMutation(prefix);
    if (scanBusyReason != null) return scanBusyReason;
    if (_securitySettingsActionInFlight ||
        state.securitySettingsActionInFlight) {
      return '$prefix while a security settings change is in progress.';
    }
    if (_configurationResetInFlight || state.configurationResetInFlight) {
      return '$prefix while configuration reset is in progress.';
    }
    if (_serviceActionInFlight || state.serviceActionInFlight) {
      return '$prefix while service recovery is in progress.';
    }
    if (_developerCloudOverrideInFlight ||
        state.developerCloudOverrideInFlight) {
      return '$prefix while a developer cloud override change is in progress.';
    }
    if (_protectedAppActionInFlight || state.protectedAppActionInFlight) {
      return '$prefix while a protected-app action is in progress.';
    }
    return _manualDispositionBusyReason(prefix);
  }

  Future<bool> _rejectProtectionActionDuringUpdateMutation({
    required String eventType,
    required String title,
    required String prefix,
  }) async {
    final status = state.updateStatus;
    if (!_isUpdateMutationStatusBusy(status)) return false;
    final message =
        '$prefix while update package work is in progress: ${status.label}.';
    await logEvent(
      eventType,
      title,
      details: message,
      category: 'protection',
      severity: 'warning',
    );
    state = state.copyWith(
      protectionOperationInFlight:
          _protectionOperationInFlight || state.protectionOperationInFlight,
      protectionSelfTestInFlight:
          _protectionSelfTestInFlight || state.protectionSelfTestInFlight,
      updateOperationInFlight:
          _updateOperationInFlight || state.updateOperationInFlight,
      errorMessage: message,
    );
    return true;
  }

  Future<bool> saveDeveloperCloudOverride({
    required bool enabled,
    required String apiBaseUrl,
    required String projectId,
    required String publicClientKey,
    bool confirmed = false,
  }) async {
    if (!confirmed) {
      const message =
          'Developer cloud override changes require explicit confirmation because they alter Avorax cloud endpoints and client credentials used by this app.';
      await logEvent(
        'developer_cloud_override_confirmation_required',
        'Developer cloud override confirmation required',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (_developerCloudOverrideInFlight) {
      const message = 'Developer cloud override change is already in progress.';
      await logEvent(
        'developer_cloud_override_busy',
        'Developer cloud override already in progress',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        developerCloudOverrideInFlight:
            _developerCloudOverrideInFlight ||
            state.developerCloudOverrideInFlight,
        errorMessage: message,
      );
      return false;
    }
    final updateBusyReason = _configurationMutationUpdateBusyReason(
      'Developer cloud override cannot change',
    );
    if (updateBusyReason != null) {
      await logEvent(
        'developer_cloud_override_busy',
        'Developer cloud override blocked by update package work',
        details: updateBusyReason,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        updateOperationInFlight:
            _updateOperationInFlight || state.updateOperationInFlight,
        errorMessage: updateBusyReason,
      );
      return false;
    }
    _developerCloudOverrideInFlight = true;
    state = state.copyWith(developerCloudOverrideInFlight: true);
    try {
      final updated = state.config.copyWith(
        developerOverrideEnabled: enabled,
        apiBaseUrl: enabled
            ? apiBaseUrl.trim()
            : _configRepository.buildConfig.apiBaseUrl,
        projectId: enabled
            ? projectId.trim()
            : _configRepository.buildConfig.projectId,
        publicClientKey: enabled
            ? publicClientKey.trim()
            : _configRepository.buildConfig.publicClientKey,
      );
      if (enabled) {
        final validation = updated.validateCloudConfiguration();
        if (validation.isNotEmpty) {
          throw FormatException(
            'Developer cloud override is invalid: ${validation.join(' ')}',
          );
        }
      }
      await _configRepository.save(updated);
      await logEvent(
        'configuration_saved',
        'Cloud configuration saved',
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(config: updated, clearError: true);
      await unawaitedCheckCloud();
      return true;
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'configuration_save_failed',
        'Cloud configuration save failed',
        details: details,
        category: 'settings',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Unable to save cloud configuration: $details',
      );
      return false;
    } finally {
      _developerCloudOverrideInFlight = false;
      if (mounted) {
        state = state.copyWith(developerCloudOverrideInFlight: false);
      }
    }
  }

  Future<void> unawaitedDetectApps() async {
    if (_appDetectionInFlight) {
      const message = 'Protected app detection is already in progress.';
      await logEvent(
        'app_detection_busy',
        'Protected app detection already in progress',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      if (!mounted) return;
      state = state.copyWith(
        appDetectionInFlight:
            _appDetectionInFlight || state.appDetectionInFlight,
        errorMessage: message,
      );
      return;
    }
    _appDetectionInFlight = true;
    state = state.copyWith(appDetectionInFlight: true);
    try {
      if (!_appDetector.supportsAutomaticDetection) {
        await logEvent(
          'app_detection_disabled',
          'Automatic protected app detection disabled',
          details:
              'No supported protected-app registry entries are configured. Use manual file or folder selection when needed.',
          category: 'protection',
          severity: 'warning',
        );
        if (!mounted) return;
        state = state.copyWith(
          detectedApps: const [],
          appDetectionStatus: state.config.protectedAppConfig.isConfigured
              ? AppDetectionStatus.manual
              : AppDetectionStatus.notFound,
        );
        return;
      }
      await logEvent(
        'app_detection_started',
        'Protected app detection started',
        category: 'protection',
        severity: 'info',
      );
      if (!mounted) return;
      state = state.copyWith(
        appDetectionStatus: AppDetectionStatus.scanning,
        clearError: true,
      );
      final apps = await _appDetector.detect();
      await _evaluateProcessSnapshotForAppDetection();
      if (!mounted) return;
      if (apps.isEmpty) {
        await logEvent(
          'no_supported_app_detected',
          'No supported app detected',
          category: 'protection',
          severity: 'warning',
        );
        state = state.copyWith(
          detectedApps: const [],
          appDetectionStatus: state.config.protectedAppConfig.isConfigured
              ? AppDetectionStatus.manual
              : AppDetectionStatus.notFound,
        );
        return;
      }
      await logEvent(
        'protected_app_detected',
        'Protected app detected',
        category: 'protection',
        severity: 'info',
      );
      state = state.copyWith(
        detectedApps: apps,
        appDetectionStatus: AppDetectionStatus.detected,
      );
    } on Object catch (error) {
      if (!mounted) return;
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'app_detection_failed',
        'Protected app detection failed',
        details: details,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(
        detectedApps: const [],
        appDetectionStatus: state.config.protectedAppConfig.isConfigured
            ? AppDetectionStatus.manual
            : AppDetectionStatus.notFound,
        errorMessage: 'Unable to detect protected apps: $details',
      );
    } finally {
      _appDetectionInFlight = false;
      if (mounted) {
        state = state.copyWith(appDetectionInFlight: false);
      }
    }
  }

  Future<void> _evaluateProcessSnapshotForAppDetection() async {
    await _evaluateProcessSnapshot(
      emptyType: 'process_snapshot_empty',
      emptyMessage: 'Process snapshot contained no observations',
      emptyDetails:
          'Protected-app detection completed without process snapshot observations.',
      evaluatedType: 'process_snapshot_evaluated',
      evaluatedMessage: 'Process snapshot evaluated',
      suspiciousType: 'process_snapshot_suspicious',
      suspiciousMessage: 'Process snapshot reported suspicious findings',
      failedType: 'process_snapshot_failed',
      failedMessage: 'Process snapshot evaluation failed',
      emptySeverity: 'warning',
    );
  }

  Future<void> _evaluateProcessSnapshotForActiveProtection() async {
    await _evaluateProcessSnapshot(
      emptyType: 'process_snapshot_loop_empty',
      emptyMessage: 'Protection process snapshot contained no observations',
      emptyDetails:
          'Active protection process observation tick completed without process snapshot observations.',
      evaluatedType: 'process_snapshot_loop_evaluated',
      evaluatedMessage: 'Protection process snapshot evaluated',
      suspiciousType: 'process_snapshot_loop_suspicious',
      suspiciousMessage:
          'Protection process snapshot reported suspicious findings',
      failedType: 'process_snapshot_loop_failed',
      failedMessage: 'Protection process snapshot evaluation failed',
      emptySeverity: 'info',
      dedupeRepeatedRoutineEvents: true,
      updateProcessSnapshotLoopState: true,
    );
  }

  Future<void> _evaluateProcessSnapshot({
    required String emptyType,
    required String emptyMessage,
    required String emptyDetails,
    required String evaluatedType,
    required String evaluatedMessage,
    required String suspiciousType,
    required String suspiciousMessage,
    required String failedType,
    required String failedMessage,
    required String emptySeverity,
    bool dedupeRepeatedRoutineEvents = false,
    bool updateProcessSnapshotLoopState = false,
  }) async {
    if (_processSnapshotEvaluationInFlight) {
      const busyDetails =
          'A process snapshot evaluation was skipped because a previous snapshot is still running.';
      if (updateProcessSnapshotLoopState) {
        _setProcessSnapshotLoopState(status: 'limited', reason: busyDetails);
      }
      await logEvent(
        '${evaluatedType}_busy',
        'Process snapshot evaluation already in progress',
        details: busyDetails,
        category: 'protection',
        severity: 'warning',
      );
      return;
    }
    _processSnapshotEvaluationInFlight = true;
    try {
      final observations = await _appDetector.processSnapshotObservations();
      if (!mounted) return;
      if (observations.isEmpty) {
        if (updateProcessSnapshotLoopState) {
          _setProcessSnapshotLoopState(status: 'active', reason: emptyDetails);
        }
        if (_shouldSkipRepeatedProcessSnapshotRoutineEvent(
          type: emptyType,
          details: emptyDetails,
          severity: emptySeverity,
          dedupe: dedupeRepeatedRoutineEvents,
        )) {
          return;
        }
        await logEvent(
          emptyType,
          emptyMessage,
          details: emptyDetails,
          category: 'protection',
          severity: emptySeverity,
        );
        return;
      }
      final report = await _localCoreClient.evaluateProcessSnapshot(
        observations,
      );
      if (!mounted) return;
      if (!report.ok) {
        final diagnosticParts = <String>[
          'Local Core rejected process snapshot evaluation:',
          report.statusReason,
          if (report.diagnostics.isNotEmpty)
            'diagnostics=${report.diagnostics.take(2).join("; ")}',
        ];
        await _recordProcessSnapshotFailure(
          failedType: failedType,
          failedMessage: failedMessage,
          details: diagnosticParts.join(' '),
          dedupeRepeatedRoutineEvents: dedupeRepeatedRoutineEvents,
          updateProcessSnapshotLoopState: updateProcessSnapshotLoopState,
        );
        return;
      }
      if (report.diagnostics.isNotEmpty) {
        await _recordProcessSnapshotFailure(
          failedType: failedType,
          failedMessage: failedMessage,
          details:
              'Local Core returned incomplete process snapshot evidence: '
              'findings=${report.findings.length} '
              'diagnostics=${report.diagnostics.take(2).join("; ")}',
          dedupeRepeatedRoutineEvents: dedupeRepeatedRoutineEvents,
          updateProcessSnapshotLoopState: updateProcessSnapshotLoopState,
        );
        return;
      }
      final findingCount = report.findings.length;
      final detailParts = <String>[
        'observed=${report.observedProcesses}',
        'skipped=${report.skippedProcesses}',
        'findings=$findingCount',
        'status=${report.status}',
        'capability=${report.capability}',
      ];
      final eventType = findingCount > 0 ? suspiciousType : evaluatedType;
      final eventMessage = findingCount > 0
          ? suspiciousMessage
          : evaluatedMessage;
      final eventSeverity = findingCount > 0 ? 'warning' : 'info';
      final eventDetails = _boundedUiDiagnostic(detailParts.join(' '));
      if (updateProcessSnapshotLoopState) {
        _setProcessSnapshotLoopState(
          status: findingCount > 0 ? 'attention' : 'active',
          reason: eventDetails,
        );
      }
      if (_shouldSkipRepeatedProcessSnapshotRoutineEvent(
        type: eventType,
        details: eventDetails,
        severity: eventSeverity,
        dedupe: dedupeRepeatedRoutineEvents,
      )) {
        return;
      }
      await logEvent(
        eventType,
        eventMessage,
        details: eventDetails,
        category: 'protection',
        severity: eventSeverity,
      );
    } on Object catch (error) {
      if (!mounted) return;
      await _recordProcessSnapshotFailure(
        failedType: failedType,
        failedMessage: failedMessage,
        details: _boundedUiDiagnostic(error),
        dedupeRepeatedRoutineEvents: dedupeRepeatedRoutineEvents,
        updateProcessSnapshotLoopState: updateProcessSnapshotLoopState,
      );
    } finally {
      _processSnapshotEvaluationInFlight = false;
    }
  }

  Future<void> _recordProcessSnapshotFailure({
    required String failedType,
    required String failedMessage,
    required Object details,
    required bool dedupeRepeatedRoutineEvents,
    required bool updateProcessSnapshotLoopState,
  }) async {
    final boundedDetails = _boundedUiDiagnostic(details);
    if (updateProcessSnapshotLoopState) {
      _setProcessSnapshotLoopState(status: 'limited', reason: boundedDetails);
    }
    if (dedupeRepeatedRoutineEvents) {
      _lastProcessSnapshotLoopRoutineEventKey = null;
    }
    await logEvent(
      failedType,
      failedMessage,
      details: boundedDetails,
      category: 'protection',
      severity: 'warning',
    );
  }

  bool _shouldSkipRepeatedProcessSnapshotRoutineEvent({
    required String type,
    required String details,
    required String severity,
    required bool dedupe,
  }) {
    if (!dedupe) return false;
    if (severity != 'info') {
      _lastProcessSnapshotLoopRoutineEventKey = null;
      return false;
    }
    final key = '$type\n$details';
    if (_lastProcessSnapshotLoopRoutineEventKey == key) return true;
    _lastProcessSnapshotLoopRoutineEventKey = key;
    return false;
  }

  String? _startProcessSnapshotLoop() {
    try {
      _stopProcessSnapshotLoop();
      _lastProcessSnapshotLoopRoutineEventKey = null;
      _processSnapshotTimer = _processSnapshotTimerFactory(
        _processSnapshotLoopInterval,
        (_) => _runProcessSnapshotLoopTickSafely(),
      );
      return null;
    } on Object catch (error) {
      _stopProcessSnapshotLoop();
      return 'Process observation loop did not start: ${_boundedUiDiagnostic(error)}.';
    }
  }

  void _stopProcessSnapshotLoop() {
    _processSnapshotTimer?.cancel();
    _processSnapshotTimer = null;
    _lastProcessSnapshotLoopRoutineEventKey = null;
  }

  void _runProcessSnapshotLoopTickSafely() {
    if (!mounted || !_processSnapshotLoopShouldRun()) return;
    unawaited(
      _evaluateProcessSnapshotForActiveProtection().catchError((
        Object error,
      ) async {
        if (!mounted) return;
        final details = _boundedUiDiagnostic(error);
        _setProcessSnapshotLoopState(status: 'limited', reason: details);
        await logEvent(
          'process_snapshot_loop_failed',
          'Protection process snapshot evaluation failed',
          details: details,
          category: 'protection',
          severity: 'warning',
        );
      }),
    );
  }

  void _setProcessSnapshotLoopState({
    required String status,
    required String reason,
  }) {
    if (!mounted) return;
    state = state.copyWith(
      processSnapshotLoopStatus: status,
      processSnapshotLoopStatusReason: _boundedUiDiagnostic(reason),
    );
  }

  bool _processSnapshotLoopShouldRun() =>
      state.config.realtimeProtectionEnabled &&
      (state.protectionStatus == ProtectionStatus.protected ||
          state.protectionStatus == ProtectionStatus.partiallyProtected ||
          state.protectionStatus == ProtectionStatus.localOnly);

  String? _startWatchPollLoop(List<String> watchedPaths) {
    if (watchedPaths.isEmpty) {
      return 'Finite watch-poll loop did not start: no watched paths were reported.';
    }
    try {
      _stopWatchPollLoop();
      _watchPollPaths = List<String>.unmodifiable(watchedPaths);
      _lastWatchPollLoopRoutineEventKey = null;
      _watchPollTimer = _watchPollTimerFactory(
        _watchPollLoopInterval,
        (_) => _runWatchPollLoopTickSafely(),
      );
      return null;
    } on Object catch (error) {
      _stopWatchPollLoop();
      return 'Finite watch-poll loop did not start: ${_boundedUiDiagnostic(error)}.';
    }
  }

  void _stopWatchPollLoop() {
    _watchPollTimer?.cancel();
    _watchPollTimer = null;
    _watchPollPaths = const [];
    _lastWatchPollLoopRoutineEventKey = null;
  }

  void _runWatchPollLoopTickSafely() {
    if (!mounted || !_watchPollLoopShouldRun()) return;
    unawaited(
      _evaluateWatchPollForActiveProtection().catchError((Object error) async {
        if (!mounted) return;
        final details = _boundedUiDiagnostic(error);
        _setWatchPollLoopState(status: 'limited', reason: details);
        await logEvent(
          'watch_poll_loop_failed',
          'Protection watch-poll scan failed',
          details: details,
          category: 'protection',
          severity: 'warning',
        );
      }),
    );
  }

  Future<void> _evaluateWatchPollForActiveProtection({
    bool dedupeRepeatedRoutineEvents = true,
  }) async {
    if (_watchPollEvaluationInFlight) {
      const busyDetails =
          'A finite watch-poll scan was skipped because a previous watch-poll scan is still running.';
      _setWatchPollLoopState(status: 'limited', reason: busyDetails);
      await logEvent(
        'watch_poll_loop_busy',
        'Protection watch-poll scan already in progress',
        details: busyDetails,
        category: 'protection',
        severity: 'warning',
      );
      return;
    }
    final paths = _watchPollPaths;
    if (paths.isEmpty) {
      const details =
          'Finite watch-poll scan skipped because no watched paths are active.';
      _setWatchPollLoopState(status: 'off', reason: details);
      return;
    }
    _watchPollEvaluationInFlight = true;
    try {
      final result = await _localCoreClient.watchPollScan(
        paths,
        duration: _watchPollScanDuration,
        pollInterval: _watchPollScanPollInterval,
        maxEvents: _watchPollScanMaxEvents,
      );
      if (!mounted) return;
      final poll = result.poll;
      final detailParts = <String>[
        'mode=${poll.mode}',
        'active=${poll.active}',
        'eventsObserved=${poll.eventsObserved}',
        'filesScanned=${poll.filesScanned}',
        'threatsFound=${poll.threatsFound}',
        'quarantinedFiles=${poll.quarantinedFiles}',
        'durationMs=${poll.durationMs}',
        'pollIntervalMs=${poll.pollIntervalMs}',
        'maxEvents=${poll.maxEvents}',
        if (poll.limitations.isNotEmpty)
          'limitations=${poll.limitations.take(4).join("; ")}',
        if (poll.scanErrors.isNotEmpty)
          'diagnostics=${poll.scanErrors.take(2).join("; ")}',
      ];
      final eventDetails = _boundedUiDiagnostic(detailParts.join(' '));
      if (!result.ok) {
        final failureDetails = _boundedUiDiagnostic(
          [
            result.error ?? 'Watch-poll scan request failed.',
            eventDetails,
          ].join(' '),
        );
        _setWatchPollLoopState(status: 'limited', reason: failureDetails);
        _lastWatchPollLoopRoutineEventKey = null;
        await logEvent(
          'watch_poll_loop_failed',
          'Protection watch-poll scan failed',
          details: failureDetails,
          category: 'protection',
          severity: 'warning',
        );
        return;
      }
      final hasThreats = poll.threatsFound > 0 || poll.quarantinedFiles > 0;
      final hasDiagnostics = poll.scanErrors.isNotEmpty || !poll.active;
      final eventType = hasThreats
          ? 'watch_poll_loop_threats_found'
          : hasDiagnostics
          ? 'watch_poll_loop_limited'
          : 'watch_poll_loop_clean';
      final eventMessage = hasThreats
          ? 'Protection watch-poll scan found threats'
          : hasDiagnostics
          ? 'Protection watch-poll scan completed with diagnostics'
          : 'Protection watch-poll scan completed cleanly';
      final eventSeverity = hasThreats || hasDiagnostics ? 'warning' : 'info';
      _setWatchPollLoopState(
        status: hasThreats
            ? 'attention'
            : hasDiagnostics
            ? 'limited'
            : 'active',
        reason: eventDetails,
      );
      if (_shouldSkipRepeatedWatchPollRoutineEvent(
        type: eventType,
        details: eventDetails,
        severity: eventSeverity,
        dedupe: dedupeRepeatedRoutineEvents,
      )) {
        return;
      }
      await logEvent(
        eventType,
        eventMessage,
        details: eventDetails,
        category: 'protection',
        severity: eventSeverity,
      );
    } on Object catch (error) {
      if (!mounted) return;
      final details = _boundedUiDiagnostic(error);
      _setWatchPollLoopState(status: 'limited', reason: details);
      _lastWatchPollLoopRoutineEventKey = null;
      await logEvent(
        'watch_poll_loop_failed',
        'Protection watch-poll scan failed',
        details: details,
        category: 'protection',
        severity: 'warning',
      );
    } finally {
      _watchPollEvaluationInFlight = false;
    }
  }

  void _setWatchPollLoopState({
    required String status,
    required String reason,
  }) {
    if (!mounted) return;
    state = state.copyWith(
      watchPollLoopStatus: status,
      watchPollLoopStatusReason: _boundedUiDiagnostic(reason),
    );
  }

  bool _watchPollLoopShouldRun() =>
      state.config.realtimeProtectionEnabled &&
      _watchPollPaths.isNotEmpty &&
      (state.protectionStatus == ProtectionStatus.protected ||
          state.protectionStatus == ProtectionStatus.partiallyProtected ||
          state.protectionStatus == ProtectionStatus.localOnly);

  bool _shouldSkipRepeatedWatchPollRoutineEvent({
    required String type,
    required String details,
    required String severity,
    required bool dedupe,
  }) {
    if (!dedupe) return false;
    if (severity != 'info') {
      _lastWatchPollLoopRoutineEventKey = null;
      return false;
    }
    final key = '$type\n$details';
    if (_lastWatchPollLoopRoutineEventKey == key) return true;
    _lastWatchPollLoopRoutineEventKey = key;
    return false;
  }

  Future<void> unawaitedCheckMalwareEngine() async {
    if (_malwareEngineHealthCheckInFlight) {
      const message = 'Malware engine health check is already in progress.';
      await logEvent(
        'malware_engine_health_busy',
        'Malware engine health check already in progress',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      if (!mounted) return;
      state = state.copyWith(
        malwareEngineHealthCheckInFlight:
            _malwareEngineHealthCheckInFlight ||
            state.malwareEngineHealthCheckInFlight,
        errorMessage: message,
      );
      return;
    }
    _malwareEngineHealthCheckInFlight = true;
    try {
      if (!mounted) return;
      state = state.copyWith(
        malwareEngineHealthCheckInFlight: true,
        malwareEngineStatus: MalwareEngineStatus.checking,
      );
      final health = await _localCoreClient.healthSummary();
      final serviceBoundaryHealth = await _localCoreClient
          .serviceBoundaryHealth();
      if (!mounted) return;
      final status = health.malwareEngineStatus;
      final healthDetails =
          [
                health.lastError,
                if (health.nativeSelfTestPassed == false &&
                    !(health.nativeSelfTestError?.trim().isNotEmpty ?? false))
                  'Native self-test failed without detail',
                health.nativeSelfTestError,
                if (health.aiSelfTestPassed == false &&
                    !(health.aiSelfTestError?.trim().isNotEmpty ?? false))
                  'AI self-test failed without detail',
                health.aiSelfTestError,
                if (serviceBoundaryHealth.status ==
                    CoreServiceBoundaryStatus.unavailable)
                  serviceBoundaryHealth.diagnostic,
              ]
              .whereType<String>()
              .map((detail) => detail.trim())
              .where((detail) => detail.isNotEmpty)
              .join('\n');
      final healthEventSeverity =
          status == MalwareEngineStatus.available && healthDetails.isEmpty
          ? 'info'
          : 'warning';
      await logEvent(
        status == MalwareEngineStatus.available
            ? 'malware_engine_available'
            : 'malware_engine_unavailable',
        status == MalwareEngineStatus.available
            ? 'Malware engine available'
            : 'Malware engine unavailable',
        details: healthDetails.isEmpty ? null : healthDetails,
        category: 'protection',
        severity: healthEventSeverity,
      );
      if (!mounted) return;
      final recoveredFromStaleEngineError =
          status == MalwareEngineStatus.available &&
          state.lastScanReport?.status == ScanStatus.engineUnavailable;
      state = state.copyWith(
        malwareEngineStatus: status,
        aiStatus: health.aiStatus,
        aiModelInfo: health.aiModelInfo,
        yaraStatus: health.yaraStatus,
        yaraRuleCount: health.yaraRuleCount,
        nativeEngineStatus: health.nativeEngineStatus,
        nativeSignatureCount: health.nativeSignatureCount,
        nativeRuleCount: health.nativeRuleCount,
        nativeMlStatus: health.nativeMlStatus,
        nativeMlModelVersion: health.nativeMlModelVersion,
        nativeMlProductionReady: health.nativeMlProductionReady,
        nativeEngineError: health.nativeEngineError,
        clearNativeEngineError: health.nativeEngineError == null,
        nativeSelfTestPassed: health.nativeSelfTestPassed,
        clearNativeSelfTestPassed: health.nativeSelfTestPassed == null,
        nativeSelfTestError: health.nativeSelfTestError,
        clearNativeSelfTestError: health.nativeSelfTestError == null,
        aiSelfTestPassed: health.aiSelfTestPassed,
        clearAiSelfTestPassed: health.aiSelfTestPassed == null,
        aiSelfTestError: health.aiSelfTestError,
        clearAiSelfTestError: health.aiSelfTestError == null,
        ipcMode: health.ipcMode,
        networkExposed: health.networkExposed,
        clearNetworkExposed: health.networkExposed == null,
        compatibilityEnginesEnabled: health.compatibilityEnginesEnabled,
        coreServiceStatus: health.coreServiceStatus,
        coreServiceBoundaryHealth: serviceBoundaryHealth,
        guardStatus: health.guardStatus,
        driverStatus: health.driverStatus,
        processMonitorStatus: health.processMonitorStatus,
        processMonitorCapability: health.processMonitorCapability,
        processMonitorStatusReason: health.processMonitorStatusReason,
        clearProcessMonitorStatusReason:
            health.processMonitorStatusReason == null,
        behaviorMonitorStatus: health.behaviorMonitorStatus,
        behaviorMonitorStatusReason: health.behaviorMonitorStatusReason,
        clearBehaviorMonitorStatusReason:
            health.behaviorMonitorStatusReason == null,
        reputationStatus: health.reputationStatus,
        reputationStatusReason: health.reputationStatusReason,
        clearReputationStatusReason: health.reputationStatusReason == null,
        installPath: health.installPath,
        clearInstallPath: health.installPath == null,
        engineDirectory: health.engineDirectory,
        clearEngineDirectory: health.engineDirectory == null,
        nativeSignaturesDirectory: health.nativeSignaturesDirectory,
        nativeRulesDirectory: health.nativeRulesDirectory,
        nativeMlDirectory: health.nativeMlDirectory,
        nativeTrustDirectory: health.nativeTrustDirectory,
        nativeConfigDirectory: health.nativeConfigDirectory,
        clearNativeSignaturesDirectory:
            health.nativeSignaturesDirectory == null,
        clearNativeRulesDirectory: health.nativeRulesDirectory == null,
        clearNativeMlDirectory: health.nativeMlDirectory == null,
        clearNativeTrustDirectory: health.nativeTrustDirectory == null,
        clearNativeConfigDirectory: health.nativeConfigDirectory == null,
        enginePathsChecked: health.enginePathsChecked,
        programDataDirectory: health.programDataDirectory,
        clearProgramDataDirectory: health.programDataDirectory == null,
        programDataDirectoryError: health.programDataDirectoryError,
        clearProgramDataDirectoryError:
            health.programDataDirectoryError == null,
        coreServiceStatusError: health.coreServiceStatusError,
        clearCoreServiceStatusError: health.coreServiceStatusError == null,
        guardStatusError: health.guardStatusError,
        clearGuardStatusError: health.guardStatusError == null,
        lastEngineError: healthDetails,
        clearLastEngineError: healthDetails.isEmpty,
        scanStatus: recoveredFromStaleEngineError ? ScanStatus.idle : null,
        clearLastScanReport: recoveredFromStaleEngineError,
        clearError: recoveredFromStaleEngineError,
      );
    } on Object catch (error) {
      if (!mounted) return;
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'malware_engine_health_failed',
        'Malware engine health check failed',
        details: details,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(
        malwareEngineStatus: MalwareEngineStatus.error,
        aiStatus: AiModelStatus.modelMissing,
        nativeEngineStatus: 'error',
        nativeMlProductionReady: false,
        clearNativeEngineError: true,
        clearNativeSelfTestPassed: true,
        clearNativeSelfTestError: true,
        clearAiSelfTestPassed: true,
        clearAiSelfTestError: true,
        ipcMode: 'unknown',
        clearNetworkExposed: true,
        clearNativeSignaturesDirectory: true,
        clearNativeRulesDirectory: true,
        clearNativeMlDirectory: true,
        clearNativeTrustDirectory: true,
        clearNativeConfigDirectory: true,
        coreServiceStatus: 'unknown',
        clearCoreServiceStatusError: true,
        coreServiceBoundaryHealth: CoreServiceBoundaryHealth.unavailable(
          details,
        ),
        guardStatus: 'unknown',
        clearGuardStatusError: true,
        driverStatus: 'unknown',
        processMonitorStatus: 'unknown',
        processMonitorCapability: 'unknown',
        clearProcessMonitorStatusReason: true,
        behaviorMonitorStatus: 'unknown',
        clearBehaviorMonitorStatusReason: true,
        reputationStatus: 'unavailable',
        clearReputationStatusReason: true,
        clearInstallPath: true,
        clearEngineDirectory: true,
        enginePathsChecked: const [],
        clearProgramDataDirectory: true,
        clearProgramDataDirectoryError: true,
        lastEngineError: details,
        errorMessage: 'Unable to check Avorax Native Engine: $details',
      );
    } finally {
      _malwareEngineHealthCheckInFlight = false;
      if (mounted) {
        state = state.copyWith(malwareEngineHealthCheckInFlight: false);
      }
    }
  }

  Future<void> unawaitedRefreshQuarantine() async {
    if (!mounted) return;
    if (_quarantineRefreshInFlight) {
      _quarantineRefreshPending = true;
      state = state.copyWith(quarantineRefreshInFlight: true);
      return;
    }
    _quarantineRefreshInFlight = true;
    state = state.copyWith(quarantineRefreshInFlight: true);
    try {
      do {
        _quarantineRefreshPending = false;
        if (!mounted) return;
        try {
          final quarantine = await _localCoreClient.listQuarantine();
          if (!mounted) return;
          state = state.copyWith(
            quarantine: quarantine,
            clearError:
                state.errorMessage?.startsWith(
                  'Unable to refresh quarantine:',
                ) ??
                false,
          );
        } catch (error) {
          if (!mounted) return;
          final details = _boundedUiDiagnostic(error);
          await logEvent(
            'quarantine_refresh_failed',
            'Quarantine refresh failed',
            details: details,
            category: 'quarantine',
            severity: 'error',
          );
          state = state.copyWith(
            errorMessage: 'Unable to refresh quarantine: $details',
          );
        }
      } while (_quarantineRefreshPending);
    } finally {
      _quarantineRefreshInFlight = false;
      if (mounted) {
        state = state.copyWith(quarantineRefreshInFlight: false);
      }
    }
  }

  Future<void> unawaitedRefreshAllowlist() async {
    if (!mounted) return;
    if (_allowlistRefreshInFlight) {
      _allowlistRefreshPending = true;
      state = state.copyWith(allowlistRefreshInFlight: true);
      return;
    }
    _allowlistRefreshInFlight = true;
    state = state.copyWith(allowlistRefreshInFlight: true);
    try {
      do {
        _allowlistRefreshPending = false;
        if (!mounted) return;
        try {
          final allowlist = await _localCoreClient.listAllowlist();
          if (!mounted) return;
          state = state.copyWith(
            allowlist: allowlist,
            clearError:
                state.errorMessage?.startsWith(
                  'Unable to refresh allowlist:',
                ) ??
                false,
          );
        } catch (error) {
          if (!mounted) return;
          final details = _boundedUiDiagnostic(error);
          await logEvent(
            'allowlist_refresh_failed',
            'Allowlist refresh failed',
            details: details,
            category: 'protection',
            severity: 'error',
          );
          state = state.copyWith(
            errorMessage: 'Unable to refresh allowlist: $details',
          );
        }
      } while (_allowlistRefreshPending);
    } finally {
      _allowlistRefreshInFlight = false;
      if (mounted) {
        state = state.copyWith(allowlistRefreshInFlight: false);
      }
    }
  }

  Future<void> startCoreService({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Starting the Avorax Core Service requires explicit confirmation because it asks Windows to start an installed service and may prompt for administrator approval.';
      await logEvent(
        'core_service_start_confirmation_required',
        'Core Service start confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!await _beginServiceAction('Start Core Service')) return;
    try {
      final result = await _localCoreClient.startCoreService();
      await logEvent(
        'core_service_start_requested',
        'Core Service start requested',
        details: result,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: result);
      await unawaitedCheckMalwareEngine();
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      final message = 'Unable to start Avorax Core Service: $details';
      await logEvent(
        'core_service_start_failed',
        'Core Service start failed',
        details: details,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(errorMessage: message);
    } finally {
      _endServiceAction();
    }
  }

  Future<void> openInstallReport({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Opening the install report requires explicit confirmation because it launches Windows Explorer for local installation metadata.';
      await logEvent(
        'install_report_open_confirmation_required',
        'Install report open confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!await _beginServiceAction('Open install report')) return;
    try {
      final result = await _localCoreClient.openInstallReport();
      await logEvent(
        'install_report_open_requested',
        'Install report open requested',
        details: result,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: result);
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      final message = 'Unable to open Avorax install report: $details';
      await logEvent(
        'install_report_open_failed',
        'Install report open failed',
        details: details,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(errorMessage: message);
    } finally {
      _endServiceAction();
    }
  }

  Future<void> repairInstallation({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Installation repair requires explicit confirmation because it can register or reconfigure the Avorax Core Service and may prompt for administrator approval.';
      await logEvent(
        'installation_repair_confirmation_required',
        'Installation repair confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!await _beginServiceAction('Repair installation')) return;
    try {
      final result = await _localCoreClient.repairInstallation();
      await logEvent(
        'installation_repair_requested',
        'Installation repair requested',
        details: result,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: result);
      await unawaitedCheckMalwareEngine();
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      final message = 'Unable to repair Avorax installation: $details';
      await logEvent(
        'installation_repair_failed',
        'Installation repair failed',
        details: details,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(errorMessage: message);
    } finally {
      _endServiceAction();
    }
  }

  Future<bool> _beginServiceAction(String target) async {
    if (_serviceActionInFlight) {
      const message = 'Service recovery action is already in progress.';
      await logEvent(
        'service_action_busy',
        'Service recovery action already in progress',
        details: target.trim().isEmpty ? message : '$target\n$message',
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        serviceActionInFlight:
            _serviceActionInFlight || state.serviceActionInFlight,
        errorMessage: message,
      );
      return false;
    }
    final updateBusyReason = _configurationMutationUpdateBusyReason(
      'Service recovery action cannot run',
    );
    if (updateBusyReason != null) {
      await logEvent(
        'service_action_busy',
        'Service recovery action blocked by update package work',
        details: target.trim().isEmpty
            ? updateBusyReason
            : '$target\n$updateBusyReason',
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        updateOperationInFlight:
            _updateOperationInFlight || state.updateOperationInFlight,
        errorMessage: updateBusyReason,
      );
      return false;
    }
    _serviceActionInFlight = true;
    state = state.copyWith(serviceActionInFlight: true);
    return true;
  }

  void _endServiceAction() {
    _serviceActionInFlight = false;
    if (mounted) {
      state = state.copyWith(serviceActionInFlight: false);
    }
  }

  Future<bool> addManualProtectedAppFile({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Manual protected app selection requires explicit confirmation because it changes the protected app and scan scope.';
      await logEvent(
        'manual_protected_app_selection_confirmation_required',
        'Manual protected app selection confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!_hashService.supportsPathHashing) {
      const message =
          'Selected file protection is unavailable on this mobile platform.';
      await logEvent(
        'manual_protected_app_file_unavailable',
        'Manual protected app file selection unavailable',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!await _beginProtectedAppAction('Add protected app file')) {
      return false;
    }
    try {
      final file = await _fileSelectionService.pickFile();
      if (file == null) return false;
      return await _saveManualAppPath(file.name, file.path, 'Manual');
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'manual_protected_app_file_failed',
        'Manual protected app file selection failed',
        details: details,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Unable to add selected file or app: $details',
      );
      return false;
    } finally {
      _endProtectedAppAction();
    }
  }

  Future<bool> addManualProtectedAppFolder({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Manual protected app selection requires explicit confirmation because it changes the protected app and scan scope.';
      await logEvent(
        'manual_protected_app_selection_confirmation_required',
        'Manual protected app selection confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!_hashService.supportsPathHashing) {
      const message =
          'Selected folder protection is unavailable on this mobile platform.';
      await logEvent(
        'manual_protected_app_folder_unavailable',
        'Manual protected app folder selection unavailable',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!await _beginProtectedAppAction('Add protected app folder')) {
      return false;
    }
    try {
      final path = await _fileSelectionService.pickDirectory();
      if (path == null) return false;
      return await _saveManualAppPath(
        path.split(Platform.pathSeparator).last,
        path,
        'Manual',
      );
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'manual_protected_app_folder_failed',
        'Manual protected app folder selection failed',
        details: details,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Unable to add selected folder: $details',
      );
      return false;
    } finally {
      _endProtectedAppAction();
    }
  }

  Future<bool> selectDetectedApp(
    DetectedApp app, {
    bool confirmed = false,
  }) async {
    if (!confirmed) {
      const message =
          'Protected app selection requires explicit confirmation because it changes the protected app and scan scope.';
      await logEvent(
        'protected_app_selection_confirmation_required',
        'Protected app selection confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!await _beginProtectedAppAction(app.path)) return false;
    try {
      final updated = state.config.copyWith(
        protectedAppConfig: app.toProtectedAppConfig(),
        scanPaths: {...state.config.scanPaths, app.path}.toList(),
      );
      await _configRepository.save(updated);
      await logEvent(
        'protected_app_selected',
        'Protected app selected',
        details: app.path,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        config: updated,
        appDetectionStatus: AppDetectionStatus.detected,
        appVerificationStatus: _verificationStatusFor(
          updated.protectedAppConfig,
        ),
        clearError: true,
      );
      return true;
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'protected_app_select_failed',
        'Protected app selection failed',
        details: details,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Unable to select protected app: $details',
      );
      return false;
    } finally {
      _endProtectedAppAction();
    }
  }

  Future<bool> _saveManualAppPath(
    String name,
    String path,
    String source,
  ) async {
    final app = state.config.protectedAppConfig
        .copyWith(
          appName: name,
          appPath: path,
          source: source,
          platform: _currentPlatformName(),
        )
        .normalized();
    final updated = state.config.copyWith(
      protectedAppConfig: app,
      scanPaths: {...state.config.scanPaths, app.appPath}.toList(),
    );
    await _configRepository.save(updated);
    await logEvent(
      'protected_app_added_manually',
      'Protected app added manually',
      details: path,
      category: 'protection',
      severity: 'warning',
    );
    state = state.copyWith(
      config: updated,
      appDetectionStatus: AppDetectionStatus.manual,
      appVerificationStatus: _verificationStatusFor(app),
      clearError: true,
    );
    return true;
  }

  Future<bool> calculateProtectedAppHash({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Protected app build-hash calculation requires explicit confirmation because it writes local verification evidence.';
      await logEvent(
        'protected_app_hash_confirmation_required',
        'Protected app hash confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!await _beginProtectedAppAction('Calculate protected app hash')) {
      return false;
    }
    try {
      final path = state.config.protectedAppConfig.appPath;
      if (path.trim().isEmpty) {
        const message = 'No selected app path.';
        await logEvent(
          'protected_app_hash_no_target',
          'Build hash calculation blocked',
          details: message,
          category: 'protection',
          severity: 'warning',
        );
        state = state.copyWith(errorMessage: message);
        return false;
      }
      final directoryProbe = _directoryProbe(path);
      final directoryDiagnostic = directoryProbe.diagnostic;
      if (directoryDiagnostic != null) {
        final message = 'Unable to inspect selected app path before hashing.';
        await logEvent(
          'protected_app_hash_path_probe_failed',
          'Build hash path inspection failed',
          details: '$message $directoryDiagnostic',
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          appVerificationStatus: AppVerificationStatus.failed,
          errorMessage: '$message $directoryDiagnostic',
        );
        return false;
      }
      final pathIsDirectory = directoryProbe.isDirectory;
      if (!_hashService.supportsPathHashing || pathIsDirectory) {
        const message =
            'Build hashing is available for a selected executable or manifest file.';
        await logEvent(
          'protected_app_hash_unavailable',
          'Build hash calculation unavailable',
          details: pathIsDirectory
              ? '$message Selected path is a folder: $path'
              : message,
          category: 'protection',
          severity: 'warning',
        );
        state = state.copyWith(
          appVerificationStatus: AppVerificationStatus.failed,
          errorMessage: message,
        );
        return false;
      }
      state = state.copyWith(
        appVerificationStatus: AppVerificationStatus.pending,
        loading: true,
        hashProgress: 0,
        clearError: true,
      );
      try {
        final hash = await _hashService.sha256ForFile(
          path,
          onProgress: (progress) =>
              state = state.copyWith(hashProgress: progress),
        );
        final app = state.config.protectedAppConfig.copyWith(
          lastCalculatedHash: hash,
        );
        final updated = state.config.copyWith(protectedAppConfig: app);
        await _configRepository.save(updated);
        await logEvent(
          'file_hash_calculated',
          'Build hash calculated',
          category: 'protection',
          severity: 'warning',
        );
        state = state.copyWith(
          config: updated,
          appVerificationStatus: _verificationStatusFor(app),
          loading: false,
          clearHashProgress: true,
        );
        return true;
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'file_hash_failed',
          'Build hash calculation failed',
          details: details,
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          appVerificationStatus: AppVerificationStatus.failed,
          loading: false,
          clearHashProgress: true,
          errorMessage: details,
        );
        return false;
      }
    } finally {
      _endProtectedAppAction();
    }
  }

  Future<bool> _beginProtectedAppAction(String target) async {
    final updateBusyReason = _configurationMutationUpdateBusyReason(
      'Protected app action cannot run',
    );
    if (updateBusyReason != null) {
      await logEvent(
        'protected_app_action_busy',
        'Protected app action blocked by update package work',
        details: target.trim().isEmpty
            ? updateBusyReason
            : '$target\n$updateBusyReason',
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        updateOperationInFlight:
            _updateOperationInFlight || state.updateOperationInFlight,
        errorMessage: updateBusyReason,
      );
      return false;
    }
    if (_protectedAppActionInFlight) {
      const message = 'Protected app action is already in progress.';
      await logEvent(
        'protected_app_action_busy',
        'Protected app action already in progress',
        details: target.trim().isEmpty ? message : '$target\n$message',
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        protectedAppActionInFlight:
            _protectedAppActionInFlight || state.protectedAppActionInFlight,
        errorMessage: message,
      );
      return false;
    }
    _protectedAppActionInFlight = true;
    state = state.copyWith(protectedAppActionInFlight: true);
    return true;
  }

  void _endProtectedAppAction() {
    _protectedAppActionInFlight = false;
    if (mounted) {
      state = state.copyWith(protectedAppActionInFlight: false);
    }
  }

  _RealtimeWatchPathPlan _realtimeWatchPathPlan() {
    final candidates = <String>{
      ...state.config.scanPaths,
      ...state.config.ransomwareProtectedRoots,
    };
    final appPath = state.config.protectedAppConfig.appPath.trim();
    if (appPath.isNotEmpty) candidates.add(appPath);
    final paths = <String>[];
    final limitations = <String>[];
    for (final candidate in candidates) {
      final probe = _directoryExistsOrNeedsCoreValidation(candidate);
      if (probe.include) paths.add(candidate);
      final limitation = probe.limitation;
      if (limitation != null) limitations.add(limitation);
    }
    return _RealtimeWatchPathPlan(paths, limitations);
  }

  _RealtimeWatchPathProbe _directoryExistsOrNeedsCoreValidation(String path) {
    try {
      final type = _fileSystemTypeProbe(path, followLinks: false);
      return _RealtimeWatchPathProbe(
        type == FileSystemEntityType.directory ||
            type == FileSystemEntityType.link,
      );
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      final displayPath = _boundedUiDiagnostic(
        path,
        fallback: 'watch path unavailable',
      );
      return _RealtimeWatchPathProbe(
        true,
        'Unable to inspect real-time watch path $displayPath before Core validation: $details',
      );
    }
  }

  _DirectoryProbe _directoryProbe(String path) {
    try {
      return _DirectoryProbe(
        _fileSystemTypeProbe(path, followLinks: false) ==
            FileSystemEntityType.directory,
      );
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      return _DirectoryProbe(
        false,
        'Unable to inspect selected app path $path: $details',
      );
    }
  }

  _ScanTargetFileProbe _scanTargetFileProbe(String path) {
    try {
      final type = _fileSystemTypeProbe(path, followLinks: false);
      return _ScanTargetFileProbe(type == FileSystemEntityType.file);
    } on FileSystemException catch (error) {
      final details = _boundedUiDiagnostic(error.message);
      return _ScanTargetFileProbe(
        false,
        'Unable to inspect scan target path $path: $details',
      );
    } on ArgumentError catch (error) {
      final details = _boundedUiDiagnostic(error);
      return _ScanTargetFileProbe(
        false,
        'Unable to inspect scan target path $path: $details',
      );
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      return _ScanTargetFileProbe(
        false,
        'Unable to inspect scan target path $path: $details',
      );
    }
  }

  Future<void> startProtection({
    bool persistPreference = true,
    bool confirmed = false,
    bool restoringSavedPreference = false,
  }) async {
    if (!confirmed) {
      const message =
          'Starting protection requires explicit confirmation because it enables real-time monitoring and applies Guard policy.';
      await logEvent(
        'protection_start_confirmation_required',
        'Protection start confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (_protectionOperationInFlight ||
        state.protectionOperationInFlight ||
        _protectionSelfTestInFlight ||
        state.protectionSelfTestInFlight) {
      const message = 'Protection action is already in progress.';
      await logEvent(
        'protection_action_busy',
        'Protection action already in progress',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        protectionOperationInFlight:
            _protectionOperationInFlight || state.protectionOperationInFlight,
        protectionSelfTestInFlight:
            _protectionSelfTestInFlight || state.protectionSelfTestInFlight,
        errorMessage: message,
      );
      return;
    }
    if (await _rejectProtectionActionDuringUpdateMutation(
      eventType: 'protection_action_busy',
      title: 'Protection action already in progress',
      prefix: 'Protection action cannot run',
    )) {
      return;
    }
    _protectionOperationInFlight = true;
    state = state.copyWith(protectionOperationInFlight: true);
    try {
      try {
        await logEvent(
          restoringSavedPreference
              ? 'protection_restore_start_requested'
              : 'protection_start_requested',
          restoringSavedPreference
              ? 'Saved protection restore start requested'
              : 'Protection start requested',
          category: 'protection',
          severity: restoringSavedPreference ? 'warning' : 'info',
        );
        var configForStart = state.config;
        if (configForStart.protectionMode == ProtectionMode.off) {
          final recovered = configForStart.copyWith(
            protectionMode: ProtectionMode.balanced,
          );
          await _configRepository.save(recovered);
          configForStart = recovered;
          state = state.copyWith(config: recovered);
          await logEvent(
            'protection_mode_recovered',
            'Protection profile recovered',
            details:
                'Persisted Off profile was reset to Balanced before starting protection.',
            category: 'protection',
            severity: 'warning',
          );
        }
        state = state.copyWith(
          protectionStatus: ProtectionStatus.starting,
          loading: true,
          clearError: true,
        );
        await unawaitedCheckMalwareEngine();
        final engineDiagnosticWarning =
            state.lastEngineError?.trim().isEmpty ?? true
            ? null
            : 'Engine diagnostics require attention: ${_boundedUiDiagnostic(state.lastEngineError!)}.';
        final nativeEngineReadyWithoutDiagnostic =
            state.nativeEngineStatus == 'ready' &&
            engineDiagnosticWarning == null;
        final hasLocalPrevention =
            state.malwareEngineStatus == MalwareEngineStatus.available ||
            state.malwareEngineStatus ==
                MalwareEngineStatus.signaturesOutdated ||
            nativeEngineReadyWithoutDiagnostic ||
            configForStart.protectionMode == ProtectionMode.lockdown;
        if (hasLocalPrevention) {
          final modeResult = await _localCoreClient.configureGuardMode(
            configForStart.protectionMode,
          );
          final modeConfigured = modeResult.ok;
          final watchPlan = _realtimeWatchPathPlan();
          final watchPaths = watchPlan.paths;
          final watcher = watchPaths.isEmpty
              ? const RealtimeWatcherState(active: false, mode: 'off')
              : await _localCoreClient.startWatch(watchPaths);
          final watcherLimitations = [
            ...watchPlan.limitations,
            ...watcher.limitations,
          ];
          final modeError = modeResult.error == null
              ? null
              : _boundedUiDiagnostic(modeResult.error!);
          final watcherError = watcher.error == null
              ? null
              : _boundedUiDiagnostic(watcher.error!);
          final modeWarning = modeConfigured
              ? null
              : 'Avorax could not write the shared Guard mode config: $modeError. Existing service mode may remain active until the service is restarted or configured by installer.';
          final watcherWarning = watchPaths.isEmpty
              ? null
              : !watcher.active
              ? 'Best-effort folder watch plan did not start${watcherError == null ? '' : ': $watcherError'}.'
              : watcherError != null
              ? 'Best-effort folder watch plan was accepted with diagnostics: $watcherError.'
              : null;
          final watcherLimitationWarning = watcherLimitations.isEmpty
              ? null
              : 'Best-effort folder watch limitations: ${_boundedUiDiagnostic(watcherLimitations.join('; '))}.';
          final startDetails = watcher.active
              ? 'Watcher plan ${watcher.mode}: ${watcher.watchedPaths.join('; ')}'
              : 'Watcher not active';
          final localProtectionActive = modeConfigured || watcher.active;
          if (!localProtectionActive) {
            _stopWatchPollLoop();
            final startWarning = [
              ?modeWarning,
              ?watcherWarning,
              ?engineDiagnosticWarning,
              ?watcherLimitationWarning,
            ].join(' ').trim();
            final details = [
              startDetails,
              startWarning.isEmpty
                  ? 'No local protection layer reported active.'
                  : startWarning,
            ].join('\n');
            await logEvent(
              'protection_start_failed',
              'Protection start failed',
              details: details,
              category: 'protection',
              severity: 'error',
            );
            state = state.copyWith(
              protectionStatus: ProtectionStatus.error,
              loading: false,
              realtimeWatcherMode: watcher.mode,
              realtimeWatchedPaths: watcher.watchedPaths,
              realtimeWatcherLimitations: watcherLimitations,
              processSnapshotLoopStatus: 'off',
              processSnapshotLoopStatusReason:
                  'Protection did not start, so the app-lifetime process observation loop is off.',
              watchPollLoopStatus: 'off',
              watchPollLoopStatusReason:
                  'Protection did not start, so the finite watch-poll scan loop is off.',
              errorMessage: [
                'Unable to start protection: no local protection layer reported active.',
                if (startWarning.isNotEmpty) startWarning,
              ].join(' '),
            );
            return;
          }
          if (persistPreference && !state.config.realtimeProtectionEnabled) {
            final updated = configForStart.copyWith(
              realtimeProtectionEnabled: true,
            );
            await _configRepository.save(updated);
            state = state.copyWith(config: updated);
          }
          final processSnapshotLoopWarning = _startProcessSnapshotLoop();
          final watchPollLoopWarning = watcher.active
              ? _startWatchPollLoop(watcher.watchedPaths)
              : null;
          final startWarning = [
            ?modeWarning,
            ?watcherWarning,
            ?engineDiagnosticWarning,
            ?watcherLimitationWarning,
            ?processSnapshotLoopWarning,
            ?watchPollLoopWarning,
          ].join(' ').trim();
          await logEvent(
            startWarning.isEmpty
                ? 'protection_started'
                : 'protection_start_limited',
            startWarning.isEmpty
                ? 'Protection started'
                : 'Protection started with limitations',
            details: startWarning.isEmpty
                ? startDetails
                : '$startDetails\n$startWarning',
            category: 'protection',
            severity: startWarning.isEmpty ? 'info' : 'warning',
          );
          final engineFullyReady =
              state.malwareEngineStatus == MalwareEngineStatus.available &&
              nativeEngineReadyWithoutDiagnostic;
          final serviceBoundaryReady =
              !Platform.isWindows ||
              state.coreServiceBoundaryHealth.fullProtectionReady;
          state = state.copyWith(
            protectionStatus:
                state.driverStatus == 'running' &&
                    engineFullyReady &&
                    serviceBoundaryReady
                ? ProtectionStatus.protected
                : ProtectionStatus.partiallyProtected,
            loading: false,
            realtimeWatcherMode: watcher.mode,
            realtimeWatchedPaths: watcher.watchedPaths,
            realtimeWatcherLimitations: watcherLimitations,
            processSnapshotLoopStatus: processSnapshotLoopWarning == null
                ? 'active'
                : 'limited',
            processSnapshotLoopStatusReason:
                processSnapshotLoopWarning ??
                'App-lifetime process snapshots run every 2 minutes while protection is active.',
            watchPollLoopStatus: watcher.active
                ? watchPollLoopWarning == null
                      ? 'active'
                      : 'limited'
                : 'off',
            watchPollLoopStatusReason: watcher.active
                ? watchPollLoopWarning ??
                      'Finite user-mode watch-poll scans run every 1 minute while protection is active.'
                : 'Best-effort folder watch is off, so the finite watch-poll scan loop is off.',
            clearError:
                modeConfigured &&
                watcherWarning == null &&
                watcherLimitationWarning == null &&
                processSnapshotLoopWarning == null &&
                watchPollLoopWarning == null,
            errorMessage: [
              ?modeWarning,
              ?watcherWarning,
              ?engineDiagnosticWarning,
              ?watcherLimitationWarning,
              ?processSnapshotLoopWarning,
              ?watchPollLoopWarning,
            ].join(' '),
          );
          return;
        }
        _stopWatchPollLoop();
        final preventionFailureDetails = [
          'Malware engine unavailable.',
          ?engineDiagnosticWarning,
        ].join(' ').trim();
        await logEvent(
          'protection_start_failed',
          'Protection start failed',
          details: preventionFailureDetails,
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          protectionStatus: ProtectionStatus.error,
          loading: false,
          processSnapshotLoopStatus: 'off',
          processSnapshotLoopStatusReason:
              'Protection did not start because no local prevention engine is ready.',
          watchPollLoopStatus: 'off',
          watchPollLoopStatusReason:
              'Protection did not start because no local prevention engine is ready.',
          errorMessage: [
            'No local prevention engine is ready. Install the Avorax MSI or verify Avorax Native Engine assets.',
            ?engineDiagnosticWarning,
          ].join(' '),
        );
      } on Object catch (error) {
        _stopWatchPollLoop();
        _stopProcessSnapshotLoop();
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'protection_start_failed',
          'Protection start failed',
          details: details,
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          protectionStatus: ProtectionStatus.error,
          loading: false,
          processSnapshotLoopStatus: 'off',
          processSnapshotLoopStatusReason:
              'Protection did not start because start-up failed: $details',
          watchPollLoopStatus: 'off',
          watchPollLoopStatusReason:
              'Protection did not start because start-up failed: $details',
          errorMessage: 'Unable to start protection: $details',
        );
      }
    } finally {
      _protectionOperationInFlight = false;
      if (mounted) {
        state = state.copyWith(protectionOperationInFlight: false);
      }
    }
  }

  Future<void> stopProtection({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Stopping protection requires explicit confirmation because it turns off real-time monitoring.';
      await logEvent(
        'protection_stop_confirmation_required',
        'Protection stop confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (_protectionOperationInFlight ||
        state.protectionOperationInFlight ||
        _protectionSelfTestInFlight ||
        state.protectionSelfTestInFlight) {
      const message = 'Protection action is already in progress.';
      await logEvent(
        'protection_action_busy',
        'Protection action already in progress',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        protectionOperationInFlight:
            _protectionOperationInFlight || state.protectionOperationInFlight,
        protectionSelfTestInFlight:
            _protectionSelfTestInFlight || state.protectionSelfTestInFlight,
        errorMessage: message,
      );
      return;
    }
    if (await _rejectProtectionActionDuringUpdateMutation(
      eventType: 'protection_action_busy',
      title: 'Protection action already in progress',
      prefix: 'Protection action cannot run',
    )) {
      return;
    }
    _protectionOperationInFlight = true;
    state = state.copyWith(protectionOperationInFlight: true);
    try {
      try {
        state = state.copyWith(
          protectionStatus: ProtectionStatus.stopping,
          loading: true,
          clearError: true,
        );
        _stopWatchPollLoop();
        _stopProcessSnapshotLoop();
        state = state.copyWith(
          processSnapshotLoopStatus: 'off',
          processSnapshotLoopStatusReason:
              'Stop requested; app-lifetime process observation loop is off.',
          watchPollLoopStatus: 'off',
          watchPollLoopStatusReason:
              'Stop requested; finite watch-poll scan loop is off.',
        );
        final protectionRun = state.protectionRun;
        final modeResult = await _localCoreClient.configureGuardMode(
          ProtectionMode.off,
        );
        final modeConfigured = modeResult.ok;
        final watcher = await _localCoreClient.stopWatch();
        final watcherStopped = !watcher.active && watcher.error == null;
        final modeError = modeResult.error == null
            ? null
            : _boundedUiDiagnostic(modeResult.error!);
        final watcherError = watcher.error == null
            ? null
            : _boundedUiDiagnostic(watcher.error!);
        final watcherWarning = watcherError == null
            ? null
            : 'Avorax could not stop real-time folder monitoring cleanly: $watcherError.';
        final watcherStillActiveWarning = watcher.active
            ? 'Avorax local core reported that real-time folder monitoring is still active.'
            : null;
        final stopWarnings = [
          if (!modeConfigured)
            'Avorax could not write the shared Guard disabled config: $modeError. Protection remains enabled in saved settings so Avorax can retry on restart.',
          ?watcherWarning,
          ?watcherStillActiveWarning,
        ].join(' ');
        if (!modeConfigured || !watcherStopped) {
          await logEvent(
            'protection_stop_incomplete',
            'Protection stop incomplete',
            details: stopWarnings,
            category: 'protection',
            severity: 'error',
          );
          state = state.copyWith(
            protectionStatus: ProtectionStatus.error,
            loading: false,
            realtimeWatcherMode: watcher.mode,
            realtimeWatchedPaths: watcher.watchedPaths,
            realtimeWatcherLimitations: watcher.limitations,
            processSnapshotLoopStatus: 'off',
            processSnapshotLoopStatusReason:
                'Stop requested; app-lifetime process observation loop is off while stop errors are reported.',
            watchPollLoopStatus: 'off',
            watchPollLoopStatusReason:
                'Stop requested; finite watch-poll scan loop is off while stop errors are reported.',
            errorMessage: stopWarnings,
          );
          return;
        }
        String? runEndWarning;
        if (protectionRun != null) {
          final runEndResult = await _apiClient.endProtectionRun(
            state.config,
            protectionRun,
          );
          if (runEndResult is ApiFailure<void>) {
            runEndWarning =
                'Protection stopped locally, but the cloud protection run could not be closed: ${runEndResult.message}';
            await logEvent(
              'protection_run_end_failed',
              'Protection run end failed',
              details: runEndResult.message,
              category: 'protection',
              severity: 'warning',
            );
          }
        }
        final updated = state.config.copyWith(realtimeProtectionEnabled: false);
        await _configRepository.save(updated);
        state = state.copyWith(config: updated);
        await logEvent(
          'protection_stopped',
          'Protection stopped',
          details:
              'Guard mode disabled and real-time folder monitoring stopped locally.',
          category: 'protection',
          severity: 'info',
        );
        state = state.copyWith(
          clearProtectionRun: true,
          protectionStatus: ProtectionStatus.idle,
          heartbeat: const HeartbeatStatus(),
          realtimeWatcherMode: watcher.mode,
          realtimeWatchedPaths: watcher.watchedPaths,
          realtimeWatcherLimitations: watcher.limitations,
          processSnapshotLoopStatus: 'off',
          processSnapshotLoopStatusReason:
              'Protection is stopped; app-lifetime process observation loop is off.',
          watchPollLoopStatus: 'off',
          watchPollLoopStatusReason:
              'Protection is stopped; finite watch-poll scan loop is off.',
          loading: false,
          clearError: runEndWarning == null,
          errorMessage: runEndWarning,
        );
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'protection_stop_failed',
          'Protection stop failed',
          details: details,
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          protectionStatus: ProtectionStatus.error,
          loading: false,
          processSnapshotLoopStatus: 'off',
          processSnapshotLoopStatusReason:
              'Stop failed after the app-lifetime process observation loop was turned off: $details',
          watchPollLoopStatus: 'off',
          watchPollLoopStatusReason:
              'Stop failed after the finite watch-poll scan loop was turned off: $details',
          errorMessage:
              'Unable to stop protection cleanly: $details. Check Windows Services if Avorax services are still running.',
        );
      }
    } finally {
      _protectionOperationInFlight = false;
      if (mounted) {
        state = state.copyWith(protectionOperationInFlight: false);
      }
    }
  }

  Future<bool> setProtectionMode(
    ProtectionMode mode, {
    bool confirmed = false,
  }) async {
    if (mode == ProtectionMode.off) {
      const message =
          'Use Stop protection to turn protection off; protection profile cannot be set to Off directly.';
      await logEvent(
        'protection_mode_change_failed',
        'Protection profile change failed',
        details: message,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!confirmed) {
      const message =
          'Protection profile changes require explicit confirmation because they alter Guard behavior and local protection policy.';
      await logEvent(
        'protection_mode_confirmation_required',
        'Protection profile confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!await _beginSecuritySettingsAction(mode.label)) return false;
    var guardModeApplied = false;
    final previousMode = state.config.protectionMode;
    try {
      final updated = state.config.copyWith(protectionMode: mode);
      final modeResult = await _localCoreClient.configureGuardMode(mode);
      if (!modeResult.ok) {
        final details = _boundedUiDiagnostic(
          modeResult.error ?? 'Guard mode config failed.',
        );
        final message =
            'Avorax could not write the shared Guard mode config: $details.';
        await logEvent(
          'protection_mode_change_failed',
          'Protection profile change failed',
          details: message,
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(errorMessage: message);
        return false;
      }
      guardModeApplied = true;
      await _configRepository.save(updated);
      await logEvent(
        'protection_mode_changed',
        'Protection profile changed',
        details: mode.label,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(config: updated, clearError: true);
      return true;
    } on Object catch (error) {
      var rollbackDetails = '';
      if (guardModeApplied) {
        try {
          final rollbackResult = await _localCoreClient.configureGuardMode(
            previousMode,
          );
          rollbackDetails = rollbackResult.ok
              ? 'Rolled Guard mode back to the previous profile.'
              : 'Guard mode rollback failed: ${_boundedUiDiagnostic(rollbackResult.error ?? 'Rollback failed.')}.';
        } on Object catch (rollbackError) {
          rollbackDetails =
              'Guard mode rollback failed: ${_boundedUiDiagnostic(rollbackError)}.';
        }
      }
      final primaryDetails = _boundedUiDiagnostic(error);
      final details = rollbackDetails.isEmpty
          ? primaryDetails
          : '$primaryDetails\n$rollbackDetails';
      await logEvent(
        'protection_mode_change_failed',
        'Protection profile change failed',
        details: details,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: rollbackDetails.isEmpty
            ? 'Unable to save protection profile: $primaryDetails'
            : 'Unable to save protection profile: $primaryDetails $rollbackDetails',
      );
      return false;
    } finally {
      _endSecuritySettingsAction();
    }
  }

  Future<bool> updateRansomwareGuardSettings({
    required List<String> protectedRoots,
    required List<String> trustedProcesses,
    bool confirmed = false,
  }) async {
    if (!confirmed) {
      const message =
          'Ransomware guard settings changes require explicit confirmation because they alter protected folders and trusted process allowlist policy.';
      await logEvent(
        'ransomware_guard_settings_confirmation_required',
        'Ransomware guard settings confirmation required',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!await _beginSecuritySettingsAction('Ransomware guard settings')) {
      return false;
    }
    var corePolicyApplied = false;
    var previousRoots = const <String>[];
    var previousTrustedProcesses = const <String>[];
    try {
      previousRoots = List<String>.of(state.config.ransomwareProtectedRoots);
      previousTrustedProcesses = List<String>.of(
        state.config.ransomwareTrustedProcesses,
      );
      final normalizedRoots = _normalizeUserPaths(protectedRoots);
      final normalizedTrustedProcesses = _normalizeUserPaths(trustedProcesses);
      final updated = state.config.copyWith(
        ransomwareProtectedRoots: normalizedRoots,
        ransomwareTrustedProcesses: normalizedTrustedProcesses,
      );
      final coreResult = await _localCoreClient.configureRansomwareGuard(
        protectedRoots: normalizedRoots,
        trustedProcesses: normalizedTrustedProcesses,
      );
      if (!coreResult.ok) {
        final details = _boundedUiDiagnostic(
          coreResult.error ?? 'Guard policy config failed.',
        );
        final message =
            'Avorax could not write the shared guard policy config: $details.';
        await logEvent(
          'ransomware_guard_settings_failed',
          'Ransomware guard settings change failed',
          details: message,
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(errorMessage: message);
        return false;
      }
      corePolicyApplied = true;
      await _configRepository.save(updated);
      await logEvent(
        'ransomware_guard_settings_changed',
        'Ransomware guard settings changed',
        details:
            '${normalizedRoots.length} protected roots; ${normalizedTrustedProcesses.length} trusted processes',
        category: 'protection',
        severity: 'info',
      );
      state = state.copyWith(config: updated, clearError: true);
      return true;
    } on Object catch (error) {
      var rollbackDetails = '';
      if (corePolicyApplied) {
        try {
          final rollbackResult = await _localCoreClient
              .configureRansomwareGuard(
                protectedRoots: previousRoots,
                trustedProcesses: previousTrustedProcesses,
              );
          rollbackDetails = rollbackResult.ok
              ? 'Rolled guard policy back to the previous settings.'
              : 'Guard policy rollback failed: ${_boundedUiDiagnostic(rollbackResult.error ?? 'Rollback failed.')}.';
        } on Object catch (rollbackError) {
          rollbackDetails =
              'Guard policy rollback failed: ${_boundedUiDiagnostic(rollbackError)}.';
        }
      }
      final primaryDetails = _boundedUiDiagnostic(error);
      final details = rollbackDetails.isEmpty
          ? primaryDetails
          : '$primaryDetails\n$rollbackDetails';
      await logEvent(
        'ransomware_guard_settings_failed',
        'Ransomware guard settings change failed',
        details: details,
        category: 'protection',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: rollbackDetails.isEmpty
            ? 'Unable to save ransomware guard settings: $primaryDetails'
            : 'Unable to save ransomware guard settings: $primaryDetails $rollbackDetails',
      );
      return false;
    } finally {
      _endSecuritySettingsAction();
    }
  }

  Future<bool> updateScheduledQuickScanSettings({
    required bool enabled,
    required int intervalHours,
    bool confirmed = false,
  }) async {
    if (intervalHours < ZentorConfig.minScheduledQuickScanIntervalHours ||
        intervalHours > ZentorConfig.maxScheduledQuickScanIntervalHours) {
      final message =
          'Scheduled quick scan interval must be between '
          '${ZentorConfig.minScheduledQuickScanIntervalHours} and '
          '${ZentorConfig.maxScheduledQuickScanIntervalHours} hours.';
      await logEvent(
        'scheduled_quick_scan_settings_failed',
        'Scheduled quick scan settings change failed',
        details: message,
        category: 'scan',
        severity: 'error',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!confirmed) {
      const message =
          'Scheduled quick scan settings require explicit confirmation because they can start recurring in-app scans while Avorax is open.';
      await logEvent(
        'scheduled_quick_scan_confirmation_required',
        'Scheduled quick scan confirmation required',
        details: message,
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (!await _beginSecuritySettingsAction('Scheduled quick scan settings')) {
      return false;
    }
    Timer? pendingScheduledQuickScanTimer;
    try {
      final updated = state.config.copyWith(
        scheduledQuickScanEnabled: enabled,
        scheduledQuickScanIntervalHours: intervalHours,
      );
      pendingScheduledQuickScanTimer = _createScheduledQuickScanTimer(updated);
      await _configRepository.save(updated);
      _replaceScheduledQuickScanTimer(pendingScheduledQuickScanTimer);
      pendingScheduledQuickScanTimer = null;
      await logEvent(
        'scheduled_quick_scan_settings_changed',
        'Scheduled quick scan settings changed',
        details: enabled
            ? 'In-app quick scan every $intervalHours hour(s)'
            : 'In-app quick scan disabled',
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(config: updated, clearError: true);
      return true;
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'scheduled_quick_scan_settings_failed',
        'Scheduled quick scan settings change failed',
        details: details,
        category: 'scan',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Unable to save scheduled quick scan settings: $details',
      );
      return false;
    } finally {
      pendingScheduledQuickScanTimer?.cancel();
      _endSecuritySettingsAction();
    }
  }

  Future<bool> _beginSecuritySettingsAction(String target) async {
    final protectionBusy =
        _protectionOperationInFlight ||
        state.protectionOperationInFlight ||
        _protectionSelfTestInFlight ||
        state.protectionSelfTestInFlight;
    if (protectionBusy) {
      const message =
          'Security settings cannot be changed while protection state is changing or self-test is running.';
      await logEvent(
        'security_settings_action_busy',
        'Security settings change already in progress',
        details: target.trim().isEmpty ? message : '$target\n$message',
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        protectionOperationInFlight:
            _protectionOperationInFlight || state.protectionOperationInFlight,
        protectionSelfTestInFlight:
            _protectionSelfTestInFlight || state.protectionSelfTestInFlight,
        errorMessage: message,
      );
      return false;
    }
    if (_configurationResetInFlight || state.configurationResetInFlight) {
      const message =
          'Security settings cannot be changed while configuration reset is in progress.';
      await logEvent(
        'security_settings_action_busy',
        'Security settings change already in progress',
        details: target.trim().isEmpty ? message : '$target\n$message',
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        configurationResetInFlight:
            _configurationResetInFlight || state.configurationResetInFlight,
        errorMessage: message,
      );
      return false;
    }
    final scanBusyReason = _scanBusyReasonForConfigurationMutation(
      'Security settings cannot be changed',
    );
    if (scanBusyReason != null) {
      await logEvent(
        'security_settings_action_busy',
        'Security settings change already in progress',
        details: target.trim().isEmpty
            ? scanBusyReason
            : '$target\n$scanBusyReason',
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        scanStartInFlight: _scanStartInFlight || state.scanStartInFlight,
        scanTargetSelectionInFlight:
            _scanTargetSelectionInFlight || state.scanTargetSelectionInFlight,
        scanCancelInFlight: _scanCancelInFlight || state.scanCancelInFlight,
        errorMessage: scanBusyReason,
      );
      return false;
    }
    final updateBusyReason = _configurationMutationUpdateBusyReason(
      'Security settings cannot be changed',
    );
    if (updateBusyReason != null) {
      await logEvent(
        'security_settings_action_busy',
        'Security settings change already in progress',
        details: target.trim().isEmpty
            ? updateBusyReason
            : '$target\n$updateBusyReason',
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        updateOperationInFlight:
            _updateOperationInFlight || state.updateOperationInFlight,
        errorMessage: updateBusyReason,
      );
      return false;
    }
    final manualActionBusyReason = _manualDispositionBusyReason(
      'Security settings cannot be changed',
    );
    if (manualActionBusyReason != null) {
      await logEvent(
        'security_settings_action_busy',
        'Security settings change already in progress',
        details: target.trim().isEmpty
            ? manualActionBusyReason
            : '$target\n$manualActionBusyReason',
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        quarantineActionInFlight:
            _quarantineActionInFlight || state.quarantineActionInFlight,
        allowlistActionInFlight:
            _allowlistActionInFlight || state.allowlistActionInFlight,
        detectionFeedbackInFlight:
            _detectionFeedbackInFlight || state.detectionFeedbackInFlight,
        errorMessage: manualActionBusyReason,
      );
      return false;
    }
    if (_securitySettingsActionInFlight) {
      const message = 'Security settings change is already in progress.';
      await logEvent(
        'security_settings_action_busy',
        'Security settings change already in progress',
        details: target.trim().isEmpty ? message : '$target\n$message',
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        securitySettingsActionInFlight: true,
        errorMessage: message,
      );
      return false;
    }
    _securitySettingsActionInFlight = true;
    state = state.copyWith(securitySettingsActionInFlight: true);
    return true;
  }

  void _endSecuritySettingsAction() {
    _securitySettingsActionInFlight = false;
    if (mounted) {
      state = state.copyWith(securitySettingsActionInFlight: false);
    }
  }

  String? _manualDispositionBusyReason(String prefix) {
    if (_quarantineActionInFlight || state.quarantineActionInFlight) {
      return '$prefix while a quarantine action is in progress.';
    }
    if (_allowlistActionInFlight || state.allowlistActionInFlight) {
      return '$prefix while an allowlist action is in progress.';
    }
    if (_detectionFeedbackInFlight || state.detectionFeedbackInFlight) {
      return '$prefix while detection feedback is in progress.';
    }
    return null;
  }

  String? _scanBusyReasonForConfigurationMutation(String prefix) {
    if (_scanStartInFlight || state.scanStartInFlight) {
      return '$prefix while a scan is starting.';
    }
    if (state.scanStatus == ScanStatus.running) {
      return '$prefix while a scan is running.';
    }
    if (_scanTargetSelectionInFlight || state.scanTargetSelectionInFlight) {
      return '$prefix while scan target selection is in progress.';
    }
    if (_scanCancelInFlight || state.scanCancelInFlight) {
      return '$prefix while scan cancellation is in progress.';
    }
    return null;
  }

  void _configureScheduledQuickScan(ZentorConfig config) {
    _replaceScheduledQuickScanTimer(_createScheduledQuickScanTimer(config));
  }

  Timer? _createScheduledQuickScanTimer(ZentorConfig config) {
    if (!config.scheduledQuickScanEnabled) return null;
    final intervalHours = config.scheduledQuickScanIntervalHours;
    if (intervalHours < ZentorConfig.minScheduledQuickScanIntervalHours ||
        intervalHours > ZentorConfig.maxScheduledQuickScanIntervalHours) {
      throw RangeError.range(
        intervalHours,
        ZentorConfig.minScheduledQuickScanIntervalHours,
        ZentorConfig.maxScheduledQuickScanIntervalHours,
        'scheduledQuickScanIntervalHours',
      );
    }
    return _scheduledQuickScanTimerFactory(
      Duration(hours: intervalHours),
      (_) => _runScheduledQuickScanSafely(),
    );
  }

  void _replaceScheduledQuickScanTimer(Timer? timer) {
    _scheduledQuickScanTimer?.cancel();
    _scheduledQuickScanTimer = timer;
  }

  void _runScheduledQuickScanSafely() {
    unawaited(
      _runScheduledQuickScan().catchError((Object error) async {
        if (!mounted) return;
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'scheduled_quick_scan_failed',
          'Scheduled quick scan failed',
          details: details,
          category: 'scan',
          severity: 'error',
        );
        if (!mounted) return;
        state = state.copyWith(
          errorMessage: 'Scheduled quick scan failed: $details',
        );
      }),
    );
  }

  Future<void> _runScheduledQuickScan() async {
    if (!mounted) return;
    final busyReason = _scheduledQuickScanBusyReason();
    if (busyReason != null) {
      await logEvent(
        'scheduled_quick_scan_skipped',
        'Scheduled quick scan skipped',
        details: busyReason,
        category: 'scan',
        severity: 'warning',
      );
      return;
    }
    final scheduledScanDiagnostic =
        state.lastEngineError?.trim().isEmpty ?? true
        ? null
        : 'Engine diagnostics require attention: '
              '${_boundedUiDiagnostic(state.lastEngineError!)}.';
    await logEvent(
      'scheduled_quick_scan_started',
      'Scheduled quick scan started',
      details: scheduledScanDiagnostic,
      category: 'scan',
      severity: scheduledScanDiagnostic == null ? 'info' : 'warning',
    );
    await runQuickScan(actionMode: ScanActionMode.detectOnly);
  }

  String? _scheduledQuickScanBusyReason() {
    if (_scanStartInFlight || state.scanStatus == ScanStatus.running) {
      return 'A scan is already running.';
    }
    if (_scanTargetSelectionInFlight || state.scanTargetSelectionInFlight) {
      return 'Scan target selection is already in progress.';
    }
    final updateBusyReason = _scanUpdateMutationBusyReason();
    if (updateBusyReason != null) return updateBusyReason;
    return null;
  }

  List<String> _normalizeUserPaths(List<String> paths) {
    final normalized = <String>[];
    for (final raw in paths) {
      if (_runtimePathListControlPattern.hasMatch(raw)) {
        throw FormatException(
          'Path entries must not contain control characters.',
        );
      }
      final value = raw.trim().replaceAll('\\\\', '/');
      if (value.isEmpty || normalized.contains(value)) continue;
      if (value.length > ZentorConfig.maxConfigStringListEntryLength) {
        throw FormatException(
          'Path entries must be at most '
          '${ZentorConfig.maxConfigStringListEntryLength} characters.',
        );
      }
      normalized.add(value);
      if (normalized.length > ZentorConfig.maxConfigStringListEntries) {
        throw FormatException(
          'Path lists must contain at most '
          '${ZentorConfig.maxConfigStringListEntries} entries.',
        );
      }
    }
    return normalized;
  }

  Future<void> runProtectionSelfTest() async {
    if (_protectionSelfTestInFlight ||
        state.protectionSelfTestInFlight ||
        _protectionOperationInFlight ||
        state.protectionOperationInFlight) {
      const message =
          'Protection self-test is already in progress or protection state is changing.';
      await logEvent(
        'protection_self_test_busy',
        'Protection self-test already in progress',
        details: message,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        protectionSelfTestInFlight:
            _protectionSelfTestInFlight || state.protectionSelfTestInFlight,
        errorMessage: message,
      );
      return;
    }
    if (await _rejectProtectionActionDuringUpdateMutation(
      eventType: 'protection_self_test_busy',
      title: 'Protection self-test already in progress',
      prefix: 'Protection self-test cannot run',
    )) {
      return;
    }
    _protectionSelfTestInFlight = true;
    try {
      try {
        await logEvent(
          'protection_self_test_started',
          'Protection self-test started',
          category: 'protection',
          severity: 'info',
        );
        state = state.copyWith(
          loading: true,
          protectionSelfTestInFlight: true,
          clearError: true,
        );
        final result = await _localCoreClient.runProtectionSelfTest();
        final failed =
            result.contains('FAIL') ||
            result.toLowerCase().contains('failed') ||
            result.toLowerCase().contains('not active');
        await logEvent(
          'protection_self_test_completed',
          failed
              ? 'Protection self-test completed with issues'
              : 'Protection self-test completed',
          details: result,
          category: 'protection',
          severity: failed ? 'warning' : 'info',
        );
        state = state.copyWith(
          loading: false,
          protectionSelfTestResult: result,
          clearError: !failed,
          errorMessage: failed
              ? 'Protection self-test completed with issues. See the self-test result panel for exact failing checks.'
              : null,
        );
        await unawaitedCheckMalwareEngine();
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'protection_self_test_failed',
          'Protection self-test failed',
          details: details,
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          loading: false,
          protectionSelfTestResult: 'Protection self-test failed: $details',
          errorMessage: 'Unable to run protection self-test: $details',
        );
      }
    } finally {
      _protectionSelfTestInFlight = false;
      if (mounted) {
        state = state.copyWith(protectionSelfTestInFlight: false);
      }
    }
  }

  Future<void> sendHeartbeat() async {
    final protectionRun = state.protectionRun;
    if (protectionRun == null) return;
    if (state.heartbeat.inFlight) return;
    state = state.copyWith(heartbeat: state.heartbeat.copyWith(inFlight: true));
    try {
      final result = await _apiClient.sendHeartbeat(
        state.config,
        protectionRun,
      );
      switch (result) {
        case ApiSuccess<void>():
          await logEvent(
            'heartbeat_sent',
            'Heartbeat sent',
            category: 'protection',
            severity: 'info',
          );
          state = state.copyWith(
            heartbeat: HeartbeatStatus(lastSentAt: DateTime.now().toUtc()),
          );
        case ApiFailure<void>(:final message):
          await logEvent(
            'heartbeat_failed',
            'Heartbeat failed',
            details: message,
            category: 'protection',
            severity: 'warning',
          );
          state = state.copyWith(
            heartbeat: state.heartbeat.copyWith(
              inFlight: false,
              lastError: message,
            ),
          );
      }
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'heartbeat_failed',
        'Heartbeat failed',
        details: details,
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        heartbeat: state.heartbeat.copyWith(
          inFlight: false,
          lastError: details,
        ),
      );
    }
  }

  void setScanActionMode(ScanActionMode mode) {
    final targetSelectionBusy =
        _scanTargetSelectionInFlight || state.scanTargetSelectionInFlight;
    if (_scanStartInFlight ||
        state.scanStatus == ScanStatus.running ||
        targetSelectionBusy) {
      final message = targetSelectionBusy
          ? 'Scan action mode cannot be changed while scan target selection is in progress.'
          : 'Scan action mode cannot be changed while a scan is running.';
      unawaited(
        logEvent(
          'scan_action_mode_change_blocked',
          'Scan action mode change blocked',
          details: '${mode.label}\n$message',
          category: 'scan',
          severity: 'warning',
        ),
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    state = state.copyWith(scanActionMode: mode, clearError: true);
    unawaited(
      logEvent(
        'scan_action_mode_changed',
        'Scan action mode changed',
        details: mode.label,
        category: 'scan',
        severity: mode == ScanActionMode.detectOnly ? 'info' : 'warning',
      ),
    );
  }

  bool _scanModeMayQuarantine(ScanActionMode actionMode) {
    return actionMode != ScanActionMode.detectOnly;
  }

  Future<bool> _ensureScanAutoActionConfirmed({
    required ScanKind kind,
    required ScanActionMode actionMode,
    required bool confirmedAutoAction,
  }) async {
    if (!_scanModeMayQuarantine(actionMode) || confirmedAutoAction) {
      return true;
    }
    const message =
        'Starting a scan with automatic quarantine requires explicit confirmation because Avorax may move confirmed threats into quarantine during the scan.';
    await logEvent(
      'scan_auto_action_confirmation_required',
      'Scan auto-action confirmation required',
      details: '${kind.label}: ${actionMode.label}\n$message',
      category: 'scan',
      severity: 'warning',
    );
    state = state.copyWith(errorMessage: message);
    return false;
  }

  Future<void> scanSelectedFile({bool confirmedAutoAction = false}) async {
    if (await _rejectScanStartDuringConfigurationChange('Custom file scan')) {
      return;
    }
    if (await _rejectScanStartDuringUpdateMutation('Custom file scan')) {
      return;
    }
    final actionMode = state.scanActionMode;
    if (!await _ensureScanAutoActionConfirmed(
      kind: ScanKind.custom,
      actionMode: actionMode,
      confirmedAutoAction: confirmedAutoAction,
    )) {
      return;
    }
    if (!_localCoreClient.isDesktop) {
      const message =
          'Malware quarantine is not available on this platform because mobile OS sandboxing prevents full-device scanning.';
      await logEvent(
        'scan_file_unavailable',
        'Custom file scan unavailable',
        details: message,
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(
        scanStatus: ScanStatus.engineUnavailable,
        lastScanReport: _engineUnavailableScanReport(
          ScanKind.custom,
          actionMode,
          message,
        ),
        errorMessage: message,
      );
      return;
    }
    if (!await _beginScanTargetSelection('Custom file scan')) return;
    try {
      final file = await _fileSelectionService.pickFile();
      if (file == null) return;
      await _scanPaths(
        [file.path],
        kind: ScanKind.custom,
        actionMode: actionMode,
      );
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'scan_file_picker_failed',
        'Custom scan file selection failed',
        details: details,
        category: 'scan',
        severity: 'error',
      );
      state = state.copyWith(
        scanStatus: ScanStatus.failed,
        errorMessage: 'Unable to select a file for scanning: $details',
      );
    } finally {
      _endScanTargetSelection();
    }
  }

  Future<void> rescanQuarantineOriginal(QuarantineRecord item) async {
    final displayPath = _boundedQuarantinePath(item.originalPath);
    if (item.status == QuarantineItemStatus.quarantined) {
      const message =
          'Rescan is available after restore or deletion status changes. Active quarantine payloads stay isolated and are not executed or scanned through their opaque storage path.';
      await logEvent(
        'quarantine_rescan_unavailable',
        'Quarantine rescan unavailable',
        details: '$displayPath\n$message',
        category: 'quarantine',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (await _rejectScanStartDuringTargetSelection(
      'Quarantine original rescan',
    )) {
      return;
    }
    if (await _rejectScanStartDuringConfigurationChange(
      'Quarantine original rescan',
    )) {
      return;
    }
    if (await _rejectScanStartDuringUpdateMutation(
      'Quarantine original rescan',
    )) {
      return;
    }
    await logEvent(
      'quarantine_original_rescan_requested',
      'Quarantine original rescan requested',
      details: '$displayPath\nDetect-only custom scan of the original path.',
      category: 'scan',
      severity: 'warning',
    );
    await _scanPaths(
      [item.originalPath],
      kind: ScanKind.custom,
      actionMode: ScanActionMode.detectOnly,
    );
  }

  Future<void> scanSelectedFolder({bool confirmedAutoAction = false}) async {
    if (await _rejectScanStartDuringConfigurationChange('Custom folder scan')) {
      return;
    }
    if (await _rejectScanStartDuringUpdateMutation('Custom folder scan')) {
      return;
    }
    final actionMode = state.scanActionMode;
    if (!await _ensureScanAutoActionConfirmed(
      kind: ScanKind.custom,
      actionMode: actionMode,
      confirmedAutoAction: confirmedAutoAction,
    )) {
      return;
    }
    if (!_localCoreClient.isDesktop) {
      const message =
          'Malware quarantine is not available on this platform because mobile OS sandboxing prevents full-device scanning.';
      await logEvent(
        'scan_folder_unavailable',
        'Custom folder scan unavailable',
        details: message,
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(
        scanStatus: ScanStatus.engineUnavailable,
        lastScanReport: _engineUnavailableScanReport(
          ScanKind.custom,
          actionMode,
          message,
        ),
        errorMessage: message,
      );
      return;
    }
    if (!await _beginScanTargetSelection('Custom folder scan')) return;
    try {
      final path = await _fileSelectionService.pickDirectory();
      if (path == null) return;
      await _scanPaths([path], kind: ScanKind.custom, actionMode: actionMode);
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'scan_folder_picker_failed',
        'Custom scan folder selection failed',
        details: details,
        category: 'scan',
        severity: 'error',
      );
      state = state.copyWith(
        scanStatus: ScanStatus.failed,
        errorMessage: 'Unable to select a folder for scanning: $details',
      );
    } finally {
      _endScanTargetSelection();
    }
  }

  Future<bool> _beginScanTargetSelection(String target) async {
    final busyReason = _scanTargetSelectionBusyReason();
    if (busyReason != null) {
      await logEvent(
        'scan_target_selection_busy',
        'Scan target selection already in progress',
        details: target.trim().isEmpty ? busyReason : '$target\n$busyReason',
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(
        scanTargetSelectionInFlight:
            _scanTargetSelectionInFlight || state.scanTargetSelectionInFlight,
        errorMessage: busyReason,
      );
      return false;
    }
    _scanTargetSelectionInFlight = true;
    state = state.copyWith(scanTargetSelectionInFlight: true);
    return true;
  }

  String? _scanTargetSelectionBusyReason() {
    if (_scanTargetSelectionInFlight || state.scanTargetSelectionInFlight) {
      return 'Scan target selection is already in progress.';
    }
    if (_scanStartInFlight || state.scanStartInFlight) {
      return 'A scan is already starting.';
    }
    if (state.scanStatus == ScanStatus.running) {
      return 'A scan is already running.';
    }
    return null;
  }

  void _endScanTargetSelection() {
    _scanTargetSelectionInFlight = false;
    if (mounted) {
      state = state.copyWith(scanTargetSelectionInFlight: false);
    }
  }

  Future<void> runQuickScan({
    ScanActionMode? actionMode,
    bool confirmedAutoAction = false,
  }) async {
    if (await _rejectScanStartDuringTargetSelection('Quick scan')) return;
    if (await _rejectScanStartDuringConfigurationChange('Quick scan')) return;
    if (await _rejectScanStartDuringUpdateMutation('Quick scan')) return;
    final effectiveActionMode = actionMode ?? state.scanActionMode;
    if (!await _ensureScanAutoActionConfirmed(
      kind: ScanKind.quick,
      actionMode: effectiveActionMode,
      confirmedAutoAction: confirmedAutoAction,
    )) {
      return;
    }
    final targetPlan = _scanTargetService.quickScanTargetPlan();
    final paths = targetPlan.paths;
    if (paths.isEmpty) {
      await logEvent(
        'scan_completed',
        'Scan completed',
        details: 'No quick scan locations were accessible.',
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(
        scanStatus: ScanStatus.completedWithErrors,
        lastScanReport: ScanReport(
          status: ScanStatus.completedWithErrors,
          kind: ScanKind.quick,
          actionMode: effectiveActionMode,
          filesScanned: 0,
          threatsFound: 0,
          skippedFiles: 0,
          elapsedMs: 0,
          message: 'No quick scan locations were accessible.',
          threats: const [],
        ),
        errorMessage: 'No quick scan locations were accessible.',
      );
      return;
    }
    await _scanPaths(
      paths,
      kind: ScanKind.quick,
      actionMode: effectiveActionMode,
      targetLimitations: targetPlan.limitations,
    );
  }

  Future<void> runFullScan({
    ScanActionMode? actionMode,
    bool confirmedAutoAction = false,
  }) async {
    if (await _rejectScanStartDuringTargetSelection('Full scan')) return;
    if (await _rejectScanStartDuringConfigurationChange('Full scan')) return;
    if (await _rejectScanStartDuringUpdateMutation('Full scan')) return;
    final effectiveActionMode = actionMode ?? state.scanActionMode;
    if (!await _ensureScanAutoActionConfirmed(
      kind: ScanKind.full,
      actionMode: effectiveActionMode,
      confirmedAutoAction: confirmedAutoAction,
    )) {
      return;
    }
    final targetPlan = _scanTargetService.fullScanRootPlan();
    final paths = targetPlan.paths;
    if (paths.isEmpty) {
      const message = 'No full scan roots were accessible.';
      await logEvent(
        'scan_targets_unavailable',
        'Full scan targets unavailable',
        details: message,
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(
        scanStatus: ScanStatus.completedWithErrors,
        lastScanReport: ScanReport(
          status: ScanStatus.completedWithErrors,
          kind: ScanKind.full,
          actionMode: effectiveActionMode,
          filesScanned: 0,
          threatsFound: 0,
          skippedFiles: 0,
          elapsedMs: 0,
          message: message,
          threats: const [],
        ),
        errorMessage: message,
      );
      return;
    }
    await _scanPaths(
      paths,
      kind: ScanKind.full,
      actionMode: effectiveActionMode,
      targetLimitations: targetPlan.limitations,
    );
  }

  Future<bool> _rejectScanStartDuringTargetSelection(String target) async {
    if (!_scanTargetSelectionInFlight && !state.scanTargetSelectionInFlight) {
      return false;
    }
    const message = 'Scan target selection is already in progress.';
    await logEvent(
      'scan_start_ignored',
      'Scan start ignored',
      details: target.trim().isEmpty ? message : '$target\n$message',
      category: 'scan',
      severity: 'warning',
    );
    state = state.copyWith(errorMessage: message);
    return true;
  }

  Future<bool> _rejectScanStartDuringConfigurationChange(String target) async {
    final busyReason = _scanConfigurationBusyReason();
    if (busyReason == null) return false;
    await logEvent(
      'scan_start_ignored',
      'Scan start ignored',
      details: target.trim().isEmpty ? busyReason : '$target\n$busyReason',
      category: 'scan',
      severity: 'warning',
    );
    state = state.copyWith(
      securitySettingsActionInFlight:
          _securitySettingsActionInFlight ||
          state.securitySettingsActionInFlight,
      configurationResetInFlight:
          _configurationResetInFlight || state.configurationResetInFlight,
      errorMessage: busyReason,
    );
    return true;
  }

  Future<bool> _rejectScanStartDuringUpdateMutation(String target) async {
    final busyReason = _scanUpdateMutationBusyReason();
    if (busyReason == null) return false;
    await logEvent(
      'scan_start_ignored',
      'Scan start ignored',
      details: target.trim().isEmpty ? busyReason : '$target\n$busyReason',
      category: 'scan',
      severity: 'warning',
    );
    state = state.copyWith(
      updateOperationInFlight:
          _updateOperationInFlight || state.updateOperationInFlight,
      errorMessage: busyReason,
    );
    return true;
  }

  String? _scanUpdateMutationBusyReason() {
    final status = state.updateStatus;
    if (!_isUpdateMutationStatusBusy(status)) return null;
    return 'Scan cannot start while update package work is in progress: ${status.label}.';
  }

  String? _scanConfigurationBusyReason() {
    if (_configurationResetInFlight || state.configurationResetInFlight) {
      return 'Configuration reset is in progress.';
    }
    if (_securitySettingsActionInFlight ||
        state.securitySettingsActionInFlight) {
      return 'Security settings change is in progress.';
    }
    return null;
  }

  String? _configurationMutationUpdateBusyReason(String prefix) {
    final status = state.updateStatus;
    if (!_isUpdateMutationStatusBusy(status)) return null;
    return '$prefix while update package work is in progress: ${status.label}.';
  }

  Future<bool> _rejectManualDispositionDuringUpdateMutation({
    required String target,
    required String eventType,
    required String eventTitle,
    required String category,
    required String prefix,
  }) async {
    final busyReason = _configurationMutationUpdateBusyReason(prefix);
    if (busyReason == null) return false;
    await logEvent(
      eventType,
      eventTitle,
      details: target.trim().isEmpty ? busyReason : '$target\n$busyReason',
      category: category,
      severity: 'warning',
    );
    state = state.copyWith(
      updateOperationInFlight:
          _updateOperationInFlight || state.updateOperationInFlight,
      errorMessage: busyReason,
    );
    return true;
  }

  Future<bool> _rejectDuringConfigurationChange({
    required String target,
    required String eventType,
    required String eventTitle,
    required String category,
  }) async {
    final busyReason = _scanConfigurationBusyReason();
    if (busyReason == null) return false;
    await logEvent(
      eventType,
      eventTitle,
      details: target.trim().isEmpty ? busyReason : '$target\n$busyReason',
      category: category,
      severity: 'warning',
    );
    state = state.copyWith(
      securitySettingsActionInFlight:
          _securitySettingsActionInFlight ||
          state.securitySettingsActionInFlight,
      configurationResetInFlight:
          _configurationResetInFlight || state.configurationResetInFlight,
      errorMessage: busyReason,
    );
    return true;
  }

  Future<void> quarantineThreat(
    ThreatResult threat, {
    bool confirmed = false,
  }) async {
    if (!confirmed) {
      const message =
          'Manual quarantine requires explicit confirmation because Avorax will move the file into isolated storage.';
      await logEvent(
        'quarantine_confirmation_required',
        'Quarantine confirmation required',
        details: '${threat.path}\n$message',
        category: 'quarantine',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!await _beginQuarantineAction(threat.path)) return;
    try {
      LocalCoreActionResult result;
      try {
        result = await _localCoreClient.quarantineThreat(threat);
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'quarantine_failed',
          'Quarantine failed',
          details: '${threat.path}\n$details',
          category: 'quarantine',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to quarantine ${threat.fileName}: $details',
        );
        return;
      }
      if (!result.ok) {
        final details = _boundedUiDiagnostic(
          result.error ?? 'Quarantine failed.',
        );
        await logEvent(
          'quarantine_failed',
          'Quarantine failed',
          details: '${threat.path}\n$details',
          category: 'quarantine',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to quarantine ${threat.fileName}: $details',
        );
        return;
      }
      await logEvent(
        'file_quarantined',
        'File quarantined',
        details: threat.path,
        category: 'quarantine',
        severity: 'warning',
      );
      _replaceThreat(
        threat.id,
        threat.copyWith(status: ThreatResultStatus.quarantined),
      );
      await unawaitedRefreshQuarantine();
    } finally {
      _endQuarantineAction();
    }
  }

  Future<void> quarantineSelectedFile({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Manual file quarantine requires explicit confirmation before Avorax opens a file picker and moves the selected file into isolated storage.';
      await logEvent(
        'manual_quarantine_confirmation_required',
        'Manual quarantine confirmation required',
        details: message,
        category: 'quarantine',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!_localCoreClient.isDesktop) {
      const message =
          'Manual file quarantine is not available on this platform because mobile OS sandboxing prevents full-device file access.';
      await logEvent(
        'manual_quarantine_unavailable',
        'Manual quarantine unavailable',
        details: message,
        category: 'quarantine',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    final scanBusyReason = _scanBusyReasonForConfigurationMutation(
      'Manual quarantine cannot run',
    );
    if (scanBusyReason != null) {
      await logEvent(
        'manual_quarantine_busy',
        'Manual quarantine blocked by scan work',
        details: scanBusyReason,
        category: 'quarantine',
        severity: 'warning',
      );
      state = state.copyWith(
        scanStartInFlight: _scanStartInFlight || state.scanStartInFlight,
        scanTargetSelectionInFlight:
            _scanTargetSelectionInFlight || state.scanTargetSelectionInFlight,
        scanCancelInFlight: _scanCancelInFlight || state.scanCancelInFlight,
        errorMessage: scanBusyReason,
      );
      return;
    }
    if (await _rejectDuringConfigurationChange(
      target: 'Manual quarantine',
      eventType: 'manual_quarantine_busy',
      eventTitle: 'Manual quarantine blocked by configuration change',
      category: 'quarantine',
    )) {
      return;
    }
    if (await _rejectManualDispositionDuringUpdateMutation(
      target: 'Manual quarantine',
      eventType: 'manual_quarantine_busy',
      eventTitle: 'Manual quarantine blocked by update package work',
      category: 'quarantine',
      prefix: 'Manual quarantine cannot run',
    )) {
      return;
    }
    final manualBusyReason = _manualDispositionBusyReason(
      'Manual quarantine cannot run',
    );
    if (manualBusyReason != null) {
      await logEvent(
        'manual_quarantine_busy',
        'Manual quarantine already blocked',
        details: manualBusyReason,
        category: 'quarantine',
        severity: 'warning',
      );
      state = state.copyWith(
        quarantineActionInFlight:
            _quarantineActionInFlight || state.quarantineActionInFlight,
        allowlistActionInFlight:
            _allowlistActionInFlight || state.allowlistActionInFlight,
        detectionFeedbackInFlight:
            _detectionFeedbackInFlight || state.detectionFeedbackInFlight,
        errorMessage: manualBusyReason,
      );
      return;
    }
    if (!await _beginScanTargetSelection('Manual quarantine file selection')) {
      return;
    }
    SelectedFilePath? selectedFile;
    try {
      selectedFile = await _fileSelectionService.pickFile();
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'manual_quarantine_file_picker_failed',
        'Manual quarantine file selection failed',
        details: details,
        category: 'quarantine',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Unable to select a file for quarantine: $details',
      );
      return;
    } finally {
      _endScanTargetSelection();
    }
    final selectedPath = selectedFile?.path.trim();
    if (selectedPath == null || selectedPath.isEmpty) return;
    final displayPath = _boundedQuarantinePath(selectedPath);
    final postSelectionScanBusyReason = _scanBusyReasonForConfigurationMutation(
      'Manual quarantine cannot run',
    );
    if (postSelectionScanBusyReason != null) {
      await logEvent(
        'manual_quarantine_busy',
        'Manual quarantine blocked by scan work',
        details: '$displayPath\n$postSelectionScanBusyReason',
        category: 'quarantine',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: postSelectionScanBusyReason);
      return;
    }
    if (!await _beginQuarantineAction(displayPath)) return;
    try {
      LocalCoreActionResult result;
      try {
        result = await _localCoreClient.quarantineFile(
          selectedPath,
          threatName: 'Manual quarantine',
          engine: 'avorax-ui-manual-quarantine',
        );
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'manual_quarantine_failed',
          'Manual quarantine failed',
          details: '$displayPath\n$details',
          category: 'quarantine',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to quarantine $displayPath: $details',
        );
        return;
      }
      if (!result.ok) {
        final details = _boundedUiDiagnostic(
          result.error ?? 'Manual quarantine failed.',
        );
        await logEvent(
          'manual_quarantine_failed',
          'Manual quarantine failed',
          details: '$displayPath\n$details',
          category: 'quarantine',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to quarantine $displayPath: $details',
        );
        return;
      }
      await logEvent(
        'manual_file_quarantined',
        'Manual file quarantined',
        details:
            '$displayPath\nDetection: Manual quarantine\nEngine: avorax-ui-manual-quarantine',
        category: 'quarantine',
        severity: 'warning',
      );
      await unawaitedRefreshQuarantine();
    } finally {
      _endQuarantineAction();
    }
  }

  Future<void> ignoreThreat(
    ThreatResult threat, {
    bool confirmed = false,
  }) async {
    if (!confirmed) {
      const message =
          'Ignoring a detected file requires explicit confirmation because Avorax will leave the file in place and hide the detection in this scan result.';
      await logEvent(
        'threat_ignore_confirmation_required',
        'Threat ignore confirmation required',
        details: '${threat.path}\n$message',
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (await _rejectDuringConfigurationChange(
      target: threat.path,
      eventType: 'threat_ignore_busy',
      eventTitle: 'Threat ignore blocked by configuration change',
      category: 'scan',
    )) {
      return;
    }
    if (await _rejectManualDispositionDuringUpdateMutation(
      target: threat.path,
      eventType: 'threat_ignore_busy',
      eventTitle: 'Threat ignore blocked by update package work',
      category: 'scan',
      prefix: 'Threat ignore cannot run',
    )) {
      return;
    }
    if (_threatIgnoreActionInFlight) {
      const message = 'Threat ignore action is already in progress.';
      await logEvent(
        'threat_ignore_busy',
        'Threat ignore already in progress',
        details: threat.path.trim().isEmpty
            ? message
            : '${threat.path}\n$message',
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(
        threatIgnoreActionInFlight:
            _threatIgnoreActionInFlight || state.threatIgnoreActionInFlight,
        errorMessage: message,
      );
      return;
    }
    _threatIgnoreActionInFlight = true;
    state = state.copyWith(threatIgnoreActionInFlight: true);
    try {
      await logEvent(
        'threat_ignored',
        'Threat kept by user',
        details: threat.path,
        category: 'scan',
        severity: 'warning',
      );
      _replaceThreat(
        threat.id,
        threat.copyWith(status: ThreatResultStatus.ignored),
      );
    } finally {
      _threatIgnoreActionInFlight = false;
      if (mounted) {
        state = state.copyWith(threatIgnoreActionInFlight: false);
      }
    }
  }

  Future<void> markThreatFalsePositive(
    ThreatResult threat, {
    bool confirmed = false,
  }) async {
    if (!confirmed) {
      const message =
          'False-positive feedback requires explicit confirmation because it can suppress future detections for the same file hash.';
      await logEvent(
        'false_positive_label_confirmation_required',
        'False-positive feedback confirmation required',
        details: '${threat.path}\n$message',
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!await _beginDetectionFeedback(threat.path)) return;
    try {
      LocalCoreActionResult result;
      try {
        result = await _localCoreClient.labelDetection(threat, 'falsePositive');
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'false_positive_label_failed',
          'False-positive feedback failed',
          details: '${threat.path}\n$details',
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to save false-positive feedback: $details',
        );
        return;
      }
      if (!result.ok) {
        final details = _boundedUiDiagnostic(
          result.error ?? 'False-positive feedback failed.',
        );
        await logEvent(
          'false_positive_label_failed',
          'False-positive feedback failed',
          details: '${threat.path}\n$details',
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to save false-positive feedback: $details',
        );
        return;
      }
      await logEvent(
        'false_positive_label_saved',
        'False-positive feedback saved',
        details:
            '${threat.path}\nFeedback: false positive\nCurrent scan row: ignored by user; future detections for this hash may be suppressed.',
        category: 'protection',
        severity: 'warning',
      );
      _replaceThreat(
        threat.id,
        threat.copyWith(status: ThreatResultStatus.ignored),
      );
    } finally {
      _endDetectionFeedback();
    }
  }

  Future<void> markThreatMalicious(
    ThreatResult threat, {
    bool confirmed = false,
  }) async {
    if (!confirmed) {
      const message =
          'Malicious feedback requires explicit confirmation because it can change future detection decisions for the same file hash.';
      await logEvent(
        'malicious_label_confirmation_required',
        'Malicious feedback confirmation required',
        details: '${threat.path}\n$message',
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!await _beginDetectionFeedback(threat.path)) return;
    try {
      LocalCoreActionResult result;
      try {
        result = await _localCoreClient.labelDetection(
          threat,
          'confirmedMalicious',
        );
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'malicious_label_failed',
          'Malicious feedback failed',
          details: '${threat.path}\n$details',
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to save malicious feedback: $details',
        );
        return;
      }
      if (!result.ok) {
        final details = _boundedUiDiagnostic(
          result.error ?? 'Malicious feedback failed.',
        );
        await logEvent(
          'malicious_label_failed',
          'Malicious feedback failed',
          details: '${threat.path}\n$details',
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to save malicious feedback: $details',
        );
        return;
      }
      await logEvent(
        'malicious_label_saved',
        'Malicious feedback saved',
        details:
            '${threat.path}\nFeedback: confirmed malicious\nCurrent scan row: unchanged; no quarantine, delete, or execution was performed.',
        category: 'protection',
        severity: 'warning',
      );
    } finally {
      _endDetectionFeedback();
    }
  }

  Future<bool> _beginDetectionFeedback(String target) async {
    if (await _rejectDuringConfigurationChange(
      target: target,
      eventType: 'detection_feedback_busy',
      eventTitle: 'Detection feedback blocked by configuration change',
      category: 'protection',
    )) {
      return false;
    }
    if (await _rejectManualDispositionDuringUpdateMutation(
      target: target,
      eventType: 'detection_feedback_busy',
      eventTitle: 'Detection feedback blocked by update package work',
      category: 'protection',
      prefix: 'Detection feedback cannot run',
    )) {
      return false;
    }
    if (_detectionFeedbackInFlight) {
      const message = 'Detection feedback is already in progress.';
      await logEvent(
        'detection_feedback_busy',
        'Detection feedback already in progress',
        details: target.trim().isEmpty ? message : '$target\n$message',
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        detectionFeedbackInFlight:
            _detectionFeedbackInFlight || state.detectionFeedbackInFlight,
        errorMessage: message,
      );
      return false;
    }
    _detectionFeedbackInFlight = true;
    state = state.copyWith(detectionFeedbackInFlight: true);
    return true;
  }

  void _endDetectionFeedback() {
    _detectionFeedbackInFlight = false;
    if (mounted) {
      state = state.copyWith(detectionFeedbackInFlight: false);
    }
  }

  Future<void> addThreatToAllowlist(
    ThreatResult threat, {
    bool confirmed = false,
  }) async {
    if (!confirmed) {
      const message =
          'Adding a file to the allowlist requires explicit confirmation because it suppresses automatic quarantine for that path.';
      await logEvent(
        'allowlist_entry_add_confirmation_required',
        'Allowlist entry add confirmation required',
        details: '${threat.path}\n$message',
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!await _beginAllowlistAction(threat.path)) return;
    try {
      LocalCoreActionResult result;
      try {
        result = await _localCoreClient.addAllowlistEntry(threat.path);
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'allowlist_entry_add_failed',
          'Allowlist entry add failed',
          details: '${threat.path}\n$details',
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to allowlist ${threat.fileName}: $details',
        );
        return;
      }
      if (!result.ok) {
        final details = _boundedUiDiagnostic(
          result.error ?? 'Allowlist entry add failed.',
        );
        await logEvent(
          'allowlist_entry_add_failed',
          'Allowlist entry add failed',
          details: '${threat.path}\n$details',
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to allowlist ${threat.fileName}: $details',
        );
        return;
      }
      await logEvent(
        'allowlist_entry_added',
        'Allowlist entry added',
        details: threat.path,
        category: 'protection',
        severity: 'warning',
      );
      _replaceThreat(
        threat.id,
        threat.copyWith(
          recommendedAction: RecommendedAction.allowlist,
          status: ThreatResultStatus.allowlisted,
        ),
      );
      await unawaitedRefreshAllowlist();
    } finally {
      _endAllowlistAction();
    }
  }

  Future<void> removeAllowlistEntry(
    AllowlistEntry entry, {
    bool confirmed = false,
  }) async {
    if (!confirmed) {
      const message =
          'Removing an allowlist entry requires explicit confirmation because Avorax will resume normal scan and quarantine policy for that path.';
      await logEvent(
        'allowlist_entry_remove_confirmation_required',
        'Allowlist entry remove confirmation required',
        details: '${entry.path}\n$message',
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!await _beginAllowlistAction(entry.path)) return;
    try {
      LocalCoreActionResult result;
      try {
        result = await _localCoreClient.removeAllowlistEntry(entry.id);
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'allowlist_entry_remove_failed',
          'Allowlist entry remove failed',
          details: '${entry.path}\n$details',
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to remove allowlist entry: $details',
        );
        return;
      }
      if (!result.ok) {
        final details = _boundedUiDiagnostic(
          result.error ?? 'Allowlist entry remove failed.',
        );
        await logEvent(
          'allowlist_entry_remove_failed',
          'Allowlist entry remove failed',
          details: '${entry.path}\n$details',
          category: 'protection',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to remove allowlist entry: $details',
        );
        return;
      }
      await logEvent(
        'allowlist_entry_removed',
        'Allowlist entry removed',
        details: entry.path,
        category: 'protection',
        severity: 'warning',
      );
      _replaceAllowlistEntryActive(entry.id, false);
      await unawaitedRefreshAllowlist();
    } finally {
      _endAllowlistAction();
    }
  }

  Future<bool> _beginAllowlistAction(String target) async {
    if (await _rejectDuringConfigurationChange(
      target: target,
      eventType: 'allowlist_action_busy',
      eventTitle: 'Allowlist action blocked by configuration change',
      category: 'protection',
    )) {
      return false;
    }
    if (await _rejectManualDispositionDuringUpdateMutation(
      target: target,
      eventType: 'allowlist_action_busy',
      eventTitle: 'Allowlist action blocked by update package work',
      category: 'protection',
      prefix: 'Allowlist action cannot run',
    )) {
      return false;
    }
    if (_allowlistActionInFlight) {
      const message = 'An allowlist action is already in progress.';
      await logEvent(
        'allowlist_action_busy',
        'Allowlist action already in progress',
        details: target.trim().isEmpty ? message : '$target\n$message',
        category: 'protection',
        severity: 'warning',
      );
      state = state.copyWith(
        allowlistActionInFlight:
            _allowlistActionInFlight || state.allowlistActionInFlight,
        errorMessage: message,
      );
      return false;
    }
    _allowlistActionInFlight = true;
    state = state.copyWith(allowlistActionInFlight: true);
    return true;
  }

  void _endAllowlistAction() {
    _allowlistActionInFlight = false;
    if (mounted) {
      state = state.copyWith(allowlistActionInFlight: false);
    }
  }

  Future<void> restoreQuarantineItem(
    QuarantineRecord item, {
    bool confirmed = false,
  }) async {
    final displayPath = _boundedQuarantinePath(item.originalPath);
    if (!confirmed) {
      const message =
          'Quarantine restore requires explicit confirmation because Avorax will move the file back to its original path.';
      await logEvent(
        'quarantine_restore_confirmation_required',
        'Quarantine restore confirmation required',
        details: '$displayPath\n$message',
        category: 'quarantine',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!await _beginQuarantineAction(displayPath)) return;
    try {
      await logEvent(
        'quarantine_restore_requested',
        'Quarantine restore requested',
        details: displayPath,
        category: 'quarantine',
        severity: 'warning',
      );
      LocalCoreActionResult result;
      try {
        result = await _localCoreClient.restoreQuarantineItem(
          item.quarantineId,
        );
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'quarantine_restore_failed',
          'Quarantine restore failed',
          details: '$displayPath\n$details',
          category: 'quarantine',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to restore $displayPath: $details',
        );
        return;
      }
      if (!result.ok) {
        final details = _boundedUiDiagnostic(
          result.error ?? 'Quarantine restore failed.',
        );
        await logEvent(
          'quarantine_restore_failed',
          'Quarantine restore failed',
          details: '$displayPath\n$details',
          category: 'quarantine',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to restore $displayPath: $details',
        );
        return;
      }
      await logEvent(
        'quarantine_item_restored',
        'Quarantine item restored',
        details: displayPath,
        category: 'quarantine',
        severity: 'warning',
      );
      _replaceQuarantineRecordStatus(
        item.quarantineId,
        QuarantineItemStatus.restored,
      );
      await unawaitedRefreshQuarantine();
    } finally {
      _endQuarantineAction();
    }
  }

  Future<void> deleteQuarantineItem(
    QuarantineRecord item, {
    bool confirmed = false,
  }) async {
    final displayPath = _boundedQuarantinePath(item.originalPath);
    if (!confirmed) {
      const message =
          'Quarantine delete requires explicit confirmation because Avorax will permanently remove the isolated quarantine payload.';
      await logEvent(
        'quarantine_delete_confirmation_required',
        'Quarantine delete confirmation required',
        details: '$displayPath\n$message',
        category: 'quarantine',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    if (!await _beginQuarantineAction(displayPath)) return;
    try {
      LocalCoreActionResult result;
      try {
        result = await _localCoreClient.deleteQuarantineItem(item.quarantineId);
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        await logEvent(
          'quarantine_delete_failed',
          'Quarantine delete failed',
          details: '$displayPath\n$details',
          category: 'quarantine',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to delete $displayPath: $details',
        );
        return;
      }
      if (!result.ok) {
        final details = _boundedUiDiagnostic(
          result.error ?? 'Quarantine delete failed.',
        );
        await logEvent(
          'quarantine_delete_failed',
          'Quarantine delete failed',
          details: '$displayPath\n$details',
          category: 'quarantine',
          severity: 'error',
        );
        state = state.copyWith(
          errorMessage: 'Unable to delete $displayPath: $details',
        );
        return;
      }
      await logEvent(
        'quarantine_item_deleted',
        'Quarantine item deleted',
        details: displayPath,
        category: 'quarantine',
        severity: 'warning',
      );
      _replaceQuarantineRecordStatus(
        item.quarantineId,
        QuarantineItemStatus.deleted,
      );
      await unawaitedRefreshQuarantine();
    } finally {
      _endQuarantineAction();
    }
  }

  Future<bool> _beginQuarantineAction(String target) async {
    final displayTarget = _boundedQuarantinePath(target);
    if (await _rejectDuringConfigurationChange(
      target: displayTarget,
      eventType: 'quarantine_action_busy',
      eventTitle: 'Quarantine action blocked by configuration change',
      category: 'quarantine',
    )) {
      return false;
    }
    if (await _rejectManualDispositionDuringUpdateMutation(
      target: displayTarget,
      eventType: 'quarantine_action_busy',
      eventTitle: 'Quarantine action blocked by update package work',
      category: 'quarantine',
      prefix: 'Quarantine action cannot run',
    )) {
      return false;
    }
    if (_quarantineActionInFlight) {
      const message = 'A quarantine action is already in progress.';
      await logEvent(
        'quarantine_action_busy',
        'Quarantine action already in progress',
        details: '$displayTarget\n$message',
        category: 'quarantine',
        severity: 'warning',
      );
      state = state.copyWith(
        quarantineActionInFlight:
            _quarantineActionInFlight || state.quarantineActionInFlight,
        errorMessage: message,
      );
      return false;
    }
    _quarantineActionInFlight = true;
    state = state.copyWith(quarantineActionInFlight: true);
    return true;
  }

  void _endQuarantineAction() {
    _quarantineActionInFlight = false;
    if (mounted) {
      state = state.copyWith(quarantineActionInFlight: false);
    }
  }

  void _replaceQuarantineRecordStatus(
    String quarantineId,
    QuarantineItemStatus status,
  ) {
    state = state.copyWith(
      quarantine: [
        for (final item in state.quarantine)
          if (item.quarantineId == quarantineId)
            QuarantineRecord(
              quarantineId: item.quarantineId,
              originalPath: item.originalPath,
              quarantinePath: item.quarantinePath,
              sha256: item.sha256,
              fileSize: item.fileSize,
              detectionName: item.detectionName,
              engine: item.engine,
              quarantinedAt: item.quarantinedAt,
              status: status,
              userNote: item.userNote,
              source: item.source,
              blockedBeforeExecution: item.blockedBeforeExecution,
              processStarted: item.processStarted,
              actionTaken: _quarantineActionTakenForStatus(status),
            )
          else
            item,
      ],
    );
  }

  String _quarantineActionTakenForStatus(QuarantineItemStatus status) {
    return switch (status) {
      QuarantineItemStatus.quarantined => 'quarantined',
      QuarantineItemStatus.restored => 'restored',
      QuarantineItemStatus.deleted => 'deleted',
    };
  }

  void _replaceAllowlistEntryActive(String id, bool active) {
    state = state.copyWith(
      allowlist: [
        for (final entry in state.allowlist)
          if (entry.id == id)
            AllowlistEntry(
              id: entry.id,
              type: entry.type,
              path: entry.path,
              reason: entry.reason,
              createdAt: entry.createdAt,
              sha256: entry.sha256,
              createdBy: entry.createdBy,
              active: active,
            )
          else
            entry,
      ],
    );
  }

  Future<void> cancelScan() async {
    if (_scanCancelInFlight) {
      const message = 'Scan cancellation is already in progress.';
      await logEvent(
        'scan_cancel_ignored',
        'Scan cancellation ignored',
        details: message,
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(
        scanCancelInFlight: _scanCancelInFlight || state.scanCancelInFlight,
        errorMessage: message,
      );
      return;
    }
    if (state.scanStatus != ScanStatus.running) {
      const message = 'No scan is running to cancel.';
      await logEvent(
        'scan_cancel_ignored',
        'Scan cancellation ignored',
        details: message,
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return;
    }
    _scanCancelInFlight = true;
    state = state.copyWith(scanCancelInFlight: true);
    _scanCancelled = true;
    try {
      final warning = await _localCoreClient.cancelActiveScan();
      await logEvent(
        'scan_cancelled',
        warning == null ? 'Scan cancelled' : 'Scan cancelled with fallback',
        details: warning,
        category: 'scan',
        severity: warning == null ? 'info' : 'warning',
      );
      if (warning != null) {
        state = state.copyWith(errorMessage: warning);
      }
    } on Object catch (error) {
      _scanCancelled = false;
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'scan_cancel_failed',
        'Scan cancellation failed',
        details: details,
        category: 'scan',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Unable to request scan cancellation: $details',
      );
      return;
    } finally {
      _scanCancelInFlight = false;
      if (mounted) {
        state = state.copyWith(scanCancelInFlight: false);
      }
    }
    state = state.copyWith(
      scanStatus: ScanStatus.cancelled,
      scanProgress: state.scanProgress == null
          ? null
          : ScanProgress(
              jobId: state.scanProgress!.jobId,
              scanType: state.scanProgress!.scanType,
              status: ScanJobStatus.cancelled,
              currentPath: state.scanProgress!.currentPath,
              filesScanned: state.scanProgress!.filesScanned,
              foldersScanned: state.scanProgress!.foldersScanned,
              bytesScanned: state.scanProgress!.bytesScanned,
              totalFilesEstimated: state.scanProgress!.totalFilesEstimated,
              totalBytesEstimated: state.scanProgress!.totalBytesEstimated,
              threatsFound: state.scanProgress!.threatsFound,
              suspiciousFound: state.scanProgress!.suspiciousFound,
              skippedFiles: state.scanProgress!.skippedFiles,
              permissionDeniedCount: state.scanProgress!.permissionDeniedCount,
              startedAt: state.scanProgress!.startedAt,
              updatedAt: DateTime.now().toUtc(),
              elapsedSeconds: state.scanProgress!.elapsedSeconds,
              estimatedRemainingSeconds:
                  state.scanProgress!.estimatedRemainingSeconds,
              progressPercent: state.scanProgress!.progressPercent,
            ),
      clearCurrentScanPath: true,
    );
  }

  void _replaceThreat(String id, ThreatResult replacement) {
    final report = state.lastScanReport;
    if (report == null) return;
    final threats = [
      for (final threat in report.threats)
        threat.id == id ? replacement : threat,
    ];
    state = state.copyWith(
      lastScanReport: ScanReport(
        status: report.status,
        kind: report.kind,
        actionMode: report.actionMode,
        filesScanned: report.filesScanned,
        threatsFound: report.threatsFound,
        skippedFiles: report.skippedFiles,
        elapsedMs: report.elapsedMs,
        foldersScanned: report.foldersScanned,
        bytesScanned: report.bytesScanned,
        totalFilesEstimated: report.totalFilesEstimated,
        totalBytesEstimated: report.totalBytesEstimated,
        suspiciousFound: report.suspiciousFound,
        quarantinedFiles: report.quarantinedFiles,
        permissionDeniedCount: report.permissionDeniedCount,
        progress: report.progress,
        currentPath: report.currentPath,
        message: report.message,
        scanErrors: report.scanErrors,
        threats: threats,
      ),
      clearError: true,
    );
  }

  Future<void> _scanPaths(
    List<String> paths, {
    required ScanKind kind,
    required ScanActionMode actionMode,
    List<String> targetLimitations = const [],
  }) async {
    if (await _rejectScanStartDuringConfigurationChange(kind.label)) return;
    if (await _rejectScanStartDuringUpdateMutation(kind.label)) return;
    if (_scanStartInFlight || state.scanStatus == ScanStatus.running) {
      const message = 'A scan is already running.';
      await logEvent(
        'scan_start_ignored',
        'Scan start ignored',
        details: message,
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(
        scanStartInFlight: _scanStartInFlight || state.scanStartInFlight,
        errorMessage: message,
      );
      return;
    }
    if (paths.isEmpty) {
      const message = 'No scan targets were provided.';
      await logEvent(
        'scan_targets_unavailable',
        'Scan targets unavailable',
        details: message,
        category: 'scan',
        severity: 'warning',
      );
      state = state.copyWith(
        scanStatus: ScanStatus.completedWithErrors,
        lastScanReport: ScanReport(
          status: ScanStatus.completedWithErrors,
          kind: kind,
          actionMode: actionMode,
          filesScanned: 0,
          threatsFound: 0,
          skippedFiles: 0,
          elapsedMs: 0,
          message: message,
          threats: const [],
        ),
        clearCurrentScanPath: true,
        errorMessage: message,
      );
      return;
    }
    _scanStartInFlight = true;
    state = state.copyWith(scanStartInFlight: true);
    try {
      if (!_localCoreClient.isDesktop) {
        const message =
            'Malware quarantine is not available on this platform because mobile OS sandboxing prevents full-device scanning.';
        await logEvent(
          'scan_engine_unavailable',
          'Scan engine unavailable',
          details: message,
          category: 'scan',
          severity: 'warning',
        );
        state = state.copyWith(
          scanStatus: ScanStatus.engineUnavailable,
          lastScanReport: _engineUnavailableScanReport(
            kind,
            actionMode,
            message,
          ),
          errorMessage: message,
        );
        return;
      }
      final engineDiagnosticLimitation =
          state.lastEngineError?.trim().isEmpty ?? true
          ? null
          : 'Engine diagnostics require attention: '
                '${_boundedUiDiagnostic(state.lastEngineError!)}.';
      final scanStartLimitations = [
        for (final limitation in targetLimitations)
          _boundedUiDiagnostic(limitation),
        ?engineDiagnosticLimitation,
      ];
      await logEvent(
        scanStartLimitations.isEmpty
            ? 'scan_started'
            : 'scan_started_with_limitations',
        scanStartLimitations.isEmpty
            ? '${kind.label} started'
            : '${kind.label} started with limitations',
        details: scanStartLimitations.isEmpty
            ? paths.join('\n')
            : '${paths.join('\n')}\nLimitations: ${scanStartLimitations.join('; ')}',
        category: 'scan',
        severity: scanStartLimitations.isEmpty ? 'info' : 'warning',
      );
      _scanCancelled = false;
      state = state.copyWith(
        scanStatus: ScanStatus.running,
        currentScanPath: paths.first,
        scanActionMode: actionMode,
        scanProgress: ScanProgress(
          jobId: 'local',
          scanType: kind,
          status: ScanJobStatus.running,
          currentPath: paths.first,
          filesScanned: 0,
          foldersScanned: 0,
          bytesScanned: 0,
          threatsFound: 0,
          suspiciousFound: 0,
          skippedFiles: 0,
          permissionDeniedCount: 0,
          startedAt: DateTime.now().toUtc(),
          updatedAt: DateTime.now().toUtc(),
          elapsedSeconds: 0,
        ),
        clearError: true,
      );
      ScanReport report;
      try {
        void updateProgress(ScanProgress progress) {
          if (!mounted || _scanCancelled) return;
          state = state.copyWith(
            scanProgress: progress,
            currentScanPath: progress.currentPath,
          );
        }

        final scanTargetProbe = paths.length == 1
            ? _scanTargetFileProbe(paths.first)
            : null;
        final probeDiagnostic = scanTargetProbe?.diagnostic;
        if (probeDiagnostic != null) {
          final message =
              'Unable to inspect scan target before launch: '
              '$probeDiagnostic';
          report = _failedScanReport(
            paths,
            kind: kind,
            actionMode: actionMode,
            message: message,
            scanError: 'Scan target inspection failed: $probeDiagnostic',
          );
          await logEvent(
            'scan_failed',
            'Scan failed',
            details: message,
            category: 'scan',
            severity: 'error',
          );
        } else if (scanTargetProbe?.isFile == true) {
          report = await _localCoreClient.scanFile(
            paths.first,
            kind: kind,
            actionMode: actionMode,
            onProgress: updateProgress,
          );
        } else {
          report = await _localCoreClient.scanPaths(
            paths,
            kind: kind,
            actionMode: actionMode,
            onProgress: updateProgress,
          );
        }
      } on Object catch (error) {
        final details = _boundedUiDiagnostic(error);
        report = _failedScanReport(
          paths,
          kind: kind,
          actionMode: actionMode,
          message: 'Scan failed before completion: $details',
          scanError: 'Scan orchestration failed: $details',
        );
        await logEvent(
          'scan_failed',
          'Scan failed',
          details: details,
          category: 'scan',
          severity: 'error',
        );
      }
      if (_scanCancelled) {
        final cancelledReport = _cancelledScanReport(report);
        final scanErrorMessage = _scanCoverageWarning(cancelledReport);
        state = state.copyWith(
          scanStatus: ScanStatus.cancelled,
          lastScanReport: cancelledReport,
          clearCurrentScanPath: true,
          clearError: scanErrorMessage == null,
          errorMessage: scanErrorMessage,
        );
        return;
      }
      if (report.threats.isNotEmpty) {
        await logEvent(
          'threat_detected',
          'Threats found',
          details: _scanEventDetails(report),
          category: 'scan',
          severity: 'warning',
        );
        for (final threat in report.threats.where(
          (threat) => threat.status == ThreatResultStatus.quarantined,
        )) {
          await logEvent(
            'file_quarantined',
            'File quarantined',
            details: _quarantinedThreatEventDetails(threat),
            category: 'quarantine',
            severity: 'warning',
          );
        }
      }
      final scanErrorMessage = _scanCoverageWarning(report);
      await logEvent(
        'scan_completed',
        scanErrorMessage == null
            ? 'Scan completed'
            : 'Scan completed with errors',
        details: _scanEventDetails(report, coverageWarning: scanErrorMessage),
        category: 'scan',
        severity: scanErrorMessage == null ? 'info' : 'warning',
      );
      state = state.copyWith(
        scanStatus: report.status,
        lastScanReport: report,
        clearCurrentScanPath: true,
        clearError:
            report.status != ScanStatus.engineUnavailable &&
            scanErrorMessage == null,
        errorMessage: report.status == ScanStatus.engineUnavailable
            ? _engineUnavailableMessage()
            : scanErrorMessage,
      );
      await unawaitedRefreshQuarantine();
    } finally {
      _scanStartInFlight = false;
      if (mounted) {
        state = state.copyWith(scanStartInFlight: false);
      }
    }
  }

  String _engineUnavailableMessage() {
    if (state.coreServiceStatus == 'stopped') {
      return 'Avorax Core Service is stopped. Start the service, then retry the scan.';
    }
    if (state.coreServiceStatus == 'installed') {
      return 'Avorax Core Service is installed but not running. Start the service, then retry the scan.';
    }
    if (state.coreServiceStatus == 'missing') {
      return 'Avorax Core Service is not registered. Use Repair installation or reinstall Avorax.';
    }
    if (state.coreServiceStatus == 'unknown') {
      return 'Avorax Core Service status is unknown. Check service diagnostics, then retry the scan.';
    }
    if (state.coreServiceStatus == 'error') {
      return 'Avorax Core Service status check failed. Review local engine diagnostics, then retry the scan.';
    }
    return 'Avorax Native Engine unavailable. Install the Avorax MSI or verify native engine assets.';
  }

  Future<String?> exportLogs({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Log export requires explicit confirmation because local event history can include file paths, protection actions, update diagnostics, and error details.';
      await logEvent(
        'logs_export_confirmation_required',
        'Logs export confirmation required',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return null;
    }
    if (_logExportInFlight) {
      const message = 'Log export is already in progress.';
      await logEvent(
        'logs_export_busy',
        'Logs export already in progress',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        logExportInFlight: _logExportInFlight || state.logExportInFlight,
        errorMessage: message,
      );
      return null;
    }
    _logExportInFlight = true;
    state = state.copyWith(logExportInFlight: true);
    try {
      final file = await _eventRepository.export();
      final exportedPath = _boundedExportPath(file.path);
      await logEvent(
        'logs_exported',
        'Logs exported',
        details: exportedPath,
        category: 'settings',
        severity: 'info',
      );
      return exportedPath;
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'logs_export_failed',
        'Logs export failed',
        details: details,
        category: 'settings',
        severity: 'error',
      );
      state = state.copyWith(errorMessage: 'Unable to export logs: $details');
      return null;
    } finally {
      _logExportInFlight = false;
      if (mounted) {
        state = state.copyWith(logExportInFlight: false);
      }
    }
  }

  Future<String?> exportSupportBundle({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Support bundle export requires explicit confirmation because it includes local event history, status summaries, file paths from events, and diagnostic details.';
      await logEvent(
        'support_bundle_confirmation_required',
        'Support bundle export confirmation required',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return null;
    }
    if (_supportBundleExportInFlight) {
      const message = 'Support bundle export is already in progress.';
      await logEvent(
        'support_bundle_export_busy',
        'Support bundle export already in progress',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        supportBundleExportInFlight:
            _supportBundleExportInFlight || state.supportBundleExportInFlight,
        errorMessage: message,
      );
      return null;
    }
    _supportBundleExportInFlight = true;
    state = state.copyWith(supportBundleExportInFlight: true);
    try {
      final file = await _eventRepository.exportSupportBundle(
        diagnostics: _supportBundleDiagnostics(),
      );
      final exportedPath = _boundedExportPath(file.path);
      await logEvent(
        'support_bundle_exported',
        'Support bundle exported',
        details: exportedPath,
        category: 'settings',
        severity: 'info',
      );
      return exportedPath;
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'support_bundle_export_failed',
        'Support bundle export failed',
        details: details,
        category: 'settings',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Unable to export support bundle: $details',
      );
      return null;
    } finally {
      _supportBundleExportInFlight = false;
      if (mounted) {
        state = state.copyWith(supportBundleExportInFlight: false);
      }
    }
  }

  Map<String, Object?> _supportBundleDiagnostics() {
    final report = state.lastScanReport;
    return {
      'app': {'version': state.currentAppVersion},
      'privacy': const {
        'contains_file_contents': false,
        'contains_quarantine_payloads': false,
        'contains_live_malware': false,
        'contains_credentials': false,
        'includes_local_file_paths_from_events': true,
        'manual_review_required_before_sharing': true,
      },
      'status': {
        'cloud': state.cloudStatus.label,
        'protection': state.protectionStatus.label,
        'scan': state.scanStatus.label,
        'malware_engine': state.malwareEngineStatus.label,
        'update': state.updateStatus.label,
      },
      'engine': {
        'native_engine_status': state.nativeEngineStatus,
        'native_signature_count': state.nativeSignatureCount,
        'native_rule_count': state.nativeRuleCount,
        'native_ml_status': state.nativeMlStatus,
        'native_ml_model_version': state.nativeMlModelVersion,
        'native_ml_production_ready': state.nativeMlProductionReady,
        'native_self_test_passed': state.nativeSelfTestPassed,
        'ai_self_test_passed': state.aiSelfTestPassed,
        'compatibility_engines_enabled': state.compatibilityEnginesEnabled,
      },
      'services': {
        'core_service_status': state.coreServiceStatus,
        'core_service_boundary_status':
            state.coreServiceBoundaryHealth.status.name,
        'core_service_boundary_protocol_version':
            state.coreServiceBoundaryHealth.protocolVersion,
        'core_service_boundary_transport':
            state.coreServiceBoundaryHealth.transport,
        'core_service_boundary_command_scope':
            state.coreServiceBoundaryHealth.commandScope,
        'core_service_boundary_network_exposed':
            state.coreServiceBoundaryHealth.networkExposed,
        'core_service_boundary_client_authenticated':
            state.coreServiceBoundaryHealth.clientAuthenticated,
        'core_service_boundary_server_authenticated':
            state.coreServiceBoundaryHealth.serverAuthenticated,
        'core_service_boundary_pid_match':
            state.coreServiceBoundaryHealth.serverPid > 0 &&
            state.coreServiceBoundaryHealth.serverPid ==
                state.coreServiceBoundaryHealth.servicePid,
        'core_service_boundary_service_ready':
            state.coreServiceBoundaryHealth.serviceReady,
        'core_service_boundary_engine_ready':
            state.coreServiceBoundaryHealth.engineReady,
        'core_service_boundary_signature_count':
            state.coreServiceBoundaryHealth.nativeSignatureCount,
        'core_service_boundary_rule_count':
            state.coreServiceBoundaryHealth.nativeRuleCount,
        'core_service_boundary_ml_production_ready':
            state.coreServiceBoundaryHealth.nativeMlProductionReady,
        'core_service_boundary_limitations':
            state.coreServiceBoundaryHealth.limitations,
        'core_service_boundary_diagnostic':
            state.coreServiceBoundaryHealth.diagnostic,
        'guard_status': state.guardStatus,
        'driver_status': state.driverStatus,
        'ipc_mode': state.ipcMode,
        'network_exposed': state.networkExposed,
      },
      'monitoring': {
        'realtime_watcher_mode': state.realtimeWatcherMode,
        'realtime_watched_path_count': state.realtimeWatchedPaths.length,
        'realtime_watcher_limitations': state.realtimeWatcherLimitations,
        'process_monitor_status': state.processMonitorStatus,
        'process_monitor_capability': state.processMonitorCapability,
        'process_snapshot_loop_status': state.processSnapshotLoopStatus,
        'watch_poll_loop_status': state.watchPollLoopStatus,
      },
      'counts': {
        'events': state.events.length,
        'quarantine_records': state.quarantine.length,
        'allowlist_entries': state.allowlist.length,
        'detected_apps': state.detectedApps.length,
      },
      'busy': {
        'scan_start_in_flight': state.scanStartInFlight,
        'scan_cancel_in_flight': state.scanCancelInFlight,
        'protection_operation_in_flight': state.protectionOperationInFlight,
        'update_operation_in_flight': state.updateOperationInFlight,
        'configuration_reset_in_flight': state.configurationResetInFlight,
        'log_export_in_flight': state.logExportInFlight,
        'support_bundle_export_in_flight': state.supportBundleExportInFlight,
      },
      'last_scan': report == null
          ? null
          : {
              'status': report.status.label,
              'kind': report.kind.label,
              'action_mode': report.actionMode.label,
              'files_scanned': report.filesScanned,
              'folders_scanned': report.foldersScanned,
              'bytes_scanned': report.bytesScanned,
              'threats_found': report.threatsFound,
              'suspicious_found': report.suspiciousFound,
              'quarantined_files': report.quarantinedFiles,
              'skipped_files': report.skippedFiles,
              'permission_denied_count': report.permissionDeniedCount,
              'elapsed_ms': report.elapsedMs,
              'scan_error_count': report.scanErrors.length,
            },
      'limitations': const [
        'No file contents are included.',
        'No quarantine payloads are included.',
        'No live malware samples are included.',
        'Local event details can include paths and diagnostics.',
      ],
    };
  }

  Future<bool> resetConfiguration({bool confirmed = false}) async {
    if (!confirmed) {
      const message =
          'Configuration reset requires explicit confirmation because it can remove local protection, scan, cloud, and scheduling preferences.';
      await logEvent(
        'configuration_reset_confirmation_required',
        'Configuration reset confirmation required',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(errorMessage: message);
      return false;
    }
    if (_configurationResetInFlight) {
      const message = 'Configuration reset is already in progress.';
      await logEvent(
        'configuration_reset_busy',
        'Configuration reset already in progress',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        configurationResetInFlight:
            _configurationResetInFlight || state.configurationResetInFlight,
        errorMessage: message,
      );
      return false;
    }
    if (_protectionOperationInFlight ||
        state.protectionOperationInFlight ||
        _protectionSelfTestInFlight ||
        state.protectionSelfTestInFlight) {
      const message =
          'Configuration reset cannot run while protection state is changing or self-test is running.';
      await logEvent(
        'configuration_reset_busy',
        'Configuration reset already in progress',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        protectionOperationInFlight:
            _protectionOperationInFlight || state.protectionOperationInFlight,
        protectionSelfTestInFlight:
            _protectionSelfTestInFlight || state.protectionSelfTestInFlight,
        errorMessage: message,
      );
      return false;
    }
    if (_securitySettingsActionInFlight ||
        state.securitySettingsActionInFlight) {
      const message =
          'Configuration reset cannot run while a security settings change is in progress.';
      await logEvent(
        'configuration_reset_busy',
        'Configuration reset already in progress',
        details: message,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        securitySettingsActionInFlight:
            _securitySettingsActionInFlight ||
            state.securitySettingsActionInFlight,
        errorMessage: message,
      );
      return false;
    }
    final scanBusyReason = _scanBusyReasonForConfigurationMutation(
      'Configuration reset cannot run',
    );
    if (scanBusyReason != null) {
      await logEvent(
        'configuration_reset_busy',
        'Configuration reset already in progress',
        details: scanBusyReason,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        scanStartInFlight: _scanStartInFlight || state.scanStartInFlight,
        scanTargetSelectionInFlight:
            _scanTargetSelectionInFlight || state.scanTargetSelectionInFlight,
        scanCancelInFlight: _scanCancelInFlight || state.scanCancelInFlight,
        errorMessage: scanBusyReason,
      );
      return false;
    }
    final updateBusyReason = _configurationMutationUpdateBusyReason(
      'Configuration reset cannot run',
    );
    if (updateBusyReason != null) {
      await logEvent(
        'configuration_reset_busy',
        'Configuration reset already in progress',
        details: updateBusyReason,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        updateOperationInFlight:
            _updateOperationInFlight || state.updateOperationInFlight,
        errorMessage: updateBusyReason,
      );
      return false;
    }
    final manualActionBusyReason = _manualDispositionBusyReason(
      'Configuration reset cannot run',
    );
    if (manualActionBusyReason != null) {
      await logEvent(
        'configuration_reset_busy',
        'Configuration reset already in progress',
        details: manualActionBusyReason,
        category: 'settings',
        severity: 'warning',
      );
      state = state.copyWith(
        quarantineActionInFlight:
            _quarantineActionInFlight || state.quarantineActionInFlight,
        allowlistActionInFlight:
            _allowlistActionInFlight || state.allowlistActionInFlight,
        detectionFeedbackInFlight:
            _detectionFeedbackInFlight || state.detectionFeedbackInFlight,
        errorMessage: manualActionBusyReason,
      );
      return false;
    }
    _configurationResetInFlight = true;
    state = state.copyWith(configurationResetInFlight: true);
    try {
      if (_configurationResetRequiresProtectionStop()) {
        await stopProtection(confirmed: true);
        if (_configurationResetRequiresProtectionStop()) {
          const message =
              'Configuration reset blocked because protection did not stop cleanly.';
          await logEvent(
            'configuration_reset_failed',
            'Configuration reset failed',
            details: message,
            category: 'settings',
            severity: 'error',
          );
          final stopDetails = state.errorMessage;
          state = state.copyWith(
            errorMessage: stopDetails == null || stopDetails.trim().isEmpty
                ? message
                : '$message $stopDetails',
          );
          return false;
        }
      }
      await _configRepository.reset();
      final resetConfig = _configRepository.load();
      _configureScheduledQuickScan(resetConfig);
      await logEvent(
        'configuration_reset',
        'Configuration reset',
        category: 'settings',
        severity: 'warning',
      );
      state = ZentorState(
        config: resetConfig,
        events: _eventRepository.load(),
        cloudStatus: CloudStatus.disabled,
        protectionStatus: ProtectionStatus.idle,
        updatePackageMutationSupported: _updateService.packageMutationSupported,
        appVerificationStatus: _verificationStatusFor(
          resetConfig.protectedAppConfig,
        ),
      );
      return true;
    } on Object catch (error) {
      final details = _boundedUiDiagnostic(error);
      await logEvent(
        'configuration_reset_failed',
        'Configuration reset failed',
        details: details,
        category: 'settings',
        severity: 'error',
      );
      state = state.copyWith(
        errorMessage: 'Unable to reset configuration: $details',
      );
      return false;
    } finally {
      _configurationResetInFlight = false;
      if (mounted) {
        state = state.copyWith(configurationResetInFlight: false);
      }
    }
  }

  bool _configurationResetRequiresProtectionStop() =>
      state.config.realtimeProtectionEnabled ||
      state.protectionStatus == ProtectionStatus.starting ||
      state.protectionStatus == ProtectionStatus.localOnly ||
      state.protectionStatus == ProtectionStatus.protected ||
      state.protectionStatus == ProtectionStatus.partiallyProtected ||
      state.protectionStatus == ProtectionStatus.stopping ||
      state.realtimeWatcherMode != 'off' ||
      state.realtimeWatchedPaths.isNotEmpty ||
      state.watchPollLoopStatus != 'off';

  AppVerificationStatus _verificationStatusFor(
    ProtectedAppConfig protectedAppConfig,
  ) {
    if (!protectedAppConfig.isConfigured) {
      return AppVerificationStatus.notConfigured;
    }
    if (protectedAppConfig.lastCalculatedHash.isEmpty) {
      return AppVerificationStatus.pending;
    }
    if (protectedAppConfig.expectedBuildHash.isEmpty ||
        protectedAppConfig.expectedBuildHash ==
            protectedAppConfig.lastCalculatedHash) {
      return AppVerificationStatus.verified;
    }
    return AppVerificationStatus.mismatch;
  }

  String _currentPlatformName() {
    if (Platform.isAndroid) return 'Android';
    if (Platform.isIOS) return 'iOS';
    if (Platform.isWindows) return 'Windows';
    if (Platform.isMacOS) return 'macOS';
    if (Platform.isLinux) return 'Linux';
    return Platform.operatingSystem;
  }

  ScanReport _failedScanReport(
    List<String> paths, {
    required ScanKind kind,
    required ScanActionMode actionMode,
    required String message,
    required String scanError,
  }) {
    return ScanReport(
      status: ScanStatus.failed,
      kind: kind,
      actionMode: actionMode,
      filesScanned: 0,
      threatsFound: 0,
      skippedFiles: paths.length,
      elapsedMs: 0,
      currentPath: paths.first,
      message: message,
      scanErrors: [scanError],
      threats: const [],
    );
  }

  ScanReport _engineUnavailableScanReport(
    ScanKind kind,
    ScanActionMode actionMode,
    String message,
  ) {
    return ScanReport(
      status: ScanStatus.engineUnavailable,
      kind: kind,
      actionMode: actionMode,
      filesScanned: 0,
      threatsFound: 0,
      skippedFiles: 0,
      elapsedMs: 0,
      message: message,
      scanErrors: [message],
      threats: const [],
    );
  }

  ScanReport _cancelledScanReport(ScanReport report) {
    return ScanReport(
      status: ScanStatus.cancelled,
      kind: report.kind,
      actionMode: report.actionMode,
      filesScanned: report.filesScanned,
      threatsFound: report.threatsFound,
      skippedFiles: report.skippedFiles,
      elapsedMs: report.elapsedMs,
      foldersScanned: report.foldersScanned,
      bytesScanned: report.bytesScanned,
      totalFilesEstimated: report.totalFilesEstimated,
      totalBytesEstimated: report.totalBytesEstimated,
      suspiciousFound: report.suspiciousFound,
      quarantinedFiles: report.quarantinedFiles,
      permissionDeniedCount: report.permissionDeniedCount,
      progress: report.progress,
      currentPath: report.currentPath,
      message: report.message ?? 'Scan cancelled by user request.',
      scanErrors: report.scanErrors,
      threats: report.threats,
    );
  }

  String? _scanCoverageWarning(ScanReport report) {
    if (report.scanErrors.isEmpty) return null;
    return report.message ??
        'Scan completed with ${report.scanErrors.length} file error(s); skipped files were not reported clean.';
  }
}

class _ScanTargetFileProbe {
  const _ScanTargetFileProbe(this.isFile, [this.diagnostic]);

  final bool isFile;
  final String? diagnostic;
}

class _DirectoryProbe {
  const _DirectoryProbe(this.isDirectory, [this.diagnostic]);

  final bool isDirectory;
  final String? diagnostic;
}

class _RealtimeWatchPathPlan {
  const _RealtimeWatchPathPlan(this.paths, this.limitations);

  final List<String> paths;
  final List<String> limitations;
}

class _RealtimeWatchPathProbe {
  const _RealtimeWatchPathProbe(this.include, [this.limitation]);

  final bool include;
  final String? limitation;
}
