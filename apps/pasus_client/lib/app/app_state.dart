import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:pasus_protocol/pasus_protocol.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/config/config_repository.dart';
import '../core/games/game_detector.dart';
import '../core/local_core/local_core_client.dart';
import '../core/logging/local_event_repository.dart';
import '../core/network/api_result.dart';
import '../core/network/pasus_api_client.dart';
import '../core/platform/platform_info_service.dart';
import '../core/scanning/scan_target_service.dart';
import '../core/security/device_hash_service.dart';
import '../core/security/hash_service.dart';

final sharedPreferencesProvider = Provider<SharedPreferences>((ref) {
  throw StateError('SharedPreferences must be overridden at startup.');
});

final configRepositoryProvider = Provider<ConfigRepository>(
  (ref) => ConfigRepository(ref.watch(sharedPreferencesProvider)),
);

final localEventRepositoryProvider = Provider<LocalEventRepository>(
  (ref) => LocalEventRepository(ref.watch(sharedPreferencesProvider)),
);

final apiClientProvider = Provider<PasusApiClient>((ref) => PasusApiClient());
final hashServiceProvider = Provider<HashService>((ref) => HashService());
final gameDetectorProvider = Provider<GameDetector>((ref) => GameDetector());
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

final pasusControllerProvider =
    StateNotifierProvider<PasusController, PasusState>((ref) {
      return PasusController(
        configRepository: ref.watch(configRepositoryProvider),
        eventRepository: ref.watch(localEventRepositoryProvider),
        apiClient: ref.watch(apiClientProvider),
        hashService: ref.watch(hashServiceProvider),
        gameDetector: ref.watch(gameDetectorProvider),
        localCoreClient: ref.watch(localCoreClientProvider),
        scanTargetService: ref.watch(scanTargetServiceProvider),
      )..load();
    });

final deviceSummaryProvider = FutureProvider<DeviceIntegritySummary>((ref) {
  return ref.watch(platformInfoServiceProvider).load();
});

class PasusState {
  const PasusState({
    this.config = const PasusConfig(),
    this.cloudStatus = CloudStatus.disabled,
    this.protectionStatus = ProtectionStatus.idle,
    this.gameDetectionStatus = GameDetectionStatus.idle,
    this.gameVerificationStatus = GameVerificationStatus.notConfigured,
    this.malwareEngineStatus = MalwareEngineStatus.checking,
    this.aiModelInfo = const AiModelInfo(),
    this.yaraStatus = 'rulesUnavailable',
    this.yaraRuleCount = 0,
    this.guardStatus = 'off',
    this.driverStatus = 'missing',
    this.scanStatus = ScanStatus.idle,
    this.scanActionMode = ScanActionMode.detectOnly,
    this.scanProgress,
    this.lastScanReport,
    this.session,
    this.heartbeat = const HeartbeatStatus(),
    this.events = const [],
    this.detectedGames = const [],
    this.quarantine = const [],
    this.loading = false,
    this.errorMessage,
    this.hashProgress,
    this.currentScanPath,
    this.protectionSelfTestResult,
  });

  final PasusConfig config;
  final CloudStatus cloudStatus;
  final ProtectionStatus protectionStatus;
  final GameDetectionStatus gameDetectionStatus;
  final GameVerificationStatus gameVerificationStatus;
  final MalwareEngineStatus malwareEngineStatus;
  final AiModelInfo aiModelInfo;
  final String yaraStatus;
  final int yaraRuleCount;
  final String guardStatus;
  final String driverStatus;
  final ScanStatus scanStatus;
  final ScanActionMode scanActionMode;
  final ScanProgress? scanProgress;
  final ScanReport? lastScanReport;
  final ProtectionSession? session;
  final HeartbeatStatus heartbeat;
  final List<LocalEvent> events;
  final List<DetectedGame> detectedGames;
  final List<QuarantineRecord> quarantine;
  final bool loading;
  final String? errorMessage;
  final double? hashProgress;
  final String? currentScanPath;
  final String? protectionSelfTestResult;

  PasusState copyWith({
    PasusConfig? config,
    CloudStatus? cloudStatus,
    ProtectionStatus? protectionStatus,
    GameDetectionStatus? gameDetectionStatus,
    GameVerificationStatus? gameVerificationStatus,
    MalwareEngineStatus? malwareEngineStatus,
    AiModelInfo? aiModelInfo,
    String? yaraStatus,
    int? yaraRuleCount,
    String? guardStatus,
    String? driverStatus,
    ScanStatus? scanStatus,
    ScanActionMode? scanActionMode,
    ScanProgress? scanProgress,
    bool clearScanProgress = false,
    ScanReport? lastScanReport,
    ProtectionSession? session,
    bool clearSession = false,
    HeartbeatStatus? heartbeat,
    List<LocalEvent>? events,
    List<DetectedGame>? detectedGames,
    List<QuarantineRecord>? quarantine,
    bool? loading,
    String? errorMessage,
    bool clearError = false,
    double? hashProgress,
    bool clearHashProgress = false,
    String? currentScanPath,
    bool clearCurrentScanPath = false,
    String? protectionSelfTestResult,
    bool clearProtectionSelfTestResult = false,
  }) {
    return PasusState(
      config: config ?? this.config,
      cloudStatus: cloudStatus ?? this.cloudStatus,
      protectionStatus: protectionStatus ?? this.protectionStatus,
      gameDetectionStatus: gameDetectionStatus ?? this.gameDetectionStatus,
      gameVerificationStatus:
          gameVerificationStatus ?? this.gameVerificationStatus,
      malwareEngineStatus: malwareEngineStatus ?? this.malwareEngineStatus,
      aiModelInfo: aiModelInfo ?? this.aiModelInfo,
      yaraStatus: yaraStatus ?? this.yaraStatus,
      yaraRuleCount: yaraRuleCount ?? this.yaraRuleCount,
      guardStatus: guardStatus ?? this.guardStatus,
      driverStatus: driverStatus ?? this.driverStatus,
      scanStatus: scanStatus ?? this.scanStatus,
      scanActionMode: scanActionMode ?? this.scanActionMode,
      scanProgress: clearScanProgress
          ? null
          : scanProgress ?? this.scanProgress,
      lastScanReport: lastScanReport ?? this.lastScanReport,
      session: clearSession ? null : session ?? this.session,
      heartbeat: heartbeat ?? this.heartbeat,
      events: events ?? this.events,
      detectedGames: detectedGames ?? this.detectedGames,
      quarantine: quarantine ?? this.quarantine,
      loading: loading ?? this.loading,
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
    );
  }
}

class PasusController extends StateNotifier<PasusState> {
  PasusController({
    required ConfigRepository configRepository,
    required LocalEventRepository eventRepository,
    required PasusApiClient apiClient,
    required HashService hashService,
    required GameDetector gameDetector,
    required LocalCoreClient localCoreClient,
    required ScanTargetService scanTargetService,
  }) : this._(
         configRepository,
         eventRepository,
         apiClient,
         hashService,
         gameDetector,
         localCoreClient,
         scanTargetService,
       );

  PasusController._(
    this._configRepository,
    this._eventRepository,
    this._apiClient,
    this._hashService,
    this._gameDetector,
    this._localCoreClient,
    this._scanTargetService,
  ) : super(const PasusState());

  final ConfigRepository _configRepository;
  final LocalEventRepository _eventRepository;
  final PasusApiClient _apiClient;
  final HashService _hashService;
  final GameDetector _gameDetector;
  final LocalCoreClient _localCoreClient;
  final ScanTargetService _scanTargetService;
  bool _scanCancelled = false;

  void load() {
    final config = _configRepository.load();
    state = state.copyWith(
      config: config,
      events: _eventRepository.load(),
      cloudStatus: CloudStatus.disabled,
      gameVerificationStatus: _verificationStatusFor(config.gameConfig),
    );
    logEvent('app_started', 'App started');
    logEvent('local_scanner_initialized', 'Local scanner initialized');
    unawaitedDetectGames();
    unawaitedCheckMalwareEngine();
    unawaitedRefreshQuarantine();
  }

  Future<void> logEvent(String type, String message, {String? details}) async {
    await _eventRepository.add(type, message, details: details);
    if (!mounted) return;
    state = state.copyWith(events: _eventRepository.load());
  }

  Future<void> completeOnboarding() async {
    final updated = state.config.copyWith(onboardingComplete: true);
    await _configRepository.save(updated);
    state = state.copyWith(config: updated);
  }

  Future<void> unawaitedCheckCloud() async {
    await logEvent('cloud_health_check_started', 'Cloud health check started');
    if (!mounted) return;
    state = state.copyWith(cloudStatus: CloudStatus.checking, clearError: true);
    final result = await _apiClient.healthCheck(state.config);
    if (!mounted) return;
    switch (result) {
      case ApiSuccess<void>():
        await logEvent('cloud_online', 'Cloud online');
        state = state.copyWith(cloudStatus: CloudStatus.online);
      case ApiFailure<void>(:final message):
        await logEvent('cloud_offline', 'Cloud offline', details: message);
        state = state.copyWith(cloudStatus: CloudStatus.offline);
    }
  }

  Future<void> testCloudConnection() => unawaitedCheckCloud();

  Future<void> saveDeveloperCloudOverride({
    required bool enabled,
    required String apiBaseUrl,
    required String projectId,
    required String publicGameKey,
  }) async {
    final updated = state.config.copyWith(
      developerOverrideEnabled: enabled,
      apiBaseUrl: apiBaseUrl.trim(),
      projectId: projectId.trim(),
      publicGameKey: publicGameKey.trim(),
    );
    await _configRepository.save(updated);
    await logEvent('configuration_saved', 'Cloud configuration saved');
    state = state.copyWith(config: updated, clearError: true);
    await unawaitedCheckCloud();
  }

  Future<void> unawaitedDetectGames() async {
    await logEvent('game_detection_started', 'Game detection started');
    if (!mounted) return;
    state = state.copyWith(gameDetectionStatus: GameDetectionStatus.scanning);
    final games = await _gameDetector.detect();
    if (!mounted) return;
    if (games.isEmpty) {
      await logEvent(
        'no_supported_game_detected',
        'No supported game detected',
      );
      state = state.copyWith(
        detectedGames: const [],
        gameDetectionStatus: state.config.gameConfig.isConfigured
            ? GameDetectionStatus.manual
            : GameDetectionStatus.notFound,
      );
      return;
    }
    await logEvent('game_detected', 'Game detected');
    state = state.copyWith(
      detectedGames: games,
      gameDetectionStatus: GameDetectionStatus.detected,
    );
  }

  Future<void> unawaitedCheckMalwareEngine() async {
    if (!mounted) return;
    state = state.copyWith(malwareEngineStatus: MalwareEngineStatus.checking);
    final health = await _localCoreClient.healthSummary();
    if (!mounted) return;
    final status = health.malwareEngineStatus;
    await logEvent(
      status == MalwareEngineStatus.available
          ? 'malware_engine_available'
          : 'malware_engine_unavailable',
      status == MalwareEngineStatus.available
          ? 'Malware engine available'
          : 'Malware engine unavailable',
    );
    if (!mounted) return;
    state = state.copyWith(
      malwareEngineStatus: status,
      aiModelInfo: health.aiModelInfo,
      yaraStatus: health.yaraStatus,
      yaraRuleCount: health.yaraRuleCount,
      guardStatus: health.guardStatus,
      driverStatus: health.driverStatus,
    );
  }

  Future<void> unawaitedRefreshQuarantine() async {
    if (!mounted) return;
    final quarantine = await _localCoreClient.listQuarantine();
    if (!mounted) return;
    state = state.copyWith(quarantine: quarantine);
  }

  Future<void> addManualGameFile() async {
    if (!_hashService.supportsPathHashing) {
      state = state.copyWith(
        errorMessage:
            'Selected file protection is unavailable on this mobile platform.',
      );
      return;
    }
    final file = await openFile();
    if (file == null) return;
    await _saveManualGamePath(file.name, file.path, 'Manual');
  }

  Future<void> addManualGameFolder() async {
    if (!_hashService.supportsPathHashing) {
      state = state.copyWith(
        errorMessage:
            'Selected folder protection is unavailable on this mobile platform.',
      );
      return;
    }
    final path = await getDirectoryPath();
    if (path == null) return;
    await _saveManualGamePath(
      path.split(Platform.pathSeparator).last,
      path,
      'Manual',
    );
  }

  Future<void> selectDetectedGame(DetectedGame game) async {
    final updated = state.config.copyWith(gameConfig: game.toGameConfig());
    await _configRepository.save(updated);
    await logEvent('game_added_manually', 'Game selected', details: game.path);
    state = state.copyWith(
      config: updated,
      gameDetectionStatus: GameDetectionStatus.detected,
      gameVerificationStatus: _verificationStatusFor(updated.gameConfig),
      clearError: true,
    );
  }

  Future<void> _saveManualGamePath(
    String name,
    String path,
    String source,
  ) async {
    final game = state.config.gameConfig.copyWith(
      gameName: name,
      gamePath: path,
      source: source,
      platform: _currentPlatformName(),
    );
    final updated = state.config.copyWith(
      gameConfig: game,
      scanPaths: {...state.config.scanPaths, path}.toList(),
    );
    await _configRepository.save(updated);
    await logEvent('game_added_manually', 'Game added manually', details: path);
    state = state.copyWith(
      config: updated,
      gameDetectionStatus: GameDetectionStatus.manual,
      gameVerificationStatus: _verificationStatusFor(game),
      clearError: true,
    );
  }

  Future<void> calculateGameHash() async {
    final path = state.config.gameConfig.gamePath;
    if (path.trim().isEmpty) {
      state = state.copyWith(errorMessage: 'No selected game path.');
      return;
    }
    if (!_hashService.supportsPathHashing || Directory(path).existsSync()) {
      state = state.copyWith(
        gameVerificationStatus: GameVerificationStatus.failed,
        errorMessage:
            'Build hashing is available for a selected executable or manifest file.',
      );
      return;
    }
    state = state.copyWith(
      gameVerificationStatus: GameVerificationStatus.pending,
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
      final game = state.config.gameConfig.copyWith(lastCalculatedHash: hash);
      final updated = state.config.copyWith(gameConfig: game);
      await _configRepository.save(updated);
      await logEvent('build_hash_calculated', 'Build hash calculated');
      state = state.copyWith(
        config: updated,
        gameVerificationStatus: _verificationStatusFor(game),
        loading: false,
        clearHashProgress: true,
      );
    } on Object catch (error) {
      await logEvent(
        'build_hash_failed',
        'Build hash calculation failed',
        details: '$error',
      );
      state = state.copyWith(
        gameVerificationStatus: GameVerificationStatus.failed,
        loading: false,
        clearHashProgress: true,
        errorMessage: '$error',
      );
    }
  }

  Future<void> startProtection() async {
    await logEvent('protection_start_requested', 'Protection start requested');
    state = state.copyWith(
      protectionStatus: ProtectionStatus.starting,
      loading: true,
      clearError: true,
    );
    await unawaitedCheckMalwareEngine();
    final hasLocalPrevention =
        state.malwareEngineStatus == MalwareEngineStatus.available ||
        state.malwareEngineStatus == MalwareEngineStatus.signaturesOutdated ||
        state.yaraStatus == 'available' ||
        state.config.protectionMode == ProtectionMode.lockdown;
    if (hasLocalPrevention) {
      await logEvent('protection_started', 'Protection started');
      state = state.copyWith(
        protectionStatus: state.driverStatus == 'running'
            ? ProtectionStatus.protected
            : ProtectionStatus.partiallyProtected,
        loading: false,
        clearError: true,
      );
      return;
    }
    await logEvent(
      'protection_start_failed',
      'Protection start failed',
      details: 'Malware engine unavailable.',
    );
    state = state.copyWith(
      protectionStatus: ProtectionStatus.error,
      loading: false,
      errorMessage:
          'No local prevention engine is ready. Install the Pasus MSI, verify YARA/model assets, or configure ClamAV for development.',
    );
  }

  Future<void> stopProtection() async {
    state = state.copyWith(protectionStatus: ProtectionStatus.stopping);
    final session = state.session;
    if (session != null) {
      await _apiClient.endSession(state.config, session);
    }
    await logEvent('protection_stopped', 'Protection stopped');
    state = state.copyWith(
      clearSession: true,
      protectionStatus: ProtectionStatus.idle,
      heartbeat: const HeartbeatStatus(),
      clearError: true,
    );
  }

  Future<void> setProtectionMode(ProtectionMode mode) async {
    final updated = state.config.copyWith(protectionMode: mode);
    await _configRepository.save(updated);
    await logEvent(
      'protection_mode_changed',
      'Protection profile changed',
      details: mode.label,
    );
    state = state.copyWith(config: updated, clearError: true);
  }

  Future<void> runProtectionSelfTest() async {
    await logEvent(
      'protection_self_test_started',
      'Protection self-test started',
    );
    state = state.copyWith(loading: true, clearError: true);
    final result = await _localCoreClient.runProtectionSelfTest();
    await logEvent(
      'protection_self_test_completed',
      'Protection self-test completed',
      details: result,
    );
    state = state.copyWith(
      loading: false,
      protectionSelfTestResult: result,
      clearError: true,
    );
  }

  Future<void> sendHeartbeat() async {
    final session = state.session;
    if (session == null) return;
    state = state.copyWith(heartbeat: state.heartbeat.copyWith(inFlight: true));
    final result = await _apiClient.sendHeartbeat(state.config, session);
    switch (result) {
      case ApiSuccess<void>():
        await logEvent('heartbeat_sent', 'Heartbeat sent');
        state = state.copyWith(
          heartbeat: HeartbeatStatus(lastSentAt: DateTime.now().toUtc()),
        );
      case ApiFailure<void>(:final message):
        await logEvent(
          'heartbeat_failed',
          'Heartbeat failed',
          details: message,
        );
        state = state.copyWith(
          heartbeat: state.heartbeat.copyWith(
            inFlight: false,
            lastError: message,
          ),
        );
    }
  }

  void setScanActionMode(ScanActionMode mode) {
    state = state.copyWith(scanActionMode: mode);
  }

  Future<void> scanSelectedFile() async {
    if (!_localCoreClient.isDesktop) {
      state = state.copyWith(
        scanStatus: ScanStatus.engineUnavailable,
        errorMessage:
            'Malware quarantine is not available on this platform because mobile OS sandboxing prevents full-device scanning.',
      );
      return;
    }
    final file = await openFile();
    if (file == null) return;
    await _scanPaths(
      [file.path],
      kind: ScanKind.custom,
      actionMode: state.scanActionMode,
    );
  }

  Future<void> scanSelectedFolder() async {
    if (!_localCoreClient.isDesktop) {
      state = state.copyWith(
        scanStatus: ScanStatus.engineUnavailable,
        errorMessage:
            'Malware quarantine is not available on this platform because mobile OS sandboxing prevents full-device scanning.',
      );
      return;
    }
    final path = await getDirectoryPath();
    if (path == null) return;
    await _scanPaths(
      [path],
      kind: ScanKind.custom,
      actionMode: state.scanActionMode,
    );
  }

  Future<void> runQuickScan({ScanActionMode? actionMode}) async {
    final paths = _scanTargetService.quickScanTargets();
    if (paths.isEmpty) {
      await logEvent(
        'scan_completed',
        'Scan completed',
        details: 'No quick scan locations were accessible.',
      );
      state = state.copyWith(
        scanStatus: ScanStatus.completedWithErrors,
        lastScanReport: ScanReport(
          status: ScanStatus.completedWithErrors,
          kind: ScanKind.quick,
          actionMode: actionMode ?? ScanActionMode.autoQuarantineConfirmedOnly,
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
      actionMode: actionMode ?? ScanActionMode.autoQuarantineConfirmedOnly,
    );
  }

  Future<void> runFullScan({ScanActionMode? actionMode}) async {
    final paths = _scanTargetService.fullScanRoots();
    if (paths.isEmpty) {
      state = state.copyWith(
        scanStatus: ScanStatus.completedWithErrors,
        errorMessage: 'No full scan roots were accessible.',
      );
      return;
    }
    await _scanPaths(
      paths,
      kind: ScanKind.full,
      actionMode: actionMode ?? state.scanActionMode,
    );
  }

  Future<void> quarantineThreat(ThreatResult threat) async {
    final quarantined = await _localCoreClient.quarantineThreat(threat);
    if (!quarantined) {
      state = state.copyWith(
        errorMessage: 'Unable to quarantine ${threat.fileName}.',
      );
      return;
    }
    await logEvent(
      'file_quarantined',
      'File quarantined',
      details: threat.path,
    );
    _replaceThreat(
      threat.id,
      threat.copyWith(status: ThreatResultStatus.quarantined),
    );
    await unawaitedRefreshQuarantine();
  }

  Future<void> ignoreThreat(ThreatResult threat) async {
    await logEvent(
      'threat_ignored',
      'Threat kept by user',
      details: threat.path,
    );
    _replaceThreat(
      threat.id,
      threat.copyWith(status: ThreatResultStatus.ignored),
    );
  }

  Future<void> markThreatFalsePositive(ThreatResult threat) async {
    final saved = await _localCoreClient.labelDetection(
      threat,
      'falsePositive',
    );
    if (!saved) {
      state = state.copyWith(
        errorMessage: 'Unable to save false-positive feedback.',
      );
      return;
    }
    await logEvent(
      'false_positive_label_saved',
      'False-positive feedback saved',
      details: threat.fileName,
    );
    _replaceThreat(
      threat.id,
      threat.copyWith(status: ThreatResultStatus.ignored),
    );
  }

  Future<void> markThreatMalicious(ThreatResult threat) async {
    final saved = await _localCoreClient.labelDetection(
      threat,
      'confirmedMalicious',
    );
    if (!saved) {
      state = state.copyWith(
        errorMessage: 'Unable to save malicious feedback.',
      );
      return;
    }
    await logEvent(
      'malicious_label_saved',
      'Malicious feedback saved',
      details: threat.fileName,
    );
  }

  Future<void> addThreatToAllowlist(ThreatResult threat) async {
    final added = await _localCoreClient.addAllowlistEntry(threat.path);
    if (!added) {
      state = state.copyWith(
        errorMessage: 'Unable to allowlist ${threat.fileName}.',
      );
      return;
    }
    await logEvent(
      'allowlist_entry_added',
      'Allowlist entry added',
      details: threat.path,
    );
    _replaceThreat(
      threat.id,
      threat.copyWith(
        recommendedAction: RecommendedAction.allowlist,
        status: ThreatResultStatus.allowlisted,
      ),
    );
  }

  Future<void> deleteThreatPermanently(ThreatResult threat) async {
    state = state.copyWith(
      errorMessage:
          'Permanent deletion requires confirmation from the quarantine screen.',
    );
    await logEvent(
      'delete_requested',
      'Permanent delete requested',
      details: threat.path,
    );
  }

  Future<void> restoreQuarantineItem(QuarantineRecord item) async {
    await logEvent(
      'quarantine_restore_requested',
      'Quarantine restore requested',
      details: item.originalPath,
    );
    final restored = await _localCoreClient.restoreQuarantineItem(
      item.quarantineId,
    );
    if (!restored) {
      state = state.copyWith(
        errorMessage: 'Unable to restore ${item.originalPath}.',
      );
      return;
    }
    await logEvent(
      'quarantine_item_restored',
      'Quarantine item restored',
      details: item.originalPath,
    );
    await unawaitedRefreshQuarantine();
  }

  Future<void> deleteQuarantineItem(QuarantineRecord item) async {
    final deleted = await _localCoreClient.deleteQuarantineItem(
      item.quarantineId,
    );
    if (!deleted) {
      state = state.copyWith(
        errorMessage: 'Unable to delete ${item.originalPath}.',
      );
      return;
    }
    await logEvent(
      'quarantine_item_deleted',
      'Quarantine item deleted',
      details: item.originalPath,
    );
    await unawaitedRefreshQuarantine();
  }

  Future<void> cancelScan() async {
    _scanCancelled = true;
    await _localCoreClient.cancelActiveScan();
    await logEvent('scan_cancelled', 'Scan cancelled');
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
        threats: threats,
      ),
      clearError: true,
    );
  }

  Future<void> _scanPaths(
    List<String> paths, {
    required ScanKind kind,
    required ScanActionMode actionMode,
  }) async {
    if (!_localCoreClient.isDesktop) {
      state = state.copyWith(
        scanStatus: ScanStatus.engineUnavailable,
        errorMessage:
            'Malware quarantine is not available on this platform because mobile OS sandboxing prevents full-device scanning.',
      );
      return;
    }
    await logEvent(
      'scan_started',
      '${kind.label} started',
      details: paths.join('\n'),
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
    final report = paths.length == 1 && File(paths.first).existsSync()
        ? await _localCoreClient.scanFile(
            paths.first,
            kind: kind,
            actionMode: actionMode,
            onProgress: (progress) => state = state.copyWith(
              scanProgress: progress,
              currentScanPath: progress.currentPath,
            ),
          )
        : await _localCoreClient.scanPaths(
            paths,
            kind: kind,
            actionMode: actionMode,
            onProgress: (progress) => state = state.copyWith(
              scanProgress: progress,
              currentScanPath: progress.currentPath,
            ),
          );
    if (_scanCancelled) {
      state = state.copyWith(
        scanStatus: ScanStatus.cancelled,
        clearCurrentScanPath: true,
      );
      return;
    }
    if (report.threats.isNotEmpty) {
      await logEvent(
        'threat_detected',
        'Threats found',
        details: '${report.threats.length} suspicious files',
      );
      for (final threat in report.threats.where(
        (threat) => threat.status == ThreatResultStatus.quarantined,
      )) {
        await logEvent(
          'file_quarantined',
          'File quarantined',
          details: threat.path,
        );
      }
    }
    await logEvent(
      'scan_completed',
      'Scan completed',
      details: report.message ?? report.status.label,
    );
    state = state.copyWith(
      scanStatus: report.status,
      lastScanReport: report,
      clearCurrentScanPath: true,
      errorMessage: report.status == ScanStatus.engineUnavailable
          ? 'Malware engine unavailable. Install the Pasus MSI with bundled ClamAV, or configure ClamAV for development.'
          : null,
    );
    await unawaitedRefreshQuarantine();
  }

  Future<String?> exportLogs() async {
    final file = await _eventRepository.export();
    await logEvent('logs_exported', 'Logs exported', details: file.path);
    return file.path;
  }

  Future<void> resetConfiguration() async {
    await _configRepository.reset();
    await logEvent('configuration_reset', 'Configuration reset');
    state = PasusState(
      config: _configRepository.load(),
      events: _eventRepository.load(),
    );
  }

  GameVerificationStatus _verificationStatusFor(GameConfig gameConfig) {
    if (!gameConfig.isConfigured) {
      return GameVerificationStatus.notConfigured;
    }
    if (gameConfig.lastCalculatedHash.isEmpty) {
      return GameVerificationStatus.pending;
    }
    if (gameConfig.expectedBuildHash.isEmpty ||
        gameConfig.expectedBuildHash == gameConfig.lastCalculatedHash) {
      return GameVerificationStatus.verified;
    }
    return GameVerificationStatus.mismatch;
  }

  String _currentPlatformName() {
    if (Platform.isAndroid) return 'Android';
    if (Platform.isIOS) return 'iOS';
    if (Platform.isWindows) return 'Windows';
    if (Platform.isMacOS) return 'macOS';
    if (Platform.isLinux) return 'Linux';
    return Platform.operatingSystem;
  }
}
