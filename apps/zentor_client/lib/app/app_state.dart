import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zentor_protocol/zentor_protocol.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:url_launcher/url_launcher.dart';

import '../core/config/config_repository.dart';
import '../core/apps/app_detector.dart';
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

final zentorControllerProvider =
    StateNotifierProvider<ZentorController, ZentorState>((ref) {
      return ZentorController(
        configRepository: ref.watch(configRepositoryProvider),
        eventRepository: ref.watch(localEventRepositoryProvider),
        apiClient: ref.watch(apiClientProvider),
        hashService: ref.watch(hashServiceProvider),
        appDetector: ref.watch(appDetectorProvider),
        localCoreClient: ref.watch(localCoreClientProvider),
        scanTargetService: ref.watch(scanTargetServiceProvider),
        updateService: ref.watch(updateServiceProvider),
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
    this.lastEngineError,
    this.scanStatus = ScanStatus.idle,
    this.scanActionMode = ScanActionMode.detectOnly,
    this.scanProgress,
    this.lastScanReport,
    this.protectionRun,
    this.heartbeat = const HeartbeatStatus(),
    this.events = const [],
    this.detectedApps = const [],
    this.quarantine = const [],
    this.loading = false,
    this.errorMessage,
    this.hashProgress,
    this.currentScanPath,
    this.protectionSelfTestResult,
    this.updateStatus = UpdateStatus.notChecked,
    this.currentAppVersion = 'Unknown',
    this.updateInfo,
    this.updateError,
  });

  final ZentorConfig config;
  final CloudStatus cloudStatus;
  final ProtectionStatus protectionStatus;
  final AppDetectionStatus appDetectionStatus;
  final AppVerificationStatus appVerificationStatus;
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
  final String? lastEngineError;
  final ScanStatus scanStatus;
  final ScanActionMode scanActionMode;
  final ScanProgress? scanProgress;
  final ScanReport? lastScanReport;
  final ProtectionRun? protectionRun;
  final HeartbeatStatus heartbeat;
  final List<LocalEvent> events;
  final List<DetectedApp> detectedApps;
  final List<QuarantineRecord> quarantine;
  final bool loading;
  final String? errorMessage;
  final double? hashProgress;
  final String? currentScanPath;
  final String? protectionSelfTestResult;
  final UpdateStatus updateStatus;
  final String currentAppVersion;
  final UpdateInfo? updateInfo;
  final String? updateError;

  ZentorState copyWith({
    ZentorConfig? config,
    CloudStatus? cloudStatus,
    ProtectionStatus? protectionStatus,
    AppDetectionStatus? appDetectionStatus,
    AppVerificationStatus? appVerificationStatus,
    MalwareEngineStatus? malwareEngineStatus,
    AiModelInfo? aiModelInfo,
    String? yaraStatus,
    int? yaraRuleCount,
    String? nativeEngineStatus,
    int? nativeSignatureCount,
    int? nativeRuleCount,
    String? nativeMlStatus,
    String? nativeMlModelVersion,
    bool clearNativeMlModelVersion = false,
    bool? compatibilityEnginesEnabled,
    String? coreServiceStatus,
    String? guardStatus,
    String? driverStatus,
    String? installPath,
    String? engineDirectory,
    List<String>? enginePathsChecked,
    String? programDataDirectory,
    String? lastEngineError,
    ScanStatus? scanStatus,
    ScanActionMode? scanActionMode,
    ScanProgress? scanProgress,
    bool clearScanProgress = false,
    ScanReport? lastScanReport,
    ProtectionRun? protectionRun,
    bool clearProtectionRun = false,
    HeartbeatStatus? heartbeat,
    List<LocalEvent>? events,
    List<DetectedApp>? detectedApps,
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
    UpdateStatus? updateStatus,
    String? currentAppVersion,
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
      compatibilityEnginesEnabled:
          compatibilityEnginesEnabled ?? this.compatibilityEnginesEnabled,
      coreServiceStatus: coreServiceStatus ?? this.coreServiceStatus,
      guardStatus: guardStatus ?? this.guardStatus,
      driverStatus: driverStatus ?? this.driverStatus,
      installPath: installPath ?? this.installPath,
      engineDirectory: engineDirectory ?? this.engineDirectory,
      enginePathsChecked: enginePathsChecked ?? this.enginePathsChecked,
      programDataDirectory: programDataDirectory ?? this.programDataDirectory,
      lastEngineError: lastEngineError ?? this.lastEngineError,
      scanStatus: scanStatus ?? this.scanStatus,
      scanActionMode: scanActionMode ?? this.scanActionMode,
      scanProgress: clearScanProgress
          ? null
          : scanProgress ?? this.scanProgress,
      lastScanReport: lastScanReport ?? this.lastScanReport,
      protectionRun: clearProtectionRun
          ? null
          : protectionRun ?? this.protectionRun,
      heartbeat: heartbeat ?? this.heartbeat,
      events: events ?? this.events,
      detectedApps: detectedApps ?? this.detectedApps,
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
      updateStatus: updateStatus ?? this.updateStatus,
      currentAppVersion: currentAppVersion ?? this.currentAppVersion,
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
    required LocalCoreClient localCoreClient,
    required ScanTargetService scanTargetService,
    required ZentorUpdateService updateService,
  }) : this._(
         configRepository,
         eventRepository,
         apiClient,
         hashService,
         appDetector,
         localCoreClient,
         scanTargetService,
         updateService,
       );

  ZentorController._(
    this._configRepository,
    this._eventRepository,
    this._apiClient,
    this._hashService,
    this._appDetector,
    this._localCoreClient,
    this._scanTargetService,
    this._updateService,
  ) : super(const ZentorState());

  final ConfigRepository _configRepository;
  final LocalEventRepository _eventRepository;
  final ZentorApiClient _apiClient;
  final HashService _hashService;
  final AppDetector _appDetector;
  final LocalCoreClient _localCoreClient;
  final ScanTargetService _scanTargetService;
  final ZentorUpdateService _updateService;
  bool _scanCancelled = false;

  void load() {
    final config = _configRepository.load();
    state = state.copyWith(
      config: config,
      events: _eventRepository.load(),
      cloudStatus: CloudStatus.disabled,
      appVerificationStatus: _verificationStatusFor(config.protectedAppConfig),
    );
    logEvent('app_started', 'App started');
    logEvent('local_scanner_initialized', 'Local scanner initialized');
    unawaitedDetectApps();
    unawaitedCheckMalwareEngine();
    unawaitedRefreshQuarantine();
    unawaitedCheckForUpdates(silent: true);
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

  Future<void> unawaitedCheckForUpdates({bool silent = false}) async {
    if (!mounted) return;
    if (!silent) {
      await logEvent('update_check_started', 'Update check started');
    }
    state = state.copyWith(
      updateStatus: UpdateStatus.checking,
      clearUpdateError: true,
    );
    final result = await _updateService.checkForUpdate();
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
      );
    } else if (!silent && result.status == UpdateStatus.upToDate) {
      await logEvent('update_check_completed', 'Avorax is up to date');
    } else if (!silent && result.status == UpdateStatus.failed) {
      await logEvent(
        'update_check_failed',
        'Update check failed',
        details: result.error,
      );
    }
  }

  Future<void> openUpdateDownload() async {
    final update = state.updateInfo;
    if (update == null) {
      await unawaitedCheckForUpdates();
      return;
    }
    final uri = update.downloadUrl ?? update.releaseUrl;
    final opened = await launchUrl(uri, mode: LaunchMode.externalApplication);
    if (!opened) {
      state = state.copyWith(errorMessage: 'Unable to open update link.');
      return;
    }
    await logEvent(
      'update_download_opened',
      'Update download opened',
      details: uri.toString(),
    );
  }

  Future<void> saveDeveloperCloudOverride({
    required bool enabled,
    required String apiBaseUrl,
    required String projectId,
    required String publicClientKey,
  }) async {
    final updated = state.config.copyWith(
      developerOverrideEnabled: enabled,
      apiBaseUrl: apiBaseUrl.trim(),
      projectId: projectId.trim(),
      publicClientKey: publicClientKey.trim(),
    );
    await _configRepository.save(updated);
    await logEvent('configuration_saved', 'Cloud configuration saved');
    state = state.copyWith(config: updated, clearError: true);
    await unawaitedCheckCloud();
  }

  Future<void> unawaitedDetectApps() async {
    await logEvent('app_detection_started', 'Protected app detection started');
    if (!mounted) return;
    state = state.copyWith(appDetectionStatus: AppDetectionStatus.scanning);
    final apps = await _appDetector.detect();
    if (!mounted) return;
    if (apps.isEmpty) {
      await logEvent('no_supported_app_detected', 'No supported app detected');
      state = state.copyWith(
        detectedApps: const [],
        appDetectionStatus: state.config.protectedAppConfig.isConfigured
            ? AppDetectionStatus.manual
            : AppDetectionStatus.notFound,
      );
      return;
    }
    await logEvent('protected_app_detected', 'Protected app detected');
    state = state.copyWith(
      detectedApps: apps,
      appDetectionStatus: AppDetectionStatus.detected,
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
      nativeEngineStatus: health.nativeEngineStatus,
      nativeSignatureCount: health.nativeSignatureCount,
      nativeRuleCount: health.nativeRuleCount,
      nativeMlStatus: health.nativeMlStatus,
      nativeMlModelVersion: health.nativeMlModelVersion,
      compatibilityEnginesEnabled: health.compatibilityEnginesEnabled,
      coreServiceStatus: health.coreServiceStatus,
      guardStatus: health.guardStatus,
      driverStatus: health.driverStatus,
      installPath: health.installPath,
      engineDirectory: health.engineDirectory,
      enginePathsChecked: health.enginePathsChecked,
      programDataDirectory: health.programDataDirectory,
      lastEngineError: health.lastError,
    );
  }

  Future<void> unawaitedRefreshQuarantine() async {
    if (!mounted) return;
    final quarantine = await _localCoreClient.listQuarantine();
    if (!mounted) return;
    state = state.copyWith(quarantine: quarantine);
  }

  Future<void> addManualProtectedAppFile() async {
    if (!_hashService.supportsPathHashing) {
      state = state.copyWith(
        errorMessage:
            'Selected file protection is unavailable on this mobile platform.',
      );
      return;
    }
    final file = await openFile();
    if (file == null) return;
    await _saveManualAppPath(file.name, file.path, 'Manual');
  }

  Future<void> addManualProtectedAppFolder() async {
    if (!_hashService.supportsPathHashing) {
      state = state.copyWith(
        errorMessage:
            'Selected folder protection is unavailable on this mobile platform.',
      );
      return;
    }
    final path = await getDirectoryPath();
    if (path == null) return;
    await _saveManualAppPath(
      path.split(Platform.pathSeparator).last,
      path,
      'Manual',
    );
  }

  Future<void> selectDetectedApp(DetectedApp app) async {
    final updated = state.config.copyWith(
      protectedAppConfig: app.toProtectedAppConfig(),
    );
    await _configRepository.save(updated);
    await logEvent(
      'protected_app_added_manually',
      'Protected app selected',
      details: app.path,
    );
    state = state.copyWith(
      config: updated,
      appDetectionStatus: AppDetectionStatus.detected,
      appVerificationStatus: _verificationStatusFor(updated.protectedAppConfig),
      clearError: true,
    );
  }

  Future<void> _saveManualAppPath(
    String name,
    String path,
    String source,
  ) async {
    final app = state.config.protectedAppConfig.copyWith(
      appName: name,
      appPath: path,
      source: source,
      platform: _currentPlatformName(),
    );
    final updated = state.config.copyWith(
      protectedAppConfig: app,
      scanPaths: {...state.config.scanPaths, path}.toList(),
    );
    await _configRepository.save(updated);
    await logEvent(
      'protected_app_added_manually',
      'Protected app added manually',
      details: path,
    );
    state = state.copyWith(
      config: updated,
      appDetectionStatus: AppDetectionStatus.manual,
      appVerificationStatus: _verificationStatusFor(app),
      clearError: true,
    );
  }

  Future<void> calculateProtectedAppHash() async {
    final path = state.config.protectedAppConfig.appPath;
    if (path.trim().isEmpty) {
      state = state.copyWith(errorMessage: 'No selected app path.');
      return;
    }
    if (!_hashService.supportsPathHashing || Directory(path).existsSync()) {
      state = state.copyWith(
        appVerificationStatus: AppVerificationStatus.failed,
        errorMessage:
            'Build hashing is available for a selected executable or manifest file.',
      );
      return;
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
      await logEvent('file_hash_calculated', 'Build hash calculated');
      state = state.copyWith(
        config: updated,
        appVerificationStatus: _verificationStatusFor(app),
        loading: false,
        clearHashProgress: true,
      );
    } on Object catch (error) {
      await logEvent(
        'file_hash_failed',
        'Build hash calculation failed',
        details: '$error',
      );
      state = state.copyWith(
        appVerificationStatus: AppVerificationStatus.failed,
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
        state.nativeEngineStatus == 'ready' ||
        state.config.protectionMode == ProtectionMode.lockdown;
    if (hasLocalPrevention) {
      final modeConfigured = await _localCoreClient.configureGuardMode(
        state.config.protectionMode,
      );
      await logEvent('protection_started', 'Protection started');
      state = state.copyWith(
        protectionStatus: state.driverStatus == 'running'
            ? ProtectionStatus.protected
            : ProtectionStatus.partiallyProtected,
        loading: false,
        clearError: modeConfigured,
        errorMessage: modeConfigured
            ? null
            : 'Protection started, but Avorax could not write the shared Guard mode config. Existing service mode may remain active until the service is restarted or configured by installer.',
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
          'No local prevention engine is ready. Install the Avorax MSI or verify Avorax Native Engine assets.',
    );
  }

  Future<void> stopProtection() async {
    state = state.copyWith(protectionStatus: ProtectionStatus.stopping);
    final protectionRun = state.protectionRun;
    if (protectionRun != null) {
      await _apiClient.endProtectionRun(state.config, protectionRun);
    }
    final modeConfigured = await _localCoreClient.configureGuardMode(
      ProtectionMode.off,
    );
    await logEvent('protection_stopped', 'Protection stopped');
    state = state.copyWith(
      clearProtectionRun: true,
      protectionStatus: ProtectionStatus.idle,
      heartbeat: const HeartbeatStatus(),
      clearError: modeConfigured,
      errorMessage: modeConfigured
          ? null
          : 'Protection was stopped in the UI, but Avorax could not write the shared Guard disabled config. Stop the service from Windows Services if it is still running.',
    );
  }

  Future<void> setProtectionMode(ProtectionMode mode) async {
    final updated = state.config.copyWith(protectionMode: mode);
    await _configRepository.save(updated);
    final modeConfigured = await _localCoreClient.configureGuardMode(mode);
    await logEvent(
      'protection_mode_changed',
      'Protection profile changed',
      details: modeConfigured
          ? mode.label
          : '${mode.label}; shared Guard mode config unavailable',
    );
    state = state.copyWith(
      config: updated,
      clearError: modeConfigured,
      errorMessage: modeConfigured
          ? null
          : 'Saved UI profile, but Avorax could not write the shared Guard mode config. The running service may keep its previous mode.',
    );
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
    final protectionRun = state.protectionRun;
    if (protectionRun == null) return;
    state = state.copyWith(heartbeat: state.heartbeat.copyWith(inFlight: true));
    final result = await _apiClient.sendHeartbeat(state.config, protectionRun);
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
          ? 'Avorax Native Engine unavailable. Install the Avorax MSI or verify native engine assets.'
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
    state = ZentorState(
      config: _configRepository.load(),
      events: _eventRepository.load(),
    );
  }

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
}
