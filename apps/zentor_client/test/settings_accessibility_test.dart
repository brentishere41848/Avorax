import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:zentor_client/app/app_state.dart';
import 'package:zentor_client/app/theme/zentor_theme.dart';
import 'package:zentor_client/core/apps/app_detector.dart';
import 'package:zentor_client/core/config/config_repository.dart';
import 'package:zentor_client/core/local_core/local_core_client.dart';
import 'package:zentor_client/core/logging/local_event_repository.dart';
import 'package:zentor_client/core/network/api_result.dart';
import 'package:zentor_client/core/network/zentor_api_client.dart';
import 'package:zentor_client/core/scanning/scan_target_service.dart';
import 'package:zentor_client/core/security/hash_service.dart';
import 'package:zentor_client/core/updates/update_service.dart';
import 'package:zentor_client/features/device/device_screen.dart';
import 'package:zentor_client/features/home/home_screen.dart';
import 'package:zentor_client/features/logs/logs_screen.dart';
import 'package:zentor_client/features/protection/protection_screen.dart';
import 'package:zentor_client/features/protected_apps/protected_apps_screen.dart';
import 'package:zentor_client/features/scan/scan_screen.dart';
import 'package:zentor_client/features/settings/settings_screen.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

class _SupportedAppDetector extends AppDetector {
  const _SupportedAppDetector();

  @override
  bool get supportsAutomaticDetection => true;

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

class _FakeShortcutScanTargetService extends ScanTargetService {
  const _FakeShortcutScanTargetService();

  @override
  ScanTargetPlan quickScanTargetPlan({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => const ScanTargetPlan([r'C:\AvoraxTest\Quick'], []);

  @override
  ScanTargetPlan fullScanRootPlan({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => const ScanTargetPlan([r'C:\AvoraxTest\FullRoot'], []);
}

class _RecordingShortcutLocalCoreClient extends LocalCoreClient {
  int scanCalls = 0;
  int guardModeCalls = 0;
  int watchCalls = 0;
  int stopWatchCalls = 0;
  int protectionSelfTestCalls = 0;
  int ransomwareGuardCalls = 0;
  ScanKind? lastKind;
  ScanActionMode? lastActionMode;
  ProtectionMode? lastGuardMode;
  List<String> lastPaths = const [];
  List<String> lastWatchPaths = const [];
  List<String> lastRansomwareProtectedRoots = const [];
  List<String> lastRansomwareTrustedProcesses = const [];

  @override
  bool get isDesktop => true;

  @override
  Future<MalwareEngineStatus> health() async => MalwareEngineStatus.available;

  @override
  Future<LocalCoreHealth> healthSummary() async => const LocalCoreHealth(
    malwareEngineStatus: MalwareEngineStatus.available,
    nativeEngineStatus: 'ready',
    coreServiceStatus: 'running',
  );

  @override
  Future<ScanReport> scanPaths(
    List<String> paths, {
    required ScanKind kind,
    required ScanActionMode actionMode,
    void Function(ScanProgress progress)? onProgress,
  }) async {
    scanCalls += 1;
    lastKind = kind;
    lastActionMode = actionMode;
    lastPaths = List<String>.of(paths);
    return ScanReport(
      status: ScanStatus.clean,
      kind: kind,
      actionMode: actionMode,
      filesScanned: 1,
      threatsFound: 0,
      skippedFiles: 0,
      elapsedMs: 1,
      message: 'clean',
      threats: const [],
    );
  }

  @override
  Future<LocalCoreActionResult> configureGuardMode(ProtectionMode mode) async {
    guardModeCalls += 1;
    lastGuardMode = mode;
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<LocalCoreActionResult> configureRansomwareGuard({
    required List<String> protectedRoots,
    required List<String> trustedProcesses,
  }) async {
    ransomwareGuardCalls += 1;
    lastRansomwareProtectedRoots = List<String>.of(protectedRoots);
    lastRansomwareTrustedProcesses = List<String>.of(trustedProcesses);
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<RealtimeWatcherState> startWatch(List<String> paths) async {
    watchCalls += 1;
    lastWatchPaths = List<String>.of(paths);
    return RealtimeWatcherState(
      active: paths.isNotEmpty,
      mode: paths.isEmpty ? 'off' : 'userModeBestEffort',
      watchedPaths: List<String>.of(paths),
    );
  }

  @override
  Future<RealtimeWatcherState> stopWatch() async {
    stopWatchCalls += 1;
    return const RealtimeWatcherState(active: false, mode: 'off');
  }

  @override
  Future<String> runProtectionSelfTest() async {
    protectionSelfTestCalls += 1;
    return 'PASS fixture protection self-test';
  }
}

class _RecordingUpdateService extends ZentorUpdateService {
  final List<String> calls = [];

  @override
  bool get packageMutationSupported => true;

  @override
  Future<UpdateCheckResult> checkForUpdate({String? currentVersion}) async {
    calls.add('check');
    return UpdateCheckResult.available(
      UpdateInfo(
        currentVersion: '0.2.15',
        latestVersion: '0.2.16',
        feedUrl: Uri.parse('https://updates.example.test/feed.json'),
        packageUrl: Uri.parse('https://updates.example.test/Avorax.aup'),
        packageSha256: 'a' * 64,
        channel: 'stable',
        rollbackSupported: false,
        packageName: 'Avorax.aup',
        releaseNotes: null,
        localPackagePath: null,
      ),
    );
  }

  @override
  Future<UpdateInfo> downloadUpdatePackage(UpdateInfo update) async {
    calls.add('download');
    return update.copyWith(
      localPackagePath: r'C:\AvoraxTest\updates\Avorax.aup',
    );
  }

  @override
  Future<void> verifyDownloadedPackage(UpdateInfo update) async {
    calls.add('verify');
  }

  @override
  Future<void> installDownloadedPackage(UpdateInfo update) async {
    calls.add('install');
  }
}

void main() {
  testWidgets('settings exposes screen-reader section headers', (tester) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          appDetectorProvider.overrideWithValue(const _FakeAppDetector()),
        ],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: SettingsScreen()),
          ),
        ),
      ),
    );

    expect(
      find.bySemanticsLabel('Settings section, Protection'),
      findsOneWidget,
    );
    expect(
      find.bySemanticsLabel('Settings section, Avorax Native Engine'),
      findsOneWidget,
    );
    expect(
      find.bySemanticsLabel('Settings section, Diagnostics'),
      findsOneWidget,
    );
  });

  testWidgets('self-test buttons disable and relabel while busy', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();

    final controller = ZentorController(
      configRepository: ConfigRepository(preferences),
      eventRepository: LocalEventRepository(preferences),
      apiClient: ZentorApiClient(),
      hashService: HashService(),
      appDetector: const _FakeAppDetector(),
      localCoreClient: const LocalCoreClient(),
      scanTargetService: const ScanTargetService(),
      updateService: ZentorUpdateService(),
    );
    controller.state = const ZentorState(protectionSelfTestInFlight: true);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(
              child: Column(children: [ProtectionScreen(), SettingsScreen()]),
            ),
          ),
        ),
      ),
    );

    final protectionButton = find.widgetWithText(
      OutlinedButton,
      'Running self-test...',
    );
    final settingsButton = find.widgetWithText(
      OutlinedButton,
      'Running Protection Self-Test',
    );

    expect(protectionButton, findsOneWidget);
    expect(settingsButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(protectionButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(settingsButton).onPressed, isNull);
  });

  testWidgets(
    'settings check engine button disables while health check is busy',
    (tester) async {
      await _pumpScreenWithState(
        tester,
        const ZentorState(malwareEngineHealthCheckInFlight: true),
        const SettingsScreen(),
      );

      final checkButton = find.widgetWithText(
        OutlinedButton,
        'Checking engine',
      );

      expect(checkButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(checkButton).onPressed, isNull);
      expect(find.widgetWithText(OutlinedButton, 'Check engine'), findsNothing);
    },
  );

  testWidgets('settings cloud check button runs health check once', (
    tester,
  ) async {
    final apiClient = _FakeApiClient();
    final controller = await _pumpScreenWithState(
      tester,
      const ZentorState(cloudStatus: CloudStatus.disabled),
      const SettingsScreen(),
      apiClient: apiClient,
    );

    final cloudButton = find.widgetWithText(
      OutlinedButton,
      'Test Cloud Connection',
    );
    await tester.ensureVisible(cloudButton);
    await tester.tap(cloudButton);
    await tester.pumpAndSettle();

    expect(apiClient.healthCalls, 1);
    expect(controller.state.cloudStatus, CloudStatus.online);
    expect(controller.state.cloudHealthCheckInFlight, isFalse);
    expect(
      controller.state.events.map((event) => event.type),
      containsAll(['cloud_health_check_started', 'cloud_online']),
    );
  });

  testWidgets(
    'settings cloud check button disables while cloud check is busy',
    (tester) async {
      final apiClient = _FakeApiClient();
      await _pumpScreenWithState(
        tester,
        const ZentorState(
          cloudHealthCheckInFlight: true,
          cloudStatus: CloudStatus.checking,
        ),
        const SettingsScreen(),
        apiClient: apiClient,
      );

      final cloudButton = find.widgetWithText(OutlinedButton, 'Checking Cloud');

      expect(cloudButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(cloudButton).onPressed, isNull);
      expect(
        find.widgetWithText(OutlinedButton, 'Test Cloud Connection'),
        findsNothing,
      );
      expect(apiClient.healthCalls, 0);
    },
  );

  testWidgets('settings update check button runs update service once', (
    tester,
  ) async {
    final updateService = _RecordingUpdateService();
    final controller = await _pumpScreenWithState(
      tester,
      const ZentorState(updateStatus: UpdateStatus.notChecked),
      const SettingsScreen(),
      updateService: updateService,
    );

    final checkButton = find.widgetWithText(
      OutlinedButton,
      'Check for updates',
    );
    await tester.ensureVisible(checkButton);
    await tester.tap(checkButton);
    await tester.pumpAndSettle();

    expect(updateService.calls, ['check']);
    expect(controller.state.updateStatus, UpdateStatus.updateAvailable);
    expect(controller.state.updateInfo?.latestVersion, '0.2.16');
    expect(find.text('Status'), findsWidgets);
    expect(find.text('Update available'), findsOneWidget);
    expect(
      controller.state.events.map((event) => event.type),
      containsAll(['update_check_started', 'update_available']),
    );
  });

  testWidgets('settings update check button disables while update busy', (
    tester,
  ) async {
    final updateService = _RecordingUpdateService();
    await _pumpScreenWithState(
      tester,
      const ZentorState(updateStatus: UpdateStatus.checking),
      const SettingsScreen(),
      updateService: updateService,
    );

    final checkButton = find.widgetWithText(OutlinedButton, 'Checking');

    expect(checkButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(checkButton).onPressed, isNull);
    expect(
      find.widgetWithText(OutlinedButton, 'Check for updates'),
      findsNothing,
    );
    expect(updateService.calls, isEmpty);
  });

  testWidgets(
    'settings update install disables while active security work is busy',
    (tester) async {
      for (final state in [
        _updateAvailableState().copyWith(scanStatus: ScanStatus.running),
        _updateAvailableState().copyWith(
          protectionStatus: ProtectionStatus.protected,
        ),
        _updateAvailableState().copyWith(configurationResetInFlight: true),
        _updateAvailableState().copyWith(serviceActionInFlight: true),
        _updateAvailableState().copyWith(developerCloudOverrideInFlight: true),
        _updateAvailableState().copyWith(protectedAppActionInFlight: true),
      ]) {
        final updateService = _RecordingUpdateService();
        await _pumpScreenWithState(
          tester,
          state,
          const SettingsScreen(),
          updateService: updateService,
        );

        final checkButton = find.widgetWithText(
          OutlinedButton,
          'Check for updates',
        );
        final installButton = find.widgetWithText(
          FilledButton,
          'Download, verify, install',
        );
        await tester.ensureVisible(installButton);

        expect(checkButton, findsOneWidget);
        expect(tester.widget<OutlinedButton>(checkButton).onPressed, isNotNull);
        expect(installButton, findsOneWidget);
        expect(tester.widget<FilledButton>(installButton).onPressed, isNull);
        expect(updateService.calls, isEmpty);
      }
    },
  );

  testWidgets('settings update install dialog cancel does not call service', (
    tester,
  ) async {
    final updateService = _RecordingUpdateService();
    final controller = await _pumpScreenWithState(
      tester,
      _updateAvailableState(),
      const SettingsScreen(),
      updateService: updateService,
    );

    final installButton = find.widgetWithText(
      FilledButton,
      'Download, verify, install',
    );
    await tester.ensureVisible(installButton);
    await tester.tap(installButton);
    await tester.pumpAndSettle();

    expect(find.text('Download, verify, and install update?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(updateService.calls, isEmpty);
    expect(controller.state.updateStatus, UpdateStatus.updateAvailable);
    expect(
      controller.state.events.where(
        (event) => event.type == 'update_install_started',
      ),
      isEmpty,
    );
  });

  testWidgets('settings update install dialog confirm runs service once', (
    tester,
  ) async {
    final updateService = _RecordingUpdateService();
    final controller = await _pumpScreenWithState(
      tester,
      _updateAvailableState(),
      const SettingsScreen(),
      updateService: updateService,
    );

    final installButton = find.widgetWithText(
      FilledButton,
      'Download, verify, install',
    );
    await tester.ensureVisible(installButton);
    await tester.tap(installButton);
    await tester.pumpAndSettle();

    expect(find.text('Download, verify, and install update?'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();

    expect(updateService.calls, ['download', 'verify', 'install']);
    expect(controller.state.updateStatus, UpdateStatus.readyToRestart);
    expect(
      controller.state.events.map((event) => event.type),
      containsAll(['update_install_started', 'update_install_ready']),
    );
  });

  testWidgets(
    'settings security controls disable while security save is busy',
    (tester) async {
      await _pumpScreenWithState(
        tester,
        const ZentorState(securitySettingsActionInFlight: true),
        const SettingsScreen(),
      );

      final protectionModeDropdown = find.byWidgetPredicate(
        (widget) =>
            widget is DropdownButtonFormField<ProtectionMode> &&
            widget.onChanged == null,
      );
      final intervalDropdown = find.byWidgetPredicate(
        (widget) =>
            widget is DropdownButtonFormField<int> && widget.onChanged == null,
      );
      final scheduledSwitch = find.byWidgetPredicate(
        (widget) =>
            widget is SwitchListTile &&
            widget.title is Text &&
            (widget.title as Text).data ==
                'Enable in-app scheduled quick scan' &&
            widget.onChanged == null,
      );
      final ransomwareSaveButton = find.widgetWithText(
        OutlinedButton,
        'Saving security settings',
      );

      expect(protectionModeDropdown, findsOneWidget);
      expect(intervalDropdown, findsOneWidget);
      expect(scheduledSwitch, findsOneWidget);
      expect(
        tester
            .widget<TextField>(
              find.widgetWithText(TextField, 'Ransomware protected folders'),
            )
            .enabled,
        isFalse,
      );
      expect(
        tester
            .widget<TextField>(
              find.widgetWithText(TextField, 'Trusted backup/sync processes'),
            )
            .enabled,
        isFalse,
      );
      expect(ransomwareSaveButton, findsOneWidget);
      expect(
        tester.widget<OutlinedButton>(ransomwareSaveButton).onPressed,
        isNull,
      );
      expect(
        find.widgetWithText(
          OutlinedButton,
          'Save ransomware protection settings',
        ),
        findsNothing,
      );
    },
  );

  testWidgets(
    'settings security controls disable while protection state is busy',
    (tester) async {
      for (final state in const [
        ZentorState(protectionOperationInFlight: true),
        ZentorState(protectionSelfTestInFlight: true),
      ]) {
        await _pumpScreenWithState(tester, state, const SettingsScreen());

        final protectionModeDropdown = find.byWidgetPredicate(
          (widget) =>
              widget is DropdownButtonFormField<ProtectionMode> &&
              widget.onChanged == null,
        );
        final intervalDropdown = find.byWidgetPredicate(
          (widget) =>
              widget is DropdownButtonFormField<int> &&
              widget.onChanged == null,
        );
        final scheduledSwitch = find.byWidgetPredicate(
          (widget) =>
              widget is SwitchListTile &&
              widget.title is Text &&
              (widget.title as Text).data ==
                  'Enable in-app scheduled quick scan' &&
              widget.onChanged == null,
        );
        final ransomwareSaveButton = find.widgetWithText(
          OutlinedButton,
          'Save ransomware protection settings',
        );

        expect(protectionModeDropdown, findsOneWidget);
        expect(intervalDropdown, findsOneWidget);
        expect(scheduledSwitch, findsOneWidget);
        expect(
          tester
              .widget<TextField>(
                find.widgetWithText(TextField, 'Ransomware protected folders'),
              )
              .enabled,
          isFalse,
        );
        expect(
          tester
              .widget<TextField>(
                find.widgetWithText(TextField, 'Trusted backup/sync processes'),
              )
              .enabled,
          isFalse,
        );
        expect(ransomwareSaveButton, findsOneWidget);
        expect(
          tester.widget<OutlinedButton>(ransomwareSaveButton).onPressed,
          isNull,
        );
      }
    },
  );

  testWidgets(
    'settings security controls disable while configuration or manual actions are busy',
    (tester) async {
      for (final state in const [
        ZentorState(configurationResetInFlight: true),
        ZentorState(quarantineActionInFlight: true),
        ZentorState(allowlistActionInFlight: true),
        ZentorState(detectionFeedbackInFlight: true),
      ]) {
        await _pumpScreenWithState(tester, state, const SettingsScreen());

        final protectionModeDropdown = find.byWidgetPredicate(
          (widget) =>
              widget is DropdownButtonFormField<ProtectionMode> &&
              widget.onChanged == null,
        );
        final intervalDropdown = find.byWidgetPredicate(
          (widget) =>
              widget is DropdownButtonFormField<int> &&
              widget.onChanged == null,
        );
        final scheduledSwitch = find.byWidgetPredicate(
          (widget) =>
              widget is SwitchListTile &&
              widget.title is Text &&
              (widget.title as Text).data ==
                  'Enable in-app scheduled quick scan' &&
              widget.onChanged == null,
        );
        final ransomwareSaveButton = find.widgetWithText(
          OutlinedButton,
          'Save ransomware protection settings',
        );

        expect(protectionModeDropdown, findsOneWidget);
        expect(intervalDropdown, findsOneWidget);
        expect(scheduledSwitch, findsOneWidget);
        expect(
          tester
              .widget<TextField>(
                find.widgetWithText(TextField, 'Ransomware protected folders'),
              )
              .enabled,
          isFalse,
        );
        expect(
          tester
              .widget<TextField>(
                find.widgetWithText(TextField, 'Trusted backup/sync processes'),
              )
              .enabled,
          isFalse,
        );
        expect(ransomwareSaveButton, findsOneWidget);
        expect(
          tester.widget<OutlinedButton>(ransomwareSaveButton).onPressed,
          isNull,
        );
      }
    },
  );

  testWidgets('settings security controls disable while scan work is busy', (
    tester,
  ) async {
    for (final state in const [
      ZentorState(scanStartInFlight: true),
      ZentorState(scanStatus: ScanStatus.running),
      ZentorState(scanTargetSelectionInFlight: true),
      ZentorState(scanCancelInFlight: true),
    ]) {
      await _pumpScreenWithState(tester, state, const SettingsScreen());

      final protectionModeDropdown = find.byWidgetPredicate(
        (widget) =>
            widget is DropdownButtonFormField<ProtectionMode> &&
            widget.onChanged == null,
      );
      final intervalDropdown = find.byWidgetPredicate(
        (widget) =>
            widget is DropdownButtonFormField<int> && widget.onChanged == null,
      );
      final scheduledSwitch = find.byWidgetPredicate(
        (widget) =>
            widget is SwitchListTile &&
            widget.title is Text &&
            (widget.title as Text).data ==
                'Enable in-app scheduled quick scan' &&
            widget.onChanged == null,
      );
      final ransomwareSaveButton = find.widgetWithText(
        OutlinedButton,
        'Save ransomware protection settings',
      );

      expect(protectionModeDropdown, findsOneWidget);
      expect(intervalDropdown, findsOneWidget);
      expect(scheduledSwitch, findsOneWidget);
      expect(
        tester
            .widget<TextField>(
              find.widgetWithText(TextField, 'Ransomware protected folders'),
            )
            .enabled,
        isFalse,
      );
      expect(
        tester
            .widget<TextField>(
              find.widgetWithText(TextField, 'Trusted backup/sync processes'),
            )
            .enabled,
        isFalse,
      );
      expect(ransomwareSaveButton, findsOneWidget);
      expect(
        tester.widget<OutlinedButton>(ransomwareSaveButton).onPressed,
        isNull,
      );
    }
  });

  testWidgets(
    'settings security and reset controls disable while update package work is busy',
    (tester) async {
      await _pumpScreenWithState(
        tester,
        const ZentorState(updateStatus: UpdateStatus.installing),
        const SettingsScreen(),
      );

      final protectionModeDropdown = find.byWidgetPredicate(
        (widget) =>
            widget is DropdownButtonFormField<ProtectionMode> &&
            widget.onChanged == null,
      );
      final intervalDropdown = find.byWidgetPredicate(
        (widget) =>
            widget is DropdownButtonFormField<int> && widget.onChanged == null,
      );
      final scheduledSwitch = find.byWidgetPredicate(
        (widget) =>
            widget is SwitchListTile &&
            widget.title is Text &&
            (widget.title as Text).data ==
                'Enable in-app scheduled quick scan' &&
            widget.onChanged == null,
      );
      final ransomwareSaveButton = find.widgetWithText(
        OutlinedButton,
        'Save ransomware protection settings',
      );
      final resetButton = find.widgetWithText(
        OutlinedButton,
        'Reset configuration',
      );

      expect(protectionModeDropdown, findsOneWidget);
      expect(intervalDropdown, findsOneWidget);
      expect(scheduledSwitch, findsOneWidget);
      expect(
        tester
            .widget<TextField>(
              find.widgetWithText(TextField, 'Ransomware protected folders'),
            )
            .enabled,
        isFalse,
      );
      expect(
        tester
            .widget<TextField>(
              find.widgetWithText(TextField, 'Trusted backup/sync processes'),
            )
            .enabled,
        isFalse,
      );
      expect(ransomwareSaveButton, findsOneWidget);
      expect(
        tester.widget<OutlinedButton>(ransomwareSaveButton).onPressed,
        isNull,
      );
      expect(resetButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(resetButton).onPressed, isNull);
    },
  );

  testWidgets(
    'settings protection mode dialog cancel does not call local core',
    (tester) async {
      final localCore = _RecordingShortcutLocalCoreClient();
      final controller = await _pumpScreenWithState(
        tester,
        const ZentorState(),
        const SettingsScreen(),
        localCoreClient: localCore,
      );

      final dropdown = tester.widget<DropdownButtonFormField<ProtectionMode>>(
        find.byWidgetPredicate(
          (widget) => widget is DropdownButtonFormField<ProtectionMode>,
        ),
      );
      dropdown.onChanged!(ProtectionMode.lockdown);
      await tester.pumpAndSettle();

      expect(find.text('Change protection mode?'), findsOneWidget);
      await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
      await tester.pumpAndSettle();

      expect(localCore.guardModeCalls, 0);
      expect(controller.state.config.protectionMode, ProtectionMode.balanced);
      expect(find.text('Protection mode changed.'), findsNothing);
    },
  );

  testWidgets('settings protection mode dialog confirm calls local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    final controller = await _pumpScreenWithState(
      tester,
      const ZentorState(),
      const SettingsScreen(),
      localCoreClient: localCore,
    );

    final dropdown = tester.widget<DropdownButtonFormField<ProtectionMode>>(
      find.byWidgetPredicate(
        (widget) => widget is DropdownButtonFormField<ProtectionMode>,
      ),
    );
    dropdown.onChanged!(ProtectionMode.lockdown);
    await tester.pumpAndSettle();

    expect(find.text('Change protection mode?'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Change'));
    await tester.pumpAndSettle();

    expect(localCore.guardModeCalls, 1);
    expect(localCore.lastGuardMode, ProtectionMode.lockdown);
    expect(controller.state.config.protectionMode, ProtectionMode.lockdown);
    expect(find.text('Protection mode changed.'), findsOneWidget);
  });

  testWidgets(
    'settings ransomware guard dialog cancel does not call local core',
    (tester) async {
      final localCore = _RecordingShortcutLocalCoreClient();
      final controller = await _pumpScreenWithState(
        tester,
        const ZentorState(),
        const SettingsScreen(),
        localCoreClient: localCore,
      );

      await tester.enterText(
        find.widgetWithText(TextField, 'Ransomware protected folders'),
        r'C:\Users\Brent\Documents',
      );
      await tester.enterText(
        find.widgetWithText(TextField, 'Trusted backup/sync processes'),
        r'C:\Program Files\Backup\backup.exe',
      );
      tester
          .widget<OutlinedButton>(
            find.widgetWithText(
              OutlinedButton,
              'Save ransomware protection settings',
            ),
          )
          .onPressed!();
      await tester.pumpAndSettle();

      expect(find.text('Save ransomware protection settings?'), findsOneWidget);
      await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
      await tester.pumpAndSettle();

      expect(localCore.ransomwareGuardCalls, 0);
      expect(controller.state.config.ransomwareProtectedRoots, isEmpty);
      expect(controller.state.config.ransomwareTrustedProcesses, isEmpty);
      expect(find.text('Ransomware protection settings saved.'), findsNothing);
    },
  );

  testWidgets('settings ransomware guard dialog confirm calls local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    final controller = await _pumpScreenWithState(
      tester,
      const ZentorState(),
      const SettingsScreen(),
      localCoreClient: localCore,
    );

    await tester.enterText(
      find.widgetWithText(TextField, 'Ransomware protected folders'),
      r'C:\Users\Brent\Documents',
    );
    await tester.enterText(
      find.widgetWithText(TextField, 'Trusted backup/sync processes'),
      r'C:\Program Files\Backup\backup.exe',
    );
    tester
        .widget<OutlinedButton>(
          find.widgetWithText(
            OutlinedButton,
            'Save ransomware protection settings',
          ),
        )
        .onPressed!();
    await tester.pumpAndSettle();

    expect(find.text('Save ransomware protection settings?'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Save'));
    await tester.pumpAndSettle();

    expect(localCore.ransomwareGuardCalls, 1);
    expect(localCore.lastRansomwareProtectedRoots, [
      r'C:\Users\Brent\Documents',
    ]);
    expect(localCore.lastRansomwareTrustedProcesses, [
      r'C:\Program Files\Backup\backup.exe',
    ]);
    expect(controller.state.config.ransomwareProtectedRoots, [
      r'C:\Users\Brent\Documents',
    ]);
    expect(controller.state.config.ransomwareTrustedProcesses, [
      r'C:\Program Files\Backup\backup.exe',
    ]);
    expect(find.text('Ransomware protection settings saved.'), findsOneWidget);
  });

  testWidgets(
    'settings scheduled quick scan dialog cancel preserves schedule',
    (tester) async {
      final controller = await _pumpScreenWithState(
        tester,
        const ZentorState(),
        const SettingsScreen(),
      );

      final scheduledSwitch = tester.widget<SwitchListTile>(
        find.byWidgetPredicate(
          (widget) =>
              widget is SwitchListTile &&
              widget.title is Text &&
              (widget.title as Text).data ==
                  'Enable in-app scheduled quick scan',
        ),
      );
      scheduledSwitch.onChanged!(true);
      await tester.pumpAndSettle();

      expect(find.text('Change scheduled quick scan?'), findsOneWidget);
      await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
      await tester.pumpAndSettle();

      expect(controller.state.config.scheduledQuickScanEnabled, isFalse);
      expect(find.text('Scheduled quick scan settings saved.'), findsNothing);
    },
  );

  testWidgets(
    'settings scheduled quick scan dialog confirm persists schedule',
    (tester) async {
      final controller = await _pumpScreenWithState(
        tester,
        const ZentorState(),
        const SettingsScreen(),
      );

      final scheduledSwitch = tester.widget<SwitchListTile>(
        find.byWidgetPredicate(
          (widget) =>
              widget is SwitchListTile &&
              widget.title is Text &&
              (widget.title as Text).data ==
                  'Enable in-app scheduled quick scan',
        ),
      );
      scheduledSwitch.onChanged!(true);
      await tester.pumpAndSettle();

      expect(find.text('Change scheduled quick scan?'), findsOneWidget);
      await tester.tap(find.widgetWithText(FilledButton, 'Change'));
      await tester.pumpAndSettle();

      expect(controller.state.config.scheduledQuickScanEnabled, isTrue);
      expect(controller.state.config.scheduledQuickScanIntervalHours, 24);
      expect(find.text('Scheduled quick scan settings saved.'), findsOneWidget);
    },
  );

  testWidgets('settings reset button disables while reset is busy', (
    tester,
  ) async {
    await _pumpScreenWithState(
      tester,
      const ZentorState(configurationResetInFlight: true),
      const SettingsScreen(),
    );

    final resetButton = find.widgetWithText(
      OutlinedButton,
      'Reset configuration',
    );

    expect(resetButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(resetButton).onPressed, isNull);
  });

  testWidgets('settings reset button disables while protection state is busy', (
    tester,
  ) async {
    for (final state in const [
      ZentorState(protectionOperationInFlight: true),
      ZentorState(protectionSelfTestInFlight: true),
    ]) {
      await _pumpScreenWithState(tester, state, const SettingsScreen());

      final resetButton = find.widgetWithText(
        OutlinedButton,
        'Reset configuration',
      );

      expect(resetButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(resetButton).onPressed, isNull);
    }
  });

  testWidgets(
    'settings reset button disables while security or manual actions are busy',
    (tester) async {
      for (final state in const [
        ZentorState(securitySettingsActionInFlight: true),
        ZentorState(quarantineActionInFlight: true),
        ZentorState(allowlistActionInFlight: true),
        ZentorState(detectionFeedbackInFlight: true),
      ]) {
        await _pumpScreenWithState(tester, state, const SettingsScreen());

        final resetButton = find.widgetWithText(
          OutlinedButton,
          'Reset configuration',
        );

        expect(resetButton, findsOneWidget);
        expect(tester.widget<OutlinedButton>(resetButton).onPressed, isNull);
      }
    },
  );

  testWidgets('settings reset button disables while scan work is busy', (
    tester,
  ) async {
    for (final state in const [
      ZentorState(scanStartInFlight: true),
      ZentorState(scanStatus: ScanStatus.running),
      ZentorState(scanTargetSelectionInFlight: true),
      ZentorState(scanCancelInFlight: true),
    ]) {
      await _pumpScreenWithState(tester, state, const SettingsScreen());

      final resetButton = find.widgetWithText(
        OutlinedButton,
        'Reset configuration',
      );

      expect(resetButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(resetButton).onPressed, isNull);
    }
  });

  testWidgets('settings reset configuration dialog cancel preserves settings', (
    tester,
  ) async {
    final controller = await _pumpScreenWithState(
      tester,
      const ZentorState(
        config: ZentorConfig(
          protectionMode: ProtectionMode.lockdown,
          scheduledQuickScanEnabled: true,
          scheduledQuickScanIntervalHours: 6,
          developerOverrideEnabled: true,
          apiBaseUrl: 'https://dev.example.test',
          projectId: 'dev-project',
          publicClientKey: 'dev-public-key',
        ),
      ),
      const SettingsScreen(),
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.widgetWithText(OutlinedButton, 'Reset configuration'),
      500,
      scrollable: scrollable,
    );
    await tester.tap(
      find.widgetWithText(OutlinedButton, 'Reset configuration'),
    );
    await tester.pumpAndSettle();

    expect(find.text('Reset configuration?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(controller.state.config.protectionMode, ProtectionMode.lockdown);
    expect(controller.state.config.scheduledQuickScanEnabled, isTrue);
    expect(controller.state.config.scheduledQuickScanIntervalHours, 6);
    expect(controller.state.config.developerOverrideEnabled, isTrue);
    expect(controller.state.config.apiBaseUrl, 'https://dev.example.test');
    expect(find.text('Configuration reset.'), findsNothing);
  });

  testWidgets('settings reset configuration dialog confirm restores defaults', (
    tester,
  ) async {
    final controller = await _pumpScreenWithState(
      tester,
      const ZentorState(
        config: ZentorConfig(
          protectionMode: ProtectionMode.lockdown,
          scheduledQuickScanEnabled: true,
          scheduledQuickScanIntervalHours: 6,
          developerOverrideEnabled: true,
          apiBaseUrl: 'https://dev.example.test',
          projectId: 'dev-project',
          publicClientKey: 'dev-public-key',
        ),
      ),
      const SettingsScreen(),
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.widgetWithText(OutlinedButton, 'Reset configuration'),
      500,
      scrollable: scrollable,
    );
    await tester.tap(
      find.widgetWithText(OutlinedButton, 'Reset configuration'),
    );
    await tester.pumpAndSettle();

    expect(find.text('Reset configuration?'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Reset'));
    await tester.pumpAndSettle();

    expect(controller.state.config.protectionMode, ProtectionMode.balanced);
    expect(controller.state.config.scheduledQuickScanEnabled, isFalse);
    expect(controller.state.config.scheduledQuickScanIntervalHours, 24);
    expect(controller.state.config.developerOverrideEnabled, isFalse);
    expect(controller.state.protectionStatus, ProtectionStatus.idle);
    expect(controller.state.cloudStatus, CloudStatus.disabled);
    expect(find.text('Configuration reset.'), findsOneWidget);
  });

  testWidgets('protected apps rescan button disables while detection is busy', (
    tester,
  ) async {
    await _pumpScreenWithState(
      tester,
      const ZentorState(appDetectionInFlight: true),
      const ProtectedAppsScreen(),
      appDetector: const _SupportedAppDetector(),
    );

    final rescanButton = find.widgetWithText(OutlinedButton, 'Rescanning');

    expect(rescanButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(rescanButton).onPressed, isNull);
    expect(find.widgetWithText(OutlinedButton, 'Rescan'), findsNothing);
  });

  testWidgets('protected apps action busy disables mutation controls', (
    tester,
  ) async {
    await _pumpScreenWithState(
      tester,
      const ZentorState(
        protectedAppActionInFlight: true,
        config: ZentorConfig(
          protectedAppConfig: ProtectedAppConfig(
            appId: 'manual-tool',
            appName: 'Manual Tool',
            appPath: r'C:\Users\Brent\Tools\manual-tool.exe',
            source: 'Manual',
          ),
        ),
        detectedApps: [
          DetectedApp(
            appId: 'detected-tool',
            displayName: 'Detected Tool',
            path: r'C:\Users\Brent\Tools\detected-tool.exe',
            source: 'Known path',
          ),
        ],
      ),
      const ProtectedAppsScreen(),
      appDetector: const _SupportedAppDetector(),
    );

    final addFileButton = find.widgetWithText(
      OutlinedButton,
      'Add file or app',
    );
    final addFolderButton = find.widgetWithText(OutlinedButton, 'Add folder');
    final hashButton = find.widgetWithText(
      FilledButton,
      'Calculate build hash',
    );
    final detectedAppRow = find.widgetWithText(ListTile, 'Detected Tool');

    expect(addFileButton, findsOneWidget);
    expect(addFolderButton, findsOneWidget);
    expect(hashButton, findsOneWidget);
    expect(detectedAppRow, findsOneWidget);
    expect(tester.widget<OutlinedButton>(addFileButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(addFolderButton).onPressed, isNull);
    expect(tester.widget<FilledButton>(hashButton).onPressed, isNull);
    expect(tester.widget<ListTile>(detectedAppRow).onTap, isNull);
  });

  testWidgets(
    'protection operation busy disables start stop and self-test UI',
    (tester) async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();

      Future<void> pumpBusyProtection(
        ProtectionStatus status,
        Widget child,
      ) async {
        await tester.pumpWidget(const SizedBox.shrink());
        await tester.pump();
        final controller = ZentorController(
          configRepository: ConfigRepository(preferences),
          eventRepository: LocalEventRepository(preferences),
          apiClient: ZentorApiClient(),
          hashService: HashService(),
          appDetector: const _FakeAppDetector(),
          localCoreClient: const LocalCoreClient(),
          scanTargetService: const ScanTargetService(),
          updateService: ZentorUpdateService(),
        );
        controller.state = ZentorState(
          protectionStatus: status,
          protectionOperationInFlight: true,
        );

        await tester.pumpWidget(
          ProviderScope(
            overrides: [
              zentorControllerProvider.overrideWith((ref) => controller),
            ],
            child: MaterialApp(
              theme: ZentorTheme.dark(),
              home: Scaffold(body: SingleChildScrollView(child: child)),
            ),
          ),
        );
      }

      await pumpBusyProtection(ProtectionStatus.idle, const HomeScreen());

      final homeStartButton = find.widgetWithText(
        OutlinedButton,
        'Enable Protection',
      );
      expect(homeStartButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(homeStartButton).onPressed, isNull);

      await pumpBusyProtection(ProtectionStatus.protected, const HomeScreen());

      final homeStopButton = find.widgetWithText(
        OutlinedButton,
        'Stop Protection',
      );
      expect(homeStopButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(homeStopButton).onPressed, isNull);

      await pumpBusyProtection(ProtectionStatus.idle, const ProtectionScreen());

      final protectionStartButton = find.widgetWithText(
        FilledButton,
        'Enable Protection',
      );
      final protectionSelfTestButton = find.widgetWithText(
        OutlinedButton,
        'Run protection self-test',
      );

      expect(protectionStartButton, findsOneWidget);
      expect(
        tester.widget<FilledButton>(protectionStartButton).onPressed,
        isNull,
      );
      expect(
        tester.widget<OutlinedButton>(protectionSelfTestButton).onPressed,
        isNull,
      );

      await pumpBusyProtection(ProtectionStatus.idle, const SettingsScreen());

      final settingsSelfTestButton = find.widgetWithText(
        OutlinedButton,
        'Run Protection Self-Test',
      );
      expect(settingsSelfTestButton, findsOneWidget);
      expect(
        tester.widget<OutlinedButton>(settingsSelfTestButton).onPressed,
        isNull,
      );

      await pumpBusyProtection(
        ProtectionStatus.protected,
        const ProtectionScreen(),
      );

      final protectionStopButton = find.widgetWithText(
        OutlinedButton,
        'Stop Protection',
      );
      expect(protectionStopButton, findsOneWidget);
      expect(
        tester.widget<OutlinedButton>(protectionStopButton).onPressed,
        isNull,
      );
    },
  );

  testWidgets('protection self-test busy disables start stop UI', (
    tester,
  ) async {
    await _pumpScreenWithState(
      tester,
      const ZentorState(protectionSelfTestInFlight: true),
      const HomeScreen(),
    );

    final homeStartButton = find.widgetWithText(
      OutlinedButton,
      'Enable Protection',
    );
    expect(homeStartButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(homeStartButton).onPressed, isNull);

    await _pumpScreenWithState(
      tester,
      const ZentorState(
        protectionStatus: ProtectionStatus.protected,
        protectionSelfTestInFlight: true,
      ),
      const HomeScreen(),
    );

    final homeStopButton = find.widgetWithText(
      OutlinedButton,
      'Stop Protection',
    );
    expect(homeStopButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(homeStopButton).onPressed, isNull);

    await _pumpScreenWithState(
      tester,
      const ZentorState(protectionSelfTestInFlight: true),
      const ProtectionScreen(),
    );

    final protectionStartButton = find.widgetWithText(
      FilledButton,
      'Enable Protection',
    );
    expect(protectionStartButton, findsOneWidget);
    expect(
      tester.widget<FilledButton>(protectionStartButton).onPressed,
      isNull,
    );

    await _pumpScreenWithState(
      tester,
      const ZentorState(
        protectionStatus: ProtectionStatus.protected,
        protectionSelfTestInFlight: true,
      ),
      const ProtectionScreen(),
    );

    final protectionStopButton = find.widgetWithText(
      OutlinedButton,
      'Stop Protection',
    );
    expect(protectionStopButton, findsOneWidget);
    expect(
      tester.widget<OutlinedButton>(protectionStopButton).onPressed,
      isNull,
    );
  });

  testWidgets(
    'protection update package work busy disables start stop and self-test UI',
    (tester) async {
      await _pumpScreenWithState(
        tester,
        const ZentorState(updateStatus: UpdateStatus.installing),
        const HomeScreen(),
      );

      final homeStartButton = find.widgetWithText(
        OutlinedButton,
        'Enable Protection',
      );
      expect(homeStartButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(homeStartButton).onPressed, isNull);

      await _pumpScreenWithState(
        tester,
        const ZentorState(
          protectionStatus: ProtectionStatus.protected,
          updateStatus: UpdateStatus.verifying,
        ),
        const HomeScreen(),
      );

      final homeStopButton = find.widgetWithText(
        OutlinedButton,
        'Stop Protection',
      );
      expect(homeStopButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(homeStopButton).onPressed, isNull);

      await _pumpScreenWithState(
        tester,
        const ZentorState(updateStatus: UpdateStatus.downloading),
        const ProtectionScreen(),
      );

      final protectionStartButton = find.widgetWithText(
        FilledButton,
        'Enable Protection',
      );
      final protectionSelfTestButton = find.widgetWithText(
        OutlinedButton,
        'Run protection self-test',
      );
      expect(protectionStartButton, findsOneWidget);
      expect(protectionSelfTestButton, findsOneWidget);
      expect(
        tester.widget<FilledButton>(protectionStartButton).onPressed,
        isNull,
      );
      expect(
        tester.widget<OutlinedButton>(protectionSelfTestButton).onPressed,
        isNull,
      );

      await _pumpScreenWithState(
        tester,
        const ZentorState(
          protectionStatus: ProtectionStatus.protected,
          updateStatus: UpdateStatus.rollingBack,
        ),
        const ProtectionScreen(),
      );

      final protectionStopButton = find.widgetWithText(
        OutlinedButton,
        'Stop Protection',
      );
      expect(protectionStopButton, findsOneWidget);
      expect(
        tester.widget<OutlinedButton>(protectionStopButton).onPressed,
        isNull,
      );

      await _pumpScreenWithState(
        tester,
        const ZentorState(updateStatus: UpdateStatus.installing),
        const SettingsScreen(),
      );

      final settingsSelfTestButton = find.widgetWithText(
        OutlinedButton,
        'Run Protection Self-Test',
      );
      expect(settingsSelfTestButton, findsOneWidget);
      expect(
        tester.widget<OutlinedButton>(settingsSelfTestButton).onPressed,
        isNull,
      );
    },
  );

  testWidgets('home and protection scan shortcuts disable while scan busy', (
    tester,
  ) async {
    for (final state in const [
      ZentorState(scanStartInFlight: true),
      ZentorState(scanStatus: ScanStatus.running),
    ]) {
      await _pumpScreenWithState(tester, state, const HomeScreen());

      final homeQuickScanButton = find.widgetWithText(
        FilledButton,
        'Run Quick Scan',
      );
      final homeFullScanButton = find.widgetWithText(
        OutlinedButton,
        'Run Full Scan',
      );

      expect(homeQuickScanButton, findsOneWidget);
      expect(homeFullScanButton, findsOneWidget);
      expect(
        tester.widget<FilledButton>(homeQuickScanButton).onPressed,
        isNull,
      );
      expect(
        tester.widget<OutlinedButton>(homeFullScanButton).onPressed,
        isNull,
      );

      await _pumpScreenWithState(tester, state, const ProtectionScreen());

      final protectionQuickScanButton = find.widgetWithText(
        OutlinedButton,
        'Run Quick Scan',
      );

      expect(protectionQuickScanButton, findsOneWidget);
      expect(
        tester.widget<OutlinedButton>(protectionQuickScanButton).onPressed,
        isNull,
      );
    }
  });

  testWidgets(
    'home protection and scan shortcuts disable while update package work is busy',
    (tester) async {
      const state = ZentorState(updateStatus: UpdateStatus.installing);

      await _pumpScreenWithState(tester, state, const HomeScreen());

      final homeQuickScanButton = find.widgetWithText(
        FilledButton,
        'Run Quick Scan',
      );
      final homeFullScanButton = find.widgetWithText(
        OutlinedButton,
        'Run Full Scan',
      );
      expect(homeQuickScanButton, findsOneWidget);
      expect(homeFullScanButton, findsOneWidget);
      expect(
        tester.widget<FilledButton>(homeQuickScanButton).onPressed,
        isNull,
      );
      expect(
        tester.widget<OutlinedButton>(homeFullScanButton).onPressed,
        isNull,
      );

      await _pumpScreenWithState(tester, state, const ProtectionScreen());

      final protectionQuickScanButton = find.widgetWithText(
        OutlinedButton,
        'Run Quick Scan',
      );
      expect(protectionQuickScanButton, findsOneWidget);
      expect(
        tester.widget<OutlinedButton>(protectionQuickScanButton).onPressed,
        isNull,
      );
    },
  );

  testWidgets('scan shortcuts disable while configuration state is busy', (
    tester,
  ) async {
    for (final state in const [
      ZentorState(securitySettingsActionInFlight: true),
      ZentorState(configurationResetInFlight: true),
    ]) {
      await _pumpScreenWithState(tester, state, const HomeScreen());

      final homeQuickScanButton = find.widgetWithText(
        FilledButton,
        'Run Quick Scan',
      );
      final homeFullScanButton = find.widgetWithText(
        OutlinedButton,
        'Run Full Scan',
      );
      expect(homeQuickScanButton, findsOneWidget);
      expect(homeFullScanButton, findsOneWidget);
      expect(
        tester.widget<FilledButton>(homeQuickScanButton).onPressed,
        isNull,
      );
      expect(
        tester.widget<OutlinedButton>(homeFullScanButton).onPressed,
        isNull,
      );

      await _pumpScreenWithState(tester, state, const ProtectionScreen());

      final protectionQuickScanButton = find.widgetWithText(
        OutlinedButton,
        'Run Quick Scan',
      );
      expect(protectionQuickScanButton, findsOneWidget);
      expect(
        tester.widget<OutlinedButton>(protectionQuickScanButton).onPressed,
        isNull,
      );

      await _pumpScreenWithState(tester, state, const ScanScreen());

      final scanQuickButton = find.widgetWithText(FilledButton, 'Quick Scan');
      final scanFullButton = find.widgetWithText(OutlinedButton, 'Full Scan');
      final customFileButton = find.widgetWithText(
        OutlinedButton,
        'Custom File',
      );
      final customFolderButton = find.widgetWithText(
        OutlinedButton,
        'Custom Folder',
      );
      expect(scanQuickButton, findsOneWidget);
      expect(scanFullButton, findsOneWidget);
      expect(customFileButton, findsOneWidget);
      expect(customFolderButton, findsOneWidget);
      expect(tester.widget<FilledButton>(scanQuickButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(scanFullButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(customFileButton).onPressed, isNull);
      expect(
        tester.widget<OutlinedButton>(customFolderButton).onPressed,
        isNull,
      );
    }
  });

  testWidgets('home and protection scan shortcuts stay detect only', (
    tester,
  ) async {
    final homeLocalCore = _RecordingShortcutLocalCoreClient();
    const shortcutTargets = _FakeShortcutScanTargetService();
    await _pumpScreenWithState(
      tester,
      const ZentorState(
        scanActionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      ),
      const HomeScreen(),
      localCoreClient: homeLocalCore,
      scanTargetService: shortcutTargets,
    );

    await tester.tap(find.widgetWithText(FilledButton, 'Run Quick Scan'));
    await tester.pumpAndSettle();

    expect(homeLocalCore.scanCalls, 1);
    expect(homeLocalCore.lastKind, ScanKind.quick);
    expect(homeLocalCore.lastActionMode, ScanActionMode.detectOnly);
    expect(homeLocalCore.lastPaths, [r'C:\AvoraxTest\Quick']);

    await tester.tap(find.widgetWithText(OutlinedButton, 'Run Full Scan'));
    await tester.pumpAndSettle();

    expect(homeLocalCore.scanCalls, 2);
    expect(homeLocalCore.lastKind, ScanKind.full);
    expect(homeLocalCore.lastActionMode, ScanActionMode.detectOnly);
    expect(homeLocalCore.lastPaths, [r'C:\AvoraxTest\FullRoot']);

    final protectionLocalCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(
        scanActionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      ),
      const ProtectionScreen(),
      localCoreClient: protectionLocalCore,
      scanTargetService: shortcutTargets,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Run Quick Scan'));
    await tester.pumpAndSettle();

    expect(protectionLocalCore.scanCalls, 1);
    expect(protectionLocalCore.lastKind, ScanKind.quick);
    expect(protectionLocalCore.lastActionMode, ScanActionMode.detectOnly);
    expect(protectionLocalCore.lastPaths, [r'C:\AvoraxTest\Quick']);
  });

  testWidgets('home enable protection dialog cancel does not call local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(
        protectionStatus: ProtectionStatus.idle,
        malwareEngineStatus: MalwareEngineStatus.available,
      ),
      const HomeScreen(),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Enable Protection'));
    await tester.pumpAndSettle();

    expect(find.text('Enable protection?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.guardModeCalls, 0);
    expect(localCore.watchCalls, 0);
    expect(find.text('Enable protection?'), findsNothing);
  });

  testWidgets('home enable protection dialog confirm calls local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(protectionStatus: ProtectionStatus.idle),
      const HomeScreen(),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Enable Protection'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Enable'));
    await tester.pumpAndSettle();

    expect(localCore.guardModeCalls, 1);
    expect(localCore.lastGuardMode, ProtectionMode.balanced);
    expect(localCore.watchCalls, 0);
  });

  testWidgets('home stop protection dialog cancel does not call local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(protectionStatus: ProtectionStatus.protected),
      const HomeScreen(),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Stop Protection'));
    await tester.pumpAndSettle();

    expect(find.text('Stop protection?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.guardModeCalls, 0);
    expect(localCore.stopWatchCalls, 0);
    expect(find.text('Stop protection?'), findsNothing);
  });

  testWidgets('home stop protection dialog confirm calls local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(protectionStatus: ProtectionStatus.protected),
      const HomeScreen(),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Stop Protection'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Stop'));
    await tester.pumpAndSettle();

    expect(localCore.guardModeCalls, 1);
    expect(localCore.lastGuardMode, ProtectionMode.off);
    expect(localCore.stopWatchCalls, 1);
  });

  testWidgets('protection enable dialog cancel does not call local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(protectionStatus: ProtectionStatus.idle),
      const ProtectionScreen(),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(FilledButton, 'Enable Protection'));
    await tester.pumpAndSettle();

    expect(find.text('Enable protection?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.guardModeCalls, 0);
    expect(localCore.watchCalls, 0);
    expect(find.text('Enable protection?'), findsNothing);
  });

  testWidgets('protection enable dialog confirm calls local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(
        protectionStatus: ProtectionStatus.idle,
        malwareEngineStatus: MalwareEngineStatus.available,
      ),
      const ProtectionScreen(),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(FilledButton, 'Enable Protection'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Enable'));
    await tester.pumpAndSettle();

    expect(localCore.guardModeCalls, 1);
    expect(localCore.lastGuardMode, ProtectionMode.balanced);
    expect(localCore.watchCalls, 0);
  });

  testWidgets('protection stop dialog cancel does not call local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(protectionStatus: ProtectionStatus.protected),
      const ProtectionScreen(),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Stop Protection'));
    await tester.pumpAndSettle();

    expect(find.text('Stop protection?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.guardModeCalls, 0);
    expect(localCore.stopWatchCalls, 0);
    expect(find.text('Stop protection?'), findsNothing);
  });

  testWidgets('protection stop dialog confirm calls local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(protectionStatus: ProtectionStatus.protected),
      const ProtectionScreen(),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Stop Protection'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Stop'));
    await tester.pumpAndSettle();

    expect(localCore.guardModeCalls, 1);
    expect(localCore.lastGuardMode, ProtectionMode.off);
    expect(localCore.stopWatchCalls, 1);
  });

  testWidgets('protection self-test button calls local core', (tester) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(protectionStatus: ProtectionStatus.protected),
      const ProtectionScreen(),
      localCoreClient: localCore,
    );

    await tester.tap(
      find.widgetWithText(OutlinedButton, 'Run protection self-test'),
    );
    await tester.pumpAndSettle();

    expect(localCore.protectionSelfTestCalls, 1);
    expect(find.text('PASS fixture protection self-test'), findsOneWidget);
  });

  testWidgets('settings protection self-test button calls local core', (
    tester,
  ) async {
    final localCore = _RecordingShortcutLocalCoreClient();
    await _pumpScreenWithState(
      tester,
      const ZentorState(protectionStatus: ProtectionStatus.protected),
      const SettingsScreen(),
      localCoreClient: localCore,
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.widgetWithText(OutlinedButton, 'Run Protection Self-Test'),
      500,
      scrollable: scrollable,
    );
    await tester.tap(
      find.widgetWithText(OutlinedButton, 'Run Protection Self-Test'),
    );
    await tester.pumpAndSettle();

    expect(localCore.protectionSelfTestCalls, 1);
    expect(find.text('PASS fixture protection self-test'), findsOneWidget);
  });

  testWidgets(
    'pack count labels stay unknown until native engine readiness is proven',
    (tester) async {
      const unknownState = ZentorState(
        nativeEngineStatus: 'unavailable',
        nativeSignatureCount: 0,
        nativeRuleCount: 0,
      );

      await _pumpScreenWithState(tester, unknownState, const HomeScreen());
      expect(find.text('Native Rules'), findsOneWidget);
      expect(find.text('Unknown'), findsWidgets);
      expect(find.text('0 rules loaded'), findsNothing);

      await _pumpScreenWithState(
        tester,
        unknownState,
        const ProtectionScreen(),
      );
      expect(find.text('Signature Pack'), findsOneWidget);
      expect(find.text('Rule Pack'), findsOneWidget);
      expect(find.text('Unknown'), findsWidgets);
      expect(find.text('0 loaded'), findsNothing);
      expect(find.text('0 rules'), findsNothing);

      await _pumpScreenWithState(tester, unknownState, const SettingsScreen());
      expect(find.text('Native signatures'), findsOneWidget);
      expect(find.text('Native rules'), findsOneWidget);
      expect(find.text('Unknown'), findsWidgets);
      expect(find.text('0 packaged signatures loaded'), findsNothing);
      expect(find.text('0 packaged rules loaded'), findsNothing);
    },
  );

  testWidgets(
    'pack count labels can show zero only with ready native engine evidence',
    (tester) async {
      const readyState = ZentorState(
        nativeEngineStatus: 'ready',
        nativeSignatureCount: 0,
        nativeRuleCount: 0,
      );

      await _pumpScreenWithState(tester, readyState, const HomeScreen());
      expect(find.text('0 rules loaded'), findsOneWidget);

      await _pumpScreenWithState(tester, readyState, const ProtectionScreen());
      expect(find.text('0 loaded'), findsNWidgets(2));
      expect(find.text('0 rules'), findsOneWidget);

      await _pumpScreenWithState(tester, readyState, const SettingsScreen());
      expect(find.text('0 packaged signatures loaded'), findsOneWidget);
      expect(find.text('0 packaged rules loaded'), findsOneWidget);
    },
  );

  testWidgets('home threat status requires positive scan report evidence', (
    tester,
  ) async {
    await _pumpScreenWithState(tester, const ZentorState(), const HomeScreen());
    expect(find.text('Threats found'), findsNothing);
    expect(find.text('Review threats'), findsNothing);

    await _pumpScreenWithState(
      tester,
      const ZentorState(
        lastScanReport: ScanReport(
          status: ScanStatus.clean,
          kind: ScanKind.quick,
          actionMode: ScanActionMode.detectOnly,
          filesScanned: 12,
          threatsFound: 0,
          skippedFiles: 0,
          elapsedMs: 40,
          threats: [],
        ),
      ),
      const HomeScreen(),
    );
    expect(find.text('Threats found'), findsNothing);
    expect(find.text('Review threats'), findsNothing);

    await _pumpScreenWithState(
      tester,
      const ZentorState(
        lastScanReport: ScanReport(
          status: ScanStatus.infected,
          kind: ScanKind.quick,
          actionMode: ScanActionMode.detectOnly,
          filesScanned: 12,
          threatsFound: 1,
          skippedFiles: 0,
          elapsedMs: 40,
          threats: [],
        ),
      ),
      const HomeScreen(),
    );
    expect(find.text('Threats found'), findsOneWidget);
    expect(find.text('Review threats'), findsOneWidget);
    expect(find.text('1 threats found'), findsOneWidget);
  });

  testWidgets(
    'native engine status labels distinguish ready error unavailable and unknown',
    (tester) async {
      const cases = <String, String>{
        'ready': 'Ready',
        'error': 'Error',
        'unavailable': 'Unavailable',
        'unexpected': 'Unknown',
      };

      for (final entry in cases.entries) {
        final state = ZentorState(nativeEngineStatus: entry.key);
        await _pumpScreenWithState(tester, state, const HomeScreen());
        expect(find.text('Avorax Native Engine'), findsOneWidget);
        expect(find.text(entry.value), findsWidgets);

        await _pumpScreenWithState(tester, state, const ProtectionScreen());
        expect(find.text('Avorax Native Engine'), findsOneWidget);
        expect(find.text('Native Engine'), findsOneWidget);
        expect(find.text(entry.value), findsWidgets);

        await _pumpScreenWithState(tester, state, const SettingsScreen());
        expect(find.text('Native status'), findsOneWidget);
        expect(find.text(entry.value), findsWidgets);

        await _pumpDeviceScreenWithState(tester, state);
        expect(find.text('Avorax Native Engine'), findsOneWidget);
        expect(find.text(entry.value), findsWidgets);
      }
    },
  );

  testWidgets('native engine diagnostics override ready status labels', (
    tester,
  ) async {
    const state = ZentorState(
      nativeEngineStatus: 'ready',
      lastEngineError: 'native self-test failed',
    );

    await _pumpScreenWithState(tester, state, const HomeScreen());
    expect(find.text('Attention needed'), findsWidgets);
    expect(
      find.textContaining('Engine diagnostic: native self-test failed'),
      findsOneWidget,
    );

    await _pumpScreenWithState(tester, state, const ProtectionScreen());
    expect(find.text('Attention needed'), findsWidgets);
    expect(
      find.textContaining('Engine diagnostic: native self-test failed'),
      findsOneWidget,
    );

    await _pumpScreenWithState(tester, state, const SettingsScreen());
    expect(find.text('Attention needed'), findsWidgets);
    expect(find.textContaining('native self-test failed'), findsWidgets);

    await _pumpDeviceScreenWithState(tester, state);
    expect(find.text('Attention needed'), findsWidgets);
    expect(
      find.textContaining('Engine diagnostic: native self-test failed'),
      findsOneWidget,
    );
  });

  testWidgets(
    'protection native engine checklist renders unavailable distinctly',
    (tester) async {
      await _pumpScreenWithState(
        tester,
        const ZentorState(nativeEngineStatus: 'unavailable'),
        const ProtectionScreen(),
      );

      expect(find.text('Native Engine'), findsOneWidget);
      expect(find.text('Unavailable'), findsWidgets);
      expect(find.text('Error'), findsNothing);
    },
  );

  testWidgets('protection core service checklist distinguishes status labels', (
    tester,
  ) async {
    const cases = <String, String>{
      'unknown': 'Unknown',
      'unsupported': 'Unsupported on this OS',
      'error': 'Error',
      'unexpected': 'Unavailable',
    };

    for (final entry in cases.entries) {
      await _pumpScreenWithState(
        tester,
        ZentorState(coreServiceStatus: entry.key),
        const ProtectionScreen(),
      );

      expect(find.text('Core Service'), findsOneWidget);
      expect(find.text(entry.value), findsWidgets);
    }
  });

  testWidgets('native ml status labels distinguish allowed health statuses', (
    tester,
  ) async {
    const cases = <String, (String, String, String)>{
      'loaded': ('Loaded', 'Loaded', 'Loaded'),
      'developmentModel': (
        'Development model',
        'Development',
        'Development model',
      ),
      'modelMissing': ('Missing', 'Missing', 'Missing'),
      'error': ('Error', 'Error', 'Error'),
      'unexpected': ('Unavailable', 'Unavailable', 'Unavailable'),
    };

    for (final entry in cases.entries) {
      final (homeLabel, deviceLabel, settingsLabel) = entry.value;
      final state = ZentorState(nativeMlStatus: entry.key);

      await _pumpScreenWithState(tester, state, const HomeScreen());
      expect(find.text('Native ML'), findsOneWidget);
      expect(find.text(homeLabel), findsWidgets);

      await _pumpDeviceScreenWithState(tester, state);
      expect(find.textContaining('Native ML: $deviceLabel.'), findsOneWidget);

      await _pumpScreenWithState(tester, state, const SettingsScreen());
      expect(find.text('Model status'), findsOneWidget);
      expect(find.text(settingsLabel), findsWidgets);
    }
  });

  testWidgets('protection local ai labels distinguish ai statuses', (
    tester,
  ) async {
    const cases = <AiModelStatus, String>{
      AiModelStatus.active: 'Active',
      AiModelStatus.developmentModel: 'Development',
      AiModelStatus.modelMissing: 'Missing',
      AiModelStatus.error: 'Error',
    };

    for (final entry in cases.entries) {
      await _pumpScreenWithState(
        tester,
        ZentorState(aiStatus: entry.key),
        const ProtectionScreen(),
      );

      expect(find.text('Local AI'), findsOneWidget);
      expect(find.text(entry.value), findsWidgets);
    }
  });

  testWidgets(
    'settings feature schema label avoids fabricated version defaults',
    (tester) async {
      const cases = <String, String>{
        'unavailable': 'Unavailable',
        '  ': 'Unavailable',
        'zne-features-v2': 'zne-features-v2',
      };

      for (final entry in cases.entries) {
        await _pumpScreenWithState(
          tester,
          ZentorState(
            aiModelInfo: AiModelInfo(featureSchemaVersion: entry.key),
          ),
          const SettingsScreen(),
        );

        expect(find.text('Feature schema'), findsOneWidget);
        expect(find.text(entry.value), findsWidgets);
        expect(find.text('1.0.0'), findsNothing);
        expect(find.text('zne-features-v1'), findsNothing);
      }
    },
  );

  testWidgets('device guard and driver labels keep unknown evidence distinct', (
    tester,
  ) async {
    const state = ZentorState(guardStatus: 'unknown', driverStatus: 'unknown');

    await _pumpDeviceScreenWithState(tester, state);

    expect(find.text('Real-time Protection'), findsOneWidget);
    expect(find.text('Unknown'), findsWidgets);
    expect(find.textContaining('Driver: Unknown'), findsOneWidget);
    expect(find.textContaining('Driver: Missing'), findsNothing);
    expect(find.textContaining('Driver: Not running'), findsNothing);
  });

  testWidgets('device service details show missing evidence distinctly', (
    tester,
  ) async {
    await _pumpDeviceScreenWithState(
      tester,
      const ZentorState(),
      serviceStates: const {'avorax_core_service': 'running'},
    );

    expect(find.text('Avorax Services'), findsOneWidget);
    expect(find.textContaining('Core: running'), findsOneWidget);
    expect(
      find.textContaining('Guard: unknown; service evidence missing'),
      findsOneWidget,
    );
    expect(
      find.textContaining('Update: unknown; service evidence missing'),
      findsOneWidget,
    );
    expect(find.textContaining('not installed'), findsNothing);
  });

  testWidgets('device platform errors are normalized before display', (
    tester,
  ) async {
    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          deviceSummaryProvider.overrideWith(
            (ref) async =>
                throw StateError('platform failed\x00\n\twith control text'),
          ),
        ],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(body: DeviceScreen()),
        ),
      ),
    );

    await tester.pump();

    expect(find.text('Unable to read platform info'), findsOneWidget);
    expect(
      find.textContaining('Bad state: platform failed with control text'),
      findsOneWidget,
    );
    expect(find.textContaining('\x00'), findsNothing);
    expect(find.textContaining('\n\t'), findsNothing);
  });

  testWidgets(
    'settings developer cloud override save confirms and persists through UI',
    (tester) async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final apiClient = _FakeApiClient();
      final controller = ZentorController(
        configRepository: ConfigRepository(preferences),
        eventRepository: LocalEventRepository(preferences),
        apiClient: apiClient,
        hashService: HashService(),
        appDetector: const _FakeAppDetector(),
        localCoreClient: const LocalCoreClient(),
        scanTargetService: const ScanTargetService(),
        updateService: ZentorUpdateService(),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            zentorControllerProvider.overrideWith((ref) => controller),
          ],
          child: MaterialApp(
            theme: ZentorTheme.dark(),
            home: const Scaffold(
              body: SingleChildScrollView(child: SettingsScreen()),
            ),
          ),
        ),
      );

      final scrollable = find.byType(Scrollable).first;
      await tester.scrollUntilVisible(
        find.text('Developer options'),
        500,
        scrollable: scrollable,
      );
      await tester.tap(find.text('Developer options'));
      await tester.pumpAndSettle();

      await tester.enterText(
        find.widgetWithText(TextField, 'API endpoint'),
        'https://dev.example.test',
      );
      await tester.enterText(
        find.widgetWithText(TextField, 'Project ID'),
        'p1',
      );
      await tester.enterText(
        find.widgetWithText(TextField, 'Public Client Key'),
        'public-key',
      );
      await tester.scrollUntilVisible(
        find.widgetWithText(FilledButton, 'Save developer override'),
        500,
        scrollable: scrollable,
      );
      await tester.tap(
        find.widgetWithText(FilledButton, 'Save developer override'),
      );
      await tester.pumpAndSettle();

      expect(find.text('Save developer cloud override?'), findsOneWidget);
      await tester.tap(find.widgetWithText(FilledButton, 'Save override'));
      await tester.pumpAndSettle();

      final state = controller.state;
      expect(state.config.developerOverrideEnabled, isTrue);
      expect(state.config.apiBaseUrl, 'https://dev.example.test');
      expect(state.config.projectId, 'p1');
      expect(state.config.publicClientKey, 'public-key');
      expect(state.cloudStatus, CloudStatus.online);
      expect(apiClient.healthCalls, 1);
      expect(find.text('Developer cloud override saved.'), findsOneWidget);

      final raw = preferences.getString('zentor.config.v1');
      expect(raw, isNotNull);
      final stored = jsonDecode(raw!) as Map<String, Object?>;
      expect(stored['developerOverrideEnabled'], isTrue);
      expect(stored['apiBaseUrl'], 'https://dev.example.test');
      expect(stored['projectId'], 'p1');
      expect(stored['publicClientKey'], 'public-key');
    },
  );

  testWidgets(
    'settings developer cloud override invalid save fails without success UI',
    (tester) async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final apiClient = _FakeApiClient();
      final controller = ZentorController(
        configRepository: ConfigRepository(preferences),
        eventRepository: LocalEventRepository(preferences),
        apiClient: apiClient,
        hashService: HashService(),
        appDetector: const _FakeAppDetector(),
        localCoreClient: const LocalCoreClient(),
        scanTargetService: const ScanTargetService(),
        updateService: ZentorUpdateService(),
      );
      final originalConfig = controller.state.config;

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            zentorControllerProvider.overrideWith((ref) => controller),
          ],
          child: MaterialApp(
            theme: ZentorTheme.dark(),
            home: const Scaffold(
              body: SingleChildScrollView(child: SettingsScreen()),
            ),
          ),
        ),
      );

      final scrollable = find.byType(Scrollable).first;
      await tester.scrollUntilVisible(
        find.text('Developer options'),
        500,
        scrollable: scrollable,
      );
      await tester.tap(find.text('Developer options'));
      await tester.pumpAndSettle();

      await tester.enterText(
        find.widgetWithText(TextField, 'API endpoint'),
        'ftp://dev.example.test',
      );
      await tester.enterText(
        find.widgetWithText(TextField, 'Project ID'),
        'p1',
      );
      await tester.enterText(
        find.widgetWithText(TextField, 'Public Client Key'),
        'public-key',
      );
      await tester.scrollUntilVisible(
        find.widgetWithText(FilledButton, 'Save developer override'),
        500,
        scrollable: scrollable,
      );
      await tester.tap(
        find.widgetWithText(FilledButton, 'Save developer override'),
      );
      await tester.pumpAndSettle();

      expect(find.text('Save developer cloud override?'), findsOneWidget);
      await tester.tap(find.widgetWithText(FilledButton, 'Save override'));
      await tester.pumpAndSettle();

      final state = controller.state;
      expect(state.config.developerOverrideEnabled, isFalse);
      expect(state.config.apiBaseUrl, originalConfig.apiBaseUrl);
      expect(state.config.projectId, originalConfig.projectId);
      expect(state.config.publicClientKey, originalConfig.publicClientKey);
      expect(
        state.errorMessage,
        contains('Developer cloud override is invalid'),
      );
      expect(apiClient.healthCalls, 0);
      expect(preferences.getString('zentor.config.v1'), isNull);
      expect(
        find.text('Unable to save developer override. See the error banner.'),
        findsOneWidget,
      );
      expect(find.text('Developer cloud override saved.'), findsNothing);
    },
  );

  testWidgets(
    'settings developer cloud override disable restores build config through UI',
    (tester) async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final apiClient = _FakeApiClient();
      final configRepository = ConfigRepository(preferences);
      final controller = ZentorController(
        configRepository: configRepository,
        eventRepository: LocalEventRepository(preferences),
        apiClient: apiClient,
        hashService: HashService(),
        appDetector: const _FakeAppDetector(),
        localCoreClient: const LocalCoreClient(),
        scanTargetService: const ScanTargetService(),
        updateService: ZentorUpdateService(),
      );
      controller.state = const ZentorState(
        config: ZentorConfig(
          developerOverrideEnabled: true,
          apiBaseUrl: 'https://dev.example.test',
          projectId: 'p1',
          publicClientKey: 'public-key',
        ),
        cloudStatus: CloudStatus.online,
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            zentorControllerProvider.overrideWith((ref) => controller),
          ],
          child: MaterialApp(
            theme: ZentorTheme.dark(),
            home: const Scaffold(
              body: SingleChildScrollView(child: SettingsScreen()),
            ),
          ),
        ),
      );

      final scrollable = find.byType(Scrollable).first;
      await tester.scrollUntilVisible(
        find.text('Developer options'),
        500,
        scrollable: scrollable,
      );
      await tester.tap(find.text('Developer options'));
      await tester.pumpAndSettle();

      expect(find.text('Disable developer cloud override?'), findsOneWidget);
      await tester.tap(find.widgetWithText(FilledButton, 'Disable override'));
      await tester.pumpAndSettle();

      final state = controller.state;
      expect(state.config.developerOverrideEnabled, isFalse);
      expect(state.config.apiBaseUrl, configRepository.buildConfig.apiBaseUrl);
      expect(state.config.projectId, configRepository.buildConfig.projectId);
      expect(
        state.config.publicClientKey,
        configRepository.buildConfig.publicClientKey,
      );
      expect(apiClient.healthCalls, 1);
      expect(find.text('Developer cloud override disabled.'), findsOneWidget);
      expect(find.text('Developer cloud override saved.'), findsNothing);

      final raw = preferences.getString('zentor.config.v1');
      expect(raw, isNotNull);
      final stored = jsonDecode(raw!) as Map<String, Object?>;
      expect(stored['developerOverrideEnabled'], isFalse);
      expect(stored['apiBaseUrl'], configRepository.buildConfig.apiBaseUrl);
      expect(stored['projectId'], configRepository.buildConfig.projectId);
      expect(
        stored['publicClientKey'],
        configRepository.buildConfig.publicClientKey,
      );
    },
  );

  testWidgets('settings developer cloud override controls disable while busy', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = ZentorController(
      configRepository: ConfigRepository(preferences),
      eventRepository: LocalEventRepository(preferences),
      apiClient: _FakeApiClient(),
      hashService: HashService(),
      appDetector: const _FakeAppDetector(),
      localCoreClient: const LocalCoreClient(),
      scanTargetService: const ScanTargetService(),
      updateService: ZentorUpdateService(),
    );
    controller.state = const ZentorState(
      developerCloudOverrideInFlight: true,
      config: ZentorConfig(
        developerOverrideEnabled: true,
        apiBaseUrl: 'https://dev.example.test',
        projectId: 'p1',
        publicClientKey: 'public-key',
      ),
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: SettingsScreen()),
          ),
        ),
      ),
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.text('Developer options'),
      500,
      scrollable: scrollable,
    );

    final switchTile = tester.widget<SwitchListTile>(
      find.widgetWithText(SwitchListTile, 'Developer options'),
    );
    expect(switchTile.value, isTrue);
    expect(switchTile.onChanged, isNull);

    for (final label in ['API endpoint', 'Project ID', 'Public Client Key']) {
      expect(
        tester.widget<TextField>(find.widgetWithText(TextField, label)).enabled,
        isFalse,
      );
    }
    expect(
      tester
          .widget<FilledButton>(
            find.widgetWithText(FilledButton, 'Save developer override'),
          )
          .onPressed,
      isNull,
    );
  });

  testWidgets(
    'settings developer cloud override controls disable during update package work',
    (tester) async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final controller = ZentorController(
        configRepository: ConfigRepository(preferences),
        eventRepository: LocalEventRepository(preferences),
        apiClient: _FakeApiClient(),
        hashService: HashService(),
        appDetector: const _FakeAppDetector(),
        localCoreClient: const LocalCoreClient(),
        scanTargetService: const ScanTargetService(),
        updateService: ZentorUpdateService(),
      );
      controller.state = const ZentorState(
        updateStatus: UpdateStatus.installing,
        config: ZentorConfig(
          developerOverrideEnabled: true,
          apiBaseUrl: 'https://dev.example.test',
          projectId: 'p1',
          publicClientKey: 'public-key',
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            zentorControllerProvider.overrideWith((ref) => controller),
          ],
          child: MaterialApp(
            theme: ZentorTheme.dark(),
            home: const Scaffold(
              body: SingleChildScrollView(child: SettingsScreen()),
            ),
          ),
        ),
      );

      final scrollable = find.byType(Scrollable).first;
      await tester.scrollUntilVisible(
        find.text('Developer options'),
        500,
        scrollable: scrollable,
      );

      final switchTile = tester.widget<SwitchListTile>(
        find.widgetWithText(SwitchListTile, 'Developer options'),
      );
      expect(switchTile.value, isTrue);
      expect(switchTile.onChanged, isNull);

      for (final label in ['API endpoint', 'Project ID', 'Public Client Key']) {
        expect(
          tester
              .widget<TextField>(find.widgetWithText(TextField, label))
              .enabled,
          isFalse,
        );
      }
      expect(
        tester
            .widget<FilledButton>(
              find.widgetWithText(FilledButton, 'Save developer override'),
            )
            .onPressed,
        isNull,
      );
    },
  );

  testWidgets('settings log export failure shows failure UI without success', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = ZentorController(
      configRepository: ConfigRepository(preferences),
      eventRepository: _FailingExportEventRepository(preferences),
      apiClient: _FakeApiClient(),
      hashService: HashService(),
      appDetector: const _FakeAppDetector(),
      localCoreClient: const LocalCoreClient(),
      scanTargetService: const ScanTargetService(),
      updateService: ZentorUpdateService(),
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: SettingsScreen()),
          ),
        ),
      ),
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.widgetWithText(OutlinedButton, 'Export logs'),
      500,
      scrollable: scrollable,
    );
    await tester.tap(find.widgetWithText(OutlinedButton, 'Export logs'));
    await tester.pumpAndSettle();

    expect(find.text('Export logs?'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Export'));
    await tester.pumpAndSettle();

    expect(
      controller.state.errorMessage,
      contains(
        'Unable to export logs: Bad state: export failed with control text',
      ),
    );
    expect(controller.state.errorMessage, isNot(contains('\x00')));
    expect(controller.state.errorMessage, isNot(contains('\n\t')));
    expect(
      find.text('Unable to export logs. See the error banner.'),
      findsOneWidget,
    );
    expect(find.textContaining('Logs exported to'), findsNothing);
    final failedEvent = controller.state.events.singleWhere(
      (event) => event.type == 'logs_export_failed',
    );
    expect(failedEvent.category, 'settings');
    expect(failedEvent.severity, 'error');
  });

  testWidgets('settings log export dialog cancel does not export logs', (
    tester,
  ) async {
    late _RecordingExportEventRepository eventRepository;
    await _pumpScreenWithState(
      tester,
      const ZentorState(),
      const SettingsScreen(),
      eventRepositoryFactory: (preferences) {
        eventRepository = _RecordingExportEventRepository(preferences);
        return eventRepository;
      },
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.widgetWithText(OutlinedButton, 'Export logs'),
      500,
      scrollable: scrollable,
    );
    await tester.tap(find.widgetWithText(OutlinedButton, 'Export logs'));
    await tester.pumpAndSettle();

    expect(find.text('Export logs?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(eventRepository.exportCalls, 0);
    expect(find.textContaining('Logs exported to'), findsNothing);
    expect(
      find.text('Unable to export logs. See the error banner.'),
      findsNothing,
    );
  });

  testWidgets('settings log export dialog confirm exports logs once', (
    tester,
  ) async {
    late _RecordingExportEventRepository eventRepository;
    final controller = await _pumpScreenWithState(
      tester,
      const ZentorState(),
      const SettingsScreen(),
      eventRepositoryFactory: (preferences) {
        eventRepository = _RecordingExportEventRepository(preferences);
        return eventRepository;
      },
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.widgetWithText(OutlinedButton, 'Export logs'),
      500,
      scrollable: scrollable,
    );
    await tester.tap(find.widgetWithText(OutlinedButton, 'Export logs'));
    await tester.pumpAndSettle();

    expect(find.text('Export logs?'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Export'));
    await tester.pumpAndSettle();

    expect(eventRepository.exportCalls, 1);
    expect(
      find.text('Logs exported to ${eventRepository.exportPath.path}'),
      findsOneWidget,
    );
    expect(
      controller.state.events.where((event) => event.type == 'logs_exported'),
      isNotEmpty,
    );
    expect(
      find.text('Unable to export logs. See the error banner.'),
      findsNothing,
    );
  });

  testWidgets('settings log export button disables while export is busy', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = ZentorController(
      configRepository: ConfigRepository(preferences),
      eventRepository: LocalEventRepository(preferences),
      apiClient: _FakeApiClient(),
      hashService: HashService(),
      appDetector: const _FakeAppDetector(),
      localCoreClient: const LocalCoreClient(),
      scanTargetService: const ScanTargetService(),
      updateService: ZentorUpdateService(),
    );
    controller.state = const ZentorState(logExportInFlight: true);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: SettingsScreen()),
          ),
        ),
      ),
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.widgetWithText(OutlinedButton, 'Exporting logs'),
      500,
      scrollable: scrollable,
    );

    final exportButton = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Exporting logs'),
    );
    expect(exportButton.onPressed, isNull);
    expect(find.text('Export logs'), findsNothing);
  });

  testWidgets('settings support bundle dialog cancel does not export bundle', (
    tester,
  ) async {
    late _RecordingExportEventRepository eventRepository;
    await _pumpScreenWithState(
      tester,
      const ZentorState(),
      const SettingsScreen(),
      eventRepositoryFactory: (preferences) {
        eventRepository = _RecordingExportEventRepository(preferences);
        return eventRepository;
      },
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.widgetWithText(OutlinedButton, 'Export support bundle'),
      500,
      scrollable: scrollable,
    );
    await tester.tap(
      find.widgetWithText(OutlinedButton, 'Export support bundle'),
    );
    await tester.pumpAndSettle();

    expect(find.text('Export support bundle?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(eventRepository.supportBundleExportCalls, 0);
    expect(find.textContaining('Support bundle exported to'), findsNothing);
  });

  testWidgets('settings support bundle dialog confirm exports bundle once', (
    tester,
  ) async {
    late _RecordingExportEventRepository eventRepository;
    final controller = await _pumpScreenWithState(
      tester,
      const ZentorState(),
      const SettingsScreen(),
      eventRepositoryFactory: (preferences) {
        eventRepository = _RecordingExportEventRepository(preferences);
        return eventRepository;
      },
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.widgetWithText(OutlinedButton, 'Export support bundle'),
      500,
      scrollable: scrollable,
    );
    await tester.tap(
      find.widgetWithText(OutlinedButton, 'Export support bundle'),
    );
    await tester.pumpAndSettle();

    expect(find.text('Export support bundle?'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Export'));
    await tester.pumpAndSettle();

    expect(eventRepository.supportBundleExportCalls, 1);
    expect(
      find.text(
        'Support bundle exported to ${eventRepository.supportBundlePath.path}',
      ),
      findsOneWidget,
    );
    expect(
      controller.state.events.where(
        (event) => event.type == 'support_bundle_exported',
      ),
      isNotEmpty,
    );
  });

  testWidgets('settings support bundle button disables while export is busy', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = ZentorController(
      configRepository: ConfigRepository(preferences),
      eventRepository: LocalEventRepository(preferences),
      apiClient: _FakeApiClient(),
      hashService: HashService(),
      appDetector: const _FakeAppDetector(),
      localCoreClient: const LocalCoreClient(),
      scanTargetService: const ScanTargetService(),
      updateService: ZentorUpdateService(),
    );
    controller.state = const ZentorState(supportBundleExportInFlight: true);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: SettingsScreen()),
          ),
        ),
      ),
    );

    final scrollable = find.byType(Scrollable).first;
    await tester.scrollUntilVisible(
      find.widgetWithText(OutlinedButton, 'Exporting bundle'),
      500,
      scrollable: scrollable,
    );

    final exportButton = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Exporting bundle'),
    );
    expect(exportButton.onPressed, isNull);
    expect(find.text('Export support bundle'), findsNothing);
  });

  testWidgets('logs export button disables while export is busy', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = ZentorController(
      configRepository: ConfigRepository(preferences),
      eventRepository: LocalEventRepository(preferences),
      apiClient: _FakeApiClient(),
      hashService: HashService(),
      appDetector: const _FakeAppDetector(),
      localCoreClient: const LocalCoreClient(),
      scanTargetService: const ScanTargetService(),
      updateService: ZentorUpdateService(),
    );
    controller.state = const ZentorState(logExportInFlight: true);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: LogsScreen()),
          ),
        ),
      ),
    );

    final exportButton = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Exporting logs'),
    );
    expect(exportButton.onPressed, isNull);
    expect(find.text('Export logs'), findsNothing);
  });
}

ZentorState _updateAvailableState() => ZentorState(
  updateStatus: UpdateStatus.updateAvailable,
  currentAppVersion: '0.2.15',
  updateInfo: UpdateInfo(
    currentVersion: '0.2.15',
    latestVersion: '0.2.16',
    feedUrl: Uri.parse('https://updates.example.test/feed.json'),
    packageUrl: Uri.parse('https://updates.example.test/Avorax.aup'),
    packageSha256: 'a' * 64,
    channel: 'stable',
    rollbackSupported: false,
    packageName: 'Avorax.aup',
    releaseNotes: null,
    localPackagePath: null,
  ),
);

Future<ZentorController> _pumpScreenWithState(
  WidgetTester tester,
  ZentorState state,
  Widget child, {
  AppDetector appDetector = const _FakeAppDetector(),
  ZentorApiClient? apiClient,
  LocalCoreClient localCoreClient = const LocalCoreClient(),
  ScanTargetService scanTargetService = const ScanTargetService(),
  ZentorUpdateService? updateService,
  LocalEventRepository Function(SharedPreferences preferences)?
  eventRepositoryFactory,
}) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pump();
  SharedPreferences.setMockInitialValues({});
  final preferences = await SharedPreferences.getInstance();
  final controller = ZentorController(
    configRepository: ConfigRepository(preferences),
    eventRepository:
        eventRepositoryFactory?.call(preferences) ??
        LocalEventRepository(preferences),
    apiClient: apiClient ?? ZentorApiClient(),
    hashService: HashService(),
    appDetector: appDetector,
    localCoreClient: localCoreClient,
    scanTargetService: scanTargetService,
    updateService: updateService ?? ZentorUpdateService(),
  );
  controller.state = state;

  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        zentorControllerProvider.overrideWith((ref) => controller),
        appDetectorProvider.overrideWithValue(appDetector),
      ],
      child: MaterialApp(
        theme: ZentorTheme.dark(),
        home: Scaffold(body: SingleChildScrollView(child: child)),
      ),
    ),
  );
  return controller;
}

Future<void> _pumpDeviceScreenWithState(
  WidgetTester tester,
  ZentorState state, {
  Map<String, String> serviceStates = const {},
}) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pump();
  SharedPreferences.setMockInitialValues({});
  final preferences = await SharedPreferences.getInstance();
  final controller = ZentorController(
    configRepository: ConfigRepository(preferences),
    eventRepository: LocalEventRepository(preferences),
    apiClient: ZentorApiClient(),
    hashService: HashService(),
    appDetector: const _FakeAppDetector(),
    localCoreClient: const LocalCoreClient(),
    scanTargetService: const ScanTargetService(),
    updateService: ZentorUpdateService(),
  );
  controller.state = state;

  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        zentorControllerProvider.overrideWith((ref) => controller),
        deviceSummaryProvider.overrideWith(
          (ref) async => _deviceSummary(serviceStates: serviceStates),
        ),
      ],
      child: MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(
          body: SingleChildScrollView(child: DeviceScreen()),
        ),
      ),
    ),
  );
  await tester.pump();
}

DeviceIntegritySummary _deviceSummary({
  Map<String, String> serviceStates = const {},
}) => DeviceIntegritySummary(
  platform: 'Windows',
  appVersion: '1.0.0+1',
  osVersion: 'Windows fixture',
  deviceIdentifierHashStatus: 'Available',
  localCoreStatus: 'Running',
  permissionsStatus: 'User mode',
  hostName: 'fixture-host',
  userName: 'fixture-user',
  executablePath: r'C:\Avorax\Avorax.exe',
  systemArchitecture: 'x64',
  processorCount: 8,
  totalPhysicalMemory: '16 GB',
  serviceStates: serviceStates,
);

class _FakeApiClient extends ZentorApiClient {
  int healthCalls = 0;

  @override
  Future<ApiResult<void>> healthCheck(ZentorConfig config) async {
    healthCalls += 1;
    return const ApiSuccess<void>(null);
  }
}

class _FailingExportEventRepository extends LocalEventRepository {
  _FailingExportEventRepository(super.preferences);

  @override
  Future<File> export() async {
    throw StateError('export failed\x00\n\twith control text');
  }
}

class _RecordingExportEventRepository extends LocalEventRepository {
  _RecordingExportEventRepository(super.preferences);

  int exportCalls = 0;
  int supportBundleExportCalls = 0;
  final File exportPath = File(
    r'C:\AvoraxTest\exports\zentor-local-events.json',
  );
  final File supportBundlePath = File(
    r'C:\AvoraxTest\exports\avorax-support-bundle.json',
  );

  @override
  Future<File> export() async {
    exportCalls += 1;
    return exportPath;
  }

  @override
  Future<File> exportSupportBundle({
    required Map<String, Object?> diagnostics,
  }) async {
    supportBundleExportCalls += 1;
    expect(diagnostics['privacy'], isA<Map<String, Object?>>());
    return supportBundlePath;
  }
}
