import 'dart:async';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zentor_client/app/app_state.dart';
import 'package:zentor_client/core/apps/app_detector.dart';
import 'package:zentor_client/core/config/config_repository.dart';
import 'package:zentor_client/core/files/file_selection_service.dart';
import 'package:zentor_client/core/local_core/local_core_client.dart';
import 'package:zentor_client/core/logging/local_event_repository.dart';
import 'package:zentor_client/core/network/api_result.dart';
import 'package:zentor_client/core/network/zentor_api_client.dart';
import 'package:zentor_client/core/scanning/scan_target_service.dart';
import 'package:zentor_client/core/security/hash_service.dart';
import 'package:zentor_client/core/updates/update_service.dart';
import 'package:zentor_protocol/zentor_protocol.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'source_text.dart';

void main() {
  test('quick scan can run while cloud is disabled', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync('zentor-offline-');
    addTearDown(() => target.deleteSync(recursive: true));
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.runQuickScan();

    final state = container.read(zentorControllerProvider);
    expect(state.cloudStatus, CloudStatus.disabled);
    expect(state.scanStatus, ScanStatus.clean);
    expect(localCore.scanCalls, 1);
    expect(localCore.lastActionMode, ScanActionMode.detectOnly);
  });

  test('full scan can run without selecting a path', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final root = Directory.systemTemp.createTempSync('zentor-full-offline-');
    addTearDown(() => root.deleteSync(recursive: true));
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([root.path]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.runFullScan();

    expect(
      container.read(zentorControllerProvider).scanStatus,
      ScanStatus.clean,
    );
    expect(localCore.lastKind, ScanKind.full);
  });

  test('full scan without accessible roots records warning report', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          const _FakeScanTargetService([]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.runFullScan();

    final state = container.read(zentorControllerProvider);
    expect(localCore.scanCalls, 0);
    expect(state.scanStatus, ScanStatus.completedWithErrors);
    expect(state.lastScanReport?.kind, ScanKind.full);
    expect(state.lastScanReport?.status, ScanStatus.completedWithErrors);
    expect(state.lastScanReport?.message, contains('No full scan roots'));
    expect(
      state.events.map((event) => event.type),
      contains('scan_targets_unavailable'),
    );
  });

  test(
    'startup protection readiness events keep category and outcome severity',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient(
        healthSummaryResult: const LocalCoreHealth(
          malwareEngineStatus: MalwareEngineStatus.available,
          nativeEngineStatus: 'ready',
          coreServiceStatus: 'running',
          lastError: 'native diagnostic needs review',
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          appDetectorProvider.overrideWithValue(
            const _FakeAppDetector(supportsAutomatic: true),
          ),
        ],
      );
      addTearDown(container.dispose);

      container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final events = container.read(zentorControllerProvider).events;
      final detectionStarted = events.firstWhere(
        (event) => event.type == 'app_detection_started',
      );
      final snapshotEmpty = events.firstWhere(
        (event) => event.type == 'process_snapshot_empty',
      );
      final noAppDetected = events.firstWhere(
        (event) => event.type == 'no_supported_app_detected',
      );
      final engineAvailable = events.firstWhere(
        (event) => event.type == 'malware_engine_available',
      );

      expect(detectionStarted.category, 'protection');
      expect(detectionStarted.severity, 'info');
      expect(snapshotEmpty.category, 'protection');
      expect(snapshotEmpty.severity, 'warning');
      expect(noAppDetected.category, 'protection');
      expect(noAppDetected.severity, 'warning');
      expect(engineAvailable.category, 'protection');
      expect(engineAvailable.severity, 'warning');
      expect(
        engineAvailable.details,
        contains('native diagnostic needs review'),
      );
    },
  );

  test('startup protection readiness failures are protection errors', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient(
      healthSummaryException: 'health IPC failed',
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        appDetectorProvider.overrideWithValue(
          const _FakeAppDetector(
            supportsAutomatic: true,
            detectException: 'app detector failed',
          ),
        ),
      ],
    );
    addTearDown(container.dispose);

    container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    final events = container.read(zentorControllerProvider).events;
    final appDetectionFailed = events.firstWhere(
      (event) => event.type == 'app_detection_failed',
    );
    final healthFailed = events.firstWhere(
      (event) => event.type == 'malware_engine_health_failed',
    );

    expect(appDetectionFailed.category, 'protection');
    expect(appDetectionFailed.severity, 'error');
    expect(appDetectionFailed.details, contains('app detector failed'));
    expect(healthFailed.category, 'protection');
    expect(healthFailed.severity, 'error');
    expect(healthFailed.details, contains('health IPC failed'));
  });

  test(
    'start protection starts best-effort watcher for protected folders',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'avorax-watch-folder-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final localCore = _FakeLocalCoreClient(
        watcherState: RealtimeWatcherState(
          active: true,
          mode: 'userModeBestEffort',
          watchedPaths: [target.path],
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.selectDetectedApp(
        DetectedApp(
          appId: 'folder',
          displayName: 'Protected folder',
          path: target.path,
          source: 'test',
        ),
        confirmed: true,
      );
      await controller.startProtection(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.watchCalls, 1);
      expect(localCore.lastWatchPaths, [target.path]);
      expect(state.realtimeWatcherMode, 'userModeBestEffort');
      expect(state.realtimeWatchedPaths, [target.path]);
      expect(state.protectionStatus, ProtectionStatus.partiallyProtected);
      expect(state.errorMessage, isNull);
    },
  );

  test(
    'Windows full protection requires authenticated Core Service evidence',
    () async {
      if (!Platform.isWindows) return;
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient(
        healthSummaryResult: const LocalCoreHealth(
          malwareEngineStatus: MalwareEngineStatus.available,
          nativeEngineStatus: 'ready',
          coreServiceStatus: 'running',
          guardStatus: 'running',
          driverStatus: 'running',
        ),
        serviceBoundaryHealthResult: CoreServiceBoundaryHealth.unavailable(
          'SCM-authenticated service evidence fixture unavailable',
        ),
      );
      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.startProtection(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(state.protectionStatus, ProtectionStatus.partiallyProtected);
      expect(
        state.coreServiceBoundaryHealth.status,
        CoreServiceBoundaryStatus.unavailable,
      );
      expect(
        state.lastEngineError,
        contains('SCM-authenticated service evidence fixture unavailable'),
      );
    },
  );

  test(
    'Windows full protection accepts authenticated ready service evidence',
    () async {
      if (!Platform.isWindows) return;
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient(
        healthSummaryResult: const LocalCoreHealth(
          malwareEngineStatus: MalwareEngineStatus.available,
          nativeEngineStatus: 'ready',
          coreServiceStatus: 'running',
          guardStatus: 'running',
          driverStatus: 'running',
        ),
      );
      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.startProtection(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(state.protectionStatus, ProtectionStatus.protected);
      expect(state.coreServiceBoundaryHealth.fullProtectionReady, isTrue);
    },
  );

  test(
    'active protection process snapshot loop evaluates timer ticks',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'avorax-process-loop-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final timerFactory = _ManualScheduledTimerFactory();
      final observations = [
        const ProcessObservation(
          pid: 42,
          parentPid: 7,
          imagePath:
              r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
          commandLine:
              'powershell.exe -WindowStyle Hidden -EncodedCommand benignfixture',
        ),
      ];
      final localCore = _FakeLocalCoreClient(
        watcherState: RealtimeWatcherState(
          active: true,
          mode: 'userModeBestEffort',
          watchedPaths: [target.path],
        ),
        processSnapshotReport: const ProcessSnapshotReport(
          ok: true,
          status: 'snapshotOnly',
          capability: 'userModeSnapshot',
          statusReason: 'fixture snapshot evaluated',
          observedProcesses: 1,
          findings: [
            ProcessFinding(
              pid: 42,
              imagePath:
                  r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
              score: 70,
              verdict: 'suspicious',
              reasons: ['encoded command'],
            ),
          ],
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          appDetectorProvider.overrideWithValue(
            _FakeAppDetector(observations: observations),
          ),
          processSnapshotTimerFactoryProvider.overrideWithValue(
            timerFactory.create,
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.selectDetectedApp(
        DetectedApp(
          appId: 'folder',
          displayName: 'Protected folder',
          path: target.path,
          source: 'test',
        ),
        confirmed: true,
      );
      await controller.startProtection(confirmed: true);

      expect(timerFactory.timer?.duration, const Duration(minutes: 2));
      expect(localCore.processSnapshotCalls, 0);
      var state = container.read(zentorControllerProvider);
      expect(state.processSnapshotLoopStatus, 'active');
      expect(
        state.processSnapshotLoopStatusReason,
        contains('every 2 minutes'),
      );

      timerFactory.timer?.fire();
      for (
        var attempt = 0;
        attempt < 20 && localCore.processSnapshotCalls < 1;
        attempt += 1
      ) {
        await Future<void>.delayed(Duration.zero);
      }

      state = container.read(zentorControllerProvider);
      expect(localCore.processSnapshotCalls, 1);
      expect(localCore.lastProcessObservations, observations);
      expect(state.processSnapshotLoopStatus, 'attention');
      expect(state.processSnapshotLoopStatusReason, contains('findings=1'));
      expect(state.processSnapshotLoopStatusReason, contains('snapshotOnly'));
      final suspiciousEvent = state.events.lastWhere(
        (event) => event.type == 'process_snapshot_loop_suspicious',
      );
      expect(suspiciousEvent.category, 'protection');
      expect(suspiciousEvent.severity, 'warning');
      expect(suspiciousEvent.details, contains('observed=1'));
      expect(suspiciousEvent.details, contains('findings=1'));
      expect(suspiciousEvent.details, contains('snapshotOnly'));

      await controller.stopProtection(confirmed: true);
      timerFactory.timer?.fire();
      for (var attempt = 0; attempt < 5; attempt += 1) {
        await Future<void>.delayed(Duration.zero);
      }

      state = container.read(zentorControllerProvider);
      expect(localCore.processSnapshotCalls, 1);
      expect(timerFactory.timer?.isActive, isFalse);
      expect(state.protectionStatus, ProtectionStatus.idle);
      expect(state.processSnapshotLoopStatus, 'off');
      expect(
        state.processSnapshotLoopStatusReason,
        contains('Protection is stopped'),
      );
    },
  );

  test(
    'active protection process snapshot loop deduplicates routine events',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final timerFactory = _ManualScheduledTimerFactory();
      const observations = [
        ProcessObservation(
          pid: 84,
          parentPid: 8,
          imagePath: r'C:\Program Files\Benign\fixture.exe',
          commandLine: 'fixture.exe --benign',
        ),
      ];
      final localCore = _FakeLocalCoreClient(
        processSnapshotReport: const ProcessSnapshotReport(
          ok: true,
          status: 'snapshotOnly',
          capability: 'userModeSnapshot',
          statusReason: 'fixture snapshot evaluated',
          observedProcesses: 1,
          skippedProcesses: 0,
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          appDetectorProvider.overrideWithValue(
            const _FakeAppDetector(observations: observations),
          ),
          processSnapshotTimerFactoryProvider.overrideWithValue(
            timerFactory.create,
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.startProtection(confirmed: true);

      timerFactory.timer?.fire();
      for (
        var attempt = 0;
        attempt < 20 && localCore.processSnapshotCalls < 1;
        attempt += 1
      ) {
        await Future<void>.delayed(Duration.zero);
      }
      timerFactory.timer?.fire();
      for (
        var attempt = 0;
        attempt < 20 && localCore.processSnapshotCalls < 2;
        attempt += 1
      ) {
        await Future<void>.delayed(Duration.zero);
      }

      final state = container.read(zentorControllerProvider);
      expect(localCore.processSnapshotCalls, 2);
      expect(state.processSnapshotLoopStatus, 'active');
      expect(state.processSnapshotLoopStatusReason, contains('findings=0'));
      expect(
        state.events
            .where((event) => event.type == 'process_snapshot_loop_evaluated')
            .length,
        1,
      );
      expect(
        state.events.map((event) => event.type),
        isNot(contains('process_snapshot_loop_failed')),
      );
    },
  );

  test(
    'active protection process snapshot rejected reports fail closed',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final timerFactory = _ManualScheduledTimerFactory();
      final localCore = _FakeLocalCoreClient(
        processSnapshotReport: const ProcessSnapshotReport(
          ok: false,
          status: 'unknown',
          capability: 'unknown',
          statusReason: 'process snapshot request rejected',
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          appDetectorProvider.overrideWithValue(
            const _FakeAppDetector(
              observations: [
                ProcessObservation(
                  pid: 85,
                  imagePath: r'C:\Tools\fixture.exe',
                  commandLine: 'fixture.exe --benign',
                ),
              ],
            ),
          ),
          processSnapshotTimerFactoryProvider.overrideWithValue(
            timerFactory.create,
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.startProtection(confirmed: true);
      timerFactory.timer?.fire();
      for (
        var attempt = 0;
        attempt < 20 && localCore.processSnapshotCalls < 1;
        attempt += 1
      ) {
        await Future<void>.delayed(Duration.zero);
      }

      final state = container.read(zentorControllerProvider);
      expect(localCore.processSnapshotCalls, 1);
      expect(state.processSnapshotLoopStatus, 'limited');
      expect(
        state.processSnapshotLoopStatusReason,
        contains('process snapshot request rejected'),
      );
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'process_snapshot_loop_failed',
      );
      expect(failedEvent.severity, 'warning');
      expect(failedEvent.details, contains('Local Core rejected'));
      expect(
        state.events.map((event) => event.type),
        isNot(contains('process_snapshot_loop_evaluated')),
      );
    },
  );

  test(
    'active protection incomplete process snapshot evidence fails closed',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final timerFactory = _ManualScheduledTimerFactory();
      final localCore = _FakeLocalCoreClient(
        processSnapshotReport: const ProcessSnapshotReport(
          ok: true,
          status: 'snapshotOnly',
          capability: 'userModeSnapshot',
          statusReason: 'fixture snapshot evaluated',
          observedProcesses: 1,
          diagnostics: [
            'local core process snapshot response had malformed findings',
          ],
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          appDetectorProvider.overrideWithValue(
            const _FakeAppDetector(
              observations: [
                ProcessObservation(
                  pid: 86,
                  imagePath: r'C:\Tools\fixture.exe',
                  commandLine: 'fixture.exe --benign',
                ),
              ],
            ),
          ),
          processSnapshotTimerFactoryProvider.overrideWithValue(
            timerFactory.create,
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.startProtection(confirmed: true);
      timerFactory.timer?.fire();
      for (
        var attempt = 0;
        attempt < 20 && localCore.processSnapshotCalls < 1;
        attempt += 1
      ) {
        await Future<void>.delayed(Duration.zero);
      }

      final state = container.read(zentorControllerProvider);
      expect(localCore.processSnapshotCalls, 1);
      expect(state.processSnapshotLoopStatus, 'limited');
      expect(
        state.processSnapshotLoopStatusReason,
        contains('incomplete process snapshot evidence'),
      );
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'process_snapshot_loop_failed',
      );
      expect(failedEvent.details, contains('malformed findings'));
      expect(
        state.events.map((event) => event.type),
        isNot(contains('process_snapshot_loop_evaluated')),
      );
    },
  );

  test(
    'active protection process snapshot timer start failures are visible',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final timerFactory = _FailingScheduledTimerFactory();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          processSnapshotTimerFactoryProvider.overrideWithValue(
            timerFactory.create,
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.startProtection(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(timerFactory.calls, 1);
      expect(localCore.processSnapshotCalls, 0);
      expect(state.protectionStatus, ProtectionStatus.partiallyProtected);
      expect(state.processSnapshotLoopStatus, 'limited');
      expect(
        state.processSnapshotLoopStatusReason,
        contains('Process observation loop did not start'),
      );
      expect(
        state.processSnapshotLoopStatusReason,
        contains('scheduled timer fixture failure'),
      );
      expect(
        state.errorMessage,
        contains('Process observation loop did not start'),
      );
      expect(state.errorMessage, contains('scheduled timer fixture failure'));
      final limitedEvent = state.events.lastWhere(
        (event) => event.type == 'protection_start_limited',
      );
      expect(limitedEvent.category, 'protection');
      expect(limitedEvent.severity, 'warning');
      expect(
        limitedEvent.details,
        contains('Process observation loop did not start'),
      );
    },
  );

  test(
    'active protection process snapshot detector failures are visible',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final timerFactory = _ManualScheduledTimerFactory();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          appDetectorProvider.overrideWithValue(
            const _FakeAppDetector(snapshotException: 'snapshot denied'),
          ),
          processSnapshotTimerFactoryProvider.overrideWithValue(
            timerFactory.create,
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.startProtection(confirmed: true);
      timerFactory.timer?.fire();
      for (var attempt = 0; attempt < 10; attempt += 1) {
        await Future<void>.delayed(Duration.zero);
      }

      final state = container.read(zentorControllerProvider);
      expect(localCore.processSnapshotCalls, 0);
      expect(state.processSnapshotLoopStatus, 'limited');
      expect(
        state.processSnapshotLoopStatusReason,
        contains('snapshot denied'),
      );
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'process_snapshot_loop_failed',
      );
      expect(failedEvent.category, 'protection');
      expect(failedEvent.severity, 'warning');
      expect(failedEvent.details, contains('snapshot denied'));
    },
  );

  test('active protection process snapshot IPC failures are visible', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final timerFactory = _ManualScheduledTimerFactory();
    final localCore = _FakeLocalCoreClient(
      processSnapshotException: 'process snapshot IPC denied',
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        appDetectorProvider.overrideWithValue(
          const _FakeAppDetector(
            observations: [
              ProcessObservation(
                pid: 77,
                imagePath: r'C:\Tools\fixture.exe',
                commandLine: 'fixture.exe --benign',
              ),
            ],
          ),
        ),
        processSnapshotTimerFactoryProvider.overrideWithValue(
          timerFactory.create,
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.startProtection(confirmed: true);
    timerFactory.timer?.fire();
    for (
      var attempt = 0;
      attempt < 20 && localCore.processSnapshotCalls < 1;
      attempt += 1
    ) {
      await Future<void>.delayed(Duration.zero);
    }

    final state = container.read(zentorControllerProvider);
    expect(localCore.processSnapshotCalls, 1);
    expect(state.processSnapshotLoopStatus, 'limited');
    expect(
      state.processSnapshotLoopStatusReason,
      contains('process snapshot IPC denied'),
    );
    final failedEvent = state.events.lastWhere(
      (event) => event.type == 'process_snapshot_loop_failed',
    );
    expect(failedEvent.category, 'protection');
    expect(failedEvent.severity, 'warning');
    expect(failedEvent.details, contains('process snapshot IPC denied'));
  });

  test('active protection watch-poll loop evaluates timer ticks', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync(
      'avorax-watch-poll-loop-',
    );
    addTearDown(() => target.deleteSync(recursive: true));
    final processTimerFactory = _ManualScheduledTimerFactory();
    final watchPollTimerFactory = _ManualScheduledTimerFactory();
    final localCore = _FakeLocalCoreClient(
      watcherState: RealtimeWatcherState(
        active: true,
        mode: 'userModeBestEffort',
        watchedPaths: [target.path],
      ),
      watchPollResult: const WatchPollScanResult(
        ok: true,
        watcher: RealtimeWatcherState(active: true, mode: 'userModeBestEffort'),
        poll: WatchPollScanSummary(
          active: true,
          mode: 'finiteUserModePolling',
          durationMs: 4000,
          pollIntervalMs: 200,
          maxEvents: 8,
          eventsObserved: 1,
          filesScanned: 1,
          threatsFound: 1,
          quarantinedFiles: 1,
          limitations: [
            'finite-polling-session-only',
            'post-write-detection-only',
          ],
        ),
      ),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        processSnapshotTimerFactoryProvider.overrideWithValue(
          processTimerFactory.create,
        ),
        watchPollTimerFactoryProvider.overrideWithValue(
          watchPollTimerFactory.create,
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.selectDetectedApp(
      DetectedApp(
        appId: 'folder',
        displayName: 'Protected folder',
        path: target.path,
        source: 'test',
      ),
      confirmed: true,
    );
    await controller.startProtection(confirmed: true);

    expect(watchPollTimerFactory.timer?.duration, const Duration(minutes: 1));
    expect(localCore.watchPollCalls, 0);
    var state = container.read(zentorControllerProvider);
    expect(state.watchPollLoopStatus, 'active');
    expect(state.watchPollLoopStatusReason, contains('every 1 minute'));

    watchPollTimerFactory.timer?.fire();
    for (
      var attempt = 0;
      attempt < 20 && localCore.watchPollCalls < 1;
      attempt += 1
    ) {
      await Future<void>.delayed(Duration.zero);
    }
    for (
      var attempt = 0;
      attempt < 20 &&
          container.read(zentorControllerProvider).watchPollLoopStatus !=
              'attention';
      attempt += 1
    ) {
      await Future<void>.delayed(Duration.zero);
    }

    state = container.read(zentorControllerProvider);
    expect(localCore.watchPollCalls, 1);
    expect(localCore.lastWatchPollPaths, [target.path]);
    expect(localCore.lastWatchPollDuration, const Duration(seconds: 4));
    expect(
      localCore.lastWatchPollPollInterval,
      const Duration(milliseconds: 200),
    );
    expect(localCore.lastWatchPollMaxEvents, 8);
    expect(state.watchPollLoopStatus, 'attention');
    expect(state.watchPollLoopStatusReason, contains('eventsObserved=1'));
    expect(state.watchPollLoopStatusReason, contains('filesScanned=1'));
    expect(state.watchPollLoopStatusReason, contains('threatsFound=1'));
    expect(state.watchPollLoopStatusReason, contains('quarantinedFiles=1'));
    final threatEvent = state.events.lastWhere(
      (event) => event.type == 'watch_poll_loop_threats_found',
    );
    expect(threatEvent.category, 'protection');
    expect(threatEvent.severity, 'warning');
    expect(threatEvent.details, contains('finiteUserModePolling'));
    expect(threatEvent.details, contains('post-write-detection-only'));

    await controller.stopProtection(confirmed: true);
    watchPollTimerFactory.timer?.fire();
    for (var attempt = 0; attempt < 5; attempt += 1) {
      await Future<void>.delayed(Duration.zero);
    }

    state = container.read(zentorControllerProvider);
    expect(localCore.watchPollCalls, 1);
    expect(watchPollTimerFactory.timer?.isActive, isFalse);
    expect(state.protectionStatus, ProtectionStatus.idle);
    expect(state.watchPollLoopStatus, 'off');
    expect(state.watchPollLoopStatusReason, contains('Protection is stopped'));
  });

  test('active protection watch-poll loop failures are visible', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync(
      'avorax-watch-poll-failure-',
    );
    addTearDown(() => target.deleteSync(recursive: true));
    final processTimerFactory = _ManualScheduledTimerFactory();
    final watchPollTimerFactory = _ManualScheduledTimerFactory();
    final localCore = _FakeLocalCoreClient(
      watcherState: RealtimeWatcherState(
        active: true,
        mode: 'userModeBestEffort',
        watchedPaths: [target.path],
      ),
      watchPollResult: const WatchPollScanResult(
        ok: false,
        watcher: RealtimeWatcherState(active: true, mode: 'userModeBestEffort'),
        poll: WatchPollScanSummary(
          active: false,
          mode: 'stopped',
          scanErrors: ['watch poll fixture failed'],
        ),
        error: 'watch poll IPC denied',
      ),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        processSnapshotTimerFactoryProvider.overrideWithValue(
          processTimerFactory.create,
        ),
        watchPollTimerFactoryProvider.overrideWithValue(
          watchPollTimerFactory.create,
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.selectDetectedApp(
      DetectedApp(
        appId: 'folder',
        displayName: 'Protected folder',
        path: target.path,
        source: 'test',
      ),
      confirmed: true,
    );
    await controller.startProtection(confirmed: true);
    watchPollTimerFactory.timer?.fire();
    for (
      var attempt = 0;
      attempt < 20 && localCore.watchPollCalls < 1;
      attempt += 1
    ) {
      await Future<void>.delayed(Duration.zero);
    }
    for (
      var attempt = 0;
      attempt < 20 &&
          container.read(zentorControllerProvider).watchPollLoopStatus !=
              'limited';
      attempt += 1
    ) {
      await Future<void>.delayed(Duration.zero);
    }

    final state = container.read(zentorControllerProvider);
    expect(localCore.watchPollCalls, 1);
    expect(state.watchPollLoopStatus, 'limited');
    expect(state.watchPollLoopStatusReason, contains('watch poll IPC denied'));
    expect(
      state.watchPollLoopStatusReason,
      contains('watch poll fixture failed'),
    );
    final failedEvent = state.events.lastWhere(
      (event) => event.type == 'watch_poll_loop_failed',
    );
    expect(failedEvent.category, 'protection');
    expect(failedEvent.severity, 'warning');
    expect(failedEvent.details, contains('watch poll IPC denied'));
  });

  test('source marker: active protection process snapshot loop is bounded', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final startProtection = source.substring(
      source.indexOf('Future<void> startProtection'),
      source.indexOf('Future<void> stopProtection'),
    );
    final stopProtection = source.substring(
      source.indexOf('Future<void> stopProtection'),
      source.indexOf('Future<bool> setProtectionMode'),
    );
    final processLoop = source.substring(
      source.indexOf(
        'Future<void> _evaluateProcessSnapshotForActiveProtection',
      ),
      source.indexOf('Future<void> unawaitedCheckMalwareEngine'),
    );

    expect(
      source,
      contains('_processSnapshotLoopInterval = Duration(minutes: 2)'),
    );
    expect(source, contains('ProcessSnapshotTimerFactory'));
    expect(source, contains('processSnapshotTimerFactoryProvider'));
    expect(source, contains('_processSnapshotEvaluationInFlight'));
    expect(startProtection, contains('_startProcessSnapshotLoop()'));
    expect(startProtection, contains('?processSnapshotLoopWarning'));
    expect(startProtection, contains('processSnapshotLoopWarning == null'));
    expect(startProtection, contains('processSnapshotLoopStatus'));
    expect(startProtection, contains('processSnapshotLoopStatusReason'));
    expect(stopProtection, contains('_stopProcessSnapshotLoop()'));
    expect(stopProtection, contains('processSnapshotLoopStatus'));
    expect(stopProtection, contains('processSnapshotLoopStatusReason'));
    expect(processLoop, contains('_processSnapshotTimerFactory'));
    expect(processLoop, contains('_runProcessSnapshotLoopTickSafely'));
    expect(processLoop, contains('_processSnapshotLoopShouldRun()'));
    expect(processLoop, contains('_lastProcessSnapshotLoopRoutineEventKey'));
    expect(
      processLoop,
      contains('_shouldSkipRepeatedProcessSnapshotRoutineEvent'),
    );
    expect(processLoop, contains('dedupeRepeatedRoutineEvents: true'));
    expect(processLoop, contains('updateProcessSnapshotLoopState: true'));
    expect(processLoop, contains('_setProcessSnapshotLoopState'));
    expect(processLoop, contains("severity != 'info'"));
    expect(processLoop, contains('process_snapshot_loop_suspicious'));
    expect(processLoop, contains('process_snapshot_loop_failed'));
    expect(processLoop, contains('state.config.realtimeProtectionEnabled'));
    expect(
      processLoop,
      isNot(contains('_runProcessSnapshotLoopTickSafely();')),
    );
  });

  test('source marker: active protection watch-poll loop is bounded', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final localCoreSource = File(
      'lib/core/local_core/local_core_client.dart',
    ).readAsStringSync();
    final protectionScreen = File(
      'lib/features/protection/protection_screen.dart',
    ).readAsStringSync();
    final startProtection = source.substring(
      source.indexOf('Future<void> startProtection'),
      source.indexOf('Future<void> stopProtection'),
    );
    final stopProtection = source.substring(
      source.indexOf('Future<void> stopProtection'),
      source.indexOf('Future<bool> setProtectionMode'),
    );
    final watchLoop = source.substring(
      source.indexOf('String? _startWatchPollLoop'),
      source.indexOf('Future<void> unawaitedCheckMalwareEngine'),
    );

    expect(source, contains('_watchPollLoopInterval = Duration(minutes: 1)'));
    expect(source, contains('_watchPollScanDuration = Duration(seconds: 4)'));
    expect(
      source,
      contains('_watchPollScanPollInterval = Duration(milliseconds: 200)'),
    );
    expect(source, contains('_watchPollScanMaxEvents = 8'));
    expect(source, contains('WatchPollTimerFactory'));
    expect(source, contains('watchPollTimerFactoryProvider'));
    expect(source, contains('_watchPollEvaluationInFlight'));
    expect(source, contains('_lastWatchPollLoopRoutineEventKey'));
    expect(source, contains('watchPollLoopStatus'));
    expect(source, contains('watchPollLoopStatusReason'));
    expect(
      startProtection,
      contains('_startWatchPollLoop(watcher.watchedPaths)'),
    );
    expect(startProtection, contains('?watchPollLoopWarning'));
    expect(stopProtection, contains('_stopWatchPollLoop()'));
    expect(stopProtection, contains('watchPollLoopStatus'));
    expect(stopProtection, contains('watchPollLoopStatusReason'));
    expect(watchLoop, contains('_watchPollTimerFactory'));
    expect(watchLoop, contains('_runWatchPollLoopTickSafely'));
    expect(watchLoop, contains('_watchPollLoopShouldRun()'));
    expect(watchLoop, contains('_localCoreClient.watchPollScan'));
    expect(watchLoop, contains('duration: _watchPollScanDuration'));
    expect(watchLoop, contains('pollInterval: _watchPollScanPollInterval'));
    expect(watchLoop, contains('maxEvents: _watchPollScanMaxEvents'));
    expect(watchLoop, contains('watch_poll_loop_threats_found'));
    expect(watchLoop, contains('watch_poll_loop_failed'));
    expect(watchLoop, contains('state.config.realtimeProtectionEnabled'));
    expect(watchLoop, isNot(contains('_runWatchPollLoopTickSafely();')));
    expect(localCoreSource, contains("'command': 'watch_poll_scan'"));
    expect(localCoreSource, contains("'duration_ms': duration.inMilliseconds"));
    expect(
      localCoreSource,
      contains("'poll_interval_ms': pollInterval.inMilliseconds"),
    );
    expect(localCoreSource, contains("'max_events': maxEvents"));
    expect(localCoreSource, contains('WatchPollScanResult'));
    expect(localCoreSource, contains('WatchPollScanSummary'));
    expect(protectionScreen, contains('_watchPollLoopStatusLabel'));
    expect(protectionScreen, contains('finite user-mode polling'));
    expect(protectionScreen, contains('post-write detection only'));
  });

  test(
    'start protection fails when guard and watcher are both inactive',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'avorax-no-active-protection-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final localCore = _FakeLocalCoreClient(
        actionFailure: 'guard denied',
        watcherState: RealtimeWatcherState(
          active: false,
          mode: 'off',
          watchedPaths: const [],
          error: 'watcher denied',
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.selectDetectedApp(
        DetectedApp(
          appId: 'folder',
          displayName: 'Protected folder',
          path: target.path,
          source: 'test',
        ),
        confirmed: true,
      );

      await controller.startProtection(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.guardModeCalls, 1);
      expect(localCore.watchCalls, 1);
      expect(state.config.realtimeProtectionEnabled, isFalse);
      expect(state.protectionStatus, ProtectionStatus.error);
      expect(state.realtimeWatcherMode, 'off');
      expect(state.realtimeWatchedPaths, isEmpty);
      expect(
        state.errorMessage,
        contains('no local protection layer reported active'),
      );
      expect(state.errorMessage, contains('guard denied'));
      expect(state.errorMessage, contains('watcher denied'));
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'protection_start_failed',
      );
      expect(failedEvent.category, 'protection');
      expect(failedEvent.severity, 'error');
      expect(failedEvent.details, contains('Watcher not active'));
      expect(failedEvent.details, contains('guard denied'));
      expect(failedEvent.details, contains('watcher denied'));
      expect(
        state.events.map((event) => event.type),
        isNot(contains('protection_start_limited')),
      );
    },
  );

  test(
    'unconfirmed start protection does not enable guard or watcher',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient(
        watcherState: const RealtimeWatcherState(
          active: true,
          mode: 'userModeBestEffort',
          watchedPaths: [r'C:\Users\Brent\Documents'],
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      await controller.startProtection();

      final state = container.read(zentorControllerProvider);
      expect(localCore.guardModeCalls, 0);
      expect(localCore.watchCalls, 0);
      expect(state.config.realtimeProtectionEnabled, isFalse);
      expect(state.protectionStatus, ProtectionStatus.idle);
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('protection_start_confirmation_required'),
      );
    },
  );

  test(
    'watcher setup keeps uninspectable directories visible for core validation',
    () {
      final source = File('lib/app/app_state.dart').readAsStringSync();
      final realtimeMethod = source.substring(
        source.indexOf('_RealtimeWatchPathPlan _realtimeWatchPathPlan()'),
        source.indexOf('_DirectoryProbe _directoryProbe'),
      );

      expect(realtimeMethod, contains('_directoryExistsOrNeedsCoreValidation'));
      expect(
        realtimeMethod,
        contains('_fileSystemTypeProbe(path, followLinks: false)'),
      );
      expect(
        source,
        contains('FileSystemEntity.typeSync(path, followLinks: followLinks)'),
      );
      expect(realtimeMethod, contains('FileSystemEntityType.link'));
      expect(realtimeMethod, contains('_RealtimeWatchPathProbe('));
      expect(realtimeMethod, contains('_boundedUiDiagnostic(error)'));
      expect(realtimeMethod, contains("fallback: 'watch path unavailable'"));
      expect(
        realtimeMethod,
        contains('Unable to inspect real-time watch path'),
      );
      expect(
        realtimeMethod,
        isNot(
          contains('} on Object {\n      return _RealtimeWatchPathProbe(false'),
        ),
      );
    },
  );

  test(
    'watcher setup carries uninspectable path limitations at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final unsafePath = 'C:\\fixtures\\watch\x00path';
      final localCore = _FakeLocalCoreClient(
        watcherState: RealtimeWatcherState(
          active: true,
          mode: 'userModeBestEffort',
          watchedPaths: [unsafePath],
        ),
      );
      final controller = ZentorController(
        configRepository: ConfigRepository(preferences),
        eventRepository: LocalEventRepository(preferences),
        apiClient: _FakeApiClient(),
        hashService: _FakeHashService(supportsPathHashing: false),
        appDetector: const _FakeAppDetector(),
        localCoreClient: localCore,
        scanTargetService: const _FakeScanTargetService([]),
        updateService: ZentorUpdateService(),
        fileSystemTypeProbe: (path, {bool followLinks = true}) {
          if (path == unsafePath) {
            throw const FileSystemException(
              'fixture denied path inspection',
              'C:\\fixtures\\watch\x00path',
            );
          }
          return FileSystemEntity.typeSync(path, followLinks: followLinks);
        },
      );
      addTearDown(controller.dispose);

      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(scanPaths: [unsafePath]),
      );

      await controller.startProtection(confirmed: true);

      final state = controller.state;
      expect(localCore.watchCalls, 1);
      expect(localCore.lastWatchPaths, [unsafePath]);
      expect(state.realtimeWatcherLimitations, isNotEmpty);
      final limitation = state.realtimeWatcherLimitations.single;
      expect(limitation, contains('Unable to inspect real-time watch path'));
      expect(limitation, isNot(contains('\x00')));
      expect(
        state.errorMessage,
        contains('Best-effort folder watch limitations'),
      );
    },
  );

  test('app state filesystem probes use non-following type checks', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final helpers = source.substring(
      source.indexOf(
        '_RealtimeWatchPathProbe _directoryExistsOrNeedsCoreValidation',
      ),
      source.indexOf('Future<void> startProtection'),
    );

    expect(helpers, contains('_fileSystemTypeProbe(path, followLinks: false)'));
    expect(
      source,
      contains('FileSystemEntity.typeSync(path, followLinks: followLinks)'),
    );
    expect(helpers, contains('FileSystemEntityType.directory'));
    expect(helpers, contains('FileSystemEntityType.link'));
    expect(helpers, contains('FileSystemEntityType.file'));
    expect(helpers, contains('_ScanTargetFileProbe _scanTargetFileProbe'));
    expect(helpers, contains('on FileSystemException catch (error)'));
    expect(helpers, contains('on ArgumentError catch (error)'));
    expect(helpers, contains('Unable to inspect scan target path'));
    expect(helpers, isNot(contains('Directory(path).existsSync()')));
    expect(helpers, isNot(contains('File(path).existsSync()')));
  });

  test('scan routing reports target probe failures before IPC', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final scanMethod = source.substring(
      source.indexOf('Future<void> _scanPaths'),
      source.indexOf('String? _scanCoverageWarning'),
    );

    expect(scanMethod, contains('_scanTargetFileProbe(paths.first)'));
    expect(scanMethod, contains('final probeDiagnostic'));
    expect(scanMethod, contains('Unable to inspect scan target before launch'));
    expect(scanMethod, contains('_failedScanReport('));
    expect(scanMethod, contains('Scan target inspection failed'));
    expect(scanMethod, contains('scanErrors: [scanError]'));
    expect(scanMethod, isNot(contains('_fileExists(paths.first)')));
  });

  test('source marker: scan blockers preserve event history and reports', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final customScanControls = source.substring(
      source.indexOf('Future<void> scanSelectedFile'),
      source.indexOf('Future<void> runQuickScan'),
    );
    final fullScan = source.substring(
      source.indexOf('Future<void> runFullScan'),
      source.indexOf('Future<void> quarantineThreat'),
    );
    final scanMethod = source.substring(
      source.indexOf('Future<void> _scanPaths'),
      source.indexOf('ScanReport _failedScanReport'),
    );

    expect(customScanControls, contains('scan_file_unavailable'));
    expect(customScanControls, contains('scan_folder_unavailable'));
    expect(customScanControls, contains('_engineUnavailableScanReport'));
    expect(fullScan, contains('scan_targets_unavailable'));
    expect(fullScan, contains('lastScanReport: ScanReport('));
    expect(scanMethod, contains('scan_engine_unavailable'));
    expect(scanMethod, contains('_engineUnavailableScanReport'));
  });

  test('stop protection stops watcher and clears watcher state', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync('avorax-stop-watch-');
    addTearDown(() => target.deleteSync(recursive: true));
    final localCore = _FakeLocalCoreClient(
      watcherState: RealtimeWatcherState(
        active: true,
        mode: 'userModeBestEffort',
        watchedPaths: [target.path],
      ),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.selectDetectedApp(
      DetectedApp(
        appId: 'folder',
        displayName: 'Protected folder',
        path: target.path,
        source: 'test',
      ),
      confirmed: true,
    );
    await controller.startProtection(confirmed: true);
    await controller.stopProtection(confirmed: true);

    final state = container.read(zentorControllerProvider);
    expect(localCore.stopWatchCalls, 1);
    expect(state.realtimeWatcherMode, 'off');
    expect(state.realtimeWatchedPaths, isEmpty);
    expect(state.protectionStatus, ProtectionStatus.idle);
  });

  test(
    'stop protection keeps saved preference enabled when local stop is incomplete',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'avorax-stop-incomplete-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final localCore = _FakeLocalCoreClient(
        watcherState: RealtimeWatcherState(
          active: true,
          mode: 'userModeBestEffort',
          watchedPaths: [target.path],
          error: 'still active',
        ),
        stopWatcherState: RealtimeWatcherState(
          active: true,
          mode: 'userModeBestEffort',
          watchedPaths: [target.path],
          error: 'still active',
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.selectDetectedApp(
        DetectedApp(
          appId: 'folder',
          displayName: 'Protected folder',
          path: target.path,
          source: 'test',
        ),
        confirmed: true,
      );
      await controller.startProtection(confirmed: true);
      await controller.stopProtection(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.stopWatchCalls, 1);
      expect(state.config.realtimeProtectionEnabled, isTrue);
      expect(state.protectionStatus, ProtectionStatus.error);
      expect(state.realtimeWatcherMode, 'userModeBestEffort');
      expect(state.realtimeWatchedPaths, [target.path]);
      expect(state.errorMessage, contains('still active'));
      expect(
        state.events.map((event) => event.type),
        contains('protection_stop_incomplete'),
      );
    },
  );

  test(
    'stop protection keeps saved preference enabled when guard disable fails',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'avorax-stop-guard-failure-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final localCore = _FakeLocalCoreClient(
        guardModeResults: const [
          LocalCoreActionResult.ok(),
          LocalCoreActionResult.failed('guard denied'),
        ],
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.selectDetectedApp(
        DetectedApp(
          appId: 'folder',
          displayName: 'Protected folder',
          path: target.path,
          source: 'test',
        ),
        confirmed: true,
      );
      await controller.startProtection(confirmed: true);
      await controller.stopProtection(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.stopWatchCalls, 1);
      expect(localCore.guardModeCalls, 2);
      expect(state.config.realtimeProtectionEnabled, isTrue);
      expect(state.protectionStatus, ProtectionStatus.error);
      expect(state.errorMessage, contains('guard denied'));
      expect(
        state.events.map((event) => event.type),
        contains('protection_stop_incomplete'),
      );
    },
  );

  test(
    'unconfirmed stop protection does not disable watcher or guard',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'avorax-stop-confirm-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final localCore = _FakeLocalCoreClient(
        watcherState: RealtimeWatcherState(
          active: true,
          mode: 'userModeBestEffort',
          watchedPaths: [target.path],
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.selectDetectedApp(
        DetectedApp(
          appId: 'folder',
          displayName: 'Protected folder',
          path: target.path,
          source: 'test',
        ),
        confirmed: true,
      );
      await controller.startProtection(confirmed: true);
      await controller.stopProtection();

      final state = container.read(zentorControllerProvider);
      expect(localCore.stopWatchCalls, 0);
      expect(localCore.guardModeCalls, 1);
      expect(state.protectionStatus, ProtectionStatus.partiallyProtected);
      expect(state.config.realtimeProtectionEnabled, isTrue);
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('protection_stop_confirmation_required'),
      );
    },
  );

  test(
    'start protection blocks overlapping stop while guard IPC is pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingGuardMode = Completer<LocalCoreActionResult>();
      final target = Directory.systemTemp.createTempSync(
        'avorax-start-stop-busy-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final localCore = _FakeLocalCoreClient(
        pendingGuardMode: pendingGuardMode,
        watcherState: RealtimeWatcherState(
          active: true,
          mode: 'userModeBestEffort',
          watchedPaths: [target.path],
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.selectDetectedApp(
        DetectedApp(
          appId: 'folder',
          displayName: 'Protected folder',
          path: target.path,
          source: 'test',
        ),
        confirmed: true,
      );

      final start = controller.startProtection(confirmed: true);
      await Future<void>.delayed(Duration.zero);

      var state = container.read(zentorControllerProvider);
      expect(state.protectionOperationInFlight, isTrue);
      expect(localCore.guardModeCalls, 1);

      await controller.stopProtection(confirmed: true);

      state = container.read(zentorControllerProvider);
      expect(localCore.guardModeCalls, 1);
      expect(localCore.stopWatchCalls, 0);
      expect(state.protectionOperationInFlight, isTrue);
      expect(state.errorMessage, 'Protection action is already in progress.');
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'protection_action_busy',
      );
      expect(busyEvent.category, 'protection');
      expect(busyEvent.severity, 'warning');

      pendingGuardMode.complete(const LocalCoreActionResult.ok());
      await start;

      state = container.read(zentorControllerProvider);
      expect(localCore.guardModeCalls, 1);
      expect(localCore.stopWatchCalls, 0);
      expect(state.protectionOperationInFlight, isFalse);
      expect(state.protectionStatus, ProtectionStatus.partiallyProtected);
    },
  );

  test(
    'protection start blocks while public operation state is busy',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        protectionOperationInFlight: true,
      );

      await controller.startProtection(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.guardModeCalls, 0);
      expect(localCore.watchCalls, 0);
      expect(state.protectionOperationInFlight, isTrue);
      expect(state.protectionSelfTestInFlight, isFalse);
      expect(state.errorMessage, 'Protection action is already in progress.');
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'protection_action_busy',
      );
      expect(busyEvent.category, 'protection');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, 'Protection action is already in progress.');
    },
  );

  test(
    'protection start stop block while public self-test state is busy',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        protectionSelfTestInFlight: true,
      );

      await controller.startProtection(confirmed: true);

      var state = container.read(zentorControllerProvider);
      expect(localCore.guardModeCalls, 0);
      expect(localCore.watchCalls, 0);
      expect(state.protectionOperationInFlight, isFalse);
      expect(state.protectionSelfTestInFlight, isTrue);
      expect(state.errorMessage, 'Protection action is already in progress.');

      controller.state = controller.state.copyWith(
        protectionStatus: ProtectionStatus.protected,
        protectionSelfTestInFlight: true,
      );

      await controller.stopProtection(confirmed: true);

      state = container.read(zentorControllerProvider);
      expect(localCore.guardModeCalls, 0);
      expect(localCore.stopWatchCalls, 0);
      expect(state.protectionOperationInFlight, isFalse);
      expect(state.protectionSelfTestInFlight, isTrue);
      expect(state.errorMessage, 'Protection action is already in progress.');
      final busyEvents = state.events
          .where((event) => event.type == 'protection_action_busy')
          .toList();
      expect(busyEvents, hasLength(2));
      for (final event in busyEvents) {
        expect(event.category, 'protection');
        expect(event.severity, 'warning');
        expect(event.details, 'Protection action is already in progress.');
      }
    },
  );

  test(
    'protection start stop block while update package work is busy',
    () async {
      final busyUpdateStatuses = [
        UpdateStatus.downloading,
        UpdateStatus.verifying,
        UpdateStatus.installing,
        UpdateStatus.rollingBack,
      ];

      for (final status in busyUpdateStatuses) {
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final localCore = _FakeLocalCoreClient();

        final container = ProviderContainer(
          overrides: [
            sharedPreferencesProvider.overrideWithValue(preferences),
            localCoreClientProvider.overrideWithValue(localCore),
          ],
        );
        addTearDown(container.dispose);

        final controller = container.read(zentorControllerProvider.notifier);
        await _waitForControllerStartup(container);
        controller.state = controller.state.copyWith(updateStatus: status);

        await controller.startProtection(confirmed: true);

        final state = container.read(zentorControllerProvider);
        expect(localCore.guardModeCalls, 0);
        expect(localCore.watchCalls, 0);
        expect(state.protectionOperationInFlight, isFalse);
        expect(state.protectionSelfTestInFlight, isFalse);
        expect(state.errorMessage, contains('update package work'));
        expect(state.errorMessage, contains(status.label));
        final busyEvent = state.events.firstWhere(
          (event) => event.type == 'protection_action_busy',
        );
        expect(busyEvent.category, 'protection');
        expect(busyEvent.severity, 'warning');
        expect(busyEvent.details, contains('update package work'));
        expect(busyEvent.details, contains(status.label));
      }

      for (final status in busyUpdateStatuses) {
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final localCore = _FakeLocalCoreClient();

        final container = ProviderContainer(
          overrides: [
            sharedPreferencesProvider.overrideWithValue(preferences),
            localCoreClientProvider.overrideWithValue(localCore),
          ],
        );
        addTearDown(container.dispose);

        final controller = container.read(zentorControllerProvider.notifier);
        await _waitForControllerStartup(container);
        controller.state = controller.state.copyWith(
          protectionStatus: ProtectionStatus.protected,
          updateStatus: status,
          config: controller.state.config.copyWith(
            realtimeProtectionEnabled: true,
          ),
        );

        await controller.stopProtection(confirmed: true);

        final state = container.read(zentorControllerProvider);
        expect(localCore.guardModeCalls, 0);
        expect(localCore.stopWatchCalls, 0);
        expect(state.protectionOperationInFlight, isFalse);
        expect(state.protectionSelfTestInFlight, isFalse);
        expect(state.protectionStatus, ProtectionStatus.protected);
        expect(state.errorMessage, contains('update package work'));
        expect(state.errorMessage, contains(status.label));
        final busyEvent = state.events.firstWhere(
          (event) => event.type == 'protection_action_busy',
        );
        expect(busyEvent.category, 'protection');
        expect(busyEvent.severity, 'warning');
        expect(busyEvent.details, contains('update package work'));
        expect(busyEvent.details, contains(status.label));
      }
    },
  );

  test('protection mode cannot be set off without stop flow', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    await controller.setProtectionMode(ProtectionMode.off);

    final state = container.read(zentorControllerProvider);
    expect(state.config.protectionMode, ProtectionMode.balanced);
    expect(localCore.guardModeCalls, 0);
    expect(state.errorMessage, contains('Stop protection'));
    expect(
      state.events.map((event) => event.type),
      contains('protection_mode_change_failed'),
    );
  });

  test(
    'start protection recovers persisted off profile before guard IPC',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'avorax-recover-off-profile-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          protectionMode: ProtectionMode.off,
          protectedAppConfig: ProtectedAppConfig(
            appName: 'Protected folder',
            appPath: target.path,
            platform: 'windows',
          ),
        ),
      );

      await controller.startProtection(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(state.config.protectionMode, ProtectionMode.balanced);
      expect(localCore.lastGuardMode, ProtectionMode.balanced);
      expect(
        state.events.map((event) => event.type),
        contains('protection_mode_recovered'),
      );
    },
  );

  test(
    'start protection exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final rawFailure =
          'guard ipc denied\x00\n\t${'diagnostic detail ' * 260}';
      final localCore = _FakeLocalCoreClient(actionException: rawFailure);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      await controller.startProtection(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.guardModeCalls, 1);
      expect(localCore.watchCalls, 0);
      expect(state.protectionStatus, ProtectionStatus.error);
      expect(state.loading, isFalse);
      expect(state.protectionOperationInFlight, isFalse);
      expect(state.errorMessage, startsWith('Unable to start protection:'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      final failureEvent = state.events.lastWhere(
        (event) => event.type == 'protection_start_failed',
      );
      expect(failureEvent.category, 'protection');
      expect(failureEvent.severity, 'error');
      expect(failureEvent.details, contains('guard ipc denied'));
      expect(failureEvent.details, isNot(contains('\x00')));
      expect(failureEvent.details, isNot(contains('\n\t')));
      expect(failureEvent.details!.length, lessThanOrEqualTo(2048));
    },
  );

  test('source marker: protection off requires stop flow', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final setMode = appState.substring(
      appState.indexOf('Future<bool> setProtectionMode'),
      appState.indexOf('Future<bool> updateRansomwareGuardSettings'),
    );
    final stopFlow = appState.substring(
      appState.indexOf('Future<void> stopProtection'),
      appState.indexOf('Future<bool> setProtectionMode'),
    );

    expect(setMode, contains('mode == ProtectionMode.off'));
    expect(setMode, contains('Use Stop protection to turn protection off'));
    expect(setMode, contains('protection_mode_change_failed'));
    expect(setMode, contains('bool confirmed = false'));
    expect(setMode, contains('if (!confirmed)'));
    expect(setMode, contains('protection_mode_confirmation_required'));
    expect(setMode, contains('if (!modeResult.ok)'));
    expect(
      setMode.indexOf('_localCoreClient.configureGuardMode(mode)'),
      lessThan(setMode.indexOf('_configRepository.save(updated)')),
    );
    expect(stopFlow, contains('_localCoreClient.configureGuardMode('));
    expect(stopFlow, contains('ProtectionMode.off'));
    expect(
      stopFlow.indexOf('_localCoreClient.configureGuardMode'),
      lessThan(stopFlow.indexOf('ProtectionMode.off')),
    );
    expect(
      stopFlow.indexOf('_localCoreClient.configureGuardMode'),
      lessThan(stopFlow.indexOf('_configRepository.save(updated)')),
    );
    expect(
      stopFlow.indexOf('_localCoreClient.stopWatch()'),
      lessThan(stopFlow.indexOf('_configRepository.save(updated)')),
    );
    expect(stopFlow, contains('protection_stop_incomplete'));
    expect(stopFlow, contains('{bool confirmed = false}'));
    expect(stopFlow, contains('if (!confirmed)'));
    expect(stopFlow, contains('protection_stop_confirmation_required'));
  });

  test(
    'source marker: service and install-report actions require confirmation',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final startCoreService = appState.substring(
        appState.indexOf('Future<void> startCoreService'),
        appState.indexOf('Future<void> openInstallReport'),
      );
      final repairInstallation = appState.substring(
        appState.indexOf('Future<void> repairInstallation'),
        appState.indexOf('Future<bool> addManualProtectedAppFile'),
      );
      final openInstallReport = appState.substring(
        appState.indexOf('Future<void> openInstallReport'),
        appState.indexOf('Future<void> repairInstallation'),
      );

      expect(startCoreService, contains('bool confirmed = false'));
      expect(startCoreService, contains('if (!confirmed)'));
      expect(
        startCoreService,
        contains('core_service_start_confirmation_required'),
      );
      expect(
        startCoreService.indexOf('if (!confirmed)'),
        lessThan(startCoreService.indexOf('_localCoreClient.startCoreService')),
      );
      expect(repairInstallation, contains('bool confirmed = false'));
      expect(repairInstallation, contains('if (!confirmed)'));
      expect(
        repairInstallation,
        contains('installation_repair_confirmation_required'),
      );
      expect(
        repairInstallation.indexOf('if (!confirmed)'),
        lessThan(
          repairInstallation.indexOf('_localCoreClient.repairInstallation'),
        ),
      );
      expect(openInstallReport, contains('bool confirmed = false'));
      expect(openInstallReport, contains('if (!confirmed)'));
      expect(
        openInstallReport,
        contains('install_report_open_confirmation_required'),
      );
      expect(
        openInstallReport.indexOf('if (!confirmed)'),
        lessThan(
          openInstallReport.indexOf('_localCoreClient.openInstallReport'),
        ),
      );
      expect(startCoreService, contains('core_service_start_failed'));
      expect(openInstallReport, contains('install_report_open_failed'));
      expect(repairInstallation, contains('installation_repair_failed'));
    },
  );

  test('source marker: protection privilege diagnostics are bounded', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final startProtection = appState.substring(
      appState.indexOf('Future<void> startProtection'),
      appState.indexOf('Future<void> stopProtection'),
    );
    final stopProtection = appState.substring(
      appState.indexOf('Future<void> stopProtection'),
      appState.indexOf('Future<bool> setProtectionMode'),
    );
    final sections = <String>[
      appState.substring(
        appState.indexOf('Future<void> startCoreService'),
        appState.indexOf('Future<void> openInstallReport'),
      ),
      appState.substring(
        appState.indexOf('Future<void> openInstallReport'),
        appState.indexOf('Future<void> repairInstallation'),
      ),
      appState.substring(
        appState.indexOf('Future<void> repairInstallation'),
        appState.indexOf('Future<bool> addManualProtectedAppFile'),
      ),
      startProtection,
      stopProtection,
      appState.substring(
        appState.indexOf('Future<void> runProtectionSelfTest'),
        appState.indexOf('Future<void> sendHeartbeat'),
      ),
    ];

    for (final section in sections) {
      expect(section, contains('final details = _boundedUiDiagnostic(error)'));
      expect(section, contains('details: details'));
      expect(section, isNot(contains(r'$error')));
    }
    expect(appState, contains('_boundedUiDiagnostic(modeResult.error!)'));
    expect(appState, contains('_boundedUiDiagnostic(watcher.error!)'));
    final protectionStartStop = '$startProtection\n$stopProtection';
    expect(protectionStartStop, isNot(contains(r'${modeResult.error}')));
    expect(protectionStartStop, isNot(contains(r'${watcher.error}')));
  });

  test('source marker: protection start stop blocks public busy states', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final updateMutationStatusHelper = appState.substring(
      appState.indexOf('bool _isUpdateMutationStatusBusy'),
      appState.indexOf('String _updateBusyMessage'),
    );
    final startProtection = appState.substring(
      appState.indexOf('Future<void> startProtection'),
      appState.indexOf('Future<void> stopProtection'),
    );
    final stopProtection = appState.substring(
      appState.indexOf('Future<void> stopProtection'),
      appState.indexOf('Future<bool> setProtectionMode'),
    );

    for (final flow in [startProtection, stopProtection]) {
      expect(flow, contains('_protectionOperationInFlight ||'));
      expect(flow, contains('state.protectionOperationInFlight ||'));
      expect(flow, contains('_protectionSelfTestInFlight ||'));
      expect(flow, contains('state.protectionSelfTestInFlight'));
      expect(flow, contains('protection_action_busy'));
      expect(flow, contains('_rejectProtectionActionDuringUpdateMutation('));
      expect(
        flow.indexOf('state.protectionSelfTestInFlight'),
        lessThan(flow.indexOf('_protectionOperationInFlight = true;')),
      );
      expect(
        flow.indexOf('_rejectProtectionActionDuringUpdateMutation('),
        lessThan(flow.indexOf('_protectionOperationInFlight = true;')),
      );
    }
    expect(updateMutationStatusHelper, contains('UpdateStatus.downloading'));
    expect(updateMutationStatusHelper, contains('UpdateStatus.verifying'));
    expect(updateMutationStatusHelper, contains('UpdateStatus.installing'));
    expect(updateMutationStatusHelper, contains('UpdateStatus.rollingBack'));
    expect(
      updateMutationStatusHelper,
      isNot(contains('UpdateStatus.checking')),
    );
    expect(
      appState,
      contains(r"'$prefix while update package work is in progress: "),
    );
  });

  test('source marker: protection self-test blocks public busy states', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final selfTest = appState.substring(
      appState.indexOf('Future<void> runProtectionSelfTest'),
      appState.indexOf('Future<void> sendHeartbeat'),
    );

    expect(selfTest, contains('_protectionSelfTestInFlight'));
    expect(selfTest, contains('state.protectionSelfTestInFlight'));
    expect(selfTest, contains('_protectionOperationInFlight'));
    expect(selfTest, contains('state.protectionOperationInFlight'));
    expect(selfTest, contains('protection_self_test_busy'));
    expect(selfTest, contains('_rejectProtectionActionDuringUpdateMutation('));
    expect(
      selfTest,
      contains(
        'Protection self-test is already in progress or protection state is changing.',
      ),
    );
    expect(
      selfTest.indexOf('state.protectionOperationInFlight'),
      lessThan(selfTest.indexOf('_protectionSelfTestInFlight = true;')),
    );
    expect(
      selfTest.indexOf('_rejectProtectionActionDuringUpdateMutation('),
      lessThan(selfTest.indexOf('_protectionSelfTestInFlight = true;')),
    );
  });

  test(
    'unconfirmed service and install-report actions do not call local-core',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      await controller.startCoreService();
      await controller.openInstallReport();
      await controller.repairInstallation();

      final state = container.read(zentorControllerProvider);
      expect(localCore.startCoreServiceCalls, 0);
      expect(localCore.openInstallReportCalls, 0);
      expect(localCore.repairInstallationCalls, 0);
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('core_service_start_confirmation_required'),
      );
      expect(
        state.events.map((event) => event.type),
        contains('install_report_open_confirmation_required'),
      );
      expect(
        state.events.map((event) => event.type),
        contains('installation_repair_confirmation_required'),
      );
    },
  );

  test(
    'service recovery actions block overlapping local-core requests',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingStartCoreService = Completer<String>();
      final localCore = _FakeLocalCoreClient(
        pendingStartCoreService: pendingStartCoreService,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final firstStart = controller.startCoreService(confirmed: true);
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(zentorControllerProvider).serviceActionInFlight,
        isTrue,
      );
      await controller.repairInstallation(confirmed: true);

      var state = container.read(zentorControllerProvider);
      expect(localCore.startCoreServiceCalls, 1);
      expect(localCore.repairInstallationCalls, 0);
      expect(localCore.openInstallReportCalls, 0);
      expect(state.serviceActionInFlight, isTrue);
      expect(
        state.errorMessage,
        'Service recovery action is already in progress.',
      );
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'service_action_busy',
      );
      expect(busyEvent.category, 'protection');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, contains('Repair installation'));

      pendingStartCoreService.complete('Core Service start requested.');
      await firstStart;

      state = container.read(zentorControllerProvider);
      expect(localCore.startCoreServiceCalls, 1);
      expect(localCore.repairInstallationCalls, 0);
      expect(state.serviceActionInFlight, isFalse);
      expect(state.errorMessage, 'Core Service start requested.');
      expect(
        state.events.map((event) => event.type),
        contains('core_service_start_requested'),
      );
    },
  );

  test(
    'service recovery actions block while update package work is busy',
    () async {
      for (final status in const [
        UpdateStatus.downloading,
        UpdateStatus.verifying,
        UpdateStatus.installing,
        UpdateStatus.rollingBack,
      ]) {
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final localCore = _FakeLocalCoreClient();

        final container = ProviderContainer(
          overrides: [
            sharedPreferencesProvider.overrideWithValue(preferences),
            localCoreClientProvider.overrideWithValue(localCore),
          ],
        );
        addTearDown(container.dispose);

        final controller = container.read(zentorControllerProvider.notifier);
        await _waitForControllerStartup(container);
        controller.state = controller.state.copyWith(updateStatus: status);

        await controller.startCoreService(confirmed: true);
        await controller.openInstallReport(confirmed: true);
        await controller.repairInstallation(confirmed: true);

        final state = container.read(zentorControllerProvider);
        expect(localCore.startCoreServiceCalls, 0);
        expect(localCore.openInstallReportCalls, 0);
        expect(localCore.repairInstallationCalls, 0);
        expect(state.serviceActionInFlight, isFalse);
        expect(state.updateStatus, status);
        expect(
          state.errorMessage,
          'Service recovery action cannot run while update package work is in progress: ${status.label}.',
        );

        final busyEvents = state.events
            .where((event) => event.type == 'service_action_busy')
            .toList();
        expect(busyEvents, hasLength(3));
        for (final event in busyEvents) {
          expect(event.category, 'protection');
          expect(event.severity, 'warning');
          expect(event.details, contains('update package work'));
          expect(event.details, contains(status.label));
        }
        final details = busyEvents.map((event) => event.details).join('\n');
        expect(details, contains('Start Core Service'));
        expect(details, contains('Open install report'));
        expect(details, contains('Repair installation'));
      }
    },
  );

  test('confirmed service and report action exceptions are reported', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient(actionException: 'ipc exploded');

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    await controller.startCoreService(confirmed: true);
    await controller.openInstallReport(confirmed: true);
    await controller.repairInstallation(confirmed: true);

    final state = container.read(zentorControllerProvider);
    expect(localCore.startCoreServiceCalls, 1);
    expect(localCore.openInstallReportCalls, 1);
    expect(localCore.repairInstallationCalls, 1);
    expect(
      state.errorMessage,
      contains('Unable to repair Avorax installation'),
    );
    expect(state.errorMessage, contains('ipc exploded'));
    expect(
      state.events.map((event) => event.type),
      contains('core_service_start_failed'),
    );
    expect(
      state.events.map((event) => event.type),
      contains('install_report_open_failed'),
    );
    expect(
      state.events.map((event) => event.type),
      contains('installation_repair_failed'),
    );
  });

  test(
    'unconfirmed protection mode change preserves current profile',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final saved = await controller.setProtectionMode(
        ProtectionMode.monitorOnly,
      );

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(state.config.protectionMode, ProtectionMode.balanced);
      expect(localCore.guardModeCalls, 0);
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('protection_mode_confirmation_required'),
      );
    },
  );

  test(
    'protection mode local-core failure preserves current profile',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient(actionFailure: 'guard denied');

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final saved = await controller.setProtectionMode(
        ProtectionMode.monitorOnly,
        confirmed: true,
      );

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(localCore.guardModeCalls, 1);
      expect(localCore.lastGuardMode, ProtectionMode.monitorOnly);
      expect(state.config.protectionMode, ProtectionMode.balanced);
      expect(
        state.errorMessage,
        contains('could not write the shared Guard mode config'),
      );
      expect(
        state.events.map((event) => event.type),
        contains('protection_mode_change_failed'),
      );
    },
  );

  test(
    'security settings changes block while protection operation or self-test is busy',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      controller.state = controller.state.copyWith(
        protectionOperationInFlight: true,
      );
      final modeSaved = await controller.setProtectionMode(
        ProtectionMode.lockdown,
        confirmed: true,
      );

      var state = container.read(zentorControllerProvider);
      expect(modeSaved, isFalse);
      expect(localCore.guardModeCalls, 0);
      expect(state.config.protectionMode, ProtectionMode.balanced);
      expect(state.protectionOperationInFlight, isTrue);
      expect(state.securitySettingsActionInFlight, isFalse);

      controller.state = state.copyWith(
        protectionOperationInFlight: false,
        protectionSelfTestInFlight: true,
      );
      final ransomwareSaved = await controller.updateRansomwareGuardSettings(
        protectedRoots: const [r'C:\Users\Brent\Downloads'],
        trustedProcesses: const [r'C:\Temp\unknown.exe'],
        confirmed: true,
      );

      state = container.read(zentorControllerProvider);
      expect(ransomwareSaved, isFalse);
      expect(localCore.ransomwareGuardCalls, 0);
      expect(state.config.ransomwareProtectedRoots, isEmpty);
      expect(state.config.ransomwareTrustedProcesses, isEmpty);
      expect(state.protectionSelfTestInFlight, isTrue);
      expect(state.securitySettingsActionInFlight, isFalse);

      controller.state = state.copyWith(
        protectionOperationInFlight: true,
        protectionSelfTestInFlight: false,
      );
      final scheduleSaved = await controller.updateScheduledQuickScanSettings(
        enabled: true,
        intervalHours: 6,
        confirmed: true,
      );

      state = container.read(zentorControllerProvider);
      expect(scheduleSaved, isFalse);
      expect(state.config.scheduledQuickScanEnabled, isFalse);
      expect(state.config.scheduledQuickScanIntervalHours, 24);
      expect(state.protectionOperationInFlight, isTrue);
      expect(state.securitySettingsActionInFlight, isFalse);
      expect(
        state.errorMessage,
        'Security settings cannot be changed while protection state is changing or self-test is running.',
      );
      final busyEvents = state.events
          .where((event) => event.type == 'security_settings_action_busy')
          .toList();
      expect(busyEvents, hasLength(3));
      final busyDetails = busyEvents.map((event) => event.details).join('\n');
      expect(busyDetails, contains('Lockdown'));
      expect(busyDetails, contains('Ransomware guard settings'));
      expect(busyDetails, contains('Scheduled quick scan settings'));
      for (final event in busyEvents) {
        expect(event.category, 'settings');
        expect(event.severity, 'warning');
        expect(
          event.details,
          contains(
            'Security settings cannot be changed while protection state is changing or self-test is running.',
          ),
        );
      }
    },
  );

  test(
    'security settings changes block while configuration or manual actions are busy',
    () async {
      for (final testCase in const [
        (
          state: ZentorState(configurationResetInFlight: true),
          message:
              'Security settings cannot be changed while configuration reset is in progress.',
        ),
        (
          state: ZentorState(quarantineActionInFlight: true),
          message:
              'Security settings cannot be changed while a quarantine action is in progress.',
        ),
        (
          state: ZentorState(allowlistActionInFlight: true),
          message:
              'Security settings cannot be changed while an allowlist action is in progress.',
        ),
        (
          state: ZentorState(detectionFeedbackInFlight: true),
          message:
              'Security settings cannot be changed while detection feedback is in progress.',
        ),
      ]) {
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final localCore = _FakeLocalCoreClient();

        final container = ProviderContainer(
          overrides: [
            sharedPreferencesProvider.overrideWithValue(preferences),
            localCoreClientProvider.overrideWithValue(localCore),
          ],
        );
        addTearDown(container.dispose);

        final controller = container.read(zentorControllerProvider.notifier);
        await _waitForControllerStartup(container);
        controller.state = controller.state.copyWith(
          configurationResetInFlight: testCase.state.configurationResetInFlight,
          quarantineActionInFlight: testCase.state.quarantineActionInFlight,
          allowlistActionInFlight: testCase.state.allowlistActionInFlight,
          detectionFeedbackInFlight: testCase.state.detectionFeedbackInFlight,
        );

        final saved = await controller.setProtectionMode(
          ProtectionMode.lockdown,
          confirmed: true,
        );

        final state = container.read(zentorControllerProvider);
        expect(saved, isFalse);
        expect(localCore.guardModeCalls, 0);
        expect(state.config.protectionMode, ProtectionMode.balanced);
        expect(state.securitySettingsActionInFlight, isFalse);
        expect(state.errorMessage, testCase.message);
        final busyEvent = state.events.firstWhere(
          (event) => event.type == 'security_settings_action_busy',
        );
        expect(busyEvent.category, 'settings');
        expect(busyEvent.severity, 'warning');
        expect(busyEvent.details, contains('Lockdown'));
        expect(busyEvent.details, contains(testCase.message));
      }
    },
  );

  test('security settings changes block while scan work is busy', () async {
    for (final testCase in const [
      (
        state: ZentorState(scanStartInFlight: true),
        message:
            'Security settings cannot be changed while a scan is starting.',
      ),
      (
        state: ZentorState(scanStatus: ScanStatus.running),
        message: 'Security settings cannot be changed while a scan is running.',
      ),
      (
        state: ZentorState(scanTargetSelectionInFlight: true),
        message:
            'Security settings cannot be changed while scan target selection is in progress.',
      ),
      (
        state: ZentorState(scanCancelInFlight: true),
        message:
            'Security settings cannot be changed while scan cancellation is in progress.',
      ),
    ]) {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        scanStartInFlight: testCase.state.scanStartInFlight,
        scanStatus: testCase.state.scanStatus,
        scanTargetSelectionInFlight: testCase.state.scanTargetSelectionInFlight,
        scanCancelInFlight: testCase.state.scanCancelInFlight,
      );

      final saved = await controller.setProtectionMode(
        ProtectionMode.lockdown,
        confirmed: true,
      );

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(localCore.guardModeCalls, 0);
      expect(state.config.protectionMode, ProtectionMode.balanced);
      expect(state.securitySettingsActionInFlight, isFalse);
      expect(state.scanStartInFlight, testCase.state.scanStartInFlight);
      expect(state.scanStatus, testCase.state.scanStatus);
      expect(
        state.scanTargetSelectionInFlight,
        testCase.state.scanTargetSelectionInFlight,
      );
      expect(state.scanCancelInFlight, testCase.state.scanCancelInFlight);
      expect(state.errorMessage, testCase.message);
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'security_settings_action_busy',
      );
      expect(busyEvent.category, 'settings');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, contains('Lockdown'));
      expect(busyEvent.details, contains(testCase.message));
    }
  });

  test(
    'security settings changes block while update package work is busy',
    () async {
      final busyUpdateStatuses = [
        UpdateStatus.downloading,
        UpdateStatus.verifying,
        UpdateStatus.installing,
        UpdateStatus.rollingBack,
      ];

      for (final status in busyUpdateStatuses) {
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final localCore = _FakeLocalCoreClient();

        final container = ProviderContainer(
          overrides: [
            sharedPreferencesProvider.overrideWithValue(preferences),
            localCoreClientProvider.overrideWithValue(localCore),
          ],
        );
        addTearDown(container.dispose);

        final controller = container.read(zentorControllerProvider.notifier);
        await _waitForControllerStartup(container);
        controller.state = controller.state.copyWith(updateStatus: status);

        final modeSaved = await controller.setProtectionMode(
          ProtectionMode.lockdown,
          confirmed: true,
        );
        final ransomwareSaved = await controller.updateRansomwareGuardSettings(
          protectedRoots: const [r'C:\Users\Brent\Documents'],
          trustedProcesses: const [r'C:\Program Files\Backup\backup.exe'],
          confirmed: true,
        );
        final scheduleSaved = await controller.updateScheduledQuickScanSettings(
          enabled: true,
          intervalHours: 6,
          confirmed: true,
        );

        final state = container.read(zentorControllerProvider);
        final message =
            'Security settings cannot be changed while update package work is in progress: ${status.label}.';
        expect(modeSaved, isFalse);
        expect(ransomwareSaved, isFalse);
        expect(scheduleSaved, isFalse);
        expect(localCore.guardModeCalls, 0);
        expect(localCore.ransomwareGuardCalls, 0);
        expect(state.config.protectionMode, ProtectionMode.balanced);
        expect(state.config.ransomwareProtectedRoots, isEmpty);
        expect(state.config.ransomwareTrustedProcesses, isEmpty);
        expect(state.config.scheduledQuickScanEnabled, isFalse);
        expect(state.config.scheduledQuickScanIntervalHours, 24);
        expect(state.securitySettingsActionInFlight, isFalse);
        expect(state.errorMessage, message);
        final busyEvents = state.events
            .where((event) => event.type == 'security_settings_action_busy')
            .toList();
        expect(busyEvents, hasLength(3));
        final busyDetails = busyEvents.map((event) => event.details).join('\n');
        expect(busyDetails, contains('Lockdown'));
        expect(busyDetails, contains('Ransomware guard settings'));
        expect(busyDetails, contains('Scheduled quick scan settings'));
        for (final event in busyEvents) {
          expect(event.category, 'settings');
          expect(event.severity, 'warning');
          expect(event.details, contains(message));
        }
      }
    },
  );

  test(
    'protection self-test blocks duplicate run while IPC is pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingSelfTest = Completer<String>();
      final localCore = _FakeLocalCoreClient(
        pendingProtectionSelfTest: pendingSelfTest,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final firstSelfTest = controller.runProtectionSelfTest();
      await Future<void>.delayed(Duration.zero);

      var state = container.read(zentorControllerProvider);
      expect(localCore.protectionSelfTestCalls, 1);
      expect(state.protectionSelfTestInFlight, isTrue);

      await controller.runProtectionSelfTest();

      state = container.read(zentorControllerProvider);
      expect(localCore.protectionSelfTestCalls, 1);
      expect(state.protectionSelfTestInFlight, isTrue);
      expect(
        state.errorMessage,
        'Protection self-test is already in progress or protection state is changing.',
      );
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'protection_self_test_busy',
      );
      expect(busyEvent.category, 'protection');
      expect(busyEvent.severity, 'warning');

      pendingSelfTest.complete('PASS guard self-test fixture');
      await firstSelfTest;

      state = container.read(zentorControllerProvider);
      expect(localCore.protectionSelfTestCalls, 1);
      expect(state.protectionSelfTestInFlight, isFalse);
      expect(state.protectionSelfTestResult, 'PASS guard self-test fixture');
    },
  );

  test(
    'protection self-test blocks while public protection operation state is busy',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        protectionOperationInFlight: true,
      );

      await controller.runProtectionSelfTest();

      final state = container.read(zentorControllerProvider);
      expect(localCore.protectionSelfTestCalls, 0);
      expect(state.protectionSelfTestInFlight, isFalse);
      expect(state.protectionOperationInFlight, isTrue);
      expect(
        state.errorMessage,
        'Protection self-test is already in progress or protection state is changing.',
      );
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'protection_self_test_busy',
      );
      expect(busyEvent.category, 'protection');
      expect(busyEvent.severity, 'warning');
      expect(
        busyEvent.details,
        'Protection self-test is already in progress or protection state is changing.',
      );
    },
  );

  test(
    'protection self-test blocks while update package work is busy',
    () async {
      final busyUpdateStatuses = [
        UpdateStatus.downloading,
        UpdateStatus.verifying,
        UpdateStatus.installing,
        UpdateStatus.rollingBack,
      ];

      for (final status in busyUpdateStatuses) {
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final localCore = _FakeLocalCoreClient();

        final container = ProviderContainer(
          overrides: [
            sharedPreferencesProvider.overrideWithValue(preferences),
            localCoreClientProvider.overrideWithValue(localCore),
          ],
        );
        addTearDown(container.dispose);

        final controller = container.read(zentorControllerProvider.notifier);
        await _waitForControllerStartup(container);
        controller.state = controller.state.copyWith(updateStatus: status);

        await controller.runProtectionSelfTest();

        final state = container.read(zentorControllerProvider);
        expect(localCore.protectionSelfTestCalls, 0);
        expect(state.protectionSelfTestInFlight, isFalse);
        expect(state.errorMessage, contains('update package work'));
        expect(state.errorMessage, contains(status.label));
        final busyEvent = state.events.firstWhere(
          (event) => event.type == 'protection_self_test_busy',
        );
        expect(busyEvent.category, 'protection');
        expect(busyEvent.severity, 'warning');
        expect(busyEvent.details, contains('update package work'));
        expect(busyEvent.details, contains(status.label));
      }
    },
  );

  test(
    'protection self-test exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final rawFailure =
          'self-test IPC denied\x00\n\t${'diagnostic detail ' * 260}';
      final localCore = _FakeLocalCoreClient(actionException: rawFailure);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      await controller.runProtectionSelfTest();

      final state = container.read(zentorControllerProvider);
      expect(localCore.protectionSelfTestCalls, 1);
      expect(state.protectionSelfTestInFlight, isFalse);
      expect(state.loading, isFalse);
      expect(
        state.protectionSelfTestResult,
        startsWith('Protection self-test failed:'),
      );
      expect(state.protectionSelfTestResult, contains('self-test IPC denied'));
      expect(state.protectionSelfTestResult, isNot(contains('\x00')));
      expect(state.protectionSelfTestResult, isNot(contains('\n\t')));
      expect(state.protectionSelfTestResult!.length, lessThanOrEqualTo(2200));
      expect(
        state.errorMessage,
        startsWith('Unable to run protection self-test:'),
      );
      expect(state.errorMessage, contains('self-test IPC denied'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'protection_self_test_failed',
      );
      expect(failedEvent.category, 'protection');
      expect(failedEvent.severity, 'error');
      expect(failedEvent.details, contains('self-test IPC denied'));
      expect(failedEvent.details, isNot(contains('\x00')));
      expect(failedEvent.details, isNot(contains('\n\t')));
      expect(failedEvent.details!.length, lessThanOrEqualTo(2048));
    },
  );

  test('source marker: allowlist add requires confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final addAllowlist = appState.substring(
      appState.indexOf('Future<void> addThreatToAllowlist'),
      appState.indexOf('Future<void> removeAllowlistEntry'),
    );

    expect(addAllowlist, contains('{'));
    expect(addAllowlist, contains('bool confirmed = false'));
    expect(addAllowlist, contains('if (!confirmed)'));
    expect(addAllowlist, contains('allowlist_entry_add_confirmation_required'));
    expect(
      addAllowlist.indexOf('if (!confirmed)'),
      lessThan(addAllowlist.indexOf('addAllowlistEntry(threat.path)')),
    );
  });

  test('source marker: auto-action scan starts require confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();

    expect(appState, contains('_ensureScanAutoActionConfirmed'));
    expect(appState, contains('scan_auto_action_confirmation_required'));
    expect(appState, contains('bool confirmedAutoAction = false'));
    expect(appState, contains('actionMode ?? state.scanActionMode'));
    expect(
      appState,
      isNot(
        contains('actionMode ?? ScanActionMode.autoQuarantineConfirmedOnly'),
      ),
    );
  });

  test('source marker: ransomware guard settings require confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final guardSettings = appState.substring(
      appState.indexOf('Future<bool> updateRansomwareGuardSettings'),
      appState.indexOf('Future<bool> updateScheduledQuickScanSettings'),
    );

    expect(guardSettings, contains('bool confirmed = false'));
    expect(guardSettings, contains('if (!confirmed)'));
    expect(
      guardSettings,
      contains('ransomware_guard_settings_confirmation_required'),
    );
    expect(
      guardSettings.indexOf('if (!confirmed)'),
      lessThan(guardSettings.indexOf('_configRepository.save(updated)')),
    );
    expect(
      guardSettings.indexOf('if (!confirmed)'),
      lessThan(
        guardSettings.indexOf('_localCoreClient.configureRansomwareGuard'),
      ),
    );
    expect(guardSettings, contains('if (!coreResult.ok)'));
    expect(
      guardSettings.indexOf('_localCoreClient.configureRansomwareGuard'),
      lessThan(guardSettings.indexOf('_configRepository.save(updated)')),
    );
  });

  test('source marker: protection settings diagnostics are bounded', () {
    final appState = readNormalizedSource('lib/app/app_state.dart');
    final setMode = appState.substring(
      appState.indexOf('Future<bool> setProtectionMode'),
      appState.indexOf('Future<bool> updateRansomwareGuardSettings'),
    );
    final guardSettings = appState.substring(
      appState.indexOf('Future<bool> updateRansomwareGuardSettings'),
      appState.indexOf('Future<bool> updateScheduledQuickScanSettings'),
    );

    for (final section in [setMode, guardSettings]) {
      expect(
        section,
        contains('final primaryDetails = _boundedUiDiagnostic(error)'),
      );
      expect(section, contains('_boundedUiDiagnostic(rollbackError)'));
      expect(section, isNot(contains(r'$error')));
      expect(section, isNot(contains(r'${rollbackResult.error}')));
    }
    expect(
      setMode,
      contains('_boundedUiDiagnostic(\n          modeResult.error'),
    );
    expect(setMode, contains('_boundedUiDiagnostic(rollbackResult.error'));
    expect(
      guardSettings,
      contains('_boundedUiDiagnostic(\n          coreResult.error'),
    );
    expect(
      guardSettings,
      contains('_boundedUiDiagnostic(rollbackResult.error'),
    );
  });

  test('source marker: security settings block protection busy states', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final beginSecuritySettings = appState.substring(
      appState.indexOf('Future<bool> _beginSecuritySettingsAction'),
      appState.indexOf('void _endSecuritySettingsAction'),
    );

    expect(beginSecuritySettings, contains('_protectionOperationInFlight ||'));
    expect(
      beginSecuritySettings,
      contains('state.protectionOperationInFlight ||'),
    );
    expect(beginSecuritySettings, contains('_protectionSelfTestInFlight ||'));
    expect(beginSecuritySettings, contains('state.protectionSelfTestInFlight'));
    expect(
      beginSecuritySettings,
      contains(
        'Security settings cannot be changed while protection state is changing or self-test is running.',
      ),
    );
    expect(
      beginSecuritySettings,
      contains(
        'Security settings cannot be changed while configuration reset is in progress.',
      ),
    );
    expect(beginSecuritySettings, contains('_manualDispositionBusyReason('));
    expect(
      beginSecuritySettings,
      contains('_configurationMutationUpdateBusyReason('),
    );
    expect(
      beginSecuritySettings,
      contains("'Security settings cannot be changed'"),
    );
    expect(beginSecuritySettings, contains('security_settings_action_busy'));
    expect(
      beginSecuritySettings.indexOf('state.protectionSelfTestInFlight'),
      lessThan(
        beginSecuritySettings.indexOf(
          '_securitySettingsActionInFlight = true;',
        ),
      ),
    );
    expect(
      beginSecuritySettings.indexOf('_configurationMutationUpdateBusyReason('),
      lessThan(
        beginSecuritySettings.indexOf(
          '_securitySettingsActionInFlight = true;',
        ),
      ),
    );
  });

  test('source marker: configuration mutations block scan busy states', () {
    final appState = readNormalizedSource('lib/app/app_state.dart');
    final beginSecuritySettings = appState.substring(
      appState.indexOf('Future<bool> _beginSecuritySettingsAction'),
      appState.indexOf('void _endSecuritySettingsAction'),
    );
    final reset = appState.substring(
      appState.indexOf('Future<bool> resetConfiguration'),
      appState.indexOf('bool _configurationResetRequiresProtectionStop'),
    );
    final helperStart = appState.indexOf(
      'String? _scanBusyReasonForConfigurationMutation',
    );
    final helper = appState.substring(
      helperStart,
      appState.indexOf('void _configureScheduledQuickScan', helperStart),
    );

    expect(
      beginSecuritySettings,
      contains(
        "_scanBusyReasonForConfigurationMutation(\n      'Security settings cannot be changed'",
      ),
    );
    expect(
      reset,
      contains(
        "_scanBusyReasonForConfigurationMutation(\n      'Configuration reset cannot run'",
      ),
    );
    expect(helper, contains('_scanStartInFlight || state.scanStartInFlight'));
    expect(helper, contains('state.scanStatus == ScanStatus.running'));
    expect(
      helper,
      contains(
        '_scanTargetSelectionInFlight || state.scanTargetSelectionInFlight',
      ),
    );
    expect(helper, contains('_scanCancelInFlight || state.scanCancelInFlight'));
    expect(helper, contains("while a scan is starting."));
    expect(helper, contains("while a scan is running."));
    expect(helper, contains("while scan target selection is in progress."));
    expect(helper, contains("while scan cancellation is in progress."));
    expect(
      beginSecuritySettings.indexOf('_scanBusyReasonForConfigurationMutation'),
      lessThan(
        beginSecuritySettings.indexOf(
          '_securitySettingsActionInFlight = true;',
        ),
      ),
    );
    expect(
      reset.indexOf('_scanBusyReasonForConfigurationMutation'),
      lessThan(reset.indexOf('_configurationResetInFlight = true;')),
    );
  });

  test('source marker: app-state controller diagnostics are bounded', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final outsideHelper = appState.replaceFirst(
      r"final normalized = '$error'.trim();",
      '',
    );

    expect(appState, contains('String _boundedUiDiagnostic('));
    expect(appState, contains('const int _maxUiDiagnosticChars = 2048'));
    expect(appState, contains('substring(0, _maxUiDiagnosticChars - 3)'));
    expect(
      appState,
      isNot(contains('substring(0, _maxUiDiagnosticChars)}...')),
    );
    expect(outsideHelper, isNot(contains("details: '\$error'")));
    expect(outsideHelper, isNot(contains("errorMessage: '\$error'")));
    expect(outsideHelper, isNot(contains('details: error.toString()')));
  });

  test('source marker: scheduled quick scan settings require confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final scheduledSettingsStart = appState.indexOf(
      'Future<bool> updateScheduledQuickScanSettings',
    );
    final scheduledSettings = appState.substring(
      scheduledSettingsStart,
      appState.indexOf(
        'void _configureScheduledQuickScan',
        scheduledSettingsStart,
      ),
    );

    expect(scheduledSettings, contains('bool confirmed = false'));
    expect(scheduledSettings, contains('if (!confirmed)'));
    expect(
      scheduledSettings,
      contains('scheduled_quick_scan_confirmation_required'),
    );
    expect(
      scheduledSettings.indexOf('if (!confirmed)'),
      lessThan(scheduledSettings.indexOf('_configRepository.save(updated)')),
    );
    expect(
      scheduledSettings.indexOf('_createScheduledQuickScanTimer(updated)'),
      lessThan(scheduledSettings.indexOf('_configRepository.save(updated)')),
    );
    expect(
      scheduledSettings,
      contains('pendingScheduledQuickScanTimer?.cancel()'),
    );
  });

  test(
    'source marker: scan and settings operation diagnostics are bounded',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final scheduledSettingsStart = appState.indexOf(
        'Future<bool> updateScheduledQuickScanSettings',
      );
      final sections = <String>[
        appState.substring(
          scheduledSettingsStart,
          appState.indexOf(
            'void _configureScheduledQuickScan',
            scheduledSettingsStart,
          ),
        ),
        appState.substring(
          appState.indexOf('Future<void> scanSelectedFile'),
          appState.indexOf('Future<void> scanSelectedFolder'),
        ),
        appState.substring(
          appState.indexOf('Future<void> scanSelectedFolder'),
          appState.indexOf('Future<void> runQuickScan'),
        ),
        appState.substring(
          appState.indexOf('Future<void> cancelScan'),
          appState.indexOf('void _replaceThreat'),
        ),
        appState.substring(
          appState.indexOf('Future<void> _scanPaths'),
          appState.indexOf('String? _scanCoverageWarning'),
        ),
        appState.substring(
          appState.indexOf('Future<String?> exportLogs'),
          appState.indexOf('Future<bool> resetConfiguration'),
        ),
        appState.substring(
          appState.indexOf('Future<bool> resetConfiguration'),
          appState.indexOf('AppVerificationStatus _verificationStatusFor'),
        ),
      ];

      for (final section in sections) {
        expect(
          section,
          contains('final details = _boundedUiDiagnostic(error)'),
        );
        expect(section, contains('details: details'));
        expect(section, isNot(contains("details: '\$error'")));
        expect(section, isNot(contains("errorMessage: '\$error'")));
        expect(section, isNot(contains('details: error.toString()')));
      }
    },
  );

  test('source marker: scheduled quick scan skips are audited', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final scheduledRun = appState.substring(
      appState.indexOf('Future<void> _runScheduledQuickScan'),
      appState.indexOf('List<String> _normalizeUserPaths'),
    );

    expect(scheduledRun, contains('scheduled_quick_scan_skipped'));
    expect(scheduledRun, contains('A scan is already running.'));
    expect(
      scheduledRun,
      contains('Scan target selection is already in progress.'),
    );
    expect(scheduledRun, contains('_scheduledQuickScanBusyReason()'));
    expect(
      scheduledRun.indexOf('final busyReason = _scheduledQuickScanBusyReason'),
      lessThan(scheduledRun.indexOf('scheduled_quick_scan_started')),
    );
    expect(
      scheduledRun.indexOf('state.scanTargetSelectionInFlight'),
      lessThan(scheduledRun.indexOf('return null;')),
    );
  });

  test(
    'source marker: scan starts reject target-selection races before scan IPC',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final quarantineRescan = appState.substring(
        appState.indexOf('Future<void> rescanQuarantineOriginal'),
        appState.indexOf('Future<void> scanSelectedFolder'),
      );
      final quickScan = appState.substring(
        appState.indexOf('Future<void> runQuickScan'),
        appState.indexOf('Future<void> runFullScan'),
      );
      final fullScan = appState.substring(
        appState.indexOf('Future<void> runFullScan'),
        appState.indexOf('Future<bool> _rejectScanStartDuringTargetSelection'),
      );
      final helper = appState.substring(
        appState.indexOf('Future<bool> _rejectScanStartDuringTargetSelection'),
        appState.indexOf('Future<void> quarantineThreat'),
      );

      expect(
        quarantineRescan,
        contains('_rejectScanStartDuringTargetSelection'),
      );
      expect(quarantineRescan, contains('Quarantine original rescan'));
      expect(
        quarantineRescan.indexOf('_rejectScanStartDuringTargetSelection'),
        lessThan(
          quarantineRescan.indexOf('quarantine_original_rescan_requested'),
        ),
      );
      expect(
        quickScan,
        contains("_rejectScanStartDuringTargetSelection('Quick scan')"),
      );
      expect(
        quickScan.indexOf('_rejectScanStartDuringTargetSelection'),
        lessThan(quickScan.indexOf('final effectiveActionMode')),
      );
      expect(
        fullScan,
        contains("_rejectScanStartDuringTargetSelection('Full scan')"),
      );
      expect(
        fullScan.indexOf('_rejectScanStartDuringTargetSelection'),
        lessThan(fullScan.indexOf('final effectiveActionMode')),
      );
      expect(
        helper,
        contains(
          'if (!_scanTargetSelectionInFlight && !state.scanTargetSelectionInFlight)',
        ),
      );
      expect(helper, contains('scan_start_ignored'));
      expect(helper, contains('Scan target selection is already in progress.'));
      expect(helper, contains("category: 'scan'"));
      expect(helper, contains("severity: 'warning'"));
      expect(helper, contains('state = state.copyWith(errorMessage: message)'));
    },
  );

  test(
    'source marker: custom target selection rejects scan busy before picker',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final filePicker = appState.substring(
        appState.indexOf('Future<void> scanSelectedFile'),
        appState.indexOf('Future<void> scanSelectedFolder'),
      );
      final folderPicker = appState.substring(
        appState.indexOf('Future<void> scanSelectedFolder'),
        appState.indexOf('Future<bool> _beginScanTargetSelection'),
      );
      final helper = appState.substring(
        appState.indexOf('Future<bool> _beginScanTargetSelection'),
        appState.indexOf('void _endScanTargetSelection'),
      );

      expect(helper, contains('_scanTargetSelectionBusyReason()'));
      expect(
        helper,
        contains(
          '_scanTargetSelectionInFlight || state.scanTargetSelectionInFlight',
        ),
      );
      expect(helper, contains('_scanStartInFlight || state.scanStartInFlight'));
      expect(helper, contains('state.scanStatus == ScanStatus.running'));
      expect(helper, contains('Scan target selection is already in progress.'));
      expect(helper, contains('A scan is already starting.'));
      expect(helper, contains('A scan is already running.'));
      expect(helper, contains('scan_target_selection_busy'));
      expect(
        filePicker.indexOf("_beginScanTargetSelection('Custom file scan')"),
        lessThan(filePicker.indexOf('_fileSelectionService.pickFile()')),
      );
      expect(
        folderPicker.indexOf("_beginScanTargetSelection('Custom folder scan')"),
        lessThan(folderPicker.indexOf('_fileSelectionService.pickDirectory()')),
      );
    },
  );

  test('source marker: scan starts block configuration busy states', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final quickScan = appState.substring(
      appState.indexOf('Future<void> runQuickScan'),
      appState.indexOf('Future<void> runFullScan'),
    );
    final fullScan = appState.substring(
      appState.indexOf('Future<void> runFullScan'),
      appState.indexOf('Future<bool> _rejectScanStartDuringTargetSelection'),
    );
    final filePicker = appState.substring(
      appState.indexOf('Future<void> scanSelectedFile'),
      appState.indexOf('Future<void> rescanQuarantineOriginal'),
    );
    final folderPicker = appState.substring(
      appState.indexOf('Future<void> scanSelectedFolder'),
      appState.indexOf('Future<bool> _beginScanTargetSelection'),
    );
    final rescan = appState.substring(
      appState.indexOf('Future<void> rescanQuarantineOriginal'),
      appState.indexOf('Future<void> scanSelectedFolder'),
    );
    final configGuard = appState.substring(
      appState.indexOf(
        'Future<bool> _rejectScanStartDuringConfigurationChange',
      ),
      appState.indexOf('String? _scanConfigurationBusyReason'),
    );
    final configReason = appState.substring(
      appState.indexOf('String? _scanConfigurationBusyReason'),
      appState.indexOf('Future<void> quarantineThreat'),
    );
    final scanPaths = appState.substring(
      appState.indexOf('Future<void> _scanPaths'),
      appState.indexOf('ScanReport _failedScanReport'),
    );

    for (final source in [
      quickScan,
      fullScan,
      filePicker,
      folderPicker,
      rescan,
    ]) {
      expect(source, contains('_rejectScanStartDuringConfigurationChange'));
    }
    expect(
      quickScan.indexOf('_rejectScanStartDuringConfigurationChange'),
      lessThan(quickScan.indexOf('final effectiveActionMode')),
    );
    expect(
      fullScan.indexOf('_rejectScanStartDuringConfigurationChange'),
      lessThan(fullScan.indexOf('final effectiveActionMode')),
    );
    expect(
      filePicker.indexOf('_rejectScanStartDuringConfigurationChange'),
      lessThan(filePicker.indexOf('_ensureScanAutoActionConfirmed')),
    );
    expect(
      folderPicker.indexOf('_rejectScanStartDuringConfigurationChange'),
      lessThan(folderPicker.indexOf('_ensureScanAutoActionConfirmed')),
    );
    expect(
      rescan.indexOf('_rejectScanStartDuringConfigurationChange'),
      lessThan(rescan.indexOf('quarantine_original_rescan_requested')),
    );
    expect(
      scanPaths.indexOf('_rejectScanStartDuringConfigurationChange'),
      lessThan(scanPaths.indexOf('_scanStartInFlight = true;')),
    );
    expect(configGuard, contains('scan_start_ignored'));
    expect(configGuard, contains("category: 'scan'"));
    expect(configGuard, contains("severity: 'warning'"));
    expect(configReason, contains('_configurationResetInFlight'));
    expect(configReason, contains('state.configurationResetInFlight'));
    expect(configReason, contains('_securitySettingsActionInFlight'));
    expect(configReason, contains('state.securitySettingsActionInFlight'));
    expect(configReason, contains('Configuration reset is in progress.'));
    expect(configReason, contains('Security settings change is in progress.'));
  });

  test('scan starts block while update package work is busy', () async {
    final busyUpdateStatuses = [
      UpdateStatus.downloading,
      UpdateStatus.verifying,
      UpdateStatus.installing,
      UpdateStatus.rollingBack,
    ];

    for (final status in busyUpdateStatuses) {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          scanTargetServiceProvider.overrideWithValue(
            const _FakeScanTargetService([r'C:\AvoraxTest\scan-target']),
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(updateStatus: status);

      await controller.runQuickScan(actionMode: ScanActionMode.detectOnly);
      await controller.runFullScan(actionMode: ScanActionMode.detectOnly);
      await controller.scanSelectedFile();
      await controller.scanSelectedFolder();
      await controller.rescanQuarantineOriginal(
        _quarantineRecord(
          quarantineId: 'q-update-$status',
          status: QuarantineItemStatus.restored,
          actionTaken: 'restored',
        ),
      );

      final state = container.read(zentorControllerProvider);
      expect(localCore.scanCalls, 0);
      expect(state.scanStartInFlight, isFalse);
      expect(state.scanTargetSelectionInFlight, isFalse);
      expect(state.errorMessage, contains('update package work'));
      expect(state.errorMessage, contains(status.label));
      final ignoredEvents = state.events
          .where((event) => event.type == 'scan_start_ignored')
          .toList();
      expect(ignoredEvents, hasLength(5));
      for (final event in ignoredEvents) {
        expect(event.category, 'scan');
        expect(event.severity, 'warning');
        expect(event.details, contains('update package work'));
        expect(event.details, contains(status.label));
      }
      expect(
        state.events.map((event) => event.type),
        isNot(contains('scan_started')),
      );
      expect(
        state.events.map((event) => event.type),
        isNot(contains('quarantine_original_rescan_requested')),
      );
    }
  });

  test('source marker: scan starts block update package work', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final quickScan = appState.substring(
      appState.indexOf('Future<void> runQuickScan'),
      appState.indexOf('Future<void> runFullScan'),
    );
    final fullScan = appState.substring(
      appState.indexOf('Future<void> runFullScan'),
      appState.indexOf('Future<bool> _rejectScanStartDuringTargetSelection'),
    );
    final filePicker = appState.substring(
      appState.indexOf('Future<void> scanSelectedFile'),
      appState.indexOf('Future<void> rescanQuarantineOriginal'),
    );
    final rescan = appState.substring(
      appState.indexOf('Future<void> rescanQuarantineOriginal'),
      appState.indexOf('Future<void> scanSelectedFolder'),
    );
    final folderPicker = appState.substring(
      appState.indexOf('Future<void> scanSelectedFolder'),
      appState.indexOf('Future<bool> _beginScanTargetSelection'),
    );
    final scanPaths = appState.substring(
      appState.indexOf('Future<void> _scanPaths'),
      appState.indexOf('ScanReport _failedScanReport'),
    );
    final updateGuard = appState.substring(
      appState.indexOf('Future<bool> _rejectScanStartDuringUpdateMutation'),
      appState.indexOf('String? _scanConfigurationBusyReason'),
    );
    final scheduledBusy = appState.substring(
      appState.indexOf('String? _scheduledQuickScanBusyReason'),
      appState.indexOf('List<String> _normalizeUserPaths'),
    );

    for (final source in [
      quickScan,
      fullScan,
      filePicker,
      folderPicker,
      rescan,
      scanPaths,
    ]) {
      expect(source, contains('_rejectScanStartDuringUpdateMutation'));
    }
    expect(
      quickScan.indexOf('_rejectScanStartDuringUpdateMutation'),
      lessThan(quickScan.indexOf('final effectiveActionMode')),
    );
    expect(
      fullScan.indexOf('_rejectScanStartDuringUpdateMutation'),
      lessThan(fullScan.indexOf('final effectiveActionMode')),
    );
    expect(
      filePicker.indexOf('_rejectScanStartDuringUpdateMutation'),
      lessThan(filePicker.indexOf('_ensureScanAutoActionConfirmed')),
    );
    expect(
      folderPicker.indexOf('_rejectScanStartDuringUpdateMutation'),
      lessThan(folderPicker.indexOf('_ensureScanAutoActionConfirmed')),
    );
    expect(
      rescan.indexOf('_rejectScanStartDuringUpdateMutation'),
      lessThan(rescan.indexOf('quarantine_original_rescan_requested')),
    );
    expect(
      scanPaths.indexOf('_rejectScanStartDuringUpdateMutation'),
      lessThan(scanPaths.indexOf('_scanStartInFlight = true;')),
    );
    expect(updateGuard, contains('_scanUpdateMutationBusyReason()'));
    expect(updateGuard, contains('_isUpdateMutationStatusBusy(status)'));
    expect(updateGuard, contains('scan_start_ignored'));
    expect(updateGuard, contains("category: 'scan'"));
    expect(updateGuard, contains("severity: 'warning'"));
    expect(updateGuard, contains('update package work is in progress'));
    expect(updateGuard, isNot(contains('UpdateStatus.checking')));
    expect(scheduledBusy, contains('_scanUpdateMutationBusyReason()'));
  });

  test(
    'source marker: detected protected app selection requires confirmation',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final selection = appState.substring(
        appState.indexOf('Future<bool> selectDetectedApp'),
        appState.indexOf('Future<bool> _saveManualAppPath'),
      );

      expect(selection, contains('bool confirmed = false'));
      expect(selection, contains('if (!confirmed)'));
      expect(
        selection,
        contains('protected_app_selection_confirmation_required'),
      );
      expect(
        selection.indexOf('if (!confirmed)'),
        lessThan(selection.indexOf('_configRepository.save(updated)')),
      );
    },
  );

  test(
    'source marker: manual protected app selection requires confirmation',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final fileSelection = appState.substring(
        appState.indexOf('Future<bool> addManualProtectedAppFile'),
        appState.indexOf('Future<bool> addManualProtectedAppFolder'),
      );
      final folderSelection = appState.substring(
        appState.indexOf('Future<bool> addManualProtectedAppFolder'),
        appState.indexOf('Future<bool> selectDetectedApp'),
      );

      for (final selection in [fileSelection, folderSelection]) {
        expect(selection, contains('bool confirmed = false'));
        expect(selection, contains('if (!confirmed)'));
        expect(
          selection,
          contains('manual_protected_app_selection_confirmation_required'),
        );
      }
      expect(
        fileSelection.indexOf('if (!confirmed)'),
        lessThan(fileSelection.indexOf('_fileSelectionService.pickFile()')),
      );
      expect(
        folderSelection.indexOf('if (!confirmed)'),
        lessThan(
          folderSelection.indexOf('_fileSelectionService.pickDirectory()'),
        ),
      );
      expect(fileSelection, contains('manual_protected_app_file_unavailable'));
      expect(
        folderSelection,
        contains('manual_protected_app_folder_unavailable'),
      );
      expect(
        fileSelection.indexOf('manual_protected_app_file_unavailable'),
        lessThan(fileSelection.indexOf('_fileSelectionService.pickFile()')),
      );
      expect(
        folderSelection.indexOf('manual_protected_app_folder_unavailable'),
        lessThan(
          folderSelection.indexOf('_fileSelectionService.pickDirectory()'),
        ),
      );
    },
  );

  test(
    'source marker: protected app hash calculation requires confirmation',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final hashCalculation = appState.substring(
        appState.indexOf('Future<bool> calculateProtectedAppHash'),
        appState.indexOf('_RealtimeWatchPathPlan _realtimeWatchPathPlan'),
      );

      expect(hashCalculation, contains('bool confirmed = false'));
      expect(hashCalculation, contains('if (!confirmed)'));
      expect(
        hashCalculation,
        contains('protected_app_hash_confirmation_required'),
      );
      expect(
        hashCalculation.indexOf('if (!confirmed)'),
        lessThan(hashCalculation.indexOf('_hashService.sha256ForFile')),
      );
      expect(
        hashCalculation.indexOf('if (!confirmed)'),
        lessThan(hashCalculation.indexOf('_configRepository.save(updated)')),
      );
      expect(hashCalculation, contains('protected_app_hash_no_target'));
      expect(hashCalculation, contains('protected_app_hash_path_probe_failed'));
      expect(hashCalculation, contains('protected_app_hash_unavailable'));
      expect(
        hashCalculation.indexOf('protected_app_hash_no_target'),
        lessThan(hashCalculation.indexOf('_hashService.sha256ForFile')),
      );
      expect(
        hashCalculation.indexOf('protected_app_hash_path_probe_failed'),
        lessThan(hashCalculation.indexOf('_hashService.sha256ForFile')),
      );
      expect(
        hashCalculation.indexOf('protected_app_hash_unavailable'),
        lessThan(hashCalculation.indexOf('_hashService.sha256ForFile')),
      );
    },
  );

  test('source marker: protected app actions block update package work', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final helper = appState.substring(
      appState.indexOf('Future<bool> _beginProtectedAppAction'),
      appState.indexOf('void _endProtectedAppAction'),
    );
    final manualFile = appState.substring(
      appState.indexOf('Future<bool> addManualProtectedAppFile'),
      appState.indexOf('Future<bool> addManualProtectedAppFolder'),
    );
    final manualFolder = appState.substring(
      appState.indexOf('Future<bool> addManualProtectedAppFolder'),
      appState.indexOf('Future<bool> selectDetectedApp'),
    );
    final selectDetected = appState.substring(
      appState.indexOf('Future<bool> selectDetectedApp'),
      appState.indexOf('Future<bool> _saveManualAppPath'),
    );
    final hash = appState.substring(
      appState.indexOf('Future<bool> calculateProtectedAppHash'),
      appState.indexOf('Future<bool> _beginProtectedAppAction'),
    );

    expect(helper, contains('_configurationMutationUpdateBusyReason('));
    expect(helper, contains('Protected app action cannot run'));
    expect(helper, contains('updateOperationInFlight:'));
    expect(
      helper.indexOf('_configurationMutationUpdateBusyReason('),
      lessThan(helper.indexOf('_protectedAppActionInFlight = true;')),
    );
    for (final source in [manualFile, manualFolder, selectDetected, hash]) {
      expect(source, contains('if (!await _beginProtectedAppAction('));
    }
  });

  test('source marker: configuration reset requires confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final reset = appState.substring(
      appState.indexOf('Future<bool> resetConfiguration'),
      appState.indexOf('AppVerificationStatus _verificationStatusFor'),
    );

    expect(reset, contains('{bool confirmed = false}'));
    expect(reset, contains('if (!confirmed)'));
    expect(reset, contains('configuration_reset_confirmation_required'));
    expect(
      reset.indexOf('if (!confirmed)'),
      lessThan(reset.indexOf('_configRepository.reset()')),
    );
  });

  test('source marker: developer cloud override requires confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final override = appState.substring(
      appState.indexOf('Future<bool> saveDeveloperCloudOverride'),
      appState.indexOf('Future<void> unawaitedDetectApps'),
    );

    expect(override, contains('bool confirmed = false'));
    expect(override, contains('if (!confirmed)'));
    expect(
      override,
      contains('developer_cloud_override_confirmation_required'),
    );
    expect(
      override.indexOf('if (!confirmed)'),
      lessThan(override.indexOf('_configRepository.save(updated)')),
    );
  });

  test('source marker: allowlist remove requires confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final removeAllowlist = appState.substring(
      appState.indexOf('Future<void> removeAllowlistEntry'),
      appState.indexOf('Future<void> restoreQuarantineItem'),
    );

    expect(removeAllowlist, contains('bool confirmed = false'));
    expect(removeAllowlist, contains('if (!confirmed)'));
    expect(
      removeAllowlist,
      contains('allowlist_entry_remove_confirmation_required'),
    );
    expect(
      removeAllowlist.indexOf('if (!confirmed)'),
      lessThan(removeAllowlist.indexOf('removeAllowlistEntry(entry.id)')),
    );
  });

  test('source marker: manual quarantine requires confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final quarantine = appState.substring(
      appState.indexOf('Future<void> quarantineThreat'),
      appState.indexOf('Future<void> ignoreThreat'),
    );

    expect(quarantine, contains('bool confirmed = false'));
    expect(quarantine, contains('if (!confirmed)'));
    expect(quarantine, contains('quarantine_confirmation_required'));
    expect(
      quarantine.indexOf('if (!confirmed)'),
      lessThan(quarantine.indexOf('quarantineThreat(threat)')),
    );
  });

  test('source marker: ignore threat requires confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final ignore = appState.substring(
      appState.indexOf('Future<void> ignoreThreat'),
      appState.indexOf('Future<void> markThreatFalsePositive'),
    );

    expect(ignore, contains('bool confirmed = false'));
    expect(ignore, contains('if (!confirmed)'));
    expect(ignore, contains('threat_ignore_confirmation_required'));
    expect(ignore, contains('_rejectDuringConfigurationChange('));
    expect(ignore, contains("eventType: 'threat_ignore_busy'"));
    expect(
      ignore.indexOf('if (!confirmed)'),
      lessThan(ignore.indexOf('threat_ignored')),
    );
    expect(
      ignore.indexOf('_rejectDuringConfigurationChange('),
      lessThan(ignore.indexOf('threat_ignored')),
    );
  });

  test('source marker: manual trust actions block update package work', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final helper = appState.substring(
      appState.indexOf(
        'Future<bool> _rejectManualDispositionDuringUpdateMutation',
      ),
      appState.indexOf('Future<bool> _rejectDuringConfigurationChange'),
    );
    final ignore = appState.substring(
      appState.indexOf('Future<void> ignoreThreat'),
      appState.indexOf('Future<void> markThreatFalsePositive'),
    );
    final feedback = appState.substring(
      appState.indexOf('Future<bool> _beginDetectionFeedback'),
      appState.indexOf('void _endDetectionFeedback'),
    );
    final allowlist = appState.substring(
      appState.indexOf('Future<bool> _beginAllowlistAction'),
      appState.indexOf('void _endAllowlistAction'),
    );
    final quarantine = appState.substring(
      appState.indexOf('Future<bool> _beginQuarantineAction'),
      appState.indexOf('void _endQuarantineAction'),
    );

    expect(helper, contains('_configurationMutationUpdateBusyReason(prefix)'));
    expect(helper, contains('updateOperationInFlight:'));
    expect(helper, contains('errorMessage: busyReason'));
    for (final source in [ignore, feedback, allowlist, quarantine]) {
      expect(source, contains('_rejectManualDispositionDuringUpdateMutation('));
    }
    expect(
      ignore.indexOf('_rejectManualDispositionDuringUpdateMutation('),
      lessThan(ignore.indexOf('_threatIgnoreActionInFlight = true;')),
    );
    expect(
      feedback.indexOf('_rejectManualDispositionDuringUpdateMutation('),
      lessThan(feedback.indexOf('_detectionFeedbackInFlight = true;')),
    );
    expect(
      allowlist.indexOf('_rejectManualDispositionDuringUpdateMutation('),
      lessThan(allowlist.indexOf('_allowlistActionInFlight = true;')),
    );
    expect(
      quarantine.indexOf('_rejectManualDispositionDuringUpdateMutation('),
      lessThan(quarantine.indexOf('_quarantineActionInFlight = true;')),
    );
  });

  test('source marker: quarantine restore and delete require confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final restore = appState.substring(
      appState.indexOf('Future<void> restoreQuarantineItem'),
      appState.indexOf('Future<void> deleteQuarantineItem'),
    );
    final delete = appState.substring(
      appState.indexOf('Future<void> deleteQuarantineItem'),
      appState.indexOf('void _replaceQuarantineRecordStatus'),
    );

    expect(restore, contains('bool confirmed = false'));
    expect(restore, contains('if (!confirmed)'));
    expect(restore, contains('quarantine_restore_confirmation_required'));
    expect(
      restore.indexOf('if (!confirmed)'),
      lessThan(restore.indexOf('_localCoreClient.restoreQuarantineItem')),
    );
    expect(delete, contains('bool confirmed = false'));
    expect(delete, contains('if (!confirmed)'));
    expect(delete, contains('quarantine_delete_confirmation_required'));
    expect(
      delete.indexOf('if (!confirmed)'),
      lessThan(delete.indexOf('_localCoreClient.deleteQuarantineItem')),
    );
  });

  test('source marker: quarantine restore and delete path text is bounded', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final helper = appState.substring(
      appState.indexOf('String _boundedQuarantinePath'),
      appState.indexOf('String _boundedExportPath'),
    );
    final restore = appState.substring(
      appState.indexOf('Future<void> restoreQuarantineItem'),
      appState.indexOf('Future<void> deleteQuarantineItem'),
    );
    final delete = appState.substring(
      appState.indexOf('Future<void> deleteQuarantineItem'),
      appState.indexOf('Future<bool> _beginQuarantineAction'),
    );
    final begin = appState.substring(
      appState.indexOf('Future<bool> _beginQuarantineAction'),
      appState.indexOf('void _endQuarantineAction'),
    );

    expect(
      helper,
      contains(
        "_boundedUiDiagnostic(path, fallback: 'quarantine path unavailable')",
      ),
    );
    for (final section in <String>[restore, delete]) {
      expect(
        section,
        contains(
          'final displayPath = _boundedQuarantinePath(item.originalPath);',
        ),
      );
      expect(
        section,
        contains('if (!await _beginQuarantineAction(displayPath)) return;'),
      );
      expect(section, contains(r"details: '$displayPath\n$message'"));
      expect(section, contains(r"details: '$displayPath\n$details'"));
      expect(section, contains('details: displayPath'));
      expect(section, isNot(contains(r"details: '${item.originalPath}")));
      expect(section, isNot(contains('details: item.originalPath')));
    }
    expect(
      begin,
      contains('final displayTarget = _boundedQuarantinePath(target);'),
    );
    expect(begin, contains(r"details: '$displayTarget\n$message'"));
    expect(begin, isNot(contains(r'$target\n$message')));
  });

  test(
    'source marker: manual trust actions block configuration busy states',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final rejectHelper = appState.substring(
        appState.indexOf('Future<bool> _rejectDuringConfigurationChange'),
        appState.indexOf('Future<void> quarantineThreat'),
      );
      final detectionBegin = appState.substring(
        appState.indexOf('Future<bool> _beginDetectionFeedback'),
        appState.indexOf('void _endDetectionFeedback'),
      );
      final allowlistBegin = appState.substring(
        appState.indexOf('Future<bool> _beginAllowlistAction'),
        appState.indexOf('void _endAllowlistAction'),
      );
      final quarantineBegin = appState.substring(
        appState.indexOf('Future<bool> _beginQuarantineAction'),
        appState.indexOf('void _endQuarantineAction'),
      );

      expect(rejectHelper, contains('_scanConfigurationBusyReason()'));
      expect(rejectHelper, contains('securitySettingsActionInFlight:'));
      expect(rejectHelper, contains('configurationResetInFlight:'));
      expect(rejectHelper, contains('errorMessage: busyReason'));
      expect(
        detectionBegin,
        contains('eventType: \'detection_feedback_busy\''),
      );
      expect(detectionBegin, contains('_rejectDuringConfigurationChange('));
      expect(allowlistBegin, contains('eventType: \'allowlist_action_busy\''));
      expect(allowlistBegin, contains('_rejectDuringConfigurationChange('));
      expect(
        quarantineBegin,
        contains('eventType: \'quarantine_action_busy\''),
      );
      expect(quarantineBegin, contains('_rejectDuringConfigurationChange('));
      expect(
        detectionBegin.indexOf('_rejectDuringConfigurationChange('),
        lessThan(detectionBegin.indexOf('_detectionFeedbackInFlight = true;')),
      );
      expect(
        allowlistBegin.indexOf('_rejectDuringConfigurationChange('),
        lessThan(allowlistBegin.indexOf('_allowlistActionInFlight = true;')),
      );
      expect(
        quarantineBegin.indexOf('_rejectDuringConfigurationChange('),
        lessThan(quarantineBegin.indexOf('_quarantineActionInFlight = true;')),
      );
    },
  );

  test('source marker: false-positive feedback requires confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final falsePositive = appState.substring(
      appState.indexOf('Future<void> markThreatFalsePositive'),
      appState.indexOf('Future<void> markThreatMalicious'),
    );

    expect(falsePositive, contains('bool confirmed = false'));
    expect(falsePositive, contains('if (!confirmed)'));
    expect(
      falsePositive,
      contains('false_positive_label_confirmation_required'),
    );
    expect(
      falsePositive.indexOf('if (!confirmed)'),
      lessThan(falsePositive.indexOf('labelDetection(')),
    );
  });

  test('source marker: malicious feedback requires confirmation', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final maliciousFeedback = appState.substring(
      appState.indexOf('Future<void> markThreatMalicious'),
      appState.indexOf('Future<void> addThreatToAllowlist'),
    );

    expect(maliciousFeedback, contains('bool confirmed = false'));
    expect(maliciousFeedback, contains('if (!confirmed)'));
    expect(
      maliciousFeedback,
      contains('malicious_label_confirmation_required'),
    );
    expect(
      maliciousFeedback.indexOf('if (!confirmed)'),
      lessThan(maliciousFeedback.indexOf('labelDetection(')),
    );
  });

  test('source marker: local-core action failure results are audit events', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final sections = <String, String>{
      'quarantine_failed': appState.substring(
        appState.indexOf('Future<void> quarantineThreat'),
        appState.indexOf('Future<void> ignoreThreat'),
      ),
      'false_positive_label_failed': appState.substring(
        appState.indexOf('Future<void> markThreatFalsePositive'),
        appState.indexOf('Future<void> markThreatMalicious'),
      ),
      'malicious_label_failed': appState.substring(
        appState.indexOf('Future<void> markThreatMalicious'),
        appState.indexOf('Future<void> addThreatToAllowlist'),
      ),
      'allowlist_entry_add_failed': appState.substring(
        appState.indexOf('Future<void> addThreatToAllowlist'),
        appState.indexOf('Future<void> removeAllowlistEntry'),
      ),
      'allowlist_entry_remove_failed': appState.substring(
        appState.indexOf('Future<void> removeAllowlistEntry'),
        appState.indexOf('Future<void> restoreQuarantineItem'),
      ),
      'quarantine_restore_failed': appState.substring(
        appState.indexOf('Future<void> restoreQuarantineItem'),
        appState.indexOf('Future<void> deleteQuarantineItem'),
      ),
      'quarantine_delete_failed': appState.substring(
        appState.indexOf('Future<void> deleteQuarantineItem'),
        appState.indexOf('void _replaceQuarantineRecordStatus'),
      ),
    };

    for (final entry in sections.entries) {
      expect(entry.value, contains('if (!result.ok)'));
      expect(
        RegExp(
          'final details = _boundedUiDiagnostic',
        ).allMatches(entry.value).length,
        greaterThanOrEqualTo(2),
        reason: '${entry.key} must bound exceptions and failed results',
      );
      expect(
        RegExp("'${entry.key}'").allMatches(entry.value).length,
        greaterThanOrEqualTo(2),
        reason: '${entry.key} must cover exceptions and failed results',
      );
      expect(entry.value, contains(r'$details'));
      expect(entry.value, isNot(contains(r'$error')));
      expect(entry.value, isNot(contains(r'${result.error}')));
      expect(entry.value, contains('severity: \'error\''));
    }
  });

  test('source marker: start protection recovers persisted off profile', () {
    final appState = readNormalizedSource('lib/app/app_state.dart');
    final startFlow = appState.substring(
      appState.indexOf('Future<void> startProtection'),
      appState.indexOf('Future<void> stopProtection'),
    );

    expect(
      startFlow,
      contains('configForStart.protectionMode == ProtectionMode.off'),
    );
    expect(startFlow, contains('ProtectionMode.balanced'));
    expect(startFlow, contains('protection_mode_recovered'));
    expect(startFlow, contains('bool confirmed = false'));
    expect(startFlow, contains('if (!confirmed)'));
    expect(startFlow, contains('protection_start_confirmation_required'));
    expect(startFlow, contains('_localCoreClient.configureGuardMode('));
    expect(startFlow, contains('configForStart.protectionMode'));
    final guardModeCall = startFlow.indexOf(
      '_localCoreClient.configureGuardMode',
    );
    expect(
      guardModeCall,
      lessThan(
        startFlow.indexOf('configForStart.protectionMode', guardModeCall),
      ),
    );
    expect(
      appState,
      contains('confirmed: true,\n      restoringSavedPreference: true,'),
    );
  });

  test('successful scan clears a stale engine error message', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync('zentor-error-clear-');
    addTearDown(() => target.deleteSync(recursive: true));
    final localCore = _FakeLocalCoreClient(
      reports: [
        _scanReport(ScanStatus.engineUnavailable, ScanKind.quick),
        _scanReport(ScanStatus.clean, ScanKind.quick),
      ],
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    await controller.runQuickScan();
    expect(
      container.read(zentorControllerProvider).scanStatus,
      ScanStatus.engineUnavailable,
    );
    expect(container.read(zentorControllerProvider).errorMessage, isNotNull);

    await controller.runQuickScan();
    final state = container.read(zentorControllerProvider);
    expect(state.scanStatus, ScanStatus.clean);
    expect(state.errorMessage, isNull);
  });

  test('quarantine failure shows local core blocker', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient(
      actionFailure: 'restore destination already exists',
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.quarantineThreat(_threatResult(), confirmed: true);

    expect(localCore.quarantineCalls, 1);
    expect(
      container.read(zentorControllerProvider).errorMessage,
      contains('restore destination already exists'),
    );
    expect(
      container
          .read(zentorControllerProvider)
          .events
          .map((event) => event.type),
      contains('quarantine_failed'),
    );
  });

  test('quarantine exception diagnostics are normalized at runtime', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final rawFailure =
        'quarantine IPC crashed\x00\n\t${'diagnostic detail ' * 260}';
    final localCore = _FakeLocalCoreClient(actionException: rawFailure);

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final threat = _threatResult();
    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      lastScanReport: _scanReport(
        ScanStatus.infected,
        ScanKind.quick,
        threats: [threat],
      ),
    );
    await controller.quarantineThreat(threat, confirmed: true);

    final state = container.read(zentorControllerProvider);
    expect(localCore.quarantineCalls, 1);
    expect(state.quarantineActionInFlight, isFalse);
    expect(
      state.lastScanReport?.threats.single.status,
      ThreatResultStatus.detected,
    );
    expect(
      state.errorMessage,
      startsWith('Unable to quarantine ${threat.fileName}:'),
    );
    expect(state.errorMessage, contains('quarantine IPC crashed'));
    expect(state.errorMessage, isNot(contains('\x00')));
    expect(state.errorMessage, isNot(contains('\n\t')));
    expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
    final failedEvent = state.events.lastWhere(
      (event) => event.type == 'quarantine_failed',
    );
    expect(failedEvent.category, 'quarantine');
    expect(failedEvent.severity, 'error');
    expect(failedEvent.details, contains(threat.path));
    expect(failedEvent.details, contains('quarantine IPC crashed'));
    expect(failedEvent.details, isNot(contains('\x00')));
    expect(failedEvent.details, isNot(contains('\n\t')));
    expect(failedEvent.details!.length, lessThanOrEqualTo(2100));
  });

  test('unconfirmed manual quarantine does not call local core', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final threat = _threatResult();
    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      lastScanReport: _scanReport(
        ScanStatus.infected,
        ScanKind.quick,
        threats: [threat],
      ),
    );

    await controller.quarantineThreat(threat);

    final state = container.read(zentorControllerProvider);
    expect(localCore.quarantineCalls, 0);
    expect(
      state.lastScanReport?.threats.single.status,
      ThreatResultStatus.detected,
    );
    expect(state.errorMessage, contains('explicit confirmation'));
    expect(
      state.events.map((event) => event.type),
      contains('quarantine_confirmation_required'),
    );
  });

  test('unconfirmed auto-action quick scan does not call local core', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync('zentor-auto-action-');
    addTearDown(() => target.deleteSync(recursive: true));
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.setScanActionMode(ScanActionMode.autoQuarantineConfirmedOnly);

    await controller.runQuickScan();

    final state = container.read(zentorControllerProvider);
    expect(localCore.scanCalls, 0);
    expect(state.scanStatus, ScanStatus.idle);
    expect(state.errorMessage, contains('explicit confirmation'));
    expect(
      state.events.map((event) => event.type),
      contains('scan_auto_action_confirmation_required'),
    );
  });

  test('scan action mode changes are blocked during target selection', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      scanTargetSelectionInFlight: true,
    );

    controller.setScanActionMode(ScanActionMode.autoQuarantineConfirmedOnly);
    await Future<void>.delayed(Duration.zero);

    final state = container.read(zentorControllerProvider);
    expect(state.scanActionMode, ScanActionMode.detectOnly);
    expect(
      state.errorMessage,
      'Scan action mode cannot be changed while scan target selection is in progress.',
    );
    final blockedEvent = state.events.firstWhere(
      (event) => event.type == 'scan_action_mode_change_blocked',
    );
    expect(blockedEvent.category, 'scan');
    expect(blockedEvent.severity, 'warning');
    expect(
      blockedEvent.details,
      contains('scan target selection is in progress'),
    );
  });

  test(
    'scan starts block while security settings or configuration reset is busy',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        securitySettingsActionInFlight: true,
      );

      await controller.runQuickScan();
      await controller.runFullScan();
      await controller.scanSelectedFile();
      await controller.scanSelectedFolder();

      var state = container.read(zentorControllerProvider);
      expect(localCore.scanCalls, 0);
      expect(state.scanTargetSelectionInFlight, isFalse);
      expect(state.securitySettingsActionInFlight, isTrue);
      expect(state.errorMessage, 'Security settings change is in progress.');
      var ignoredEvents = state.events
          .where((event) => event.type == 'scan_start_ignored')
          .toList();
      expect(ignoredEvents, hasLength(4));
      final securityDetails = ignoredEvents
          .map((event) => event.details)
          .join('\n');
      expect(securityDetails, contains('Quick scan'));
      expect(securityDetails, contains('Full scan'));
      expect(securityDetails, contains('Custom file scan'));
      expect(securityDetails, contains('Custom folder scan'));
      expect(
        securityDetails,
        contains('Security settings change is in progress.'),
      );

      controller.state = state.copyWith(
        securitySettingsActionInFlight: false,
        configurationResetInFlight: true,
      );
      await controller.rescanQuarantineOriginal(
        _quarantineRecord(
          status: QuarantineItemStatus.restored,
          actionTaken: 'restored',
        ),
      );

      state = container.read(zentorControllerProvider);
      expect(localCore.scanCalls, 0);
      expect(state.configurationResetInFlight, isTrue);
      expect(state.errorMessage, 'Configuration reset is in progress.');
      ignoredEvents = state.events
          .where((event) => event.type == 'scan_start_ignored')
          .toList();
      expect(ignoredEvents, hasLength(5));
      final resetEvent = ignoredEvents.firstWhere(
        (event) =>
            event.details?.contains('Quarantine original rescan') ?? false,
      );
      expect(resetEvent.category, 'scan');
      expect(resetEvent.severity, 'warning');
      expect(
        resetEvent.details,
        contains('Configuration reset is in progress.'),
      );
      expect(
        state.events.map((event) => event.type),
        isNot(contains('quarantine_original_rescan_requested')),
      );
    },
  );

  test(
    'custom file scan unsupported by platform records blocker report',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient(desktop: false);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.scanSelectedFile();

      final state = container.read(zentorControllerProvider);
      expect(localCore.scanCalls, 0);
      expect(state.scanStatus, ScanStatus.engineUnavailable);
      expect(state.lastScanReport?.kind, ScanKind.custom);
      expect(state.lastScanReport?.status, ScanStatus.engineUnavailable);
      expect(
        state.events.map((event) => event.type),
        contains('scan_file_unavailable'),
      );
    },
  );

  test('confirmed auto-action quick scan uses selected scan mode', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync('zentor-auto-action-');
    addTearDown(() => target.deleteSync(recursive: true));
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.setScanActionMode(ScanActionMode.autoQuarantineConfirmedOnly);

    await controller.runQuickScan(confirmedAutoAction: true);

    expect(localCore.scanCalls, 1);
    expect(
      localCore.lastActionMode,
      ScanActionMode.autoQuarantineConfirmedOnly,
    );
  });

  test('scan events preserve small-threat review category summary', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync('zentor-small-threats-');
    addTearDown(() => target.deleteSync(recursive: true));
    final threats = [
      _threatResult(
        id: 'infostealer-review',
        fileName: 'collector.js',
        threatCategory: ThreatCategory.infostealer,
        verdict: RiskVerdict.suspicious,
        confidence: ThreatConfidence.medium,
        recommendedAction: RecommendedAction.review,
      ),
      _threatResult(
        id: 'miner-review',
        fileName: 'miner-config.ps1',
        threatCategory: ThreatCategory.miner,
        verdict: RiskVerdict.suspicious,
        confidence: ThreatConfidence.medium,
        recommendedAction: RecommendedAction.review,
      ),
      _threatResult(
        id: 'persistence-review',
        fileName: 'startup-task.ps1',
        threatCategory: ThreatCategory.persistenceIndicator,
        verdict: RiskVerdict.suspicious,
        confidence: ThreatConfidence.medium,
        recommendedAction: RecommendedAction.review,
      ),
    ];
    final localCore = _FakeLocalCoreClient(
      reports: [
        _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          actionMode: ScanActionMode.autoQuarantineConfirmedOnly,
          threats: threats,
        ),
      ],
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.runQuickScan(
      actionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      confirmedAutoAction: true,
    );

    final state = container.read(zentorControllerProvider);
    expect(state.scanStatus, ScanStatus.infected);
    final detectedEvent = state.events.firstWhere(
      (event) => event.type == 'threat_detected',
    );
    final completedEvent = state.events.firstWhere(
      (event) => event.type == 'scan_completed',
    );
    for (final event in [detectedEvent, completedEvent]) {
      expect(event.category, 'scan');
      expect(event.details, contains('Potential infostealer'));
      expect(event.details, contains('Potential miner'));
      expect(event.details, contains('Persistence indicator'));
      expect(event.details, contains('Review suggested x3'));
      expect(event.details, contains('Detected x3'));
      expect(event.details, contains('quarantined=0'));
      expect(event.details, isNot(contains('Quarantined')));
    }
  });

  test('scan events include auto-quarantine record evidence', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync(
      'zentor-quarantine-evidence-',
    );
    addTearDown(() => target.deleteSync(recursive: true));
    final threat = _threatResult(
      id: 'quarantined-eicar',
      fileName: 'safe-eicar.com',
      status: ThreatResultStatus.quarantined,
      quarantineId: 'record-eicar',
      quarantinePath: r'C:\ProgramData\Avorax\Quarantine\record-eicar.avoraxq',
      quarantineActionTaken: 'quarantined',
    );
    final localCore = _FakeLocalCoreClient(
      reports: [
        _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          actionMode: ScanActionMode.autoQuarantineConfirmedOnly,
          threats: [threat],
          quarantinedFiles: 1,
        ),
      ],
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.runQuickScan(
      actionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      confirmedAutoAction: true,
    );

    final state = container.read(zentorControllerProvider);
    final detectedEvent = state.events.firstWhere(
      (event) => event.type == 'threat_detected',
    );
    final completedEvent = state.events.firstWhere(
      (event) => event.type == 'scan_completed',
    );
    for (final event in [detectedEvent, completedEvent]) {
      expect(event.details, contains('quarantined=1'));
      expect(
        event.details,
        contains('quarantineRecords=record-eicar:quarantined'),
      );
    }
    final quarantinedEvent = state.events.firstWhere(
      (event) => event.type == 'file_quarantined',
    );
    expect(quarantinedEvent.details, contains('safe-eicar.com'));
    expect(quarantinedEvent.details, contains('quarantine_id=record-eicar'));
    expect(quarantinedEvent.details, contains('quarantine_path='));
    expect(quarantinedEvent.details, contains('.avoraxq'));
    expect(quarantinedEvent.details, contains('quarantine_action=quarantined'));
  });

  test('confirmed ignore threat updates current scan result only', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final threat = _threatResult();
    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      lastScanReport: _scanReport(
        ScanStatus.infected,
        ScanKind.quick,
        threats: [threat],
      ),
    );

    await controller.ignoreThreat(threat, confirmed: true);

    final state = container.read(zentorControllerProvider);
    expect(
      state.lastScanReport?.threats.single.status,
      ThreatResultStatus.ignored,
    );
    expect(state.events.map((event) => event.type), contains('threat_ignored'));
  });

  test('threat ignore blocks while configuration state is busy', () async {
    for (final testCase in const [
      (
        state: ZentorState(securitySettingsActionInFlight: true),
        message: 'Security settings change is in progress.',
      ),
      (
        state: ZentorState(configurationResetInFlight: true),
        message: 'Configuration reset is in progress.',
      ),
    ]) {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult();
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        securitySettingsActionInFlight:
            testCase.state.securitySettingsActionInFlight,
        configurationResetInFlight: testCase.state.configurationResetInFlight,
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
      );

      await controller.ignoreThreat(threat, confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(
        state.lastScanReport?.threats.single.status,
        ThreatResultStatus.detected,
      );
      expect(state.threatIgnoreActionInFlight, isFalse);
      expect(
        state.securitySettingsActionInFlight,
        testCase.state.securitySettingsActionInFlight,
      );
      expect(
        state.configurationResetInFlight,
        testCase.state.configurationResetInFlight,
      );
      expect(state.errorMessage, testCase.message);
      expect(
        state.events.map((event) => event.type),
        isNot(contains('threat_ignored')),
      );
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'threat_ignore_busy',
      );
      expect(busyEvent.category, 'scan');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, contains(threat.path));
      expect(busyEvent.details, contains(testCase.message));
    }
  });

  test('unconfirmed ignore threat leaves detection visible', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final threat = _threatResult();
    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      lastScanReport: _scanReport(
        ScanStatus.infected,
        ScanKind.quick,
        threats: [threat],
      ),
    );

    await controller.ignoreThreat(threat);

    final state = container.read(zentorControllerProvider);
    expect(
      state.lastScanReport?.threats.single.status,
      ThreatResultStatus.detected,
    );
    expect(state.errorMessage, contains('explicit confirmation'));
    expect(
      state.events.map((event) => event.type),
      contains('threat_ignore_confirmation_required'),
    );
  });

  test(
    'threat ignore blocks duplicate ignore while audit write is pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingThreatIgnored = Completer<LocalEvent>();
      final eventRepository = _PendingEventRepository(
        preferences,
        pendingType: 'threat_ignored',
        pendingEvent: pendingThreatIgnored,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localEventRepositoryProvider.overrideWithValue(eventRepository),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult();
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
      );

      final firstIgnore = controller.ignoreThreat(threat, confirmed: true);
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(zentorControllerProvider).threatIgnoreActionInFlight,
        isTrue,
      );
      await controller.ignoreThreat(threat, confirmed: true);

      var state = container.read(zentorControllerProvider);
      expect(eventRepository.callsFor('threat_ignored'), 1);
      expect(eventRepository.callsFor('threat_ignore_busy'), 1);
      expect(state.threatIgnoreActionInFlight, isTrue);
      expect(
        state.lastScanReport?.threats.single.status,
        ThreatResultStatus.detected,
      );
      expect(
        state.errorMessage,
        'Threat ignore action is already in progress.',
      );
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'threat_ignore_busy',
      );
      expect(busyEvent.category, 'scan');
      expect(busyEvent.severity, 'warning');

      pendingThreatIgnored.complete(
        LocalEvent(
          id: 'pending-threat-ignore',
          type: 'threat_ignored',
          message: 'Threat kept by user',
          createdAt: DateTime.now().toUtc(),
          details: threat.path,
          category: 'scan',
          severity: 'warning',
        ),
      );
      await firstIgnore;

      state = container.read(zentorControllerProvider);
      expect(eventRepository.callsFor('threat_ignored'), 1);
      expect(state.threatIgnoreActionInFlight, isFalse);
      expect(
        state.lastScanReport?.threats.single.status,
        ThreatResultStatus.ignored,
      );
    },
  );

  test(
    'quarantine restore exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final rawFailure =
          'restore IPC crashed\x00\n\t${'diagnostic detail ' * 260}';
      final localCore = _FakeLocalCoreClient(actionException: rawFailure);
      final record = _quarantineRecord();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(quarantine: [record]);
      await controller.restoreQuarantineItem(record, confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.restoreQuarantineCalls, 1);
      expect(state.quarantineActionInFlight, isFalse);
      expect(state.quarantine.single.status, QuarantineItemStatus.quarantined);
      expect(
        state.errorMessage,
        startsWith('Unable to restore ${record.originalPath}:'),
      );
      expect(state.errorMessage, contains('restore IPC crashed'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'quarantine_restore_failed',
      );
      expect(failedEvent.category, 'quarantine');
      expect(failedEvent.severity, 'error');
      expect(failedEvent.details, contains(record.originalPath));
      expect(failedEvent.details, contains('restore IPC crashed'));
      expect(failedEvent.details, isNot(contains('\x00')));
      expect(failedEvent.details, isNot(contains('\n\t')));
      expect(failedEvent.details!.length, lessThanOrEqualTo(2100));
    },
  );

  test('unconfirmed quarantine restore does not call local core', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient(
      quarantineRecords: [_quarantineRecord()],
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      quarantine: [_quarantineRecord()],
    );

    await controller.restoreQuarantineItem(_quarantineRecord());

    final state = container.read(zentorControllerProvider);
    expect(localCore.restoreQuarantineCalls, 0);
    expect(state.quarantine.single.status, QuarantineItemStatus.quarantined);
    expect(state.errorMessage, contains('explicit confirmation'));
    expect(
      state.events.map((event) => event.type),
      contains('quarantine_restore_confirmation_required'),
    );
  });

  test(
    'quarantine restore and delete confirmation paths are normalized and bounded',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final record = _quarantineRecord(
        originalPath:
            'C:\\fixtures\\unsafe\x00\n\t${List.filled(3000, 'x').join()}.exe',
      );
      final localCore = _FakeLocalCoreClient(quarantineRecords: [record]);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(quarantine: [record]);

      await controller.restoreQuarantineItem(record);
      await controller.deleteQuarantineItem(record);

      final state = container.read(zentorControllerProvider);
      final restoreEvent = state.events.firstWhere(
        (event) => event.type == 'quarantine_restore_confirmation_required',
      );
      final deleteEvent = state.events.firstWhere(
        (event) => event.type == 'quarantine_delete_confirmation_required',
      );

      expect(localCore.restoreQuarantineCalls, 0);
      expect(localCore.deleteQuarantineCalls, 0);
      for (final event in [restoreEvent, deleteEvent]) {
        expect(event.category, 'quarantine');
        expect(event.severity, 'warning');
        expect(event.details, isNotNull);
        expect(event.details, isNot(contains('\x00')));
        expect(event.details, isNot(contains('\n\t')));
        expect(event.details!.length, lessThanOrEqualTo(2250));
        expect(event.details, contains('...'));
      }
    },
  );

  test(
    'successful restore updates stale local quarantine row if refresh fails',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient(
        quarantineRecords: [_quarantineRecord()],
        listQuarantineFailure: 'quarantine list unavailable',
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        quarantine: [_quarantineRecord()],
      );

      await controller.restoreQuarantineItem(
        _quarantineRecord(),
        confirmed: true,
      );

      final state = container.read(zentorControllerProvider);
      expect(localCore.restoreQuarantineCalls, 1);
      expect(state.quarantine.single.status, QuarantineItemStatus.restored);
      expect(state.quarantine.single.actionTaken, 'restored');
      expect(state.errorMessage, contains('quarantine list unavailable'));
      expect(
        state.events.map((event) => event.type),
        contains('quarantine_refresh_failed'),
      );
    },
  );

  test(
    'confirmed quarantine lifecycle records restore and delete status events',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final restoredRecord = _quarantineRecord(quarantineId: 'q-restored');
      final deletedRecord = _quarantineRecord(
        quarantineId: 'q-deleted',
        originalPath: r'C:\fixtures\known-bad-copy.bin',
      );
      final localCore = _FakeLocalCoreClient(
        quarantineRecords: [restoredRecord, deletedRecord],
        listQuarantineFailure: 'quarantine refresh unavailable',
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        quarantine: [restoredRecord, deletedRecord],
      );

      await controller.restoreQuarantineItem(restoredRecord, confirmed: true);
      await controller.deleteQuarantineItem(deletedRecord, confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.restoreQuarantineCalls, 1);
      expect(localCore.deleteQuarantineCalls, 1);
      expect(state.quarantineActionInFlight, isFalse);
      expect(
        state.quarantine
            .singleWhere((record) => record.quarantineId == 'q-restored')
            .status,
        QuarantineItemStatus.restored,
      );
      expect(
        state.quarantine
            .singleWhere((record) => record.quarantineId == 'q-restored')
            .actionTaken,
        'restored',
      );
      expect(
        state.quarantine
            .singleWhere((record) => record.quarantineId == 'q-deleted')
            .status,
        QuarantineItemStatus.deleted,
      );
      expect(
        state.quarantine
            .singleWhere((record) => record.quarantineId == 'q-deleted')
            .actionTaken,
        'deleted',
      );
      final eventTypes = state.events.map((event) => event.type).toList();
      expect(eventTypes, contains('quarantine_restore_requested'));
      expect(eventTypes, contains('quarantine_item_restored'));
      expect(eventTypes, contains('quarantine_item_deleted'));
      expect(eventTypes, contains('quarantine_refresh_failed'));
      final restoreEvent = state.events.firstWhere(
        (event) => event.type == 'quarantine_item_restored',
      );
      final deleteEvent = state.events.firstWhere(
        (event) => event.type == 'quarantine_item_deleted',
      );
      for (final event in [restoreEvent, deleteEvent]) {
        expect(event.category, 'quarantine');
        expect(event.severity, 'warning');
      }
      expect(restoreEvent.details, restoredRecord.originalPath);
      expect(deleteEvent.details, deletedRecord.originalPath);
    },
  );

  test('restored quarantine original can be rescanned detect-only', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final original = File(
      '${Directory.systemTemp.createTempSync('zentor-rescan-').path}${Platform.pathSeparator}known-bad-copy.bin',
    );
    addTearDown(() => original.parent.deleteSync(recursive: true));
    original.writeAsBytesSync(const [1, 2, 3]);
    final record = _quarantineRecord(
      quarantineId: 'q-restored',
      originalPath: original.path,
      status: QuarantineItemStatus.restored,
      actionTaken: 'restored',
    );
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.rescanQuarantineOriginal(record);

    final state = container.read(zentorControllerProvider);
    expect(localCore.scanCalls, 1);
    expect(localCore.lastKind, ScanKind.custom);
    expect(localCore.lastActionMode, ScanActionMode.detectOnly);
    expect(localCore.lastScanFilePath, original.path);
    expect(state.scanStatus, ScanStatus.clean);
    expect(state.lastScanReport?.kind, ScanKind.custom);
    expect(state.lastScanReport?.actionMode, ScanActionMode.detectOnly);
    expect(
      state.events.map((event) => event.type),
      contains('quarantine_original_rescan_requested'),
    );
  });

  test('active quarantine payload rescan is refused without IPC', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final record = _quarantineRecord();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    await controller.rescanQuarantineOriginal(record);

    final state = container.read(zentorControllerProvider);
    expect(localCore.scanCalls, 0);
    expect(state.errorMessage, contains('Rescan is available after restore'));
    final event = state.events.firstWhere(
      (event) => event.type == 'quarantine_rescan_unavailable',
    );
    expect(event.category, 'quarantine');
    expect(event.severity, 'warning');
    expect(event.details, contains(record.originalPath));
  });

  test(
    'scan concurrency blocks quarantine original rescan during target selection',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final original = File(
        '${Directory.systemTemp.createTempSync('zentor-rescan-busy-').path}${Platform.pathSeparator}known-bad-copy.bin',
      );
      addTearDown(() => original.parent.deleteSync(recursive: true));
      original.writeAsBytesSync(const [1, 2, 3]);
      final record = _quarantineRecord(
        quarantineId: 'q-rescan-busy',
        originalPath: original.path,
        status: QuarantineItemStatus.restored,
        actionTaken: 'restored',
      );
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        scanTargetSelectionInFlight: true,
      );

      await controller.rescanQuarantineOriginal(record);

      final state = container.read(zentorControllerProvider);
      expect(localCore.scanCalls, 0);
      expect(
        state.errorMessage,
        'Scan target selection is already in progress.',
      );
      expect(
        state.events.map((event) => event.type),
        isNot(contains('quarantine_original_rescan_requested')),
      );
      final ignoredEvent = state.events.firstWhere(
        (event) => event.type == 'scan_start_ignored',
      );
      expect(ignoredEvent.category, 'scan');
      expect(ignoredEvent.severity, 'warning');
      expect(ignoredEvent.details, contains('Quarantine original rescan'));
      expect(
        ignoredEvent.details,
        contains('Scan target selection is already in progress.'),
      );
    },
  );

  test(
    'quarantine restore blocks overlapping delete while IPC is pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final record = _quarantineRecord();
      final pendingRestore = Completer<LocalCoreActionResult>();
      final localCore = _FakeLocalCoreClient(
        pendingRestoreQuarantine: pendingRestore,
        quarantineRecords: [record],
        listQuarantineFailure: 'quarantine refresh unavailable',
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(quarantine: [record]);

      final restoreAction = controller.restoreQuarantineItem(
        record,
        confirmed: true,
      );
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(zentorControllerProvider).quarantineActionInFlight,
        isTrue,
      );
      await controller.deleteQuarantineItem(record, confirmed: true);

      var state = container.read(zentorControllerProvider);
      expect(localCore.restoreQuarantineCalls, 1);
      expect(localCore.deleteQuarantineCalls, 0);
      expect(state.quarantineActionInFlight, isTrue);
      expect(state.errorMessage, 'A quarantine action is already in progress.');
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'quarantine_action_busy',
      );
      expect(busyEvent.category, 'quarantine');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, contains(record.originalPath));

      pendingRestore.complete(const LocalCoreActionResult.ok());
      await restoreAction;

      state = container.read(zentorControllerProvider);
      expect(localCore.restoreQuarantineCalls, 1);
      expect(localCore.deleteQuarantineCalls, 0);
      expect(state.quarantineActionInFlight, isFalse);
      expect(state.quarantine.single.status, QuarantineItemStatus.restored);
    },
  );

  test(
    'quarantine refresh exposes busy state and queues duplicate refresh',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final pendingRefresh = Completer<List<QuarantineRecord>>();
      final record = _quarantineRecord();
      localCore.pendingListQuarantine = pendingRefresh;
      final baselineCalls = localCore.listQuarantineCalls;

      final firstRefresh = controller.unawaitedRefreshQuarantine();
      await Future<void>.delayed(Duration.zero);

      var state = container.read(zentorControllerProvider);
      expect(state.quarantineRefreshInFlight, isTrue);
      expect(localCore.listQuarantineCalls, baselineCalls + 1);

      await controller.unawaitedRefreshQuarantine();
      await Future<void>.delayed(Duration.zero);

      state = container.read(zentorControllerProvider);
      expect(state.quarantineRefreshInFlight, isTrue);
      expect(localCore.listQuarantineCalls, baselineCalls + 1);

      pendingRefresh.complete([record]);
      await firstRefresh;

      state = container.read(zentorControllerProvider);
      expect(localCore.listQuarantineCalls, baselineCalls + 2);
      expect(state.quarantineRefreshInFlight, isFalse);
      expect(state.quarantine, [record]);
    },
  );

  test(
    'quarantine refresh failure diagnostics are normalized and bounded',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final failure =
          'quarantine refresh failed\x00\n\t${List.filled(3000, 'x').join()}';
      final localCore = _FakeLocalCoreClient(listQuarantineFailure: failure);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.unawaitedRefreshQuarantine();

      final state = container.read(zentorControllerProvider);
      final event = state.events.lastWhere(
        (event) => event.type == 'quarantine_refresh_failed',
      );
      expect(state.errorMessage, startsWith('Unable to refresh quarantine:'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      expect(event.details, isNotNull);
      expect(event.details, isNot(contains('\x00')));
      expect(event.details, isNot(contains('\n\t')));
      expect(event.details!.length, lessThanOrEqualTo(2100));
    },
  );

  test(
    'successful delete updates stale local quarantine row if refresh fails',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient(
        quarantineRecords: [_quarantineRecord()],
        listQuarantineFailure: 'quarantine list unavailable',
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        quarantine: [_quarantineRecord()],
      );

      await controller.deleteQuarantineItem(
        _quarantineRecord(),
        confirmed: true,
      );

      final state = container.read(zentorControllerProvider);
      expect(localCore.deleteQuarantineCalls, 1);
      expect(state.quarantine.single.status, QuarantineItemStatus.deleted);
      expect(state.quarantine.single.actionTaken, 'deleted');
      expect(state.errorMessage, contains('quarantine list unavailable'));
      expect(
        state.events.map((event) => event.type),
        contains('quarantine_refresh_failed'),
      );
    },
  );

  test(
    'quarantine delete exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final rawFailure =
          'delete IPC crashed\x00\n\t${'diagnostic detail ' * 260}';
      final localCore = _FakeLocalCoreClient(actionException: rawFailure);
      final record = _quarantineRecord();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(quarantine: [record]);

      await controller.deleteQuarantineItem(record, confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.deleteQuarantineCalls, 1);
      expect(state.quarantineActionInFlight, isFalse);
      expect(state.quarantine.single.status, QuarantineItemStatus.quarantined);
      expect(
        state.errorMessage,
        startsWith('Unable to delete ${record.originalPath}:'),
      );
      expect(state.errorMessage, contains('delete IPC crashed'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'quarantine_delete_failed',
      );
      expect(failedEvent.category, 'quarantine');
      expect(failedEvent.severity, 'error');
      expect(failedEvent.details, contains(record.originalPath));
      expect(failedEvent.details, contains('delete IPC crashed'));
      expect(failedEvent.details, isNot(contains('\x00')));
      expect(failedEvent.details, isNot(contains('\n\t')));
      expect(failedEvent.details!.length, lessThanOrEqualTo(2100));
    },
  );

  test('unconfirmed quarantine delete does not call local core', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient(
      quarantineRecords: [_quarantineRecord()],
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      quarantine: [_quarantineRecord()],
    );

    await controller.deleteQuarantineItem(_quarantineRecord());

    final state = container.read(zentorControllerProvider);
    expect(localCore.deleteQuarantineCalls, 0);
    expect(state.quarantine.single.status, QuarantineItemStatus.quarantined);
    expect(state.errorMessage, contains('explicit confirmation'));
    expect(
      state.events.map((event) => event.type),
      contains('quarantine_delete_confirmation_required'),
    );
  });

  test(
    'successful allowlist add updates threat state if refresh fails',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient(
        listAllowlistFailure: 'allowlist list unavailable',
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult();
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
      );

      await controller.addThreatToAllowlist(threat, confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.addAllowlistCalls, 1);
      expect(
        state.lastScanReport?.threats.single.status,
        ThreatResultStatus.allowlisted,
      );
      expect(state.errorMessage, contains('allowlist list unavailable'));
      expect(
        state.events.map((event) => event.type),
        contains('allowlist_refresh_failed'),
      );
    },
  );

  test(
    'allowlist add exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final rawFailure =
          'allowlist add denied\x00\n\t${'diagnostic detail ' * 260}';
      final localCore = _FakeLocalCoreClient(actionException: rawFailure);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult(recommendedAction: RecommendedAction.review);
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
      );

      await controller.addThreatToAllowlist(threat, confirmed: true);

      final updated = container
          .read(zentorControllerProvider)
          .lastScanReport
          ?.threats
          .single;
      final state = container.read(zentorControllerProvider);
      expect(localCore.addAllowlistCalls, 1);
      expect(state.allowlistActionInFlight, isFalse);
      expect(updated?.recommendedAction, RecommendedAction.review);
      expect(updated?.status, ThreatResultStatus.detected);
      expect(
        state.errorMessage,
        startsWith('Unable to allowlist ${threat.fileName}:'),
      );
      expect(state.errorMessage, contains('allowlist add denied'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'allowlist_entry_add_failed',
      );
      expect(failedEvent.category, 'protection');
      expect(failedEvent.severity, 'error');
      expect(failedEvent.details, contains(threat.path));
      expect(failedEvent.details, contains('allowlist add denied'));
      expect(failedEvent.details, isNot(contains('\x00')));
      expect(failedEvent.details, isNot(contains('\n\t')));
      expect(failedEvent.details!.length, lessThanOrEqualTo(2100));
    },
  );

  test('confirmed false-positive feedback updates threat state', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final threat = _threatResult();
    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      lastScanReport: _scanReport(
        ScanStatus.infected,
        ScanKind.quick,
        threats: [threat],
      ),
    );

    await controller.markThreatFalsePositive(threat, confirmed: true);

    final state = container.read(zentorControllerProvider);
    expect(localCore.labelDetectionCalls, 1);
    expect(
      state.lastScanReport?.threats.single.status,
      ThreatResultStatus.ignored,
    );
    expect(
      state.events.map((event) => event.type),
      contains('false_positive_label_saved'),
    );
    final savedEvent = state.events.lastWhere(
      (event) => event.type == 'false_positive_label_saved',
    );
    expect(savedEvent.category, 'protection');
    expect(savedEvent.severity, 'warning');
    expect(savedEvent.details, contains(threat.path));
    expect(savedEvent.details, contains('Feedback: false positive'));
    expect(savedEvent.details, contains('Current scan row: ignored by user'));
  });

  test(
    'unconfirmed false-positive feedback does not call local core',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult();
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
      );

      await controller.markThreatFalsePositive(threat);

      final state = container.read(zentorControllerProvider);
      expect(localCore.labelDetectionCalls, 0);
      expect(
        state.lastScanReport?.threats.single.status,
        ThreatResultStatus.detected,
      );
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('false_positive_label_confirmation_required'),
      );
    },
  );

  test(
    'false-positive feedback exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final rawFailure =
          'false-positive feedback denied\x00\n\t${'diagnostic detail ' * 260}';
      final localCore = _FakeLocalCoreClient(actionException: rawFailure);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult();
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
      );

      await controller.markThreatFalsePositive(threat, confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.labelDetectionCalls, 1);
      expect(state.detectionFeedbackInFlight, isFalse);
      expect(
        state.lastScanReport?.threats.single.status,
        ThreatResultStatus.detected,
      );
      expect(
        state.errorMessage,
        startsWith('Unable to save false-positive feedback:'),
      );
      expect(state.errorMessage, contains('false-positive feedback denied'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'false_positive_label_failed',
      );
      expect(failedEvent.category, 'protection');
      expect(failedEvent.severity, 'error');
      expect(failedEvent.details, contains(threat.path));
      expect(failedEvent.details, contains('false-positive feedback denied'));
      expect(failedEvent.details, isNot(contains('\x00')));
      expect(failedEvent.details, isNot(contains('\n\t')));
      expect(failedEvent.details!.length, lessThanOrEqualTo(2100));
    },
  );

  test('unconfirmed allowlist add does not call local core', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final threat = _threatResult();
    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      lastScanReport: _scanReport(
        ScanStatus.infected,
        ScanKind.quick,
        threats: [threat],
      ),
    );

    await controller.addThreatToAllowlist(threat);

    final state = container.read(zentorControllerProvider);
    expect(localCore.addAllowlistCalls, 0);
    expect(
      state.lastScanReport?.threats.single.status,
      ThreatResultStatus.detected,
    );
    expect(state.errorMessage, contains('explicit confirmation'));
    expect(
      state.events.map((event) => event.type),
      contains('allowlist_entry_add_confirmation_required'),
    );
  });

  test(
    'allowlist add blocks overlapping remove while IPC is pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingAdd = Completer<LocalCoreActionResult>();
      final existingEntry = _allowlistEntry();
      final localCore = _FakeLocalCoreClient(
        pendingAddAllowlist: pendingAdd,
        allowlistEntries: [existingEntry],
        listAllowlistFailure: 'allowlist refresh unavailable',
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult();
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
        allowlist: [existingEntry],
      );

      final addAction = controller.addThreatToAllowlist(
        threat,
        confirmed: true,
      );
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(zentorControllerProvider).allowlistActionInFlight,
        isTrue,
      );
      await controller.removeAllowlistEntry(existingEntry, confirmed: true);

      var state = container.read(zentorControllerProvider);
      expect(localCore.addAllowlistCalls, 1);
      expect(localCore.removeAllowlistCalls, 0);
      expect(state.allowlistActionInFlight, isTrue);
      expect(state.errorMessage, 'An allowlist action is already in progress.');
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'allowlist_action_busy',
      );
      expect(busyEvent.category, 'protection');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, contains(existingEntry.path));

      pendingAdd.complete(const LocalCoreActionResult.ok());
      await addAction;

      state = container.read(zentorControllerProvider);
      expect(localCore.addAllowlistCalls, 1);
      expect(localCore.removeAllowlistCalls, 0);
      expect(state.allowlistActionInFlight, isFalse);
      expect(
        state.lastScanReport?.threats.single.status,
        ThreatResultStatus.allowlisted,
      );
    },
  );

  test(
    'allowlist refresh exposes busy state and queues duplicate refresh',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final pendingRefresh = Completer<List<AllowlistEntry>>();
      final entry = _allowlistEntry();
      localCore.pendingListAllowlist = pendingRefresh;
      final baselineCalls = localCore.listAllowlistCalls;

      final firstRefresh = controller.unawaitedRefreshAllowlist();
      await Future<void>.delayed(Duration.zero);

      var state = container.read(zentorControllerProvider);
      expect(state.allowlistRefreshInFlight, isTrue);
      expect(localCore.listAllowlistCalls, baselineCalls + 1);

      await controller.unawaitedRefreshAllowlist();
      await Future<void>.delayed(Duration.zero);

      state = container.read(zentorControllerProvider);
      expect(state.allowlistRefreshInFlight, isTrue);
      expect(localCore.listAllowlistCalls, baselineCalls + 1);

      pendingRefresh.complete([entry]);
      await firstRefresh;

      state = container.read(zentorControllerProvider);
      expect(localCore.listAllowlistCalls, baselineCalls + 2);
      expect(state.allowlistRefreshInFlight, isFalse);
      expect(state.allowlist, [entry]);
    },
  );

  test(
    'allowlist refresh failure diagnostics are normalized and bounded',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final failure =
          'allowlist refresh failed\x00\n\t${List.filled(3000, 'y').join()}';
      final localCore = _FakeLocalCoreClient(listAllowlistFailure: failure);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      await controller.unawaitedRefreshAllowlist();

      final state = container.read(zentorControllerProvider);
      final event = state.events.lastWhere(
        (event) => event.type == 'allowlist_refresh_failed',
      );
      expect(state.errorMessage, startsWith('Unable to refresh allowlist:'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      expect(event.category, 'protection');
      expect(event.severity, 'error');
      expect(event.details, isNotNull);
      expect(event.details, isNot(contains('\x00')));
      expect(event.details, isNot(contains('\n\t')));
      expect(event.details!.length, lessThanOrEqualTo(2100));
    },
  );

  test(
    'successful allowlist remove deactivates stale local row if refresh fails',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final entry = _allowlistEntry();
      final localCore = _FakeLocalCoreClient(
        allowlistEntries: [entry],
        listAllowlistFailure: 'allowlist list unavailable',
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(allowlist: [entry]);

      await controller.removeAllowlistEntry(entry, confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.removeAllowlistCalls, 1);
      expect(state.allowlist.single.active, isFalse);
      expect(state.errorMessage, contains('allowlist list unavailable'));
      expect(
        state.events.map((event) => event.type),
        contains('allowlist_refresh_failed'),
      );
    },
  );

  test(
    'allowlist remove exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final entry = _allowlistEntry();
      final rawFailure =
          'allowlist remove denied\x00\n\t${'diagnostic detail ' * 260}';
      final localCore = _FakeLocalCoreClient(
        allowlistEntries: [entry],
        actionException: rawFailure,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(allowlist: [entry]);

      await controller.removeAllowlistEntry(entry, confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.removeAllowlistCalls, 1);
      expect(state.allowlistActionInFlight, isFalse);
      expect(state.allowlist.single.active, isTrue);
      expect(
        state.errorMessage,
        startsWith('Unable to remove allowlist entry:'),
      );
      expect(state.errorMessage, contains('allowlist remove denied'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'allowlist_entry_remove_failed',
      );
      expect(failedEvent.category, 'protection');
      expect(failedEvent.severity, 'error');
      expect(failedEvent.details, contains(entry.path));
      expect(failedEvent.details, contains('allowlist remove denied'));
      expect(failedEvent.details, isNot(contains('\x00')));
      expect(failedEvent.details, isNot(contains('\n\t')));
      expect(failedEvent.details!.length, lessThanOrEqualTo(2100));
    },
  );

  test('unconfirmed allowlist remove does not call local core', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final entry = _allowlistEntry();
    final localCore = _FakeLocalCoreClient(allowlistEntries: [entry]);

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(allowlist: [entry]);

    await controller.removeAllowlistEntry(entry);

    final state = container.read(zentorControllerProvider);
    expect(localCore.removeAllowlistCalls, 0);
    expect(state.allowlist.single.active, isTrue);
    expect(state.errorMessage, contains('explicit confirmation'));
    expect(
      state.events.map((event) => event.type),
      contains('allowlist_entry_remove_confirmation_required'),
    );
  });

  test(
    'successful malicious feedback leaves current recommendation unchanged',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult(recommendedAction: RecommendedAction.review);
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
      );

      await controller.markThreatMalicious(threat, confirmed: true);

      final updated = container
          .read(zentorControllerProvider)
          .lastScanReport
          ?.threats
          .single;
      final state = container.read(zentorControllerProvider);
      expect(localCore.labelDetectionCalls, 1);
      expect(updated?.recommendedAction, RecommendedAction.review);
      expect(updated?.status, ThreatResultStatus.detected);
      final savedEvent = state.events.lastWhere(
        (event) => event.type == 'malicious_label_saved',
      );
      expect(savedEvent.category, 'protection');
      expect(savedEvent.severity, 'warning');
      expect(savedEvent.details, contains(threat.path));
      expect(savedEvent.details, contains('Feedback: confirmed malicious'));
      expect(savedEvent.details, contains('Current scan row: unchanged'));
      expect(
        savedEvent.details,
        contains('no quarantine, delete, or execution'),
      );
    },
  );

  test(
    'malicious feedback exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final rawFailure =
          'malicious feedback denied\x00\n\t${'diagnostic detail ' * 260}';
      final localCore = _FakeLocalCoreClient(actionException: rawFailure);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult(recommendedAction: RecommendedAction.review);
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
      );

      await controller.markThreatMalicious(threat, confirmed: true);

      final updated = container
          .read(zentorControllerProvider)
          .lastScanReport
          ?.threats
          .single;
      final state = container.read(zentorControllerProvider);
      expect(localCore.labelDetectionCalls, 1);
      expect(state.detectionFeedbackInFlight, isFalse);
      expect(updated?.recommendedAction, RecommendedAction.review);
      expect(updated?.status, ThreatResultStatus.detected);
      expect(
        state.errorMessage,
        startsWith('Unable to save malicious feedback:'),
      );
      expect(state.errorMessage, contains('malicious feedback denied'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'malicious_label_failed',
      );
      expect(failedEvent.category, 'protection');
      expect(failedEvent.severity, 'error');
      expect(failedEvent.details, contains(threat.path));
      expect(failedEvent.details, contains('malicious feedback denied'));
      expect(failedEvent.details, isNot(contains('\x00')));
      expect(failedEvent.details, isNot(contains('\n\t')));
      expect(failedEvent.details!.length, lessThanOrEqualTo(2100));
    },
  );

  test(
    'duplicate detection feedback is blocked while label IPC is pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingLabel = Completer<LocalCoreActionResult>();
      final localCore = _FakeLocalCoreClient(
        pendingLabelDetection: pendingLabel,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult(recommendedAction: RecommendedAction.review);
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
      );

      final firstFeedback = controller.markThreatMalicious(
        threat,
        confirmed: true,
      );
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(zentorControllerProvider).detectionFeedbackInFlight,
        isTrue,
      );
      await controller.markThreatFalsePositive(threat, confirmed: true);

      var state = container.read(zentorControllerProvider);
      expect(localCore.labelDetectionCalls, 1);
      expect(state.detectionFeedbackInFlight, isTrue);
      expect(state.errorMessage, 'Detection feedback is already in progress.');
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'detection_feedback_busy',
      );
      expect(busyEvent.category, 'protection');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, contains(threat.path));

      pendingLabel.complete(const LocalCoreActionResult.ok());
      await firstFeedback;

      state = container.read(zentorControllerProvider);
      expect(localCore.labelDetectionCalls, 1);
      expect(state.detectionFeedbackInFlight, isFalse);
      expect(
        state.lastScanReport?.threats.single.recommendedAction,
        RecommendedAction.review,
      );
    },
  );

  test(
    'manual quarantine allowlist and feedback actions block while configuration state is busy',
    () async {
      for (final testCase in const [
        (
          state: ZentorState(securitySettingsActionInFlight: true),
          message: 'Security settings change is in progress.',
        ),
        (
          state: ZentorState(configurationResetInFlight: true),
          message: 'Configuration reset is in progress.',
        ),
      ]) {
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final record = _quarantineRecord();
        final entry = _allowlistEntry();
        final localCore = _FakeLocalCoreClient(
          quarantineRecords: [record],
          allowlistEntries: [entry],
        );

        final container = ProviderContainer(
          overrides: [
            sharedPreferencesProvider.overrideWithValue(preferences),
            localCoreClientProvider.overrideWithValue(localCore),
          ],
        );
        addTearDown(container.dispose);

        final threat = _threatResult(
          recommendedAction: RecommendedAction.review,
        );
        final controller = container.read(zentorControllerProvider.notifier);
        await _waitForControllerStartup(container);
        controller.state = controller.state.copyWith(
          securitySettingsActionInFlight:
              testCase.state.securitySettingsActionInFlight,
          configurationResetInFlight: testCase.state.configurationResetInFlight,
          lastScanReport: _scanReport(
            ScanStatus.infected,
            ScanKind.quick,
            threats: [threat],
          ),
          quarantine: [record],
          allowlist: [entry],
        );

        await controller.quarantineThreat(threat, confirmed: true);
        await controller.restoreQuarantineItem(record, confirmed: true);
        await controller.deleteQuarantineItem(record, confirmed: true);
        await controller.addThreatToAllowlist(threat, confirmed: true);
        await controller.removeAllowlistEntry(entry, confirmed: true);
        await controller.markThreatFalsePositive(threat, confirmed: true);
        await controller.markThreatMalicious(threat, confirmed: true);

        final state = container.read(zentorControllerProvider);
        expect(localCore.quarantineCalls, 0);
        expect(localCore.restoreQuarantineCalls, 0);
        expect(localCore.deleteQuarantineCalls, 0);
        expect(localCore.addAllowlistCalls, 0);
        expect(localCore.removeAllowlistCalls, 0);
        expect(localCore.labelDetectionCalls, 0);
        expect(
          state.securitySettingsActionInFlight,
          testCase.state.securitySettingsActionInFlight,
        );
        expect(
          state.configurationResetInFlight,
          testCase.state.configurationResetInFlight,
        );
        expect(state.errorMessage, testCase.message);

        final eventTypes = state.events.map((event) => event.type).toList();
        expect(
          eventTypes.where((type) => type == 'quarantine_action_busy'),
          hasLength(3),
        );
        expect(
          eventTypes.where((type) => type == 'allowlist_action_busy'),
          hasLength(2),
        );
        expect(
          eventTypes.where((type) => type == 'detection_feedback_busy'),
          hasLength(2),
        );
        for (final event in state.events.where(
          (event) =>
              event.type == 'quarantine_action_busy' ||
              event.type == 'allowlist_action_busy' ||
              event.type == 'detection_feedback_busy',
        )) {
          expect(event.severity, 'warning');
          expect(event.details, contains(testCase.message));
        }
      }
    },
  );

  test('manual trust actions block while update package work is busy', () async {
    for (final status in const [
      UpdateStatus.downloading,
      UpdateStatus.verifying,
      UpdateStatus.installing,
      UpdateStatus.rollingBack,
    ]) {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final record = _quarantineRecord();
      final entry = _allowlistEntry();
      final localCore = _FakeLocalCoreClient(
        quarantineRecords: [record],
        allowlistEntries: [entry],
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final threat = _threatResult(recommendedAction: RecommendedAction.review);
      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        updateStatus: status,
        lastScanReport: _scanReport(
          ScanStatus.infected,
          ScanKind.quick,
          threats: [threat],
        ),
        quarantine: [record],
        allowlist: [entry],
      );

      await controller.quarantineThreat(threat, confirmed: true);
      await controller.restoreQuarantineItem(record, confirmed: true);
      await controller.deleteQuarantineItem(record, confirmed: true);
      await controller.addThreatToAllowlist(threat, confirmed: true);
      await controller.removeAllowlistEntry(entry, confirmed: true);
      await controller.markThreatFalsePositive(threat, confirmed: true);
      await controller.markThreatMalicious(threat, confirmed: true);
      await controller.ignoreThreat(threat, confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(localCore.quarantineCalls, 0);
      expect(localCore.restoreQuarantineCalls, 0);
      expect(localCore.deleteQuarantineCalls, 0);
      expect(localCore.addAllowlistCalls, 0);
      expect(localCore.removeAllowlistCalls, 0);
      expect(localCore.labelDetectionCalls, 0);
      expect(state.quarantine.single.status, QuarantineItemStatus.quarantined);
      expect(state.allowlist.single.active, isTrue);
      expect(
        state.lastScanReport?.threats.single.status,
        ThreatResultStatus.detected,
      );
      expect(state.updateStatus, status);
      expect(
        state.errorMessage,
        'Threat ignore cannot run while update package work is in progress: ${status.label}.',
      );

      final eventTypes = state.events.map((event) => event.type).toList();
      expect(
        eventTypes.where((type) => type == 'quarantine_action_busy'),
        hasLength(3),
      );
      expect(
        eventTypes.where((type) => type == 'allowlist_action_busy'),
        hasLength(2),
      );
      expect(
        eventTypes.where((type) => type == 'detection_feedback_busy'),
        hasLength(2),
      );
      expect(
        eventTypes.where((type) => type == 'threat_ignore_busy'),
        hasLength(1),
      );
      for (final event in state.events.where(
        (event) =>
            event.type == 'quarantine_action_busy' ||
            event.type == 'allowlist_action_busy' ||
            event.type == 'detection_feedback_busy' ||
            event.type == 'threat_ignore_busy',
      )) {
        expect(event.severity, 'warning');
        expect(
          event.details,
          contains(
            'while update package work is in progress: ${status.label}.',
          ),
        );
      }
    }
  });

  test('unconfirmed malicious feedback does not call local core', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final threat = _threatResult(recommendedAction: RecommendedAction.review);
    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      lastScanReport: _scanReport(
        ScanStatus.infected,
        ScanKind.quick,
        threats: [threat],
      ),
    );

    await controller.markThreatMalicious(threat);

    final state = container.read(zentorControllerProvider);
    expect(localCore.labelDetectionCalls, 0);
    expect(
      state.lastScanReport?.threats.single.recommendedAction,
      RecommendedAction.review,
    );
    expect(state.errorMessage, contains('explicit confirmation'));
    expect(
      state.events.map((event) => event.type),
      contains('malicious_label_confirmation_required'),
    );
  });

  test(
    'scheduled quick scan settings save and log without starting a scan',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final saved = await controller.updateScheduledQuickScanSettings(
        enabled: true,
        intervalHours: 12,
        confirmed: true,
      );

      final state = container.read(zentorControllerProvider);
      expect(saved, isTrue);
      expect(state.config.scheduledQuickScanEnabled, isTrue);
      expect(state.config.scheduledQuickScanIntervalHours, 12);
      expect(localCore.scanCalls, 0);
      expect(
        state.events.map((event) => event.type),
        contains('scheduled_quick_scan_settings_changed'),
      );
      final settingsEvent = state.events.firstWhere(
        (event) => event.type == 'scheduled_quick_scan_settings_changed',
      );
      expect(settingsEvent.category, 'scan');
      expect(settingsEvent.severity, 'warning');
    },
  );

  test(
    'scheduled quick scan timer creation failures do not save schedule',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final timerFactory = _FailingScheduledTimerFactory();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          scheduledQuickScanTimerFactoryProvider.overrideWithValue(
            timerFactory.create,
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final saved = await controller.updateScheduledQuickScanSettings(
        enabled: true,
        intervalHours: 12,
        confirmed: true,
      );

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(timerFactory.calls, 1);
      expect(state.config.scheduledQuickScanEnabled, isFalse);
      expect(state.config.scheduledQuickScanIntervalHours, 24);
      expect(
        state.errorMessage,
        contains('Unable to save scheduled quick scan'),
      );
      expect(
        state.events.map((event) => event.type),
        contains('scheduled_quick_scan_settings_failed'),
      );
      expect(
        state.events.map((event) => event.type),
        isNot(contains('scheduled_quick_scan_settings_changed')),
      );
    },
  );

  test('scheduled quick scan timer fires detect-only scan', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync(
      'zentor-scheduled-scan-',
    );
    addTearDown(() => target.deleteSync(recursive: true));
    final localCore = _FakeLocalCoreClient();
    final timerFactory = _ManualScheduledTimerFactory();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
        scheduledQuickScanTimerFactoryProvider.overrideWithValue(
          timerFactory.create,
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    final saved = await controller.updateScheduledQuickScanSettings(
      enabled: true,
      intervalHours: 1,
      confirmed: true,
    );
    expect(saved, isTrue);
    expect(localCore.scanCalls, 0);
    expect(timerFactory.timer?.duration, const Duration(hours: 1));

    timerFactory.timer?.fire();
    for (var attempt = 0; attempt < 10 && localCore.scanCalls == 0; attempt++) {
      await Future<void>.delayed(Duration.zero);
    }

    final state = container.read(zentorControllerProvider);
    expect(localCore.scanCalls, 1);
    expect(localCore.lastKind, ScanKind.quick);
    expect(localCore.lastActionMode, ScanActionMode.detectOnly);
    expect(state.scanStatus, ScanStatus.clean);
    expect(
      state.events.map((event) => event.type),
      contains('scheduled_quick_scan_started'),
    );
    final startedEvent = state.events.firstWhere(
      (event) => event.type == 'scheduled_quick_scan_started',
    );
    expect(startedEvent.category, 'scan');
    expect(startedEvent.severity, 'info');
  });

  test('scheduled quick scan skips while target selection is active', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync(
      'zentor-scheduled-scan-selection-',
    );
    addTearDown(() => target.deleteSync(recursive: true));
    final localCore = _FakeLocalCoreClient();
    final timerFactory = _ManualScheduledTimerFactory();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
        scheduledQuickScanTimerFactoryProvider.overrideWithValue(
          timerFactory.create,
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    final saved = await controller.updateScheduledQuickScanSettings(
      enabled: true,
      intervalHours: 1,
      confirmed: true,
    );
    expect(saved, isTrue);
    controller.state = controller.state.copyWith(
      scanTargetSelectionInFlight: true,
    );

    timerFactory.timer?.fire();
    await Future<void>.delayed(Duration.zero);

    final state = container.read(zentorControllerProvider);
    expect(localCore.scanCalls, 0);
    expect(
      state.events.map((event) => event.type),
      contains('scheduled_quick_scan_skipped'),
    );
    expect(
      state.events.map((event) => event.type),
      isNot(contains('scheduled_quick_scan_started')),
    );
    final skippedEvent = state.events.firstWhere(
      (event) => event.type == 'scheduled_quick_scan_skipped',
    );
    expect(skippedEvent.category, 'scan');
    expect(skippedEvent.severity, 'warning');
    expect(
      skippedEvent.details,
      'Scan target selection is already in progress.',
    );
  });

  test(
    'scheduled quick scan skips while update package work is busy',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'zentor-scheduled-scan-update-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final localCore = _FakeLocalCoreClient();
      final timerFactory = _ManualScheduledTimerFactory();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          scanTargetServiceProvider.overrideWithValue(
            _FakeScanTargetService([target.path]),
          ),
          scheduledQuickScanTimerFactoryProvider.overrideWithValue(
            timerFactory.create,
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final saved = await controller.updateScheduledQuickScanSettings(
        enabled: true,
        intervalHours: 1,
        confirmed: true,
      );
      expect(saved, isTrue);
      controller.state = controller.state.copyWith(
        updateStatus: UpdateStatus.installing,
      );

      timerFactory.timer?.fire();
      await Future<void>.delayed(Duration.zero);

      final state = container.read(zentorControllerProvider);
      expect(localCore.scanCalls, 0);
      expect(
        state.events.map((event) => event.type),
        contains('scheduled_quick_scan_skipped'),
      );
      expect(
        state.events.map((event) => event.type),
        isNot(contains('scheduled_quick_scan_started')),
      );
      final skippedEvent = state.events.firstWhere(
        (event) => event.type == 'scheduled_quick_scan_skipped',
      );
      expect(skippedEvent.category, 'scan');
      expect(skippedEvent.severity, 'warning');
      expect(skippedEvent.details, contains('update package work'));
      expect(skippedEvent.details, contains(UpdateStatus.installing.label));
    },
  );

  test(
    'scheduled scan self-test and heartbeat events carry runtime metadata',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();
      final apiClient = _FakeApiClient(
        heartbeatResults: [
          const ApiSuccess<void>(null),
          const ApiFailure<void>('heartbeat fixture failure'),
        ],
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          apiClientProvider.overrideWithValue(apiClient),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        protectionRun: ProtectionRun(
          protectionRunId: 'run_fixture',
          startedAt: DateTime.utc(2026, 1, 1),
        ),
      );

      await controller.runProtectionSelfTest();
      await controller.sendHeartbeat();
      await controller.sendHeartbeat();

      final state = container.read(zentorControllerProvider);
      expect(localCore.protectionSelfTestCalls, 1);
      expect(apiClient.heartbeatCalls, 2);
      final selfTestStarted = state.events.firstWhere(
        (event) => event.type == 'protection_self_test_started',
      );
      final heartbeatSent = state.events.firstWhere(
        (event) => event.type == 'heartbeat_sent',
      );
      final heartbeatFailed = state.events.firstWhere(
        (event) => event.type == 'heartbeat_failed',
      );

      expect(selfTestStarted.category, 'protection');
      expect(selfTestStarted.severity, 'info');
      expect(heartbeatSent.category, 'protection');
      expect(heartbeatSent.severity, 'info');
      expect(heartbeatFailed.category, 'protection');
      expect(heartbeatFailed.severity, 'warning');
      expect(state.heartbeat.lastError, 'heartbeat fixture failure');
    },
  );

  test(
    'cloud health exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final rawFailure =
          'cloud health denied\x00\n\t${'diagnostic detail ' * 260}';
      final apiClient = _FakeApiClient(healthException: rawFailure);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          apiClientProvider.overrideWithValue(apiClient),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      await controller.testCloudConnection();

      final state = container.read(zentorControllerProvider);
      expect(apiClient.healthCalls, 1);
      expect(state.cloudHealthCheckInFlight, isFalse);
      expect(state.cloudStatus, CloudStatus.offline);
      expect(state.errorMessage, startsWith('Unable to check Avorax Cloud:'));
      expect(state.errorMessage, contains('cloud health denied'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      final offlineEvent = state.events.lastWhere(
        (event) => event.type == 'cloud_offline',
      );
      expect(offlineEvent.category, 'settings');
      expect(offlineEvent.severity, 'warning');
      expect(offlineEvent.details, contains('cloud health denied'));
      expect(offlineEvent.details, isNot(contains('\x00')));
      expect(offlineEvent.details, isNot(contains('\n\t')));
      expect(offlineEvent.details!.length, lessThanOrEqualTo(2048));
    },
  );

  test(
    'unconfirmed scheduled quick scan settings preserve current schedule',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final saved = await controller.updateScheduledQuickScanSettings(
        enabled: true,
        intervalHours: 12,
      );

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(state.config.scheduledQuickScanEnabled, isFalse);
      expect(state.config.scheduledQuickScanIntervalHours, 24);
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('scheduled_quick_scan_confirmation_required'),
      );
    },
  );

  test('invalid scheduled quick scan interval is rejected visibly', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    await controller.updateScheduledQuickScanSettings(
      enabled: true,
      intervalHours: 0,
    );

    final state = container.read(zentorControllerProvider);
    expect(state.config.scheduledQuickScanEnabled, isFalse);
    expect(state.errorMessage, contains('between 1 and 168 hours'));
    expect(
      state.events.map((event) => event.type),
      contains('scheduled_quick_scan_settings_failed'),
    );
  });

  test('unconfirmed configuration reset preserves current settings', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      config: controller.state.config.copyWith(
        developerOverrideEnabled: true,
        scheduledQuickScanEnabled: true,
      ),
    );

    final reset = await controller.resetConfiguration();

    final state = container.read(zentorControllerProvider);
    expect(reset, isFalse);
    expect(state.config.developerOverrideEnabled, isTrue);
    expect(state.config.scheduledQuickScanEnabled, isTrue);
    expect(state.errorMessage, contains('explicit confirmation'));
    expect(
      state.events.map((event) => event.type),
      contains('configuration_reset_confirmation_required'),
    );
  });

  test(
    'configuration reset blocks duplicate reset while protection stop is pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingGuardMode = Completer<LocalCoreActionResult>();
      final localCore = _FakeLocalCoreClient(
        pendingGuardMode: pendingGuardMode,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          realtimeProtectionEnabled: true,
          developerOverrideEnabled: true,
          scheduledQuickScanEnabled: true,
        ),
        protectionStatus: ProtectionStatus.protected,
        realtimeWatcherMode: 'recursive',
        realtimeWatchedPaths: const [r'C:\Users\Brent\Documents'],
      );

      final firstReset = controller.resetConfiguration(confirmed: true);
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(zentorControllerProvider).configurationResetInFlight,
        isTrue,
      );
      final duplicateReset = await controller.resetConfiguration(
        confirmed: true,
      );

      var state = container.read(zentorControllerProvider);
      expect(duplicateReset, isFalse);
      expect(localCore.guardModeCalls, 1);
      expect(localCore.stopWatchCalls, 0);
      expect(state.configurationResetInFlight, isTrue);
      expect(state.config.developerOverrideEnabled, isTrue);
      expect(state.config.scheduledQuickScanEnabled, isTrue);
      expect(state.errorMessage, 'Configuration reset is already in progress.');
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'configuration_reset_busy',
      );
      expect(busyEvent.category, 'settings');
      expect(busyEvent.severity, 'warning');

      pendingGuardMode.complete(const LocalCoreActionResult.ok());
      expect(await firstReset, isTrue);

      state = container.read(zentorControllerProvider);
      expect(localCore.guardModeCalls, 1);
      expect(localCore.stopWatchCalls, 1);
      expect(state.configurationResetInFlight, isFalse);
      expect(state.config.developerOverrideEnabled, isFalse);
      expect(state.config.scheduledQuickScanEnabled, isFalse);
      expect(state.protectionStatus, ProtectionStatus.idle);
      expect(
        state.events.map((event) => event.type),
        contains('configuration_reset'),
      );
    },
  );

  test(
    'configuration reset blocks while protection operation or self-test is busy',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final configRepository = _FailingResetConfigRepository(
        preferences,
        resetFailure: 'reset should not run',
      );
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          configRepositoryProvider.overrideWithValue(configRepository),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          developerOverrideEnabled: true,
          scheduledQuickScanEnabled: true,
        ),
        protectionOperationInFlight: true,
      );

      final operationBusyReset = await controller.resetConfiguration(
        confirmed: true,
      );

      var state = container.read(zentorControllerProvider);
      expect(operationBusyReset, isFalse);
      expect(configRepository.resetCalls, 0);
      expect(localCore.guardModeCalls, 0);
      expect(localCore.stopWatchCalls, 0);
      expect(state.configurationResetInFlight, isFalse);
      expect(state.protectionOperationInFlight, isTrue);
      expect(state.config.developerOverrideEnabled, isTrue);
      expect(state.config.scheduledQuickScanEnabled, isTrue);

      controller.state = state.copyWith(
        protectionOperationInFlight: false,
        protectionSelfTestInFlight: true,
      );
      final selfTestBusyReset = await controller.resetConfiguration(
        confirmed: true,
      );

      state = container.read(zentorControllerProvider);
      expect(selfTestBusyReset, isFalse);
      expect(configRepository.resetCalls, 0);
      expect(localCore.guardModeCalls, 0);
      expect(localCore.stopWatchCalls, 0);
      expect(state.configurationResetInFlight, isFalse);
      expect(state.protectionSelfTestInFlight, isTrue);
      expect(state.config.developerOverrideEnabled, isTrue);
      expect(state.config.scheduledQuickScanEnabled, isTrue);
      expect(
        state.errorMessage,
        'Configuration reset cannot run while protection state is changing or self-test is running.',
      );
      final busyEvents = state.events
          .where((event) => event.type == 'configuration_reset_busy')
          .toList();
      expect(busyEvents, hasLength(2));
      for (final event in busyEvents) {
        expect(event.category, 'settings');
        expect(event.severity, 'warning');
        expect(
          event.details,
          'Configuration reset cannot run while protection state is changing or self-test is running.',
        );
      }
    },
  );

  test(
    'configuration reset blocks while security settings or manual actions are busy',
    () async {
      for (final testCase in const [
        (
          state: ZentorState(securitySettingsActionInFlight: true),
          message:
              'Configuration reset cannot run while a security settings change is in progress.',
        ),
        (
          state: ZentorState(quarantineActionInFlight: true),
          message:
              'Configuration reset cannot run while a quarantine action is in progress.',
        ),
        (
          state: ZentorState(allowlistActionInFlight: true),
          message:
              'Configuration reset cannot run while an allowlist action is in progress.',
        ),
        (
          state: ZentorState(detectionFeedbackInFlight: true),
          message:
              'Configuration reset cannot run while detection feedback is in progress.',
        ),
      ]) {
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final configRepository = _FailingResetConfigRepository(
          preferences,
          resetFailure: 'reset should not run',
        );
        final localCore = _FakeLocalCoreClient();

        final container = ProviderContainer(
          overrides: [
            sharedPreferencesProvider.overrideWithValue(preferences),
            configRepositoryProvider.overrideWithValue(configRepository),
            localCoreClientProvider.overrideWithValue(localCore),
          ],
        );
        addTearDown(container.dispose);

        final controller = container.read(zentorControllerProvider.notifier);
        await _waitForControllerStartup(container);
        controller.state = controller.state.copyWith(
          config: controller.state.config.copyWith(
            developerOverrideEnabled: true,
            scheduledQuickScanEnabled: true,
          ),
          securitySettingsActionInFlight:
              testCase.state.securitySettingsActionInFlight,
          quarantineActionInFlight: testCase.state.quarantineActionInFlight,
          allowlistActionInFlight: testCase.state.allowlistActionInFlight,
          detectionFeedbackInFlight: testCase.state.detectionFeedbackInFlight,
        );

        final reset = await controller.resetConfiguration(confirmed: true);

        final state = container.read(zentorControllerProvider);
        expect(reset, isFalse);
        expect(configRepository.resetCalls, 0);
        expect(localCore.guardModeCalls, 0);
        expect(localCore.stopWatchCalls, 0);
        expect(state.configurationResetInFlight, isFalse);
        expect(state.config.developerOverrideEnabled, isTrue);
        expect(state.config.scheduledQuickScanEnabled, isTrue);
        expect(state.errorMessage, testCase.message);
        final busyEvent = state.events.firstWhere(
          (event) => event.type == 'configuration_reset_busy',
        );
        expect(busyEvent.category, 'settings');
        expect(busyEvent.severity, 'warning');
        expect(busyEvent.details, testCase.message);
      }
    },
  );

  test('configuration reset blocks while scan work is busy', () async {
    for (final testCase in const [
      (
        state: ZentorState(scanStartInFlight: true),
        message: 'Configuration reset cannot run while a scan is starting.',
      ),
      (
        state: ZentorState(scanStatus: ScanStatus.running),
        message: 'Configuration reset cannot run while a scan is running.',
      ),
      (
        state: ZentorState(scanTargetSelectionInFlight: true),
        message:
            'Configuration reset cannot run while scan target selection is in progress.',
      ),
      (
        state: ZentorState(scanCancelInFlight: true),
        message:
            'Configuration reset cannot run while scan cancellation is in progress.',
      ),
    ]) {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final configRepository = _FailingResetConfigRepository(
        preferences,
        resetFailure: 'reset should not run',
      );
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          configRepositoryProvider.overrideWithValue(configRepository),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          developerOverrideEnabled: true,
          scheduledQuickScanEnabled: true,
        ),
        scanStartInFlight: testCase.state.scanStartInFlight,
        scanStatus: testCase.state.scanStatus,
        scanTargetSelectionInFlight: testCase.state.scanTargetSelectionInFlight,
        scanCancelInFlight: testCase.state.scanCancelInFlight,
      );

      final reset = await controller.resetConfiguration(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(reset, isFalse);
      expect(configRepository.resetCalls, 0);
      expect(localCore.guardModeCalls, 0);
      expect(localCore.stopWatchCalls, 0);
      expect(state.configurationResetInFlight, isFalse);
      expect(state.config.developerOverrideEnabled, isTrue);
      expect(state.config.scheduledQuickScanEnabled, isTrue);
      expect(state.scanStartInFlight, testCase.state.scanStartInFlight);
      expect(state.scanStatus, testCase.state.scanStatus);
      expect(
        state.scanTargetSelectionInFlight,
        testCase.state.scanTargetSelectionInFlight,
      );
      expect(state.scanCancelInFlight, testCase.state.scanCancelInFlight);
      expect(state.errorMessage, testCase.message);
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'configuration_reset_busy',
      );
      expect(busyEvent.category, 'settings');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, testCase.message);
    }
  });

  test('configuration reset blocks while update package work is busy', () async {
    final busyUpdateStatuses = [
      UpdateStatus.downloading,
      UpdateStatus.verifying,
      UpdateStatus.installing,
      UpdateStatus.rollingBack,
    ];

    for (final status in busyUpdateStatuses) {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final configRepository = _FailingResetConfigRepository(
        preferences,
        resetFailure: 'reset should not run',
      );
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          configRepositoryProvider.overrideWithValue(configRepository),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          developerOverrideEnabled: true,
          scheduledQuickScanEnabled: true,
        ),
        updateStatus: status,
      );

      final reset = await controller.resetConfiguration(confirmed: true);

      final state = container.read(zentorControllerProvider);
      final message =
          'Configuration reset cannot run while update package work is in progress: ${status.label}.';
      expect(reset, isFalse);
      expect(configRepository.resetCalls, 0);
      expect(localCore.guardModeCalls, 0);
      expect(localCore.stopWatchCalls, 0);
      expect(state.configurationResetInFlight, isFalse);
      expect(state.config.developerOverrideEnabled, isTrue);
      expect(state.config.scheduledQuickScanEnabled, isTrue);
      expect(state.errorMessage, message);
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'configuration_reset_busy',
      );
      expect(busyEvent.category, 'settings');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, message);
    }
  });

  test('source marker: configuration reset blocks protection busy states', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final reset = appState.substring(
      appState.indexOf('Future<bool> resetConfiguration'),
      appState.indexOf('bool _configurationResetRequiresProtectionStop'),
    );

    expect(reset, contains('_protectionOperationInFlight ||'));
    expect(reset, contains('state.protectionOperationInFlight ||'));
    expect(reset, contains('_protectionSelfTestInFlight ||'));
    expect(reset, contains('state.protectionSelfTestInFlight'));
    expect(reset, contains('_securitySettingsActionInFlight ||'));
    expect(reset, contains('state.securitySettingsActionInFlight'));
    expect(reset, contains('_manualDispositionBusyReason('));
    expect(reset, contains('_configurationMutationUpdateBusyReason('));
    expect(reset, contains("'Configuration reset cannot run'"));
    expect(
      reset,
      contains(
        'Configuration reset cannot run while protection state is changing or self-test is running.',
      ),
    );
    expect(
      reset,
      contains(
        'Configuration reset cannot run while a security settings change is in progress.',
      ),
    );
    expect(
      reset.indexOf('state.protectionSelfTestInFlight'),
      lessThan(reset.indexOf('_configurationResetInFlight = true;')),
    );
    expect(
      reset.indexOf('state.securitySettingsActionInFlight'),
      lessThan(reset.indexOf('_configurationResetInFlight = true;')),
    );
    expect(
      reset.indexOf('_configurationMutationUpdateBusyReason('),
      lessThan(reset.indexOf('_configurationResetInFlight = true;')),
    );
  });

  test(
    'configuration reset exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final rawFailure =
          'configuration reset denied\x00\n\t${'diagnostic detail ' * 260}';
      final configRepository = _FailingResetConfigRepository(
        preferences,
        resetFailure: rawFailure,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          configRepositoryProvider.overrideWithValue(configRepository),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          developerOverrideEnabled: true,
          scheduledQuickScanEnabled: true,
        ),
      );

      final reset = await controller.resetConfiguration(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(reset, isFalse);
      expect(configRepository.resetCalls, 1);
      expect(state.configurationResetInFlight, isFalse);
      expect(state.config.developerOverrideEnabled, isTrue);
      expect(state.config.scheduledQuickScanEnabled, isTrue);
      expect(state.errorMessage, startsWith('Unable to reset configuration:'));
      expect(state.errorMessage, contains('configuration reset denied'));
      expect(state.errorMessage, isNot(contains('\x00')));
      expect(state.errorMessage, isNot(contains('\n\t')));
      expect(state.errorMessage!.length, lessThanOrEqualTo(2200));
      final failedEvent = state.events.lastWhere(
        (event) => event.type == 'configuration_reset_failed',
      );
      expect(failedEvent.category, 'settings');
      expect(failedEvent.severity, 'error');
      expect(failedEvent.details, contains('configuration reset denied'));
      expect(failedEvent.details, isNot(contains('\x00')));
      expect(failedEvent.details, isNot(contains('\n\t')));
      expect(failedEvent.details!.length, lessThanOrEqualTo(2048));
    },
  );

  test(
    'onboarding completion blocks duplicate saves while persistence is pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingSave = Completer<void>();
      final configRepository = _PendingSaveConfigRepository(
        preferences,
        pendingSave: pendingSave,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          configRepositoryProvider.overrideWithValue(configRepository),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final firstCompletion = controller.completeOnboarding();
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(zentorControllerProvider).onboardingCompletionInFlight,
        isTrue,
      );
      final duplicateCompletion = await controller.completeOnboarding();

      var state = container.read(zentorControllerProvider);
      expect(duplicateCompletion, isFalse);
      expect(configRepository.saveCalls, 1);
      expect(state.onboardingCompletionInFlight, isTrue);
      expect(state.config.onboardingComplete, isFalse);
      expect(
        state.errorMessage,
        'Onboarding completion is already in progress.',
      );
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'onboarding_completion_busy',
      );
      expect(busyEvent.category, 'app');
      expect(busyEvent.severity, 'warning');

      pendingSave.complete();
      expect(await firstCompletion, isTrue);

      state = container.read(zentorControllerProvider);
      expect(configRepository.saveCalls, 1);
      expect(configRepository.savedConfig?.onboardingComplete, isTrue);
      expect(state.onboardingCompletionInFlight, isFalse);
      expect(state.config.onboardingComplete, isTrue);
      expect(state.errorMessage, isNull);
    },
  );

  test(
    'unconfirmed developer cloud override preserves current settings',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      final originalConfig = container.read(zentorControllerProvider).config;

      final saved = await controller.saveDeveloperCloudOverride(
        enabled: true,
        apiBaseUrl: 'https://dev.example.test',
        projectId: 'project',
        publicClientKey: 'public',
      );

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(
        state.config.developerOverrideEnabled,
        originalConfig.developerOverrideEnabled,
      );
      expect(state.config.apiBaseUrl, originalConfig.apiBaseUrl);
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('developer_cloud_override_confirmation_required'),
      );
    },
  );

  test(
    'developer cloud override blocks duplicate saves while health check is pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingHealth = Completer<ApiResult<void>>();
      final apiClient = _FakeApiClient(pendingHealth: pendingHealth);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          apiClientProvider.overrideWithValue(apiClient),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final firstSave = controller.saveDeveloperCloudOverride(
        enabled: true,
        apiBaseUrl: 'https://dev.example.test',
        projectId: 'project',
        publicClientKey: 'public',
        confirmed: true,
      );
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(zentorControllerProvider).developerCloudOverrideInFlight,
        isTrue,
      );
      final duplicateSave = await controller.saveDeveloperCloudOverride(
        enabled: false,
        apiBaseUrl: '',
        projectId: '',
        publicClientKey: '',
        confirmed: true,
      );

      var state = container.read(zentorControllerProvider);
      expect(duplicateSave, isFalse);
      expect(apiClient.healthCalls, 1);
      expect(state.developerCloudOverrideInFlight, isTrue);
      expect(state.config.developerOverrideEnabled, isTrue);
      expect(state.config.apiBaseUrl, 'https://dev.example.test');
      expect(
        state.errorMessage,
        'Developer cloud override change is already in progress.',
      );
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'developer_cloud_override_busy',
      );
      expect(busyEvent.category, 'settings');
      expect(busyEvent.severity, 'warning');

      pendingHealth.complete(const ApiSuccess<void>(null));
      expect(await firstSave, isTrue);

      state = container.read(zentorControllerProvider);
      expect(apiClient.healthCalls, 1);
      expect(state.developerCloudOverrideInFlight, isFalse);
      expect(state.config.developerOverrideEnabled, isTrue);
      expect(state.cloudStatus, CloudStatus.online);
    },
  );

  test(
    'developer cloud override blocks while update package work is busy',
    () async {
      for (final status in const [
        UpdateStatus.downloading,
        UpdateStatus.verifying,
        UpdateStatus.installing,
        UpdateStatus.rollingBack,
      ]) {
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final apiClient = _FakeApiClient();

        final container = ProviderContainer(
          overrides: [
            sharedPreferencesProvider.overrideWithValue(preferences),
            localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
            apiClientProvider.overrideWithValue(apiClient),
          ],
        );
        addTearDown(container.dispose);

        final controller = container.read(zentorControllerProvider.notifier);
        await _waitForControllerStartup(container);
        final originalConfig = controller.state.config;
        controller.state = controller.state.copyWith(updateStatus: status);

        final enabledSaved = await controller.saveDeveloperCloudOverride(
          enabled: true,
          apiBaseUrl: 'https://dev.example.test',
          projectId: 'project',
          publicClientKey: 'public',
          confirmed: true,
        );
        final disabledSaved = await controller.saveDeveloperCloudOverride(
          enabled: false,
          apiBaseUrl: '',
          projectId: '',
          publicClientKey: '',
          confirmed: true,
        );

        final state = container.read(zentorControllerProvider);
        expect(enabledSaved, isFalse);
        expect(disabledSaved, isFalse);
        expect(apiClient.healthCalls, 0);
        expect(state.updateStatus, status);
        expect(state.developerCloudOverrideInFlight, isFalse);
        expect(
          state.config.developerOverrideEnabled,
          originalConfig.developerOverrideEnabled,
        );
        expect(state.config.apiBaseUrl, originalConfig.apiBaseUrl);
        expect(state.config.projectId, originalConfig.projectId);
        expect(state.config.publicClientKey, originalConfig.publicClientKey);
        expect(
          state.errorMessage,
          'Developer cloud override cannot change while update package work is in progress: ${status.label}.',
        );

        final busyEvents = state.events
            .where((event) => event.type == 'developer_cloud_override_busy')
            .toList();
        expect(busyEvents, hasLength(2));
        for (final event in busyEvents) {
          expect(event.category, 'settings');
          expect(event.severity, 'warning');
          expect(event.details, contains('update package work'));
          expect(event.details, contains(status.label));
        }
      }
    },
  );

  test('invalid developer cloud override is rejected before save', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final apiClient = _FakeApiClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        apiClientProvider.overrideWithValue(apiClient),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    final originalConfig = container.read(zentorControllerProvider).config;
    final healthCallsBefore = apiClient.healthCalls;

    final saved = await controller.saveDeveloperCloudOverride(
      enabled: true,
      apiBaseUrl: 'ftp://dev.example.test',
      projectId: '',
      publicClientKey: 'public',
      confirmed: true,
    );

    final state = container.read(zentorControllerProvider);
    expect(saved, isFalse);
    expect(
      state.config.developerOverrideEnabled,
      originalConfig.developerOverrideEnabled,
    );
    expect(state.config.apiBaseUrl, originalConfig.apiBaseUrl);
    expect(state.config.projectId, originalConfig.projectId);
    expect(state.config.publicClientKey, originalConfig.publicClientKey);
    expect(apiClient.healthCalls, healthCallsBefore);
    expect(state.developerCloudOverrideInFlight, isFalse);
    expect(state.errorMessage, contains('Developer cloud override is invalid'));
    final failedEvent = state.events.firstWhere(
      (event) => event.type == 'configuration_save_failed',
    );
    expect(failedEvent.category, 'settings');
    expect(failedEvent.severity, 'error');
    expect(
      failedEvent.details,
      contains('Developer cloud override is invalid'),
    );
  });

  test(
    'unconfirmed ransomware guard settings preserve current policy',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          ransomwareProtectedRoots: const [r'C:\Users\Brent\Documents'],
          ransomwareTrustedProcesses: const [
            r'C:\Program Files\Backup\safe.exe',
          ],
        ),
      );

      final saved = await controller.updateRansomwareGuardSettings(
        protectedRoots: const [r'C:\Users\Brent\Downloads'],
        trustedProcesses: const [r'C:\Temp\unknown.exe'],
      );

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(
        state.config.ransomwareProtectedRoots,
        contains(r'C:\Users\Brent\Documents'),
      );
      expect(
        state.config.ransomwareTrustedProcesses,
        contains(r'C:\Program Files\Backup\safe.exe'),
      );
      expect(localCore.ransomwareGuardCalls, 0);
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('ransomware_guard_settings_confirmation_required'),
      );
    },
  );

  test(
    'ransomware guard settings local-core failure preserves current policy',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient(actionFailure: 'policy denied');

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          ransomwareProtectedRoots: const [r'C:\Users\Brent\Documents'],
          ransomwareTrustedProcesses: const [
            r'C:\Program Files\Backup\safe.exe',
          ],
        ),
      );

      final saved = await controller.updateRansomwareGuardSettings(
        protectedRoots: const [r'C:\Users\Brent\Downloads'],
        trustedProcesses: const [r'C:\Temp\unknown.exe'],
        confirmed: true,
      );

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(localCore.ransomwareGuardCalls, 1);
      expect(
        state.config.ransomwareProtectedRoots,
        contains(r'C:\Users\Brent\Documents'),
      );
      expect(
        state.config.ransomwareTrustedProcesses,
        contains(r'C:\Program Files\Backup\safe.exe'),
      );
      expect(
        state.errorMessage,
        contains('could not write the shared guard policy config'),
      );
      expect(
        state.events.map((event) => event.type),
        contains('ransomware_guard_settings_failed'),
      );
    },
  );

  test(
    'security settings writes block overlapping ransomware policy changes',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingGuardMode = Completer<LocalCoreActionResult>();
      final localCore = _FakeLocalCoreClient(
        pendingGuardMode: pendingGuardMode,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final modeChange = controller.setProtectionMode(
        ProtectionMode.lockdown,
        confirmed: true,
      );
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(zentorControllerProvider).securitySettingsActionInFlight,
        isTrue,
      );
      final saved = await controller.updateRansomwareGuardSettings(
        protectedRoots: const [r'C:\Users\Brent\Downloads'],
        trustedProcesses: const [r'C:\Temp\unknown.exe'],
        confirmed: true,
      );

      var state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(localCore.guardModeCalls, 1);
      expect(localCore.ransomwareGuardCalls, 0);
      expect(state.securitySettingsActionInFlight, isTrue);
      expect(
        state.errorMessage,
        'Security settings change is already in progress.',
      );
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'security_settings_action_busy',
      );
      expect(busyEvent.category, 'settings');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, contains('Ransomware guard settings'));

      pendingGuardMode.complete(const LocalCoreActionResult.ok());
      expect(await modeChange, isTrue);

      state = container.read(zentorControllerProvider);
      expect(localCore.guardModeCalls, 1);
      expect(localCore.ransomwareGuardCalls, 0);
      expect(state.securitySettingsActionInFlight, isFalse);
      expect(state.config.protectionMode, ProtectionMode.lockdown);
      expect(state.config.ransomwareProtectedRoots, isEmpty);
      expect(preferences.getString('zentor.config.v1'), isNotNull);
    },
  );

  test(
    'unconfirmed detected protected app selection preserves current app',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          protectedAppConfig: const ProtectedAppConfig(
            appName: 'Current app',
            appPath: r'C:\Apps\Current\current.exe',
            source: 'Manual',
            platform: 'windows',
          ),
        ),
      );

      final saved = await controller.selectDetectedApp(
        const DetectedApp(
          appId: 'detected',
          displayName: 'Detected app',
          path: r'C:\Apps\Detected\detected.exe',
          source: 'test',
        ),
      );

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(state.config.protectedAppConfig.appName, 'Current app');
      expect(
        state.config.protectedAppConfig.appPath,
        r'C:\Apps\Current\current.exe',
      );
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('protected_app_selection_confirmation_required'),
      );
    },
  );

  test(
    'unconfirmed manual protected app selection preserves current app',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          protectedAppConfig: const ProtectedAppConfig(
            appName: 'Current app',
            appPath: r'C:\Apps\Current\current.exe',
            source: 'Manual',
            platform: 'windows',
          ),
        ),
      );

      final fileSaved = await controller.addManualProtectedAppFile();
      final folderSaved = await controller.addManualProtectedAppFolder();

      final state = container.read(zentorControllerProvider);
      expect(fileSaved, isFalse);
      expect(folderSaved, isFalse);
      expect(state.config.protectedAppConfig.appName, 'Current app');
      expect(
        state.config.protectedAppConfig.appPath,
        r'C:\Apps\Current\current.exe',
      );
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('manual_protected_app_selection_confirmation_required'),
      );
    },
  );

  test(
    'unconfirmed protected app hash calculation preserves evidence',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          protectedAppConfig: const ProtectedAppConfig(
            appName: 'Current app',
            appPath: r'C:\Apps\Current\current.exe',
            source: 'Manual',
            platform: 'windows',
            lastCalculatedHash: '',
          ),
        ),
      );

      final saved = await controller.calculateProtectedAppHash();

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(state.config.protectedAppConfig.lastCalculatedHash, isEmpty);
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('protected_app_hash_confirmation_required'),
      );
    },
  );

  test('protected app actions block while update package work is busy', () async {
    for (final status in const [
      UpdateStatus.downloading,
      UpdateStatus.verifying,
      UpdateStatus.installing,
      UpdateStatus.rollingBack,
    ]) {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final hashService = _FakeHashService(supportsPathHashing: true);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          hashServiceProvider.overrideWithValue(hashService),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        updateStatus: status,
        config: controller.state.config.copyWith(
          protectedAppConfig: const ProtectedAppConfig(
            appName: 'Current app',
            appPath: r'C:\Apps\Current\current.exe',
            source: 'Manual',
            platform: 'windows',
            lastCalculatedHash: '',
          ),
          scanPaths: const [r'C:\Apps\Current\current.exe'],
        ),
      );

      final fileSaved = await controller.addManualProtectedAppFile(
        confirmed: true,
      );
      final folderSaved = await controller.addManualProtectedAppFolder(
        confirmed: true,
      );
      final detectedSaved = await controller.selectDetectedApp(
        const DetectedApp(
          appId: 'detected',
          displayName: 'Detected app',
          path: r'C:\Apps\Detected\detected.exe',
          source: 'test',
        ),
        confirmed: true,
      );
      final hashSaved = await controller.calculateProtectedAppHash(
        confirmed: true,
      );

      final state = container.read(zentorControllerProvider);
      expect(fileSaved, isFalse);
      expect(folderSaved, isFalse);
      expect(detectedSaved, isFalse);
      expect(hashSaved, isFalse);
      expect(hashService.hashCalls, 0);
      expect(state.updateStatus, status);
      expect(state.protectedAppActionInFlight, isFalse);
      expect(state.config.protectedAppConfig.appName, 'Current app');
      expect(
        state.config.protectedAppConfig.appPath,
        r'C:\Apps\Current\current.exe',
      );
      expect(state.config.protectedAppConfig.lastCalculatedHash, isEmpty);
      expect(
        state.config.scanPaths,
        isNot(contains(r'C:\Apps\Detected\detected.exe')),
      );
      expect(
        state.errorMessage,
        'Protected app action cannot run while update package work is in progress: ${status.label}.',
      );
      final busyEvents = state.events
          .where((event) => event.type == 'protected_app_action_busy')
          .toList();
      expect(busyEvents, hasLength(4));
      for (final event in busyEvents) {
        expect(event.category, 'protection');
        expect(event.severity, 'warning');
        expect(
          event.details,
          contains(
            'Protected app action cannot run while update package work is in progress: ${status.label}.',
          ),
        );
      }
    }
  });

  test(
    'protected app hash blocks overlapping protected-app selection',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'avorax-protected-hash-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final selectedFile = File(
        '${target.path}${Platform.pathSeparator}app.exe',
      )..writeAsStringSync('benign fixture');
      final replacementFile = File(
        '${target.path}${Platform.pathSeparator}replacement.exe',
      )..writeAsStringSync('replacement fixture');
      final pendingHash = Completer<String>();
      final hashService = _FakeHashService(
        supportsPathHashing: true,
        pendingHash: pendingHash,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          hashServiceProvider.overrideWithValue(hashService),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        config: controller.state.config.copyWith(
          protectedAppConfig: ProtectedAppConfig(
            appName: 'App',
            appPath: selectedFile.path,
            platform: 'windows',
          ),
        ),
      );

      final firstHash = controller.calculateProtectedAppHash(confirmed: true);
      await Future<void>.delayed(Duration.zero);

      expect(
        container.read(zentorControllerProvider).protectedAppActionInFlight,
        isTrue,
      );
      final duplicateSelection = await controller.selectDetectedApp(
        DetectedApp(
          appId: 'replacement',
          displayName: 'Replacement',
          path: replacementFile.path,
          source: 'test',
        ),
        confirmed: true,
      );

      var state = container.read(zentorControllerProvider);
      expect(duplicateSelection, isFalse);
      expect(hashService.hashCalls, 1);
      expect(state.protectedAppActionInFlight, isTrue);
      expect(state.config.protectedAppConfig.appPath, selectedFile.path);
      expect(state.appVerificationStatus, AppVerificationStatus.pending);
      expect(
        state.errorMessage,
        'Protected app action is already in progress.',
      );
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'protected_app_action_busy',
      );
      expect(busyEvent.category, 'protection');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, contains(replacementFile.path));

      pendingHash.complete('a' * 64);
      expect(await firstHash, isTrue);

      state = container.read(zentorControllerProvider);
      expect(hashService.hashCalls, 1);
      expect(state.protectedAppActionInFlight, isFalse);
      expect(state.config.protectedAppConfig.appPath, selectedFile.path);
      expect(state.config.protectedAppConfig.lastCalculatedHash, 'a' * 64);
      expect(
        state.events.map((event) => event.type),
        contains('file_hash_calculated'),
      );
    },
  );

  test('protected app hash without selected target records blocker', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    final saved = await controller.calculateProtectedAppHash(confirmed: true);

    final state = container.read(zentorControllerProvider);
    expect(saved, isFalse);
    expect(state.errorMessage, contains('No selected app path'));
    expect(
      state.events.map((event) => event.type),
      contains('protected_app_hash_no_target'),
    );
  });

  test('protected app hash unsupported by platform records blocker', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        hashServiceProvider.overrideWithValue(
          _FakeHashService(supportsPathHashing: false),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);
    controller.state = controller.state.copyWith(
      config: controller.state.config.copyWith(
        protectedAppConfig: const ProtectedAppConfig(
          appName: 'Current app',
          appPath: r'C:\Apps\Current\current.exe',
          source: 'Manual',
          platform: 'windows',
          lastCalculatedHash: '',
        ),
      ),
    );

    final saved = await controller.calculateProtectedAppHash(confirmed: true);

    final state = container.read(zentorControllerProvider);
    expect(saved, isFalse);
    expect(state.appVerificationStatus, AppVerificationStatus.failed);
    expect(
      state.events.map((event) => event.type),
      contains('protected_app_hash_unavailable'),
    );
  });

  test(
    'manual protected app file unsupported by platform records blocker',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          hashServiceProvider.overrideWithValue(
            _FakeHashService(supportsPathHashing: false),
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final saved = await controller.addManualProtectedAppFile(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(saved, isFalse);
      expect(
        state.events.map((event) => event.type),
        contains('manual_protected_app_file_unavailable'),
      );
    },
  );

  test('cancelled scan preserves returned coverage warnings', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync(
      'zentor-cancel-coverage-',
    );
    addTearDown(() => target.deleteSync(recursive: true));
    final pendingScan = Completer<ScanReport>();
    final localCore = _FakeLocalCoreClient(pendingScan: pendingScan);

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    final scanFuture = controller.runQuickScan();
    await _waitForControllerStartup(container);
    await controller.cancelScan();
    pendingScan.complete(
      _scanReport(
        ScanStatus.cancelled,
        ScanKind.quick,
        skippedFiles: 7,
        message: 'Scan cancelled by user request; skipped 7 remaining file(s).',
        scanErrors: const [
          'scan cancelled by user request; skipped 7 remaining file(s)',
        ],
      ),
    );
    await scanFuture;

    final state = container.read(zentorControllerProvider);
    expect(localCore.cancelCalls, 1);
    expect(state.scanStatus, ScanStatus.cancelled);
    expect(state.lastScanReport?.status, ScanStatus.cancelled);
    expect(state.lastScanReport?.skippedFiles, 7);
    expect(state.lastScanReport?.scanErrors, isNotEmpty);
    expect(state.errorMessage, contains('skipped 7 remaining file(s)'));
    final cancelEvent = state.events.firstWhere(
      (event) => event.type == 'scan_cancelled',
    );
    expect(cancelEvent.category, 'scan');
    expect(cancelEvent.severity, 'info');
  });

  test(
    'duplicate scan start while running does not call local core again',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'zentor-duplicate-scan-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final pendingScan = Completer<ScanReport>();
      final localCore = _FakeLocalCoreClient(pendingScan: pendingScan);

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          scanTargetServiceProvider.overrideWithValue(
            _FakeScanTargetService([target.path]),
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final scanFuture = controller.runQuickScan();
      await _waitForControllerStartup(container);
      await controller.runQuickScan();

      final runningState = container.read(zentorControllerProvider);
      expect(localCore.scanCalls, 1);
      expect(runningState.scanStatus, ScanStatus.running);
      expect(runningState.errorMessage, contains('already running'));
      expect(
        runningState.events.map((event) => event.type),
        contains('scan_start_ignored'),
      );

      pendingScan.complete(_scanReport(ScanStatus.clean, ScanKind.quick));
      await scanFuture;
    },
  );

  test(
    'scan concurrency blocks direct quick and full starts during target selection',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'zentor-target-selection-direct-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          scanTargetServiceProvider.overrideWithValue(
            _FakeScanTargetService([target.path]),
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        scanTargetSelectionInFlight: true,
      );

      await controller.runQuickScan();
      await controller.runFullScan();

      final state = container.read(zentorControllerProvider);
      expect(localCore.scanCalls, 0);
      expect(state.scanStatus, ScanStatus.idle);
      expect(
        state.errorMessage,
        'Scan target selection is already in progress.',
      );
      expect(
        state.events.map((event) => event.type),
        isNot(contains('scan_started')),
      );
      final ignoredEvents = state.events
          .where((event) => event.type == 'scan_start_ignored')
          .toList();
      expect(ignoredEvents, hasLength(2));
      expect(
        ignoredEvents.any(
          (event) => event.details?.contains('Quick scan') ?? false,
        ),
        isTrue,
      );
      expect(
        ignoredEvents.any(
          (event) => event.details?.contains('Full scan') ?? false,
        ),
        isTrue,
      );
      for (final event in ignoredEvents) {
        expect(event.category, 'scan');
        expect(event.severity, 'warning');
        expect(
          event.details,
          contains('Scan target selection is already in progress.'),
        );
      }
    },
  );

  test(
    'scan concurrency blocks custom target selection while scan start is in flight',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(scanStartInFlight: true);

      await controller.scanSelectedFile();
      await controller.scanSelectedFolder();

      final state = container.read(zentorControllerProvider);
      expect(localCore.scanCalls, 0);
      expect(state.scanTargetSelectionInFlight, isFalse);
      expect(state.errorMessage, 'A scan is already starting.');
      final busyEvents = state.events
          .where((event) => event.type == 'scan_target_selection_busy')
          .toList();
      expect(busyEvents, hasLength(2));
      expect(
        busyEvents.any(
          (event) => event.details?.contains('Custom file scan') ?? false,
        ),
        isTrue,
      );
      expect(
        busyEvents.any(
          (event) => event.details?.contains('Custom folder scan') ?? false,
        ),
        isTrue,
      );
      for (final event in busyEvents) {
        expect(event.category, 'scan');
        expect(event.severity, 'warning');
        expect(event.details, contains('A scan is already starting.'));
      }
    },
  );

  test(
    'scan concurrency blocks custom target selection while scan is running',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        scanStatus: ScanStatus.running,
      );

      await controller.scanSelectedFolder();

      final state = container.read(zentorControllerProvider);
      expect(localCore.scanCalls, 0);
      expect(state.scanTargetSelectionInFlight, isFalse);
      expect(state.errorMessage, 'A scan is already running.');
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'scan_target_selection_busy',
      );
      expect(busyEvent.category, 'scan');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, contains('Custom folder scan'));
      expect(busyEvent.details, contains('A scan is already running.'));
    },
  );

  test('custom file picker cancel clears selection without scanning', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();
    final fileSelection = _FakeFileSelectionService();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        fileSelectionServiceProvider.overrideWithValue(fileSelection),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    await controller.scanSelectedFile();

    final state = container.read(zentorControllerProvider);
    expect(fileSelection.pickFileCalls, 1);
    expect(fileSelection.pickDirectoryCalls, 0);
    expect(localCore.scanCalls, 0);
    expect(state.scanTargetSelectionInFlight, isFalse);
    expect(state.errorMessage, isNull);
    expect(
      state.events.map((event) => event.type),
      isNot(contains('scan_file_picker_failed')),
    );
  });

  test('custom file picker failure reports normalized scan error', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();
    final fileSelection = _FakeFileSelectionService(
      fileError: StateError('file picker failed\x00\n\twith controls'),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        fileSelectionServiceProvider.overrideWithValue(fileSelection),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    await controller.scanSelectedFile();

    final state = container.read(zentorControllerProvider);
    expect(fileSelection.pickFileCalls, 1);
    expect(fileSelection.pickDirectoryCalls, 0);
    expect(localCore.scanCalls, 0);
    expect(state.scanTargetSelectionInFlight, isFalse);
    expect(state.scanStatus, ScanStatus.failed);
    expect(
      state.errorMessage,
      contains('Unable to select a file for scanning'),
    );
    expect(state.errorMessage, contains('file picker failed with controls'));
    expect(state.errorMessage, isNot(contains('\x00')));
    final failureEvent = state.events.firstWhere(
      (event) => event.type == 'scan_file_picker_failed',
    );
    expect(failureEvent.category, 'scan');
    expect(failureEvent.severity, 'error');
    expect(failureEvent.details, contains('file picker failed with controls'));
    expect(failureEvent.details, isNot(contains('\x00')));
  });

  test(
    'manual quarantine confirmation is required before file selection',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();
      final fileSelection = _FakeFileSelectionService(
        file: const SelectedFilePath(
          name: 'manual.bin',
          path: r'C:\Users\Brent\Downloads\manual.bin',
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          fileSelectionServiceProvider.overrideWithValue(fileSelection),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      await controller.quarantineSelectedFile();

      final state = container.read(zentorControllerProvider);
      expect(fileSelection.pickFileCalls, 0);
      expect(localCore.quarantineFileCalls, 0);
      expect(state.errorMessage, contains('explicit confirmation'));
      expect(
        state.events.map((event) => event.type),
        contains('manual_quarantine_confirmation_required'),
      );
    },
  );

  test('manual quarantine picker cancel clears busy state', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();
    final fileSelection = _FakeFileSelectionService();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        fileSelectionServiceProvider.overrideWithValue(fileSelection),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    await controller.quarantineSelectedFile(confirmed: true);

    final state = container.read(zentorControllerProvider);
    expect(fileSelection.pickFileCalls, 1);
    expect(localCore.quarantineFileCalls, 0);
    expect(state.scanTargetSelectionInFlight, isFalse);
    expect(state.quarantineActionInFlight, isFalse);
    expect(state.errorMessage, isNull);
  });

  test('manual quarantine picker failure reports normalized error', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();
    final fileSelection = _FakeFileSelectionService(
      fileError: StateError('manual picker failed\x00\n\twith controls'),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        fileSelectionServiceProvider.overrideWithValue(fileSelection),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    await controller.quarantineSelectedFile(confirmed: true);

    final state = container.read(zentorControllerProvider);
    expect(fileSelection.pickFileCalls, 1);
    expect(localCore.quarantineFileCalls, 0);
    expect(state.scanTargetSelectionInFlight, isFalse);
    expect(state.quarantineActionInFlight, isFalse);
    expect(
      state.errorMessage,
      contains('Unable to select a file for quarantine'),
    );
    expect(state.errorMessage, contains('manual picker failed with controls'));
    expect(state.errorMessage, isNot(contains('\x00')));
    final failureEvent = state.events.firstWhere(
      (event) => event.type == 'manual_quarantine_file_picker_failed',
    );
    expect(failureEvent.category, 'quarantine');
    expect(failureEvent.severity, 'error');
    expect(
      failureEvent.details,
      contains('manual picker failed with controls'),
    );
  });

  test(
    'confirmed manual quarantine picks and quarantines selected file',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();
      final fileSelection = _FakeFileSelectionService(
        file: const SelectedFilePath(
          name: 'manual.bin',
          path: r'C:\Users\Brent\Downloads\manual.bin',
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          fileSelectionServiceProvider.overrideWithValue(fileSelection),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      await controller.quarantineSelectedFile(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(fileSelection.pickFileCalls, 1);
      expect(localCore.quarantineFileCalls, 1);
      expect(
        localCore.lastQuarantineFilePath,
        r'C:\Users\Brent\Downloads\manual.bin',
      );
      expect(localCore.lastQuarantineThreatName, 'Manual quarantine');
      expect(localCore.lastQuarantineEngine, 'avorax-ui-manual-quarantine');
      expect(localCore.listQuarantineCalls, greaterThanOrEqualTo(1));
      expect(state.scanTargetSelectionInFlight, isFalse);
      expect(state.quarantineActionInFlight, isFalse);
      expect(state.errorMessage, isNull);
      expect(
        state.events.map((event) => event.type),
        contains('manual_file_quarantined'),
      );
    },
  );

  test(
    'manual quarantine does not pick while update package work is busy',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();
      final fileSelection = _FakeFileSelectionService(
        file: const SelectedFilePath(
          name: 'manual.bin',
          path: r'C:\Users\Brent\Downloads\manual.bin',
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          fileSelectionServiceProvider.overrideWithValue(fileSelection),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);
      controller.state = controller.state.copyWith(
        updateStatus: UpdateStatus.installing,
      );

      await controller.quarantineSelectedFile(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(fileSelection.pickFileCalls, 0);
      expect(localCore.quarantineFileCalls, 0);
      expect(state.updateOperationInFlight, isFalse);
      expect(
        state.errorMessage,
        contains('update package work is in progress'),
      );
      expect(
        state.events.map((event) => event.type),
        contains('manual_quarantine_busy'),
      );
    },
  );

  test(
    'custom folder picker cancel clears selection without scanning',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final localCore = _FakeLocalCoreClient();
      final fileSelection = _FakeFileSelectionService();

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          fileSelectionServiceProvider.overrideWithValue(fileSelection),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      await controller.scanSelectedFolder();

      final state = container.read(zentorControllerProvider);
      expect(fileSelection.pickFileCalls, 0);
      expect(fileSelection.pickDirectoryCalls, 1);
      expect(localCore.scanCalls, 0);
      expect(state.scanTargetSelectionInFlight, isFalse);
      expect(state.errorMessage, isNull);
      expect(
        state.events.map((event) => event.type),
        isNot(contains('scan_folder_picker_failed')),
      );
    },
  );

  test('custom folder picker failure reports normalized scan error', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();
    final fileSelection = _FakeFileSelectionService(
      directoryError: StateError('folder picker failed\x00\n\twith controls'),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        fileSelectionServiceProvider.overrideWithValue(fileSelection),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    await controller.scanSelectedFolder();

    final state = container.read(zentorControllerProvider);
    expect(fileSelection.pickFileCalls, 0);
    expect(fileSelection.pickDirectoryCalls, 1);
    expect(localCore.scanCalls, 0);
    expect(state.scanTargetSelectionInFlight, isFalse);
    expect(state.scanStatus, ScanStatus.failed);
    expect(
      state.errorMessage,
      contains('Unable to select a folder for scanning'),
    );
    expect(state.errorMessage, contains('folder picker failed with controls'));
    expect(state.errorMessage, isNot(contains('\x00')));
    final failureEvent = state.events.firstWhere(
      (event) => event.type == 'scan_folder_picker_failed',
    );
    expect(failureEvent.category, 'scan');
    expect(failureEvent.severity, 'error');
    expect(
      failureEvent.details,
      contains('folder picker failed with controls'),
    );
    expect(failureEvent.details, isNot(contains('\x00')));
  });

  test('cancel scan without running scan does not call local core', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCore = _FakeLocalCoreClient();

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    await controller.cancelScan();

    final state = container.read(zentorControllerProvider);
    expect(localCore.cancelCalls, 0);
    expect(state.scanStatus, ScanStatus.idle);
    expect(state.errorMessage, contains('No scan is running'));
    expect(
      state.events.map((event) => event.type),
      contains('scan_cancel_ignored'),
    );
    final ignoredEvent = state.events.firstWhere(
      (event) => event.type == 'scan_cancel_ignored',
    );
    expect(ignoredEvent.category, 'scan');
    expect(ignoredEvent.severity, 'warning');
  });

  test('cancel fallback warning is surfaced to the UI', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync(
      'zentor-cancel-fallback-',
    );
    addTearDown(() => target.deleteSync(recursive: true));
    final pendingScan = Completer<ScanReport>();
    final localCore = _FakeLocalCoreClient(
      pendingScan: pendingScan,
      cancelWarning:
          'Avorax local core cancel IPC failed; process kill fallback was requested: ipc offline',
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    final scanFuture = controller.runQuickScan();
    await _waitForControllerStartup(container);
    await controller.cancelScan();

    final cancelledState = container.read(zentorControllerProvider);
    expect(localCore.cancelCalls, 1);
    expect(cancelledState.scanStatus, ScanStatus.cancelled);
    expect(
      cancelledState.errorMessage,
      contains('process kill fallback was requested'),
    );
    final cancelEvent = cancelledState.events.firstWhere(
      (event) => event.type == 'scan_cancelled',
    );
    expect(cancelEvent.category, 'scan');
    expect(cancelEvent.severity, 'warning');
    expect(cancelEvent.details, contains('ipc offline'));

    pendingScan.complete(_scanReport(ScanStatus.cancelled, ScanKind.quick));
    await scanFuture;
  });

  test('duplicate cancel while cancellation is pending is ignored', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final target = Directory.systemTemp.createTempSync(
      'zentor-duplicate-cancel-',
    );
    addTearDown(() => target.deleteSync(recursive: true));
    final pendingScan = Completer<ScanReport>();
    final pendingCancel = Completer<String?>();
    final localCore = _FakeLocalCoreClient(
      pendingScan: pendingScan,
      pendingCancel: pendingCancel,
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(localCore),
        scanTargetServiceProvider.overrideWithValue(
          _FakeScanTargetService([target.path]),
        ),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    final scanFuture = controller.runQuickScan();
    await _waitForControllerStartup(container);
    final firstCancel = controller.cancelScan();
    await Future<void>.delayed(Duration.zero);
    await controller.cancelScan();

    final duplicateState = container.read(zentorControllerProvider);
    expect(localCore.cancelCalls, 1);
    expect(duplicateState.scanCancelInFlight, isTrue);
    expect(
      duplicateState.errorMessage,
      contains('cancellation is already in progress'),
    );
    expect(
      duplicateState.events
          .where((event) => event.type == 'scan_cancel_ignored')
          .length,
      1,
    );
    final ignoredEvent = duplicateState.events.firstWhere(
      (event) => event.type == 'scan_cancel_ignored',
    );
    expect(ignoredEvent.category, 'scan');
    expect(ignoredEvent.severity, 'warning');

    pendingCancel.complete(null);
    await firstCancel;
    pendingScan.complete(_scanReport(ScanStatus.cancelled, ScanKind.quick));
    await scanFuture;

    final state = container.read(zentorControllerProvider);
    expect(localCore.cancelCalls, 1);
    expect(state.scanCancelInFlight, isFalse);
    expect(state.scanStatus, ScanStatus.cancelled);
  });

  test(
    'failed cancellation does not convert completed scan to cancelled',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'zentor-cancel-failure-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final pendingScan = Completer<ScanReport>();
      final localCore = _FakeLocalCoreClient(
        pendingScan: pendingScan,
        cancelFailure: 'cancel IPC unavailable',
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          scanTargetServiceProvider.overrideWithValue(
            _FakeScanTargetService([target.path]),
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final scanFuture = controller.runQuickScan();
      await _waitForControllerStartup(container);
      await controller.cancelScan();
      final failedCancelState = container.read(zentorControllerProvider);
      expect(
        failedCancelState.errorMessage,
        contains('cancel IPC unavailable'),
      );
      final failedEvent = failedCancelState.events.firstWhere(
        (event) => event.type == 'scan_cancel_failed',
      );
      expect(failedEvent.category, 'scan');
      expect(failedEvent.severity, 'error');
      pendingScan.complete(_scanReport(ScanStatus.clean, ScanKind.quick));
      await scanFuture;

      final state = container.read(zentorControllerProvider);
      expect(localCore.cancelCalls, 1);
      expect(state.scanStatus, ScanStatus.clean);
      expect(state.lastScanReport?.status, ScanStatus.clean);
      expect(state.errorMessage, isNull);
    },
  );

  test(
    'scan cancellation exception diagnostics are normalized at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final target = Directory.systemTemp.createTempSync(
        'zentor-cancel-diagnostic-',
      );
      addTearDown(() => target.deleteSync(recursive: true));
      final pendingScan = Completer<ScanReport>();
      final rawFailure =
          'cancel IPC unavailable\x00\n\t${'diagnostic detail ' * 260}';
      final localCore = _FakeLocalCoreClient(
        pendingScan: pendingScan,
        cancelFailure: rawFailure,
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(localCore),
          scanTargetServiceProvider.overrideWithValue(
            _FakeScanTargetService([target.path]),
          ),
        ],
      );
      addTearDown(container.dispose);

      final controller = container.read(zentorControllerProvider.notifier);
      await _waitForControllerStartup(container);

      final scanFuture = controller.runQuickScan();
      await _waitForControllerStartup(container);
      await controller.cancelScan();

      final failedCancelState = container.read(zentorControllerProvider);
      expect(localCore.cancelCalls, 1);
      expect(failedCancelState.scanCancelInFlight, isFalse);
      expect(failedCancelState.scanStatus, ScanStatus.running);
      expect(
        failedCancelState.errorMessage,
        startsWith('Unable to request scan cancellation:'),
      );
      expect(
        failedCancelState.errorMessage,
        contains('cancel IPC unavailable'),
      );
      expect(failedCancelState.errorMessage, isNot(contains('\x00')));
      expect(failedCancelState.errorMessage, isNot(contains('\n\t')));
      expect(failedCancelState.errorMessage!.length, lessThanOrEqualTo(2200));
      final failureEvent = failedCancelState.events.firstWhere(
        (event) => event.type == 'scan_cancel_failed',
      );
      expect(failureEvent.category, 'scan');
      expect(failureEvent.severity, 'error');
      expect(failureEvent.details, contains('cancel IPC unavailable'));
      expect(failureEvent.details, isNot(contains('\x00')));
      expect(failureEvent.details, isNot(contains('\n\t')));
      expect(failureEvent.details!.length, lessThanOrEqualTo(2048));

      pendingScan.complete(_scanReport(ScanStatus.clean, ScanKind.quick));
      await scanFuture;

      final finalState = container.read(zentorControllerProvider);
      expect(finalState.scanStatus, ScanStatus.clean);
      expect(finalState.lastScanReport?.status, ScanStatus.clean);
    },
  );
}

Future<void> _waitForControllerStartup(ProviderContainer container) async {
  for (var attempt = 0; attempt < 50; attempt += 1) {
    await Future<void>.delayed(Duration.zero);
    final state = container.read(zentorControllerProvider);
    if (attempt >= 5 &&
        !state.updateOperationInFlight &&
        !state.malwareEngineHealthCheckInFlight &&
        !state.appDetectionInFlight &&
        !state.cloudHealthCheckInFlight) {
      return;
    }
  }
}

class _FakeScanTargetService extends ScanTargetService {
  const _FakeScanTargetService(this.paths);

  final List<String> paths;

  @override
  List<String> quickScanTargets({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => paths;

  @override
  ScanTargetPlan quickScanTargetPlan({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => ScanTargetPlan(paths, const []);

  @override
  List<String> fullScanRoots({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => paths;

  @override
  ScanTargetPlan fullScanRootPlan({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => ScanTargetPlan(paths, const []);
}

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector({
    this.supportsAutomatic = false,
    this.detectException,
    this.observations = const [],
    this.snapshotException,
  });

  final bool supportsAutomatic;
  final String? detectException;
  final List<ProcessObservation> observations;
  final String? snapshotException;

  @override
  bool get supportsAutomaticDetection => supportsAutomatic;

  @override
  Future<List<DetectedApp>> detect() async {
    final exception = detectException;
    if (exception != null) throw StateError(exception);
    return const [];
  }

  @override
  Future<List<ProcessObservation>> processSnapshotObservations() async {
    final exception = snapshotException;
    if (exception != null) throw StateError(exception);
    return observations;
  }
}

class _FakeHashService extends HashService {
  _FakeHashService({required this.supportsPathHashing, this.pendingHash});

  @override
  final bool supportsPathHashing;
  final Completer<String>? pendingHash;
  int hashCalls = 0;

  @override
  Future<String> sha256ForFile(
    String path, {
    void Function(double progress)? onProgress,
  }) async {
    hashCalls += 1;
    onProgress?.call(0.5);
    final pending = pendingHash;
    if (pending != null) return pending.future;
    throw StateError('Hashing should not be called by this test.');
  }
}

class _ManualScheduledTimerFactory {
  _ManualScheduledTimer? timer;

  Timer create(Duration duration, void Function(Timer timer) callback) {
    final created = _ManualScheduledTimer(duration, callback);
    timer = created;
    return created;
  }
}

class _FailingScheduledTimerFactory {
  int calls = 0;

  Timer create(Duration duration, void Function(Timer timer) callback) {
    calls += 1;
    throw StateError('scheduled timer fixture failure');
  }
}

class _ManualScheduledTimer implements Timer {
  _ManualScheduledTimer(this.duration, this._callback);

  final Duration duration;
  final void Function(Timer timer) _callback;
  var _isActive = true;
  var _tick = 0;

  void fire() {
    if (!_isActive) return;
    _tick += 1;
    _callback(this);
  }

  @override
  void cancel() {
    _isActive = false;
  }

  @override
  bool get isActive => _isActive;

  @override
  int get tick => _tick;
}

class _FakeApiClient extends ZentorApiClient {
  _FakeApiClient({
    this.pendingHealth,
    this.healthException,
    List<ApiResult<void>>? heartbeatResults,
  }) : _heartbeatResults = List<ApiResult<void>>.of(
         heartbeatResults ?? const [],
       );

  final Completer<ApiResult<void>>? pendingHealth;
  final String? healthException;
  final List<ApiResult<void>> _heartbeatResults;
  int healthCalls = 0;
  int heartbeatCalls = 0;

  @override
  Future<ApiResult<void>> healthCheck(ZentorConfig config) {
    healthCalls += 1;
    final pending = pendingHealth;
    if (pending != null) return pending.future;
    final exception = healthException;
    if (exception != null) throw StateError(exception);
    return Future.value(const ApiSuccess<void>(null));
  }

  @override
  Future<ApiResult<void>> sendHeartbeat(
    ZentorConfig config,
    ProtectionRun protectionRun,
  ) async {
    heartbeatCalls += 1;
    if (_heartbeatResults.isNotEmpty) {
      return _heartbeatResults.removeAt(0);
    }
    return const ApiSuccess<void>(null);
  }
}

class _PendingSaveConfigRepository extends ConfigRepository {
  _PendingSaveConfigRepository(super.preferences, {required this.pendingSave});

  final Completer<void> pendingSave;
  int saveCalls = 0;
  ZentorConfig? savedConfig;

  @override
  Future<void> save(ZentorConfig config) async {
    saveCalls += 1;
    savedConfig = config;
    await pendingSave.future;
    return super.save(config);
  }
}

class _FailingResetConfigRepository extends ConfigRepository {
  _FailingResetConfigRepository(
    super.preferences, {
    required this.resetFailure,
  });

  final String resetFailure;
  int resetCalls = 0;

  @override
  Future<void> reset() async {
    resetCalls += 1;
    throw StateError(resetFailure);
  }
}

class _PendingEventRepository extends LocalEventRepository {
  _PendingEventRepository(
    super.preferences, {
    required this.pendingType,
    required this.pendingEvent,
  });

  final String pendingType;
  final Completer<LocalEvent> pendingEvent;
  final Map<String, int> _addCalls = {};

  int callsFor(String type) => _addCalls[type] ?? 0;

  @override
  Future<LocalEvent> add(
    String type,
    String message, {
    String? details,
    String category = 'app',
    String severity = 'info',
  }) {
    _addCalls[type] = callsFor(type) + 1;
    if (type == pendingType) return pendingEvent.future;
    return super.add(
      type,
      message,
      details: details,
      category: category,
      severity: severity,
    );
  }
}

class _FakeFileSelectionService extends FileSelectionService {
  _FakeFileSelectionService({this.file, this.fileError, this.directoryError});

  final SelectedFilePath? file;
  final Object? fileError;
  final Object? directoryError;
  int pickFileCalls = 0;
  int pickDirectoryCalls = 0;

  @override
  Future<SelectedFilePath?> pickFile() async {
    pickFileCalls += 1;
    final error = fileError;
    if (error != null) throw error;
    return file;
  }

  @override
  Future<String?> pickDirectory() async {
    pickDirectoryCalls += 1;
    final error = directoryError;
    if (error != null) throw error;
    return null;
  }
}

class _FakeLocalCoreClient extends LocalCoreClient {
  _FakeLocalCoreClient({
    List<ScanReport>? reports,
    this.actionFailure,
    this.actionException,
    this.pendingScan,
    this.pendingCancel,
    this.cancelFailure,
    this.cancelWarning,
    this.pendingLabelDetection,
    this.pendingAddAllowlist,
    this.pendingRestoreQuarantine,
    this.pendingGuardMode,
    List<LocalCoreActionResult>? guardModeResults,
    this.pendingProtectionSelfTest,
    this.pendingStartCoreService,
    this.listQuarantineFailure,
    this.listAllowlistFailure,
    this.healthSummaryResult = const LocalCoreHealth(
      malwareEngineStatus: MalwareEngineStatus.available,
      nativeEngineStatus: 'ready',
      coreServiceStatus: 'running',
    ),
    this.serviceBoundaryHealthResult = const CoreServiceBoundaryHealth(
      status: CoreServiceBoundaryStatus.ready,
      protocolVersion: 1,
      transport: 'windowsNamedPipe',
      networkExposed: false,
      commandScope: 'healthOnly',
      clientAuthenticated: true,
      serverAuthenticated: true,
      serverPid: 4242,
      servicePid: 4242,
      serviceReady: true,
      engineReady: true,
      limitations: ['mutating commands are denied'],
    ),
    this.healthSummaryException,
    List<QuarantineRecord>? quarantineRecords,
    List<AllowlistEntry>? allowlistEntries,
    this.desktop = true,
    this._watcherState = const RealtimeWatcherState(active: false, mode: 'off'),
    RealtimeWatcherState? stopWatcherState,
    this.processSnapshotReport = const ProcessSnapshotReport(
      ok: true,
      status: 'snapshotOnly',
      capability: 'userModeSnapshot',
      statusReason: 'fixture snapshot evaluated',
    ),
    this.processSnapshotException,
    this.watchPollResult = const WatchPollScanResult(
      ok: true,
      watcher: RealtimeWatcherState(active: true, mode: 'userModeBestEffort'),
      poll: WatchPollScanSummary(active: true, mode: 'finiteUserModePolling'),
    ),
  }) : _reports = List<ScanReport>.of(reports ?? const []),
       _quarantineRecords = List<QuarantineRecord>.of(
         quarantineRecords ?? const [],
       ),
       _allowlistEntries = List<AllowlistEntry>.of(
         allowlistEntries ?? const [],
       ),
       _guardModeResults = List<LocalCoreActionResult>.of(
         guardModeResults ?? const [],
       ),
       _stopWatcherState =
           stopWatcherState ??
           const RealtimeWatcherState(active: false, mode: 'off');

  final List<ScanReport> _reports;
  final List<QuarantineRecord> _quarantineRecords;
  final List<AllowlistEntry> _allowlistEntries;
  final String? actionFailure;
  final String? actionException;
  final Completer<ScanReport>? pendingScan;
  final Completer<String?>? pendingCancel;
  final Completer<LocalCoreActionResult>? pendingLabelDetection;
  final Completer<LocalCoreActionResult>? pendingAddAllowlist;
  Completer<List<QuarantineRecord>>? pendingListQuarantine;
  Completer<List<AllowlistEntry>>? pendingListAllowlist;
  final Completer<LocalCoreActionResult>? pendingRestoreQuarantine;
  final Completer<LocalCoreActionResult>? pendingGuardMode;
  final List<LocalCoreActionResult> _guardModeResults;
  final Completer<String>? pendingProtectionSelfTest;
  final Completer<String>? pendingStartCoreService;
  final String? cancelFailure;
  final String? cancelWarning;
  final String? listQuarantineFailure;
  final String? listAllowlistFailure;
  final LocalCoreHealth healthSummaryResult;
  final CoreServiceBoundaryHealth serviceBoundaryHealthResult;
  final String? healthSummaryException;
  final bool desktop;
  final RealtimeWatcherState _watcherState;
  final RealtimeWatcherState _stopWatcherState;
  final ProcessSnapshotReport processSnapshotReport;
  final String? processSnapshotException;
  final WatchPollScanResult watchPollResult;
  int scanCalls = 0;
  int cancelCalls = 0;
  int watchCalls = 0;
  int stopWatchCalls = 0;
  int watchPollCalls = 0;
  int guardModeCalls = 0;
  int protectionSelfTestCalls = 0;
  int addAllowlistCalls = 0;
  int listQuarantineCalls = 0;
  int listAllowlistCalls = 0;
  int removeAllowlistCalls = 0;
  int labelDetectionCalls = 0;
  int quarantineCalls = 0;
  int quarantineFileCalls = 0;
  int restoreQuarantineCalls = 0;
  int deleteQuarantineCalls = 0;
  int ransomwareGuardCalls = 0;
  int startCoreServiceCalls = 0;
  int openInstallReportCalls = 0;
  int repairInstallationCalls = 0;
  int processSnapshotCalls = 0;
  ProtectionMode? lastGuardMode;
  List<String> lastWatchPaths = const [];
  List<String> lastWatchPollPaths = const [];
  Duration? lastWatchPollDuration;
  Duration? lastWatchPollPollInterval;
  int? lastWatchPollMaxEvents;
  List<ProcessObservation> lastProcessObservations = const [];
  ScanKind? lastKind;
  ScanActionMode? lastActionMode;
  String? lastScanFilePath;
  String? lastQuarantineFilePath;
  String? lastQuarantineThreatName;
  String? lastQuarantineEngine;

  @override
  bool get isDesktop => desktop;

  @override
  Future<MalwareEngineStatus> health() async => MalwareEngineStatus.available;

  @override
  Future<LocalCoreHealth> healthSummary() async {
    final exception = healthSummaryException;
    if (exception != null) throw StateError(exception);
    return healthSummaryResult;
  }

  @override
  Future<CoreServiceBoundaryHealth> serviceBoundaryHealth() async =>
      serviceBoundaryHealthResult;

  @override
  Future<String> startCoreService() async {
    startCoreServiceCalls += 1;
    final pending = pendingStartCoreService;
    if (pending != null) return pending.future;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    return 'Core Service start requested.';
  }

  @override
  Future<String> openInstallReport() async {
    openInstallReportCalls += 1;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    return 'Install report open requested.';
  }

  @override
  Future<String> repairInstallation() async {
    repairInstallationCalls += 1;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    return 'Installation repair requested.';
  }

  @override
  Future<LocalCoreActionResult> configureGuardMode(ProtectionMode mode) async {
    guardModeCalls += 1;
    lastGuardMode = mode;
    final pending = pendingGuardMode;
    if (pending != null) return pending.future;
    if (_guardModeResults.isNotEmpty) {
      return _guardModeResults.removeAt(0);
    }
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    final failure = actionFailure;
    if (failure != null) return LocalCoreActionResult.failed(failure);
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<String> runProtectionSelfTest() async {
    protectionSelfTestCalls += 1;
    final pending = pendingProtectionSelfTest;
    if (pending != null) return pending.future;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    final failure = actionFailure;
    if (failure != null) return 'FAIL $failure';
    return 'PASS guard self-test fixture';
  }

  @override
  Future<LocalCoreActionResult> configureRansomwareGuard({
    required List<String> protectedRoots,
    required List<String> trustedProcesses,
  }) async {
    ransomwareGuardCalls += 1;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    final failure = actionFailure;
    if (failure != null) return LocalCoreActionResult.failed(failure);
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<RealtimeWatcherState> startWatch(List<String> paths) async {
    watchCalls += 1;
    lastWatchPaths = List<String>.of(paths);
    return _watcherState;
  }

  @override
  Future<RealtimeWatcherState> stopWatch() async {
    stopWatchCalls += 1;
    return _stopWatcherState;
  }

  @override
  Future<WatchPollScanResult> watchPollScan(
    List<String> paths, {
    Duration duration = const Duration(seconds: 4),
    Duration pollInterval = const Duration(milliseconds: 200),
    int maxEvents = 8,
  }) async {
    watchPollCalls += 1;
    lastWatchPollPaths = List<String>.of(paths);
    lastWatchPollDuration = duration;
    lastWatchPollPollInterval = pollInterval;
    lastWatchPollMaxEvents = maxEvents;
    return watchPollResult;
  }

  @override
  Future<ProcessSnapshotReport> evaluateProcessSnapshot(
    List<ProcessObservation> observations, {
    ProcessMonitorPolicy policy = const ProcessMonitorPolicy(),
  }) async {
    processSnapshotCalls += 1;
    lastProcessObservations = List<ProcessObservation>.of(observations);
    final exception = processSnapshotException;
    if (exception != null) throw StateError(exception);
    return processSnapshotReport;
  }

  @override
  Future<LocalCoreActionResult> quarantineThreat(ThreatResult threat) async {
    quarantineCalls += 1;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    final failure = actionFailure;
    if (failure != null) return LocalCoreActionResult.failed(failure);
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<LocalCoreActionResult> quarantineFile(
    String path, {
    required String threatName,
    required String engine,
  }) async {
    quarantineFileCalls += 1;
    lastQuarantineFilePath = path;
    lastQuarantineThreatName = threatName;
    lastQuarantineEngine = engine;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    final failure = actionFailure;
    if (failure != null) return LocalCoreActionResult.failed(failure);
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<LocalCoreActionResult> restoreQuarantineItem(
    String quarantineId,
  ) async {
    restoreQuarantineCalls += 1;
    final pending = pendingRestoreQuarantine;
    if (pending != null) return pending.future;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    final failure = actionFailure;
    if (failure != null) return LocalCoreActionResult.failed(failure);
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<LocalCoreActionResult> deleteQuarantineItem(
    String quarantineId,
  ) async {
    deleteQuarantineCalls += 1;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    final failure = actionFailure;
    if (failure != null) return LocalCoreActionResult.failed(failure);
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<List<QuarantineRecord>> listQuarantine() async {
    listQuarantineCalls += 1;
    final pending = pendingListQuarantine;
    if (pending != null) return pending.future;
    final failure = listQuarantineFailure;
    if (failure != null) throw StateError(failure);
    return List<QuarantineRecord>.of(_quarantineRecords);
  }

  @override
  Future<LocalCoreActionResult> addAllowlistEntry(String path) async {
    addAllowlistCalls += 1;
    final pending = pendingAddAllowlist;
    if (pending != null) return pending.future;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    final failure = actionFailure;
    if (failure != null) return LocalCoreActionResult.failed(failure);
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<LocalCoreActionResult> labelDetection(
    ThreatResult threat,
    String label, {
    String? note,
  }) async {
    labelDetectionCalls += 1;
    final pending = pendingLabelDetection;
    if (pending != null) return pending.future;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    final failure = actionFailure;
    if (failure != null) return LocalCoreActionResult.failed(failure);
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<LocalCoreActionResult> removeAllowlistEntry(String id) async {
    removeAllowlistCalls += 1;
    final exception = actionException;
    if (exception != null) throw StateError(exception);
    final failure = actionFailure;
    if (failure != null) return LocalCoreActionResult.failed(failure);
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<List<AllowlistEntry>> listAllowlist() async {
    listAllowlistCalls += 1;
    final pending = pendingListAllowlist;
    if (pending != null) return pending.future;
    final failure = listAllowlistFailure;
    if (failure != null) throw StateError(failure);
    return List<AllowlistEntry>.of(_allowlistEntries);
  }

  @override
  Future<String?> cancelActiveScan() async {
    cancelCalls += 1;
    final pending = pendingCancel;
    if (pending != null) return pending.future;
    final failure = cancelFailure;
    if (failure != null) throw StateError(failure);
    return cancelWarning;
  }

  @override
  Future<ScanReport> scanFile(
    String path, {
    required ScanKind kind,
    required ScanActionMode actionMode,
    void Function(ScanProgress progress)? onProgress,
  }) async {
    scanCalls += 1;
    lastKind = kind;
    lastActionMode = actionMode;
    lastScanFilePath = path;
    onProgress?.call(
      ScanProgress(
        jobId: 'test',
        scanType: kind,
        status: ScanJobStatus.running,
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
    );
    final pending = pendingScan;
    if (pending != null) return pending.future;
    return _reports.isNotEmpty
        ? _reports.removeAt(0)
        : _scanReport(ScanStatus.clean, kind, actionMode: actionMode);
  }

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
    onProgress?.call(
      ScanProgress(
        jobId: 'test',
        scanType: kind,
        status: ScanJobStatus.running,
        filesScanned: 0,
        foldersScanned: 1,
        bytesScanned: 0,
        threatsFound: 0,
        suspiciousFound: 0,
        skippedFiles: 0,
        permissionDeniedCount: 0,
        startedAt: DateTime.now().toUtc(),
        updatedAt: DateTime.now().toUtc(),
        elapsedSeconds: 0,
      ),
    );
    final pending = pendingScan;
    if (pending != null) return pending.future;
    return _reports.isNotEmpty
        ? _reports.removeAt(0)
        : _scanReport(ScanStatus.clean, kind, actionMode: actionMode);
  }
}

ThreatResult _threatResult({
  String id = 'threat',
  String fileName = 'sample.exe',
  ThreatCategory threatCategory = ThreatCategory.trojan,
  RecommendedAction recommendedAction = RecommendedAction.quarantine,
  RiskVerdict verdict = RiskVerdict.confirmedMalware,
  ThreatConfidence confidence = ThreatConfidence.confirmed,
  ThreatResultStatus status = ThreatResultStatus.detected,
  String? quarantineId,
  String? quarantinePath,
  String? quarantineActionTaken,
}) {
  return ThreatResult(
    id: id,
    path: 'C:\\fixtures\\$fileName',
    fileName: fileName,
    sha256: 'a' * 64,
    sizeBytes: 12,
    detectionType: DetectionType.signature,
    threatCategory: threatCategory,
    threatName: 'Test.Threat',
    confidence: confidence,
    engine: 'test',
    detectedAt: DateTime.now().toUtc(),
    recommendedAction: recommendedAction,
    status: status,
    quarantineId: quarantineId,
    quarantinePath: quarantinePath,
    quarantineActionTaken: quarantineActionTaken,
    riskScore: RiskScore(
      score: 100,
      verdict: verdict,
      confidence: confidence,
      reasons: const [],
      recommendedAction: recommendedAction,
      enginesUsed: const [DetectionType.signature],
    ),
  );
}

QuarantineRecord _quarantineRecord({
  String quarantineId = 'q-1',
  String originalPath = r'C:\fixtures\sample.exe',
  QuarantineItemStatus status = QuarantineItemStatus.quarantined,
  String actionTaken = 'quarantined',
}) {
  return QuarantineRecord(
    quarantineId: quarantineId,
    originalPath: originalPath,
    quarantinePath: r'C:\ProgramData\Avorax\Quarantine\opaque.bin',
    sha256: 'a' * 64,
    fileSize: 12,
    detectionName: 'Test.Threat',
    engine: 'test',
    quarantinedAt: DateTime.now().toUtc(),
    status: status,
    source: 'scanner',
    blockedBeforeExecution: false,
    processStarted: false,
    actionTaken: actionTaken,
  );
}

ScanReport _scanReport(
  ScanStatus status,
  ScanKind kind, {
  ScanActionMode actionMode = ScanActionMode.autoQuarantineConfirmedOnly,
  int skippedFiles = 0,
  String? message,
  List<String> scanErrors = const [],
  List<ThreatResult> threats = const [],
  int quarantinedFiles = 0,
}) {
  return ScanReport(
    status: status,
    kind: kind,
    actionMode: actionMode,
    filesScanned: 0,
    foldersScanned: 1,
    bytesScanned: 0,
    threatsFound: threats.length,
    quarantinedFiles: quarantinedFiles,
    suspiciousFound: threats
        .where((threat) => threat.status == ThreatResultStatus.detected)
        .length,
    skippedFiles: skippedFiles,
    elapsedMs: 1,
    message: message,
    scanErrors: scanErrors,
    threats: threats,
  );
}

AllowlistEntry _allowlistEntry() {
  return AllowlistEntry(
    id: 'allow-1',
    type: AllowlistEntryType.file,
    path: r'C:\fixtures\sample.exe',
    reason: 'test fixture',
    createdAt: DateTime.now().toUtc(),
    sha256: 'a' * 64,
  );
}
