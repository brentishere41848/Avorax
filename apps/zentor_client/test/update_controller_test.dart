import 'dart:async';
import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:zentor_client/app/app_state.dart';
import 'package:zentor_client/core/local_core/local_core_client.dart';
import 'package:zentor_client/core/scanning/scan_target_service.dart';
import 'package:zentor_client/core/updates/update_service.dart';
import 'package:zentor_client/features/update/update_controller.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import 'source_text.dart';

void main() {
  test(
    'in-app update completes check download verify install and waits for restart',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final updateService = _FakeUpdateService(
        checkResult: UpdateCheckResult.available(
          _update(localPackagePath: null),
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
          updateServiceProvider.overrideWithValue(updateService),
        ],
      );
      addTearDown(container.dispose);
      await _waitForStartupUpdateIdle(container, updateService);

      final controller = container.read(zentorControllerProvider.notifier);
      await controller.checkForInAppUpdate();
      expect(
        container.read(zentorControllerProvider).updateStatus,
        UpdateStatus.updateAvailable,
      );

      await controller.downloadVerifyAndInstallUpdate(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(updateService.calls.where((call) => call == 'check'), isNotEmpty);
      expect(updateService.calls.sublist(updateService.calls.length - 3), [
        'download',
        'verify',
        'install',
      ]);
      expect(state.updateStatus, UpdateStatus.readyToRestart);
      expect(state.updateError, isNull);
      expect(
        state.updateInfo?.localPackagePath,
        endsWith('Avorax-AntiVirus-0.2.16.aup'),
      );
      final eventTypes = state.events.map((event) => event.type).toList();
      expect(
        eventTypes,
        containsAll(['update_install_started', 'update_install_ready']),
      );
      expect(
        eventTypes.indexOf('update_install_ready'),
        lessThan(eventTypes.indexOf('update_install_started')),
        reason:
            'Local event history is newest-first; ready must be recorded after started.',
      );
    },
  );

  test(
    'unconfirmed in-app update install does not start package work',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final updateService = _FakeUpdateService(
        checkResult: UpdateCheckResult.available(
          _update(localPackagePath: null),
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
          updateServiceProvider.overrideWithValue(updateService),
        ],
      );
      addTearDown(container.dispose);
      await _waitForStartupUpdateIdle(container, updateService);

      final controller = container.read(zentorControllerProvider.notifier);
      await controller.checkForInAppUpdate();
      await controller.downloadVerifyAndInstallUpdate();

      final state = container.read(zentorControllerProvider);
      final eventTypes = state.events.map((event) => event.type);
      expect(updateService.calls, isNot(contains('download')));
      expect(updateService.calls, isNot(contains('verify')));
      expect(updateService.calls, isNot(contains('install')));
      expect(state.updateStatus, UpdateStatus.updateAvailable);
      expect(state.updateError, contains('requires explicit confirmation'));
      expect(eventTypes, contains('update_install_confirmation_required'));
      expect(eventTypes, isNot(contains('update_install_started')));
    },
  );

  test('unsupported platform blocks package install and rollback', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
      mutationSupported: false,
    );
    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    await controller.checkForInAppUpdate();
    await controller.downloadVerifyAndInstallUpdate(confirmed: true);
    await controller.rollbackUpdateInApp(confirmed: true);

    final state = container.read(zentorControllerProvider);
    final events = state.events.map((event) => event.type);
    expect(updateService.calls, isNot(contains('download')));
    expect(updateService.calls, isNot(contains('verify')));
    expect(updateService.calls, isNot(contains('install')));
    expect(updateService.calls, isNot(contains('rollback')));
    expect(state.updateError, contains('unavailable on this platform'));
    expect(events, contains('update_install_platform_unsupported'));
    expect(events, contains('update_rollback_platform_unsupported'));
  });

  test('rollback button path runs update service rollback in app', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    await controller.checkForInAppUpdate();
    await controller.rollbackUpdateInApp(confirmed: true);

    final state = container.read(zentorControllerProvider);
    expect(updateService.calls, contains('rollback'));
    expect(state.updateStatus, UpdateStatus.readyToRestart);
    expect(state.updateError, isNull);
    expect(
      state.events.map((event) => event.type),
      containsAll(['update_rollback_started', 'update_rollback_ready']),
    );
  });

  test('unconfirmed rollback does not call update service', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    await controller.checkForInAppUpdate();
    await controller.rollbackUpdateInApp();

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, isNot(contains('rollback')));
    expect(state.updateStatus, UpdateStatus.updateAvailable);
    expect(state.updateError, contains('requires explicit confirmation'));
    expect(eventTypes, contains('update_rollback_confirmation_required'));
    expect(eventTypes, isNot(contains('update_rollback_started')));
  });

  test(
    'update events carry explicit category and severity at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final updateService = _FakeUpdateService(
        checkResult: UpdateCheckResult.available(
          _update(localPackagePath: null),
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
          updateServiceProvider.overrideWithValue(updateService),
        ],
      );
      addTearDown(container.dispose);
      await _waitForStartupUpdateIdle(container, updateService);

      final controller = container.read(zentorControllerProvider.notifier);
      await controller.checkForInAppUpdate();
      var state = container.read(zentorControllerProvider);
      _expectUpdateEventMetadata(state, 'update_check_started', 'info');
      _expectUpdateEventMetadata(state, 'update_available', 'warning');

      await controller.downloadVerifyAndInstallUpdate();
      state = container.read(zentorControllerProvider);
      _expectUpdateEventMetadata(
        state,
        'update_install_confirmation_required',
        'warning',
      );

      await controller.downloadVerifyAndInstallUpdate(confirmed: true);
      state = container.read(zentorControllerProvider);
      _expectUpdateEventMetadata(state, 'update_install_started', 'warning');
      _expectUpdateEventMetadata(state, 'update_install_ready', 'warning');

      await controller.rollbackUpdateInApp(confirmed: true);
      state = container.read(zentorControllerProvider);
      _expectUpdateEventMetadata(state, 'update_rollback_started', 'warning');
      _expectUpdateEventMetadata(state, 'update_rollback_ready', 'warning');

      final failingInstallService = _FakeUpdateService(
        checkResult: UpdateCheckResult.available(
          _update(localPackagePath: null),
        ),
        failInstall: true,
      );
      final failingInstallContainer = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
          updateServiceProvider.overrideWithValue(failingInstallService),
        ],
      );
      addTearDown(failingInstallContainer.dispose);
      await _waitForStartupUpdateIdle(
        failingInstallContainer,
        failingInstallService,
      );

      final failingInstallController = failingInstallContainer.read(
        zentorControllerProvider.notifier,
      );
      await failingInstallController.checkForInAppUpdate();
      await failingInstallController.downloadVerifyAndInstallUpdate(
        confirmed: true,
      );
      _expectUpdateEventMetadata(
        failingInstallContainer.read(zentorControllerProvider),
        'update_install_failed',
        'error',
      );

      final failingCheckService = _FakeUpdateService(
        checkResult: UpdateCheckResult.upToDate('0.2.15'),
        failCheck: true,
      );
      final failingCheckContainer = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
          updateServiceProvider.overrideWithValue(failingCheckService),
        ],
      );
      addTearDown(failingCheckContainer.dispose);
      await _waitForStartupUpdateIdle(
        failingCheckContainer,
        failingCheckService,
      );

      await failingCheckContainer
          .read(zentorControllerProvider.notifier)
          .checkForInAppUpdate();
      _expectUpdateEventMetadata(
        failingCheckContainer.read(zentorControllerProvider),
        'update_check_failed',
        'error',
      );
    },
  );

  test('update check blocks overlapping install work while pending', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final pendingCheck = Completer<UpdateCheckResult>();
    updateService.pendingCheck = pendingCheck;
    final controller = container.read(zentorControllerProvider.notifier);

    final firstCheck = controller.checkForInAppUpdate();
    await Future<void>.delayed(Duration.zero);

    expect(
      container.read(zentorControllerProvider).updateOperationInFlight,
      isTrue,
    );
    await controller.downloadVerifyAndInstallUpdate(confirmed: true);

    var state = container.read(zentorControllerProvider);
    expect(updateService.calls.where((call) => call == 'check').length, 1);
    expect(updateService.calls, isNot(contains('download')));
    expect(updateService.calls, isNot(contains('verify')));
    expect(updateService.calls, isNot(contains('install')));
    expect(state.updateOperationInFlight, isTrue);
    expect(
      state.updateError,
      'Update action is already in progress: Checking.',
    );
    final busyEvent = state.events.firstWhere(
      (event) => event.type == 'update_action_busy',
    );
    expect(busyEvent.category, 'update');
    expect(busyEvent.severity, 'warning');

    pendingCheck.complete(
      UpdateCheckResult.available(_update(localPackagePath: null)),
    );
    await firstCheck;

    state = container.read(zentorControllerProvider);
    expect(updateService.calls.where((call) => call == 'check').length, 1);
    expect(state.updateOperationInFlight, isFalse);
    expect(state.updateStatus, UpdateStatus.updateAvailable);
    expect(state.updateInfo?.latestVersion, '0.2.16');
  });

  test('install failure does not claim ready to restart', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
      failInstall: true,
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    await controller.checkForInAppUpdate();
    await controller.downloadVerifyAndInstallUpdate(confirmed: true);

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, contains('install'));
    expect(state.updateStatus, UpdateStatus.updateAvailable);
    expect(state.updateError, contains('simulated install failure'));
    expect(state.updateInfo?.localPackagePath, isNotNull);
    expect(eventTypes, contains('update_install_started'));
    expect(eventTypes, contains('update_install_failed'));
    expect(eventTypes, isNot(contains('update_install_ready')));
  });

  test('verify failure clears untrusted local package path', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
      failVerify: true,
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    await controller.checkForInAppUpdate();
    await controller.downloadVerifyAndInstallUpdate(confirmed: true);

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, contains('download'));
    expect(updateService.calls, contains('verify'));
    expect(updateService.calls, isNot(contains('install')));
    expect(state.updateStatus, UpdateStatus.updateAvailable);
    expect(state.updateError, contains('simulated verify failure'));
    expect(state.updateInfo?.localPackagePath, isNull);
    expect(eventTypes, contains('update_install_failed'));
    expect(eventTypes, isNot(contains('update_install_started')));
    expect(eventTypes, isNot(contains('update_install_ready')));
  });

  test('download failure diagnostics are normalized before display', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
      failDownload: true,
      downloadFailureMessage: 'download failed\x00\n\twith control text',
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    await controller.checkForInAppUpdate();
    await controller.downloadVerifyAndInstallUpdate(confirmed: true);

    final state = container.read(zentorControllerProvider);
    final failedEvent = state.events.firstWhere(
      (event) => event.type == 'update_install_failed',
    );
    expect(updateService.calls, contains('download'));
    expect(updateService.calls, isNot(contains('verify')));
    expect(updateService.calls, isNot(contains('install')));
    expect(state.updateStatus, UpdateStatus.updateAvailable);
    expect(state.updateInfo?.localPackagePath, isNull);
    expect(state.updateError, contains('download failed with control text'));
    expect(state.updateError, isNot(contains('\x00')));
    expect(state.updateError, isNot(contains('\n\t')));
    expect(state.errorMessage, contains('download failed with control text'));
    expect(failedEvent.details, contains('download failed with control text'));
    expect(failedEvent.details, isNot(contains('\x00')));
    expect(failedEvent.details, isNot(contains('\n\t')));
  });

  test('update action failure diagnostics are normalized by phase', () async {
    final scenarios = [
      (
        name: 'verify',
        service: _FakeUpdateService(
          checkResult: UpdateCheckResult.available(
            _update(localPackagePath: null),
          ),
          failVerify: true,
          verifyFailureMessage: 'verify failed\x00\n\twith control text',
        ),
        run: (ZentorController controller) =>
            controller.downloadVerifyAndInstallUpdate(confirmed: true),
        eventType: 'update_install_failed',
        expectedDiagnostic: 'verify failed with control text',
        expectedStatus: UpdateStatus.updateAvailable,
      ),
      (
        name: 'install',
        service: _FakeUpdateService(
          checkResult: UpdateCheckResult.available(
            _update(localPackagePath: null),
          ),
          failInstall: true,
          installFailureMessage: 'install failed\x00\n\twith control text',
        ),
        run: (ZentorController controller) =>
            controller.downloadVerifyAndInstallUpdate(confirmed: true),
        eventType: 'update_install_failed',
        expectedDiagnostic: 'install failed with control text',
        expectedStatus: UpdateStatus.updateAvailable,
      ),
      (
        name: 'rollback',
        service: _FakeUpdateService(
          checkResult: UpdateCheckResult.available(
            _update(localPackagePath: null),
          ),
          failRollback: true,
          rollbackFailureMessage: 'rollback failed\x00\n\twith control text',
        ),
        run: (ZentorController controller) =>
            controller.rollbackUpdateInApp(confirmed: true),
        eventType: 'update_rollback_failed',
        expectedDiagnostic: 'rollback failed with control text',
        expectedStatus: UpdateStatus.failed,
      ),
    ];

    for (final scenario in scenarios) {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
          updateServiceProvider.overrideWithValue(scenario.service),
        ],
      );
      addTearDown(container.dispose);
      await _waitForStartupUpdateIdle(container, scenario.service);

      final controller = container.read(zentorControllerProvider.notifier);
      await controller.checkForInAppUpdate();
      await scenario.run(controller);

      final state = container.read(zentorControllerProvider);
      final failedEvent = state.events.firstWhere(
        (event) => event.type == scenario.eventType,
      );
      expect(
        state.updateStatus,
        scenario.expectedStatus,
        reason: scenario.name,
      );
      expect(
        state.updateError,
        contains(scenario.expectedDiagnostic),
        reason: scenario.name,
      );
      expect(state.updateError, isNot(contains('\x00')), reason: scenario.name);
      expect(state.updateError, isNot(contains('\n\t')), reason: scenario.name);
      expect(
        state.errorMessage,
        contains(scenario.expectedDiagnostic),
        reason: scenario.name,
      );
      expect(
        failedEvent.details,
        contains(scenario.expectedDiagnostic),
        reason: scenario.name,
      );
      expect(
        failedEvent.details,
        isNot(contains('\x00')),
        reason: scenario.name,
      );
      expect(
        failedEvent.details,
        isNot(contains('\n\t')),
        reason: scenario.name,
      );
    }
  });

  test('busy update action does not start another install flow', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    await controller.checkForInAppUpdate();
    controller.state = controller.state.copyWith(
      updateStatus: UpdateStatus.verifying,
    );

    await controller.downloadVerifyAndInstallUpdate(confirmed: true);

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, isNot(contains('download')));
    expect(updateService.calls, isNot(contains('verify')));
    expect(updateService.calls, isNot(contains('install')));
    expect(state.updateStatus, UpdateStatus.verifying);
    expect(state.updateError, contains('already in progress'));
    expect(eventTypes, contains('update_action_busy'));
    expect(eventTypes, isNot(contains('update_install_started')));
  });

  test('update install blocks while protection scan or trust work is active', () async {
    for (final testCase in const [
      (
        state: ZentorState(protectionStatus: ProtectionStatus.protected),
        message:
            'Update installation cannot run while protection is enabled, changing, or self-test is running.',
      ),
      (
        state: ZentorState(scanStatus: ScanStatus.running),
        message: 'Update installation cannot run while a scan is running.',
      ),
      (
        state: ZentorState(securitySettingsActionInFlight: true),
        message:
            'Update installation cannot run while a security settings change is in progress.',
      ),
      (
        state: ZentorState(configurationResetInFlight: true),
        message:
            'Update installation cannot run while configuration reset is in progress.',
      ),
      (
        state: ZentorState(quarantineActionInFlight: true),
        message:
            'Update installation cannot run while a quarantine action is in progress.',
      ),
      (
        state: ZentorState(serviceActionInFlight: true),
        message:
            'Update installation cannot run while service recovery is in progress.',
      ),
      (
        state: ZentorState(developerCloudOverrideInFlight: true),
        message:
            'Update installation cannot run while a developer cloud override change is in progress.',
      ),
      (
        state: ZentorState(protectedAppActionInFlight: true),
        message:
            'Update installation cannot run while a protected-app action is in progress.',
      ),
    ]) {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final updateService = _FakeUpdateService(
        checkResult: UpdateCheckResult.available(
          _update(localPackagePath: null),
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
          updateServiceProvider.overrideWithValue(updateService),
        ],
      );
      addTearDown(container.dispose);
      await _waitForStartupUpdateIdle(container, updateService);

      final controller = container.read(zentorControllerProvider.notifier);
      await controller.checkForInAppUpdate();
      controller.state = controller.state.copyWith(
        protectionStatus: testCase.state.protectionStatus,
        securitySettingsActionInFlight:
            testCase.state.securitySettingsActionInFlight,
        configurationResetInFlight: testCase.state.configurationResetInFlight,
        quarantineActionInFlight: testCase.state.quarantineActionInFlight,
        serviceActionInFlight: testCase.state.serviceActionInFlight,
        developerCloudOverrideInFlight:
            testCase.state.developerCloudOverrideInFlight,
        protectedAppActionInFlight: testCase.state.protectedAppActionInFlight,
        scanStatus: testCase.state.scanStatus,
      );

      await controller.downloadVerifyAndInstallUpdate(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(updateService.calls.where((call) => call == 'check').length, 1);
      expect(updateService.calls, isNot(contains('download')));
      expect(updateService.calls, isNot(contains('verify')));
      expect(updateService.calls, isNot(contains('install')));
      expect(state.updateStatus, UpdateStatus.updateAvailable);
      expect(state.updateOperationInFlight, isFalse);
      expect(state.updateError, testCase.message);
      expect(state.errorMessage, testCase.message);
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'update_action_busy',
      );
      expect(busyEvent.category, 'update');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, testCase.message);
    }
  });

  test('update rollback blocks while protection scan or trust work is active', () async {
    for (final testCase in const [
      (
        state: ZentorState(protectionSelfTestInFlight: true),
        message:
            'Update rollback cannot run while protection is enabled, changing, or self-test is running.',
      ),
      (
        state: ZentorState(scanTargetSelectionInFlight: true),
        message:
            'Update rollback cannot run while scan target selection is in progress.',
      ),
      (
        state: ZentorState(allowlistActionInFlight: true),
        message:
            'Update rollback cannot run while an allowlist action is in progress.',
      ),
      (
        state: ZentorState(detectionFeedbackInFlight: true),
        message:
            'Update rollback cannot run while detection feedback is in progress.',
      ),
      (
        state: ZentorState(serviceActionInFlight: true),
        message:
            'Update rollback cannot run while service recovery is in progress.',
      ),
      (
        state: ZentorState(developerCloudOverrideInFlight: true),
        message:
            'Update rollback cannot run while a developer cloud override change is in progress.',
      ),
      (
        state: ZentorState(protectedAppActionInFlight: true),
        message:
            'Update rollback cannot run while a protected-app action is in progress.',
      ),
    ]) {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final updateService = _FakeUpdateService(
        checkResult: UpdateCheckResult.available(
          _update(localPackagePath: null),
        ),
      );

      final container = ProviderContainer(
        overrides: [
          sharedPreferencesProvider.overrideWithValue(preferences),
          localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
          scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
          updateServiceProvider.overrideWithValue(updateService),
        ],
      );
      addTearDown(container.dispose);
      await _waitForStartupUpdateIdle(container, updateService);

      final controller = container.read(zentorControllerProvider.notifier);
      await controller.checkForInAppUpdate();
      controller.state = controller.state.copyWith(
        protectionSelfTestInFlight: testCase.state.protectionSelfTestInFlight,
        allowlistActionInFlight: testCase.state.allowlistActionInFlight,
        detectionFeedbackInFlight: testCase.state.detectionFeedbackInFlight,
        serviceActionInFlight: testCase.state.serviceActionInFlight,
        developerCloudOverrideInFlight:
            testCase.state.developerCloudOverrideInFlight,
        protectedAppActionInFlight: testCase.state.protectedAppActionInFlight,
        scanTargetSelectionInFlight: testCase.state.scanTargetSelectionInFlight,
      );

      await controller.rollbackUpdateInApp(confirmed: true);

      final state = container.read(zentorControllerProvider);
      expect(updateService.calls.where((call) => call == 'check').length, 1);
      expect(updateService.calls, isNot(contains('rollback')));
      expect(state.updateStatus, UpdateStatus.updateAvailable);
      expect(state.updateOperationInFlight, isFalse);
      expect(state.updateError, testCase.message);
      expect(state.errorMessage, testCase.message);
      final busyEvent = state.events.firstWhere(
        (event) => event.type == 'update_action_busy',
      );
      expect(busyEvent.category, 'update');
      expect(busyEvent.severity, 'warning');
      expect(busyEvent.details, testCase.message);
    }
  });

  test('busy manual update check does not start another check', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    controller.state = controller.state.copyWith(
      updateStatus: UpdateStatus.installing,
    );

    await controller.checkForInAppUpdate();

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, isNot(contains('check')));
    expect(state.updateStatus, UpdateStatus.installing);
    expect(state.updateError, contains('already in progress'));
    expect(eventTypes, contains('update_action_busy'));
    expect(eventTypes, isNot(contains('update_check_started')));
  });

  test('busy silent update check does not report false check state', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    controller.state = controller.state.copyWith(
      updateStatus: UpdateStatus.verifying,
    );

    await controller.unawaitedCheckForUpdates(silent: true);

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, isNot(contains('check')));
    expect(state.updateStatus, UpdateStatus.verifying);
    expect(state.updateError, isNull);
    expect(eventTypes, isNot(contains('update_action_busy')));
    expect(eventTypes, isNot(contains('update_check_started')));
  });

  test('check failure is reported and does not stay checking', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.upToDate('0.2.16'),
      failCheck: true,
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    await container
        .read(zentorControllerProvider.notifier)
        .checkForInAppUpdate();

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, contains('check'));
    expect(state.updateStatus, UpdateStatus.failed);
    expect(state.updateError, contains('simulated check failure'));
    expect(state.errorMessage, contains('could not check for updates'));
    expect(state.updateInfo, isNull);
    expect(eventTypes, contains('update_check_started'));
    expect(eventTypes, contains('update_check_failed'));
  });

  test('check failure diagnostics are normalized before display', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.upToDate('0.2.16'),
      failCheck: true,
      checkFailureMessage: 'feed failed\x00\n\twith control text',
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    await container
        .read(zentorControllerProvider.notifier)
        .checkForInAppUpdate();

    final state = container.read(zentorControllerProvider);
    final failedEvent = state.events.firstWhere(
      (event) => event.type == 'update_check_failed',
    );
    expect(state.updateStatus, UpdateStatus.failed);
    expect(state.updateError, contains('feed failed with control text'));
    expect(state.updateError, isNot(contains('\x00')));
    expect(state.updateError, isNot(contains('\n')));
    expect(state.errorMessage, contains('feed failed with control text'));
    expect(failedEvent.details, contains('feed failed with control text'));
    expect(failedEvent.details, isNot(contains('\x00')));
    expect(failedEvent.details, isNot(contains('\n')));
  });

  test('silent check failure is still audited', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.upToDate('0.2.16'),
      failCheck: true,
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    await container
        .read(zentorControllerProvider.notifier)
        .unawaitedCheckForUpdates(silent: true);

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, contains('check'));
    expect(state.updateStatus, UpdateStatus.failed);
    expect(state.updateError, contains('simulated check failure'));
    expect(eventTypes, isNot(contains('update_check_started')));
    expect(eventTypes, contains('update_check_failed'));
  });

  test('silent failed check result is still audited', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.failed('0.2.16', 'simulated feed failure'),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    await container
        .read(zentorControllerProvider.notifier)
        .unawaitedCheckForUpdates(silent: true);

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, contains('check'));
    expect(state.updateStatus, UpdateStatus.failed);
    expect(state.updateError, 'simulated feed failure');
    expect(eventTypes, isNot(contains('update_check_started')));
    expect(eventTypes, contains('update_check_failed'));
  });

  test('rollback failure does not claim ready to restart', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
      failRollback: true,
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    await controller.checkForInAppUpdate();
    await controller.rollbackUpdateInApp(confirmed: true);

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, contains('rollback'));
    expect(state.updateStatus, UpdateStatus.failed);
    expect(state.updateError, contains('simulated rollback failure'));
    expect(state.errorMessage, contains('could not roll back'));
    expect(eventTypes, contains('update_rollback_started'));
    expect(eventTypes, contains('update_rollback_failed'));
    expect(eventTypes, isNot(contains('update_rollback_ready')));
  });

  test('unsupported rollback does not call update service', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(
        _update(localPackagePath: null, rollbackSupported: false),
      ),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    await controller.checkForInAppUpdate();
    await controller.rollbackUpdateInApp();

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, isNot(contains('rollback')));
    expect(state.updateStatus, UpdateStatus.failed);
    expect(state.updateError, contains('Rollback is not available'));
    expect(eventTypes, contains('update_rollback_unavailable'));
    expect(eventTypes, isNot(contains('update_rollback_started')));
  });

  test('busy rollback action does not call update service', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.available(_update(localPackagePath: null)),
    );

    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(_FakeScanTargetService()),
        updateServiceProvider.overrideWithValue(updateService),
      ],
    );
    addTearDown(container.dispose);
    await _waitForStartupUpdateIdle(container, updateService);

    final controller = container.read(zentorControllerProvider.notifier);
    await controller.checkForInAppUpdate();
    controller.state = controller.state.copyWith(
      updateStatus: UpdateStatus.installing,
    );

    await controller.rollbackUpdateInApp();

    final state = container.read(zentorControllerProvider);
    final eventTypes = state.events.map((event) => event.type);
    expect(updateService.calls, isNot(contains('rollback')));
    expect(state.updateStatus, UpdateStatus.installing);
    expect(state.updateError, contains('already in progress'));
    expect(eventTypes, contains('update_action_busy'));
    expect(eventTypes, isNot(contains('update_rollback_started')));
  });

  test('source marker: install started event precedes updater launch', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final installMethod = source.substring(
      source.indexOf('Future<void> installUpdateInApp'),
      source.indexOf('Future<void> rollbackUpdateInApp'),
    );

    expect(
      installMethod.indexOf("'update_install_started'"),
      lessThan(installMethod.indexOf('installDownloadedPackage(downloaded)')),
    );
    expect(
      installMethod.indexOf('installDownloadedPackage(downloaded)'),
      lessThan(installMethod.indexOf("'update_install_ready'")),
    );
  });

  test('source marker: install action is guarded when update is busy', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final installMethod = source.substring(
      source.indexOf('Future<void> installUpdateInApp'),
      source.indexOf('Future<void> rollbackUpdateInApp'),
    );

    expect(installMethod, contains('_isUpdateOperationBusy'));
    expect(installMethod, contains('update_action_busy'));
    expect(
      installMethod.indexOf('_isUpdateOperationBusy'),
      lessThan(installMethod.indexOf('downloadUpdatePackage(update)')),
    );
    expect(source, contains('UpdateStatus.downloading'));
    expect(source, contains('UpdateStatus.verifying'));
    expect(source, contains('UpdateStatus.installing'));
    expect(source, contains('UpdateStatus.rollingBack'));
  });

  test('source marker: update mutations block active security work', () {
    final source = readNormalizedSource('lib/app/app_state.dart');
    final installMethod = source.substring(
      source.indexOf('Future<void> installUpdateInApp'),
      source.indexOf('Future<void> rollbackUpdateInApp'),
    );
    final rollbackMethod = source.substring(
      source.indexOf('Future<void> rollbackUpdateInApp'),
      source.indexOf('bool _isUpdateOperationBusy'),
    );
    final helperStart = source.indexOf(
      'Future<bool> _rejectUpdateMutationDuringActiveWork',
    );
    final helper = source.substring(
      helperStart,
      source.indexOf('Future<bool> saveDeveloperCloudOverride', helperStart),
    );

    expect(
      installMethod,
      contains(
        "_rejectUpdateMutationDuringActiveWork(\n      'Update installation cannot run'",
      ),
    );
    expect(
      rollbackMethod,
      contains(
        "_rejectUpdateMutationDuringActiveWork(\n      'Update rollback cannot run'",
      ),
    );
    expect(helper, contains('String? _updateMutationBusyReason'));
    expect(helper, contains('_configurationResetRequiresProtectionStop()'));
    expect(helper, contains('_scanBusyReasonForConfigurationMutation(prefix)'));
    expect(helper, contains('state.serviceActionInFlight'));
    expect(helper, contains('state.developerCloudOverrideInFlight'));
    expect(helper, contains('state.protectedAppActionInFlight'));
    expect(helper, contains('_manualDispositionBusyReason(prefix)'));
    expect(helper, contains('update_action_busy'));
    expect(helper, contains("category: 'update'"));
    expect(helper, contains("severity: 'warning'"));
    expect(
      installMethod.indexOf('_rejectUpdateMutationDuringActiveWork'),
      lessThan(installMethod.indexOf('downloadUpdatePackage(update)')),
    );
    expect(
      rollbackMethod.indexOf('_rejectUpdateMutationDuringActiveWork'),
      lessThan(rollbackMethod.indexOf('rollbackPreviousVersion()')),
    );
  });

  test('source marker: update install requires explicit confirmation', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final updateController = File(
      'lib/features/update/update_controller.dart',
    ).readAsStringSync();
    final installMethod = source.substring(
      source.indexOf('Future<void> installUpdateInApp'),
      source.indexOf('Future<void> rollbackUpdateInApp'),
    );

    expect(installMethod, contains('{bool confirmed = false}'));
    expect(installMethod, contains('if (!confirmed)'));
    expect(installMethod, contains('requires explicit confirmation'));
    expect(installMethod, contains('update_install_confirmation_required'));
    expect(
      installMethod.indexOf('if (!confirmed)'),
      lessThan(installMethod.indexOf('downloadUpdatePackage(update)')),
    );
    expect(
      updateController,
      contains('downloadVerifyAndInstallUpdate({bool confirmed = false})'),
    );
    expect(
      updateController,
      contains('installUpdateInApp(confirmed: confirmed)'),
    );
  });

  test('source marker: update install UI requires confirmation', () {
    final confirmation = File(
      'lib/features/update/update_confirmation.dart',
    ).readAsStringSync();
    final updateSource = File(
      'lib/features/update/update_screen.dart',
    ).readAsStringSync();
    final homeSource = File(
      'lib/features/home/home_screen.dart',
    ).readAsStringSync();
    final settingsSource = File(
      'lib/features/settings/settings_screen.dart',
    ).readAsStringSync();

    expect(confirmation, contains('Download, verify, and install update?'));
    expect(confirmation, contains('signed .aup package'));
    expect(confirmation, contains('Avorax Update Service'));
    expect(confirmation, contains('Windows administrator prompt'));
    expect(updateSource, contains('confirmInstallUpdate(context)'));
    expect(homeSource, contains('confirmInstallUpdate(context)'));
    expect(settingsSource, contains('confirmInstallUpdate(context)'));
    expect(updateSource, contains('confirmed: true'));
    expect(homeSource, contains('confirmed: true'));
    expect(settingsSource, contains('confirmed: true'));
    expect(
      updateSource,
      isNot(contains(': controller.downloadVerifyAndInstallUpdate')),
    );
    expect(homeSource, isNot(contains(': controller.installUpdateInApp')));
    expect(settingsSource, isNot(contains(': controller.installUpdateInApp')));
  });

  test('source marker: update checks are guarded when update is busy', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final checkMethod = source.substring(
      source.indexOf('Future<void> unawaitedCheckForUpdates'),
      source.indexOf('Future<void> installUpdateInApp'),
    );

    expect(checkMethod, contains('_isUpdateOperationBusy'));
    expect(checkMethod, contains('if (!silent)'));
    expect(checkMethod, contains('update_action_busy'));
    expect(
      checkMethod.indexOf('_isUpdateOperationBusy'),
      lessThan(checkMethod.indexOf('update_check_started')),
    );
  });

  test(
    'source marker: update controller exception diagnostics are bounded',
    () {
      final source = File('lib/app/app_state.dart').readAsStringSync();
      final helper = source.substring(
        source.indexOf('String _boundedUpdateUiError'),
        source.indexOf('final zentorControllerProvider'),
      );
      final checkMethod = source.substring(
        source.indexOf('Future<void> unawaitedCheckForUpdates'),
        source.indexOf('Future<void> installUpdateInApp'),
      );
      final installMethod = source.substring(
        source.indexOf('Future<void> installUpdateInApp'),
        source.indexOf('Future<void> rollbackUpdateInApp'),
      );
      final rollbackMethod = source.substring(
        source.indexOf('Future<void> rollbackUpdateInApp'),
        source.indexOf('Future<bool> saveDeveloperCloudOverride'),
      );

      expect(source, contains('String _boundedUiDiagnostic'));
      expect(source, contains('const int _maxUiDiagnosticChars = 2048'));
      expect(source, contains('substring(0, _maxUiDiagnosticChars - 3)'));
      expect(
        helper,
        contains(
          "_boundedUiDiagnostic(error, fallback: 'Update operation failed.')",
        ),
      );
      expect(
        checkMethod,
        contains('final details = _boundedUpdateUiError(error)'),
      );
      expect(
        installMethod,
        contains('final details = _boundedUpdateUiError(error)'),
      );
      expect(
        rollbackMethod,
        contains('final details = _boundedUpdateUiError(error)'),
      );
      expect(checkMethod, contains('updateError: details'));
      expect(installMethod, contains('updateError: details'));
      expect(rollbackMethod, contains('updateError: details'));
      expect(checkMethod, contains('details: details'));
      expect(installMethod, contains('details: details'));
      expect(rollbackMethod, contains('details: details'));
      expect(checkMethod, isNot(contains(r"updateError: '$error'")));
      expect(installMethod, isNot(contains(r"updateError: '$error'")));
      expect(rollbackMethod, isNot(contains(r"updateError: '$error'")));
    },
  );

  test(
    'source marker: settings update controls disable when update is busy',
    () {
      final source = File(
        'lib/features/settings/settings_screen.dart',
      ).readAsStringSync();
      final updateBusyBlock = source.substring(
        source.indexOf('final updateBusy ='),
        source.indexOf('return Column('),
      );

      expect(updateBusyBlock, contains('UpdateStatus.checking'));
      expect(updateBusyBlock, contains('UpdateStatus.downloading'));
      expect(updateBusyBlock, contains('UpdateStatus.verifying'));
      expect(updateBusyBlock, contains('UpdateStatus.installing'));
      expect(updateBusyBlock, contains('UpdateStatus.rollingBack'));
      expect(source, contains('onPressed: updateBusy'));
    },
  );

  test('source marker: home update-available copy is not pre-verified', () {
    final source = File(
      'lib/features/home/home_screen.dart',
    ).readAsStringSync();
    final heroCopyMethod = source.substring(
      source.indexOf('String _heroCopy'),
      source.indexOf('Color _mainColor'),
    );

    expect(
      heroCopyMethod,
      contains('Download and verify it before installation'),
    );
    expect(heroCopyMethod, isNot(contains('A verified update is available')));
  });

  test('source marker: update actions name verification step', () {
    final homeSource = readNormalizedSource(
      'lib/features/home/home_screen.dart',
    );
    final settingsSource = readNormalizedSource(
      'lib/features/settings/settings_screen.dart',
    );
    final homeUpdateDetail = homeSource.substring(
      homeSource.indexOf('String _updateDetail'),
      homeSource.indexOf('}\n}\n\nString _lastScanDetail'),
    );

    expect(homeSource, contains('Download, verify, install'));
    expect(homeUpdateDetail, contains('Download, verify, and install'));
    expect(settingsSource, contains('Download, verify, install'));
    expect(settingsSource, isNot(contains('Download and install')));
    expect(homeSource, isNot(contains("'Install update'")));
  });

  test('source marker: rollback control is disabled when unsupported', () {
    final source = File(
      'lib/features/update/update_screen.dart',
    ).readAsStringSync();

    expect(source, contains('model.rollbackSupported == true'));
    expect(source, contains('Rollback status unknown'));
    expect(source, contains('Rollback unavailable'));
    expect(source, contains('rollbackEnabled'));
    expect(source, contains('controller.rollbackUpdateInApp'));
    expect(source, contains('confirmRollbackUpdate(context)'));
    expect(source, contains('confirmed: true'));
    expect(source, contains(': null'));
  });

  test('source marker: rollback requires explicit confirmation', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final confirmation = File(
      'lib/features/update/update_confirmation.dart',
    ).readAsStringSync();
    final updateSource = File(
      'lib/features/update/update_screen.dart',
    ).readAsStringSync();
    final rollbackMethod = source.substring(
      source.indexOf('Future<void> rollbackUpdateInApp'),
      source.indexOf('Future<bool> saveDeveloperCloudOverride'),
    );

    expect(rollbackMethod, contains('{bool confirmed = false}'));
    expect(rollbackMethod, contains('if (!confirmed)'));
    expect(rollbackMethod, contains('requires explicit confirmation'));
    expect(rollbackMethod, contains('update_rollback_confirmation_required'));
    expect(
      rollbackMethod.indexOf('if (!confirmed)'),
      lessThan(rollbackMethod.indexOf('rollbackPreviousVersion()')),
    );
    expect(confirmation, contains('Rollback previous version?'));
    expect(confirmation, contains('local rollback snapshot'));
    expect(confirmation, contains('Windows administrator prompt'));
    expect(updateSource, contains('confirmRollbackUpdate(context)'));
    expect(updateSource, contains('rollbackUpdateInApp(confirmed: true)'));
    expect(updateSource, isNot(contains(': controller.rollbackUpdateInApp')));
  });

  test('source marker: rollback action is guarded in controller', () {
    final source = File('lib/app/app_state.dart').readAsStringSync();
    final rollbackMethod = source.substring(
      source.indexOf('Future<void> rollbackUpdateInApp'),
      source.indexOf('Future<bool> saveDeveloperCloudOverride'),
    );

    expect(
      rollbackMethod,
      contains('state.updateInfo?.rollbackSupported != true'),
    );
    expect(rollbackMethod, contains('_isUpdateOperationBusy'));
    expect(rollbackMethod, contains('update_action_busy'));
    expect(rollbackMethod, contains('update_rollback_unavailable'));
    expect(
      rollbackMethod.indexOf('_isUpdateOperationBusy'),
      lessThan(
        rollbackMethod.indexOf('state.updateInfo?.rollbackSupported != true'),
      ),
    );
    expect(
      rollbackMethod.indexOf('state.updateInfo?.rollbackSupported != true'),
      lessThan(rollbackMethod.indexOf('rollbackPreviousVersion()')),
    );
  });
}

UpdateInfo _update({
  required String? localPackagePath,
  bool rollbackSupported = true,
}) => UpdateInfo(
  currentVersion: '0.2.15',
  latestVersion: '0.2.16',
  feedUrl: Uri.parse(
    'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
  ),
  packageUrl: Uri.parse(
    'https://github.com/brentishere41848/Avorax/releases/download/v0.2.16/Avorax-AntiVirus-0.2.16.aup',
  ),
  packageSha256: 'a' * 64,
  channel: 'dev',
  rollbackSupported: rollbackSupported,
  packageName: 'Avorax-AntiVirus-0.2.16.aup',
  releaseNotes: 'In-app updater test',
  localPackagePath: localPackagePath,
);

Future<void> _waitForStartupUpdateIdle(
  ProviderContainer container,
  _FakeUpdateService updateService,
) async {
  for (var attempt = 0; attempt < 50; attempt += 1) {
    await Future<void>.delayed(Duration.zero);
    if (!container.read(zentorControllerProvider).updateOperationInFlight) {
      updateService.calls.clear();
      return;
    }
  }
  updateService.calls.clear();
}

void _expectUpdateEventMetadata(
  ZentorState state,
  String type,
  String severity,
) {
  final event = state.events.lastWhere((event) => event.type == type);
  expect(event.category, 'update');
  expect(event.severity, severity);
}

class _FakeUpdateService extends ZentorUpdateService {
  _FakeUpdateService({
    required this.checkResult,
    this.failCheck = false,
    this.checkFailureMessage = 'simulated check failure',
    this.failDownload = false,
    this.downloadFailureMessage = 'simulated download failure',
    this.failVerify = false,
    this.verifyFailureMessage = 'simulated verify failure',
    this.failInstall = false,
    this.installFailureMessage = 'simulated install failure',
    this.failRollback = false,
    this.rollbackFailureMessage = 'simulated rollback failure',
    this.mutationSupported = true,
  });

  final UpdateCheckResult checkResult;
  final bool failCheck;
  final String checkFailureMessage;
  final bool failDownload;
  final String downloadFailureMessage;
  final bool failVerify;
  final String verifyFailureMessage;
  final bool failInstall;
  final String installFailureMessage;
  final bool failRollback;
  final String rollbackFailureMessage;
  final bool mutationSupported;
  Completer<UpdateCheckResult>? pendingCheck;
  final calls = <String>[];

  @override
  bool get packageMutationSupported => mutationSupported;

  @override
  Future<UpdateCheckResult> checkForUpdate({String? currentVersion}) async {
    calls.add('check');
    final pending = pendingCheck;
    if (pending != null) return pending.future;
    if (failCheck) {
      throw StateError(checkFailureMessage);
    }
    return checkResult;
  }

  @override
  Future<UpdateInfo> downloadUpdatePackage(UpdateInfo update) async {
    calls.add('download');
    if (failDownload) {
      throw StateError(downloadFailureMessage);
    }
    return update.copyWith(
      localPackagePath:
          '${Directory.systemTemp.path}${Platform.pathSeparator}${update.packageName}',
    );
  }

  @override
  Future<void> verifyDownloadedPackage(UpdateInfo update) async {
    calls.add('verify');
    if (failVerify) {
      throw StateError(verifyFailureMessage);
    }
  }

  @override
  Future<void> installDownloadedPackage(UpdateInfo update) async {
    calls.add('install');
    if (failInstall) {
      throw StateError(installFailureMessage);
    }
  }

  @override
  Future<void> rollbackPreviousVersion() async {
    calls.add('rollback');
    if (failRollback) {
      throw StateError(rollbackFailureMessage);
    }
  }
}

class _FakeLocalCoreClient extends LocalCoreClient {
  @override
  Future<MalwareEngineStatus> health() async => MalwareEngineStatus.available;

  @override
  Future<LocalCoreHealth> healthSummary() async => const LocalCoreHealth(
    malwareEngineStatus: MalwareEngineStatus.available,
    coreServiceStatus: 'running',
    guardStatus: 'running',
  );

  @override
  Future<List<QuarantineRecord>> listQuarantine() async => const [];
}

class _FakeScanTargetService extends ScanTargetService {
  @override
  List<String> quickScanTargets({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => const [];

  @override
  ScanTargetPlan quickScanTargetPlan({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => const ScanTargetPlan([], []);

  @override
  List<String> fullScanRoots({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => const [];

  @override
  ScanTargetPlan fullScanRootPlan({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => const ScanTargetPlan([], []);
}
