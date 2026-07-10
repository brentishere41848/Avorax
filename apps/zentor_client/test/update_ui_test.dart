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
import 'package:zentor_client/core/network/zentor_api_client.dart';
import 'package:zentor_client/core/scanning/scan_target_service.dart';
import 'package:zentor_client/core/security/hash_service.dart';
import 'package:zentor_client/core/updates/update_service.dart';
import 'package:zentor_client/features/home/home_screen.dart';
import 'package:zentor_client/features/update/update_models.dart';
import 'package:zentor_client/features/update/update_screen.dart';
import 'package:zentor_client/features/update/widgets/update_status_rows.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

void main() {
  testWidgets('update status rows keep unknown rollback support explicit', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(
          body: UpdateStatusRows(
            model: UpdateViewModel(
              status: UpdateStatus.updateAvailable,
              currentVersion: '0.2.15',
              latestVersion: '0.2.16',
              rollbackSupported: null,
            ),
          ),
        ),
      ),
    );

    expect(find.text('Rollback: Unknown'), findsOneWidget);
    expect(find.text('Rollback: Available'), findsNothing);
    expect(find.text('Rollback: Unavailable'), findsNothing);
  });

  testWidgets('update status rows distinguish rollback availability', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(
          body: Column(
            children: [
              UpdateStatusRows(
                model: UpdateViewModel(
                  status: UpdateStatus.updateAvailable,
                  currentVersion: '0.2.15',
                  rollbackSupported: false,
                ),
              ),
              UpdateStatusRows(
                model: UpdateViewModel(
                  status: UpdateStatus.updateAvailable,
                  currentVersion: '0.2.15',
                  rollbackSupported: true,
                ),
              ),
            ],
          ),
        ),
      ),
    );

    expect(find.text('Rollback: Unavailable'), findsOneWidget);
    expect(find.text('Rollback: Available'), findsOneWidget);
  });

  testWidgets('unsupported package mutation is shown as manual reinstall', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(
          body: UpdateStatusRows(
            model: UpdateViewModel(
              status: UpdateStatus.updateAvailable,
              currentVersion: '0.2.15',
              packageMutationSupported: false,
            ),
          ),
        ),
      ),
    );

    expect(find.text('Package apply: Manual reinstall only'), findsOneWidget);
  });

  testWidgets(
    'update screen hides package mutation commands when unsupported',
    (tester) async {
      final controller = await _controllerWithUpdate(
        rollbackSupported: true,
        updateService: _RecordingUpdateService(mutationSupported: false),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            zentorControllerProvider.overrideWith((ref) => controller),
          ],
          child: MaterialApp(
            theme: ZentorTheme.dark(),
            home: const Scaffold(
              body: SingleChildScrollView(child: UpdateScreen()),
            ),
          ),
        ),
      );

      expect(find.text('Manual package reinstall required'), findsOneWidget);
      expect(find.text('Download, verify, install'), findsNothing);
      expect(find.text('Rollback previous version'), findsNothing);
    },
  );

  testWidgets('update screen disables rollback unless explicitly supported', (
    tester,
  ) async {
    for (final scenario in <({bool? supported, String label, bool enabled})>[
      (supported: null, label: 'Rollback status unknown', enabled: false),
      (supported: false, label: 'Rollback unavailable', enabled: false),
      (supported: true, label: 'Rollback previous version', enabled: true),
    ]) {
      final controller = await _controllerWithUpdate(
        rollbackSupported: scenario.supported,
      );

      await tester.pumpWidget(
        ProviderScope(
          key: UniqueKey(),
          overrides: [
            zentorControllerProvider.overrideWith((ref) => controller),
          ],
          child: MaterialApp(
            theme: ZentorTheme.dark(),
            home: const Scaffold(
              body: SingleChildScrollView(child: UpdateScreen()),
            ),
          ),
        ),
      );

      expect(find.text(scenario.label), findsOneWidget);
      final button = tester
          .widgetList<OutlinedButton>(find.byType(OutlinedButton))
          .last;
      expect(button.onPressed, scenario.enabled ? isNotNull : isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    }
  });

  testWidgets(
    'update mutation buttons disable while active security work is busy',
    (tester) async {
      for (final state in const [
        ZentorState(scanStatus: ScanStatus.running),
        ZentorState(protectionStatus: ProtectionStatus.protected),
        ZentorState(configurationResetInFlight: true),
        ZentorState(serviceActionInFlight: true),
        ZentorState(developerCloudOverrideInFlight: true),
        ZentorState(protectedAppActionInFlight: true),
      ]) {
        final controller = await _controllerWithUpdate(rollbackSupported: true);
        controller.state = controller.state.copyWith(
          scanStatus: state.scanStatus,
          protectionStatus: state.protectionStatus,
          configurationResetInFlight: state.configurationResetInFlight,
          serviceActionInFlight: state.serviceActionInFlight,
          developerCloudOverrideInFlight: state.developerCloudOverrideInFlight,
          protectedAppActionInFlight: state.protectedAppActionInFlight,
        );

        await tester.pumpWidget(
          ProviderScope(
            key: UniqueKey(),
            overrides: [
              zentorControllerProvider.overrideWith((ref) => controller),
            ],
            child: MaterialApp(
              theme: ZentorTheme.dark(),
              home: const Scaffold(
                body: SingleChildScrollView(child: UpdateScreen()),
              ),
            ),
          ),
        );

        final installButton = find.widgetWithText(
          FilledButton,
          'Download, verify, install',
        );
        final rollbackButton = find.widgetWithText(
          OutlinedButton,
          'Rollback previous version',
        );

        expect(installButton, findsOneWidget);
        expect(rollbackButton, findsOneWidget);
        expect(tester.widget<FilledButton>(installButton).onPressed, isNull);
        expect(tester.widget<OutlinedButton>(rollbackButton).onPressed, isNull);
        await tester.pumpWidget(const SizedBox.shrink());
      }
    },
  );

  testWidgets('home update copy requires download and verify before install', (
    tester,
  ) async {
    final controller = await _controllerWithUpdate(rollbackSupported: true);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: HomeScreen()),
          ),
        ),
      ),
    );

    expect(
      find.textContaining('Download and verify it before installation'),
      findsOneWidget,
    );
    expect(find.text('Download, verify, install'), findsOneWidget);
    expect(
      find.textContaining(
        'Download, verify, and install it from inside Avorax',
      ),
      findsOneWidget,
    );
    expect(find.textContaining('A verified update is available'), findsNothing);
    expect(find.text('Install update'), findsNothing);
  });

  testWidgets('update check button runs update service once', (tester) async {
    final updateService = _RecordingUpdateService();
    final controller = await _controllerWithUpdate(
      rollbackSupported: false,
      updateService: updateService,
      initialStatus: UpdateStatus.notChecked,
      initialUpdate: null,
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: UpdateScreen()),
          ),
        ),
      ),
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Check for updates'));
    await tester.pumpAndSettle();

    expect(updateService.calls, ['check']);
    expect(controller.state.updateStatus, UpdateStatus.updateAvailable);
    expect(controller.state.updateInfo?.latestVersion, '0.2.16');
    expect(find.text('Status: Update available'), findsOneWidget);
    expect(
      controller.state.events.map((event) => event.type),
      containsAll(['update_check_started', 'update_available']),
    );
  });

  testWidgets('home update install disables while scan is running', (
    tester,
  ) async {
    final controller = await _controllerWithUpdate(rollbackSupported: true);
    controller.state = controller.state.copyWith(
      scanStatus: ScanStatus.running,
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: HomeScreen()),
          ),
        ),
      ),
    );

    final installButton = find.widgetWithText(
      OutlinedButton,
      'Download, verify, install',
    );

    expect(installButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(installButton).onPressed, isNull);
  });

  testWidgets('update check button is disabled while update busy', (
    tester,
  ) async {
    final updateService = _RecordingUpdateService();
    final controller = await _controllerWithUpdate(
      rollbackSupported: false,
      updateService: updateService,
      initialStatus: UpdateStatus.checking,
      initialUpdate: null,
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: UpdateScreen()),
          ),
        ),
      ),
    );

    final checkButton = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Checking'),
    );

    expect(checkButton.onPressed, isNull);
    expect(updateService.calls, isEmpty);
  });

  testWidgets('update install dialog cancel does not call update service', (
    tester,
  ) async {
    final updateService = _RecordingUpdateService();
    final controller = await _controllerWithUpdate(
      rollbackSupported: true,
      updateService: updateService,
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: UpdateScreen()),
          ),
        ),
      ),
    );

    await tester.tap(
      find.widgetWithText(FilledButton, 'Download, verify, install'),
    );
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

  testWidgets('update install dialog confirm runs update service once', (
    tester,
  ) async {
    final updateService = _RecordingUpdateService();
    final controller = await _controllerWithUpdate(
      rollbackSupported: true,
      updateService: updateService,
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: UpdateScreen()),
          ),
        ),
      ),
    );

    await tester.tap(
      find.widgetWithText(FilledButton, 'Download, verify, install'),
    );
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

  testWidgets('update rollback dialog cancel does not call update service', (
    tester,
  ) async {
    final updateService = _RecordingUpdateService();
    final controller = await _controllerWithUpdate(
      rollbackSupported: true,
      updateService: updateService,
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: UpdateScreen()),
          ),
        ),
      ),
    );

    await tester.tap(
      find.widgetWithText(OutlinedButton, 'Rollback previous version'),
    );
    await tester.pumpAndSettle();

    expect(find.text('Rollback previous version?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(updateService.calls, isEmpty);
    expect(controller.state.updateStatus, UpdateStatus.updateAvailable);
    expect(
      controller.state.events.where(
        (event) => event.type == 'update_rollback_started',
      ),
      isEmpty,
    );
  });

  testWidgets('update rollback dialog confirm runs update service once', (
    tester,
  ) async {
    final updateService = _RecordingUpdateService();
    final controller = await _controllerWithUpdate(
      rollbackSupported: true,
      updateService: updateService,
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const Scaffold(
            body: SingleChildScrollView(child: UpdateScreen()),
          ),
        ),
      ),
    );

    await tester.tap(
      find.widgetWithText(OutlinedButton, 'Rollback previous version'),
    );
    await tester.pumpAndSettle();

    expect(find.text('Rollback previous version?'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Rollback'));
    await tester.pumpAndSettle();

    expect(updateService.calls, ['rollback']);
    expect(controller.state.updateStatus, UpdateStatus.readyToRestart);
    expect(
      controller.state.events.map((event) => event.type),
      containsAll(['update_rollback_started', 'update_rollback_ready']),
    );
  });
}

Future<ZentorController> _controllerWithUpdate({
  required bool? rollbackSupported,
  ZentorUpdateService? updateService,
  UpdateStatus initialStatus = UpdateStatus.updateAvailable,
  UpdateInfo? initialUpdate,
}) async {
  SharedPreferences.setMockInitialValues({});
  final preferences = await SharedPreferences.getInstance();
  final controller = ZentorController(
    configRepository: ConfigRepository(preferences),
    eventRepository: LocalEventRepository(preferences),
    apiClient: ZentorApiClient(),
    hashService: HashService(),
    appDetector: const AppDetector(),
    localCoreClient: const LocalCoreClient(),
    scanTargetService: const ScanTargetService(),
    updateService: updateService ?? ZentorUpdateService(),
  );
  final update =
      initialUpdate ??
      UpdateInfo(
        currentVersion: '0.2.15',
        latestVersion: '0.2.16',
        feedUrl: Uri.parse('https://updates.example.test/feed.json'),
        packageUrl: Uri.parse('https://updates.example.test/Avorax.aup'),
        packageSha256: 'a' * 64,
        channel: 'stable',
        rollbackSupported: rollbackSupported,
        packageName: 'Avorax.aup',
        releaseNotes: null,
        localPackagePath: null,
      );
  controller.state = controller.state.copyWith(
    updateStatus: initialStatus,
    currentAppVersion: '0.2.15',
    updateInfo: initialStatus == UpdateStatus.updateAvailable ? update : null,
    clearUpdateInfo: initialStatus != UpdateStatus.updateAvailable,
  );
  return controller;
}

class _RecordingUpdateService extends ZentorUpdateService {
  _RecordingUpdateService({this.mutationSupported = true});

  final bool mutationSupported;
  final List<String> calls = [];

  @override
  bool get packageMutationSupported => mutationSupported;

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

  @override
  Future<void> rollbackPreviousVersion() async {
    calls.add('rollback');
  }
}
