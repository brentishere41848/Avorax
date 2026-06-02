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
      await Future<void>.delayed(Duration.zero);

      final controller = container.read(zentorControllerProvider.notifier);
      await controller.checkForInAppUpdate();
      expect(
        container.read(zentorControllerProvider).updateStatus,
        UpdateStatus.updateAvailable,
      );

      await controller.downloadVerifyAndInstallUpdate();

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
      expect(
        state.events.map((event) => event.type),
        containsAll(['update_install_started', 'update_install_ready']),
      );
    },
  );

  test('rollback button path runs update service rollback in app', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final updateService = _FakeUpdateService(
      checkResult: UpdateCheckResult.upToDate('0.2.16'),
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
    await Future<void>.delayed(Duration.zero);

    await container
        .read(zentorControllerProvider.notifier)
        .rollbackUpdateInApp();

    final state = container.read(zentorControllerProvider);
    expect(updateService.calls, contains('rollback'));
    expect(state.updateStatus, UpdateStatus.readyToRestart);
    expect(state.updateError, isNull);
    expect(
      state.events.map((event) => event.type),
      containsAll(['update_rollback_started', 'update_rollback_ready']),
    );
  });
}

UpdateInfo _update({required String? localPackagePath}) => UpdateInfo(
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
  rollbackSupported: true,
  packageName: 'Avorax-AntiVirus-0.2.16.aup',
  releaseNotes: 'In-app updater test',
  localPackagePath: localPackagePath,
);

class _FakeUpdateService extends ZentorUpdateService {
  _FakeUpdateService({required this.checkResult});

  final UpdateCheckResult checkResult;
  final calls = <String>[];

  @override
  Future<UpdateCheckResult> checkForUpdate({String? currentVersion}) async {
    calls.add('check');
    return checkResult;
  }

  @override
  Future<UpdateInfo> downloadUpdatePackage(UpdateInfo update) async {
    calls.add('download');
    return update.copyWith(
      localPackagePath:
          '${Directory.systemTemp.path}${Platform.pathSeparator}${update.packageName}',
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
  List<String> fullScanRoots({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => const [];
}
