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
import 'package:zentor_client/features/settings/settings_screen.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

void main() {
  testWidgets('settings native engine status rows render app-state evidence', (
    tester,
  ) async {
    const state = ZentorState(
      malwareEngineStatus: MalwareEngineStatus.available,
      nativeEngineStatus: 'ready',
      ipcMode: 'stdio',
      networkExposed: false,
      nativeSelfTestPassed: true,
      aiSelfTestPassed: false,
      aiSelfTestError: 'metadata fixture failed safely',
      programDataDirectory: r'C:\ProgramData\Avorax',
      installPath: r'C:\Program Files\Avorax',
      engineDirectory: r'C:\Program Files\Avorax\engine',
      enginePathsChecked: [
        r'C:\Program Files\Avorax\engine',
        r'C:\ProgramData\Avorax\engine',
        r'D:\portable\avorax\engine',
        r'E:\fallback\engine',
        r'F:\hidden\engine',
      ],
      nativeSignaturesDirectory: r'C:\Program Files\Avorax\engine\signatures',
      nativeRulesDirectory: r'C:\Program Files\Avorax\engine\rules',
      nativeMlDirectory: r'C:\Program Files\Avorax\engine\ml',
      nativeTrustDirectory: r'C:\ProgramData\Avorax\trust',
      nativeConfigDirectory: r'C:\ProgramData\Avorax\config',
      nativeSignatureCount: 123,
      nativeRuleCount: 17,
      compatibilityEnginesEnabled: true,
      reputationStatus: 'available',
      reputationStatusReason: 'local reputation fixture ready',
      aiStatus: AiModelStatus.developmentModel,
      nativeMlStatus: 'loaded',
      nativeMlModelVersion: 'zne-ml-fixture-2026.07',
      nativeMlProductionReady: true,
      aiModelInfo: AiModelInfo(featureSchemaVersion: 'zne-features-v2'),
      coreServiceStatus: 'running',
      coreServiceBoundaryHealth: CoreServiceBoundaryHealth(
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
        nativeSignatureCount: 123,
        nativeRuleCount: 17,
        limitations: ['mutating commands are denied'],
      ),
      guardStatus: 'monitorOnly',
      driverStatus: 'testSigned',
      protectionSelfTestResult: 'Driver self-test requires signed release host',
    );

    await _pumpSettings(tester, state);

    expect(find.text('Avorax Native Engine'), findsOneWidget);
    expect(find.text('Engine status'), findsOneWidget);
    expect(find.text('Available'), findsWidgets);
    expect(find.text('Native status'), findsOneWidget);
    expect(find.text('Ready'), findsOneWidget);
    expect(find.text('IPC'), findsOneWidget);
    expect(find.text('Local stdio'), findsOneWidget);
    expect(find.text('Network exposed'), findsOneWidget);
    expect(find.text('No'), findsWidgets);
    expect(find.text('Native self-test'), findsOneWidget);
    expect(find.text('Passed'), findsOneWidget);
    expect(find.text('AI self-test'), findsOneWidget);
    expect(find.text('Failed'), findsOneWidget);
    expect(find.text('AI self-test error'), findsOneWidget);
    expect(find.text('metadata fixture failed safely'), findsOneWidget);
    expect(find.text('ProgramData dir'), findsOneWidget);
    expect(find.text(r'C:\ProgramData\Avorax'), findsOneWidget);
    expect(find.text('Install root'), findsOneWidget);
    expect(find.text(r'C:\Program Files\Avorax'), findsOneWidget);
    expect(find.text('Engine directory'), findsOneWidget);
    expect(find.text(r'C:\Program Files\Avorax\engine'), findsWidgets);
    expect(find.text('Engine paths checked'), findsOneWidget);
    expect(find.textContaining('(+1 more)'), findsOneWidget);
    expect(find.text('Signatures dir'), findsOneWidget);
    expect(
      find.text(r'C:\Program Files\Avorax\engine\signatures'),
      findsOneWidget,
    );
    expect(find.text('Rules dir'), findsOneWidget);
    expect(find.text(r'C:\Program Files\Avorax\engine\rules'), findsOneWidget);
    expect(find.text('ML dir'), findsOneWidget);
    expect(find.text(r'C:\Program Files\Avorax\engine\ml'), findsOneWidget);
    expect(find.text('Trust dir'), findsOneWidget);
    expect(find.text(r'C:\ProgramData\Avorax\trust'), findsOneWidget);
    expect(find.text('Config dir'), findsOneWidget);
    expect(find.text(r'C:\ProgramData\Avorax\config'), findsOneWidget);
    expect(find.text('Native signatures'), findsOneWidget);
    expect(find.text('123 packaged signatures loaded'), findsOneWidget);
    expect(find.text('Native rules'), findsOneWidget);
    expect(find.text('17 packaged rules loaded'), findsOneWidget);
    expect(find.text('Compatibility engines'), findsOneWidget);
    expect(find.text('Enabled'), findsWidgets);
    expect(find.text('Reputation'), findsOneWidget);
    expect(find.text('Reputation detail'), findsOneWidget);
    expect(find.text('local reputation fixture ready'), findsOneWidget);
    expect(find.text('Native ML'), findsOneWidget);
    expect(find.text('Local AI status'), findsOneWidget);
    expect(find.text('Development model'), findsWidgets);
    expect(find.text('Model status'), findsOneWidget);
    expect(find.text('Loaded'), findsOneWidget);
    expect(find.text('Model version'), findsOneWidget);
    expect(find.text('zne-ml-fixture-2026.07'), findsOneWidget);
    expect(find.text('Feature schema'), findsOneWidget);
    expect(find.text('zne-features-v2'), findsOneWidget);
    expect(find.text('Production-ready'), findsOneWidget);
    expect(find.text('Yes'), findsOneWidget);
    expect(find.text('Core Service'), findsOneWidget);
    expect(find.text('Core Service IPC'), findsOneWidget);
    expect(find.text('Authenticated and ready'), findsOneWidget);
    expect(find.text('Guard mode'), findsOneWidget);
    expect(find.text('Monitor only'), findsOneWidget);
    expect(find.text('Driver status'), findsOneWidget);
    expect(find.text('Test-signed'), findsOneWidget);
    expect(find.text('Last self-test'), findsOneWidget);
  });
}

Future<void> _pumpSettings(WidgetTester tester, ZentorState state) async {
  tester.view.physicalSize = const Size(1800, 5200);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

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
  )..state = state;

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
}
