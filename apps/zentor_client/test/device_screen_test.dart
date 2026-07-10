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
import 'package:zentor_client/features/device/device_screen.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

void main() {
  testWidgets('device health cards render platform and protection evidence', (
    tester,
  ) async {
    const state = ZentorState(
      nativeEngineStatus: 'ready',
      nativeSignatureCount: 42,
      nativeRuleCount: 7,
      nativeMlStatus: 'loaded',
      nativeMlProductionReady: true,
      guardStatus: 'running',
      driverStatus: 'stopped',
    );

    await _pumpDeviceScreen(tester, state, _deviceSummary());

    for (final title in const [
      'Device & Protection Health',
      'System',
      'Hardware',
      'App version',
      'Privacy',
      'Avorax Services',
      'Avorax Native Engine',
      'Real-time Protection',
      'Permissions',
    ]) {
      expect(find.text(title), findsOneWidget);
    }
    expect(find.text('Windows'), findsOneWidget);
    expect(find.text('x64'), findsOneWidget);
    expect(find.text('1.2.3+4'), findsOneWidget);
    expect(find.text('Available'), findsOneWidget);
    expect(find.text('Running'), findsWidgets);
    expect(find.text('Ready'), findsOneWidget);
    expect(find.textContaining('42 signatures, 7 rules'), findsOneWidget);
    expect(find.textContaining('Native ML: Loaded'), findsOneWidget);
    expect(
      find.textContaining('Native ML production-ready: yes'),
      findsOneWidget,
    );
    expect(find.textContaining('Driver: Stopped'), findsOneWidget);
    expect(
      find.textContaining(
        'Pre-execution blocking is active only after driver self-test passes.',
      ),
      findsOneWidget,
    );
    expect(
      find.textContaining('Raw identifiers are not stored'),
      findsOneWidget,
    );
    expect(find.textContaining('Core: running'), findsOneWidget);
    expect(find.textContaining('Guard: stopped'), findsOneWidget);
    expect(find.textContaining('Update: missing'), findsOneWidget);
    expect(find.text('User mode'), findsOneWidget);
    expect(find.textContaining('Current user: fixture-user'), findsOneWidget);
  });

  testWidgets('device platform errors are bounded and control-normalized', (
    tester,
  ) async {
    await _pumpDeviceScreenError(
      tester,
      StateError('platform failed\x00\n\twith control text'),
    );

    expect(find.text('Device & Protection Health'), findsOneWidget);
    expect(find.text('Unable to read platform info'), findsOneWidget);
    expect(
      find.textContaining('Bad state: platform failed with control text'),
      findsOneWidget,
    );
    expect(find.textContaining('\x00'), findsNothing);
    expect(find.textContaining('\n\t'), findsNothing);
  });
}

Future<void> _pumpDeviceScreen(
  WidgetTester tester,
  ZentorState state,
  DeviceIntegritySummary summary,
) async {
  await _withViewport(tester);
  SharedPreferences.setMockInitialValues({});
  final preferences = await SharedPreferences.getInstance();
  final controller = _controller(preferences)..state = state;

  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        zentorControllerProvider.overrideWith((ref) => controller),
        deviceSummaryProvider.overrideWith((ref) async => summary),
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

Future<void> _pumpDeviceScreenError(WidgetTester tester, Object error) async {
  await _withViewport(tester);
  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        deviceSummaryProvider.overrideWith((ref) async => throw error),
      ],
      child: MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(body: DeviceScreen()),
      ),
    ),
  );
  await tester.pump();
}

Future<void> _withViewport(WidgetTester tester) async {
  tester.view.physicalSize = const Size(1400, 2200);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
}

ZentorController _controller(SharedPreferences preferences) => ZentorController(
  configRepository: ConfigRepository(preferences),
  eventRepository: LocalEventRepository(preferences),
  apiClient: ZentorApiClient(),
  hashService: HashService(),
  appDetector: const _FakeAppDetector(),
  localCoreClient: const LocalCoreClient(),
  scanTargetService: const ScanTargetService(),
  updateService: ZentorUpdateService(),
);

DeviceIntegritySummary _deviceSummary() => const DeviceIntegritySummary(
  platform: 'Windows',
  appVersion: '1.2.3+4',
  osVersion: 'Windows fixture',
  deviceIdentifierHashStatus: 'Available',
  localCoreStatus: 'Running',
  permissionsStatus: 'User mode',
  hostName: 'fixture-host',
  userName: 'fixture-user',
  executablePath: r'C:\Program Files\Avorax\Avorax.exe',
  systemArchitecture: 'x64',
  processorCount: 8,
  totalPhysicalMemory: '16 GB',
  serviceStates: {
    'avorax_core_service': 'running',
    'avorax_guard_service': 'stopped',
    'avorax_update_service': 'missing',
  },
);
