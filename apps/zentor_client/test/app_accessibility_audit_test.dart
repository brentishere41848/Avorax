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
import 'package:zentor_client/features/allowlist/allowlist_screen.dart';
import 'package:zentor_client/features/device/device_screen.dart';
import 'package:zentor_client/features/home/home_screen.dart';
import 'package:zentor_client/features/logs/logs_screen.dart';
import 'package:zentor_client/features/onboarding/onboarding_screen.dart';
import 'package:zentor_client/features/privacy/privacy_screen.dart';
import 'package:zentor_client/features/protection/protection_screen.dart';
import 'package:zentor_client/features/quarantine/quarantine_screen.dart';
import 'package:zentor_client/features/scan/scan_screen.dart';
import 'package:zentor_client/features/settings/settings_screen.dart';
import 'package:zentor_client/features/update/update_screen.dart';
import 'package:zentor_client/shared/widgets/zentor_shell.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

const _routes = <String, Widget>{
  '/home': HomeScreen(),
  '/scan': ScanScreen(),
  '/protection': ProtectionScreen(),
  '/quarantine': QuarantineScreen(),
  '/allowlist': AllowlistScreen(),
  '/logs': LogsScreen(),
  '/device': DeviceScreen(),
  '/updates': UpdateScreen(),
  '/settings': SettingsScreen(),
  '/privacy': PrivacyScreen(),
};

void main() {
  for (final entry in _routes.entries) {
    testWidgets(
      '${entry.key} labels tap targets and keeps Android target sizes',
      (tester) async {
        final semantics = tester.ensureSemantics();
        try {
          await _pumpScreen(
            tester,
            location: entry.key,
            screen: entry.value,
            viewport: const Size(1600, 2600),
          );

          await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
          await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
        } finally {
          semantics.dispose();
        }
      },
    );

    testWidgets('${entry.key} remains layout-safe at 200 percent mobile text', (
      tester,
    ) async {
      await _pumpScreen(
        tester,
        location: entry.key,
        screen: entry.value,
        viewport: const Size(480, 2400),
        textScale: 2,
      );

      expect(tester.takeException(), isNull);
      expect(
        find.bySemanticsLabel(_mainContentLabel(entry.key)),
        findsOneWidget,
      );
    });
  }

  testWidgets('onboarding labels tap targets and scales without overflow', (
    tester,
  ) async {
    final semantics = tester.ensureSemantics();
    try {
      await _pumpScreen(
        tester,
        location: '/onboarding',
        screen: const OnboardingScreen(),
        viewport: const Size(480, 1800),
        textScale: 2,
        useShell: false,
      );

      expect(tester.takeException(), isNull);
      await expectLater(tester, meetsGuideline(labeledTapTargetGuideline));
      await expectLater(tester, meetsGuideline(androidTapTargetGuideline));
    } finally {
      semantics.dispose();
    }
  });
}

Future<void> _pumpScreen(
  WidgetTester tester, {
  required String location,
  required Widget screen,
  required Size viewport,
  double textScale = 1,
  bool useShell = true,
}) async {
  tester.view.physicalSize = viewport;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  SharedPreferences.setMockInitialValues({});
  final preferences = await SharedPreferences.getInstance();
  final controller = _controller(preferences);
  final body = useShell
      ? ZentorShell(location: location, child: screen)
      : screen;

  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        appDetectorProvider.overrideWithValue(const _FakeAppDetector()),
        zentorControllerProvider.overrideWith((ref) => controller),
        deviceSummaryProvider.overrideWith((ref) async => _deviceSummary),
      ],
      child: MaterialApp(
        theme: ZentorTheme.dark(),
        builder: (context, child) => MediaQuery(
          data: MediaQuery.of(
            context,
          ).copyWith(textScaler: TextScaler.linear(textScale)),
          child: child!,
        ),
        home: body,
      ),
    ),
  );
  await tester.pump();
}

String _mainContentLabel(String location) => switch (location) {
  '/scan' => 'Main content, Scan',
  '/protection' => 'Main content, Protection',
  '/quarantine' => 'Main content, Quarantine',
  '/allowlist' => 'Main content, Allowlist',
  '/logs' => 'Main content, Security Events',
  '/device' => 'Main content, Device Integrity',
  '/updates' => 'Main content, Updates',
  '/settings' => 'Main content, Settings',
  '/privacy' => 'Main content, Privacy',
  _ => 'Main content, Protection Overview',
};

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

const _deviceSummary = DeviceIntegritySummary(
  platform: 'Windows',
  appVersion: '1.0.0+1',
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
