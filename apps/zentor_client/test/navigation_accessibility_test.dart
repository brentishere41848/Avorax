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
import 'package:zentor_client/shared/widgets/zentor_bottom_nav.dart';
import 'package:zentor_client/shared/widgets/zentor_shell.dart';
import 'package:zentor_client/shared/widgets/zentor_sidebar.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

void main() {
  testWidgets('desktop sidebar exposes navigation landmark and selected page', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(body: ZentorSidebar(location: '/scan')),
      ),
    );

    expect(find.bySemanticsLabel('Primary navigation'), findsOneWidget);
    expect(find.bySemanticsLabel('Current page, Scan'), findsOneWidget);
    expect(find.bySemanticsLabel('Open Quarantine'), findsOneWidget);
  });

  testWidgets('shell exposes page title and main content landmark', (
    tester,
  ) async {
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
          home: const ZentorShell(
            location: '/protection',
            child: Text('Protection content fixture'),
          ),
        ),
      ),
    );

    expect(find.bySemanticsLabel('Page title, Protection'), findsOneWidget);
    expect(find.bySemanticsLabel('Main content, Protection'), findsOneWidget);
    expect(find.text('Protection content fixture'), findsOneWidget);
  });

  testWidgets('shell notification text is normalized before display', (
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
    controller.state = ZentorState(
      events: [
        LocalEvent(
          id: 'notification-fixture',
          type: 'scan_failed',
          message: 'Scan failed',
          createdAt: DateTime.utc(2026, 7, 5),
          details: 'line one\x00\n\tline two',
          category: 'scan',
          severity: 'error',
        ),
      ],
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const ZentorShell(
            location: '/scan',
            child: Text('Scan content fixture'),
          ),
        ),
      ),
    );

    expect(find.text('Scan failed: line one line two'), findsOneWidget);
    expect(find.textContaining('\x00'), findsNothing);
    expect(find.textContaining('\n'), findsNothing);
  });

  testWidgets(
    'shell notification prioritizes security warnings over scan info',
    (tester) async {
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
      controller.state = ZentorState(
        events: [
          LocalEvent(
            id: 'newer-scan-completed',
            type: 'scan_completed',
            message: 'Scan completed',
            createdAt: DateTime.utc(2026, 7, 5, 12, 1),
            details: 'status=clean',
            category: 'scan',
            severity: 'info',
          ),
          LocalEvent(
            id: 'older-threat-detected',
            type: 'threat_detected',
            message: 'Threats found',
            createdAt: DateTime.utc(2026, 7, 5, 12),
            details: 'threats=1 quarantined=1',
            category: 'scan',
            severity: 'warning',
          ),
        ],
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            zentorControllerProvider.overrideWith((ref) => controller),
          ],
          child: MaterialApp(
            theme: ZentorTheme.dark(),
            home: const ZentorShell(
              location: '/scan',
              child: Text('Scan content fixture'),
            ),
          ),
        ),
      );

      expect(
        find.text('Threats found: threats=1 quarantined=1'),
        findsOneWidget,
      );
      expect(find.textContaining('Scan completed: status=clean'), findsNothing);
    },
  );

  testWidgets('shell notification uses newest event when priority matches', (
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
    controller.state = ZentorState(
      events: [
        LocalEvent(
          id: 'older-warning',
          type: 'scan_failed',
          message: 'Older warning',
          createdAt: DateTime.utc(2026, 7, 5, 12),
          category: 'scan',
          severity: 'warning',
        ),
        LocalEvent(
          id: 'newer-warning',
          type: 'file_quarantined',
          message: 'File quarantined',
          createdAt: DateTime.utc(2026, 7, 5, 12, 1),
          details: 'safe-fixture.bin',
          category: 'quarantine',
          severity: 'warning',
        ),
      ],
    );

    await tester.pumpWidget(
      ProviderScope(
        overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
        child: MaterialApp(
          theme: ZentorTheme.dark(),
          home: const ZentorShell(
            location: '/quarantine',
            child: Text('Quarantine content fixture'),
          ),
        ),
      ),
    );

    expect(find.text('File quarantined: safe-fixture.bin'), findsOneWidget);
    expect(find.text('Older warning'), findsNothing);
  });

  testWidgets('mobile bottom navigation exposes current page semantic label', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(
          bottomNavigationBar: ZentorBottomNav(location: '/settings'),
        ),
      ),
    );

    expect(find.bySemanticsLabel('Current page, Settings'), findsOneWidget);
    expect(find.byTooltip('Open Settings'), findsOneWidget);
  });
}
