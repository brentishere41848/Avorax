import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:go_router/go_router.dart';
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
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

void main() {
  testWidgets('route matrix desktop sidebar navigates primary routes', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    await _pumpRouteMatrixRouter(tester, preferences);

    const destinations = <String, String>{
      '/home': 'Protection Overview',
      '/scan': 'Scan',
      '/protection': 'Protection',
      '/quarantine': 'Quarantine',
      '/allowlist': 'Allowlist',
      '/logs': 'Security Events',
      '/device': 'Device Integrity',
      '/updates': 'Updates',
      '/settings': 'Settings',
    };

    for (final entry in destinations.entries) {
      final route = entry.key;
      final title = entry.value;
      final label = switch (title) {
        'Protection Overview' => 'Home',
        'Device Integrity' => 'Device',
        _ => title,
      };
      final openFinder = find.bySemanticsLabel('Open $label');
      final currentFinder = find.bySemanticsLabel('Current page, $label');
      if (route != '/home') {
        expect(openFinder, findsOneWidget);
        await tester.tap(openFinder);
        await tester.pumpAndSettle();
      }

      expect(find.bySemanticsLabel('Page title, $title'), findsOneWidget);
      expect(currentFinder, findsOneWidget);
      expect(find.bySemanticsLabel('Main content, $title'), findsOneWidget);
    }
  });

  testWidgets('route matrix settings privacy link opens privacy route', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    await _pumpRouteMatrixRouter(tester, preferences);

    await tester.tap(find.bySemanticsLabel('Open Settings'));
    await tester.pumpAndSettle();

    final privacyButton = find.widgetWithText(
      OutlinedButton,
      'View privacy policy',
    );
    await tester.ensureVisible(privacyButton);
    await tester.tap(privacyButton);
    await tester.pumpAndSettle();

    expect(find.bySemanticsLabel('Page title, Privacy'), findsOneWidget);
    expect(find.bySemanticsLabel('Main content, Privacy'), findsOneWidget);
  });

  testWidgets('route matrix mobile bottom nav exposes primary workflows only', (
    tester,
  ) async {
    await tester.pumpWidget(
      MaterialApp(
        home: const Scaffold(
          bottomNavigationBar: ZentorBottomNav(location: '/home'),
        ),
      ),
    );

    expect(find.byTooltip('Open Home'), findsOneWidget);
    expect(find.byTooltip('Open Scan'), findsOneWidget);
    expect(find.byTooltip('Open Quarantine'), findsOneWidget);
    expect(find.byTooltip('Open Settings'), findsOneWidget);
    expect(find.byTooltip('Open Protection'), findsNothing);
    expect(find.byTooltip('Open Allowlist'), findsNothing);
    expect(find.byTooltip('Open Security Events'), findsNothing);
    expect(find.byTooltip('Open Device'), findsNothing);
    expect(find.byTooltip('Open Updates'), findsNothing);
  });
}

Future<void> _pumpRouteMatrixRouter(
  WidgetTester tester,
  SharedPreferences preferences,
) async {
  await _withViewport(tester, const Size(1800, 2600));
  final controller = _controller(preferences);

  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        zentorControllerProvider.overrideWith((ref) => controller),
      ],
      child: MaterialApp.router(
        theme: ZentorTheme.dark(),
        routerConfig: _routeMatrixRouter(),
      ),
    ),
  );
  await tester.pump();
}

Future<void> _withViewport(WidgetTester tester, Size viewport) async {
  tester.view.physicalSize = viewport;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
}

GoRouter _routeMatrixRouter() => GoRouter(
  initialLocation: '/home',
  routes: [
    ShellRoute(
      builder: (context, state, child) =>
          ZentorShell(location: state.uri.path, child: child),
      routes: [
        for (final route in const [
          '/home',
          '/scan',
          '/protection',
          '/quarantine',
          '/allowlist',
          '/logs',
          '/device',
          '/updates',
        ])
          GoRoute(
            path: route,
            pageBuilder: (_, _) => NoTransitionPage(child: _RouteMarker(route)),
          ),
        GoRoute(
          path: '/settings',
          pageBuilder: (_, _) => NoTransitionPage(
            child: Builder(
              builder: (context) => Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const _RouteMarker('/settings'),
                  OutlinedButton(
                    onPressed: () => context.go('/privacy'),
                    child: const Text('View privacy policy'),
                  ),
                ],
              ),
            ),
          ),
        ),
        GoRoute(
          path: '/privacy',
          pageBuilder: (_, _) =>
              const NoTransitionPage(child: _RouteMarker('/privacy')),
        ),
      ],
    ),
  ],
);

class _RouteMarker extends StatelessWidget {
  const _RouteMarker(this.route);

  final String route;

  @override
  Widget build(BuildContext context) {
    return Text('Route matrix marker $route');
  }
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
