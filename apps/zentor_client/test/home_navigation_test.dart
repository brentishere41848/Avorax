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
import 'package:zentor_client/features/home/home_screen.dart';
import 'package:zentor_client/features/logs/logs_screen.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

void main() {
  testWidgets('home view all security events routes to logs screen', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = _controller(preferences);

    await _pumpHomeRouter(tester, controller);

    final viewAllButton = find.widgetWithText(TextButton, 'View all');
    await tester.ensureVisible(viewAllButton);
    await tester.tap(viewAllButton);
    await tester.pumpAndSettle();

    expect(find.text('Local events'), findsOneWidget);
    expect(find.text('No local events'), findsOneWidget);
    expect(find.text('Security events'), findsNothing);
  });
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

Future<void> _pumpHomeRouter(
  WidgetTester tester,
  ZentorController controller,
) async {
  tester.view.physicalSize = const Size(1600, 2400);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  final router = GoRouter(
    initialLocation: '/home',
    routes: [
      GoRoute(path: '/home', builder: (context, state) => const HomeScreen()),
      GoRoute(path: '/logs', builder: (context, state) => const LogsScreen()),
    ],
  );

  await tester.pumpWidget(
    ProviderScope(
      overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
      child: MaterialApp.router(
        theme: ZentorTheme.dark(),
        routerConfig: router,
      ),
    ),
  );
}
