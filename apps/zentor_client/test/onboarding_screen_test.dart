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
import 'package:zentor_client/features/onboarding/onboarding_screen.dart';
import 'package:zentor_client/features/privacy/privacy_screen.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

void main() {
  testWidgets('onboarding continue saves setup and routes home', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = _controller(preferences);

    await _pumpOnboardingRouter(tester, controller);

    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();

    expect(controller.state.config.onboardingComplete, isTrue);
    expect(find.text('Run Quick Scan'), findsWidgets);
    expect(find.text('Avorax protects your device.'), findsNothing);

    final raw = preferences.getString('zentor.config.v1');
    expect(raw, isNotNull);
    expect(raw, contains('"onboardingComplete":true'));
  });

  testWidgets('onboarding privacy details routes to privacy policy', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = _controller(preferences);

    await _pumpOnboardingRouter(tester, controller);

    await tester.tap(find.widgetWithText(OutlinedButton, 'Privacy details'));
    await tester.pumpAndSettle();

    expect(find.text('Privacy-first by design'), findsOneWidget);
    expect(find.text('Avorax protects your device.'), findsNothing);
    expect(controller.state.config.onboardingComplete, isFalse);
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

Future<void> _pumpOnboardingRouter(
  WidgetTester tester,
  ZentorController controller,
) async {
  tester.view.physicalSize = const Size(1600, 2400);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  final router = GoRouter(
    initialLocation: '/onboarding',
    routes: [
      GoRoute(
        path: '/onboarding',
        builder: (context, state) => const OnboardingScreen(),
      ),
      GoRoute(path: '/home', builder: (context, state) => const HomeScreen()),
      GoRoute(
        path: '/privacy',
        builder: (context, state) => const PrivacyScreen(),
      ),
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
