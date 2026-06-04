import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:zentor_client/app/app_state.dart';
import 'package:zentor_client/app/theme/zentor_theme.dart';
import 'package:zentor_client/core/apps/app_detector.dart';
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
