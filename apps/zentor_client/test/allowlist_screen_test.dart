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
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

class _FakeLocalCoreClient extends LocalCoreClient {
  _FakeLocalCoreClient(this.entries);

  List<AllowlistEntry> entries;
  int listAllowlistCalls = 0;
  int removeAllowlistEntryCalls = 0;
  String? lastRemovedId;

  @override
  Future<List<AllowlistEntry>> listAllowlist() async {
    listAllowlistCalls += 1;
    return entries;
  }

  @override
  Future<LocalCoreActionResult> removeAllowlistEntry(String id) async {
    removeAllowlistEntryCalls += 1;
    lastRemovedId = id;
    entries = [
      for (final entry in entries)
        entry.id == id
            ? AllowlistEntry(
                id: entry.id,
                type: entry.type,
                path: entry.path,
                reason: entry.reason,
                createdAt: entry.createdAt,
                sha256: entry.sha256,
                createdBy: entry.createdBy,
                active: false,
              )
            : entry,
    ];
    return const LocalCoreActionResult.ok();
  }
}

void main() {
  testWidgets('allowlist action busy disables refresh and remove controls', (
    tester,
  ) async {
    final entry = _allowlistEntry();

    await _pumpAllowlistScreen(
      tester,
      ZentorState(allowlistActionInFlight: true, allowlist: [entry]),
      localCoreClient: _FakeLocalCoreClient([entry]),
    );
    await tester.pumpAndSettle();

    final refreshButton = find.widgetWithText(OutlinedButton, 'Refresh');
    final removeButton = find.widgetWithText(OutlinedButton, 'Remove');

    expect(refreshButton, findsOneWidget);
    expect(removeButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(refreshButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(removeButton).onPressed, isNull);
  });

  testWidgets('allowlist controls disable while configuration state is busy', (
    tester,
  ) async {
    final entry = _allowlistEntry();
    for (final state in const [
      ZentorState(securitySettingsActionInFlight: true),
      ZentorState(configurationResetInFlight: true),
    ]) {
      await _pumpAllowlistScreen(
        tester,
        state.copyWith(allowlist: [entry]),
        localCoreClient: _FakeLocalCoreClient([entry]),
      );
      await tester.pumpAndSettle();

      final refreshButton = find.widgetWithText(OutlinedButton, 'Refresh');
      final removeButton = find.widgetWithText(OutlinedButton, 'Remove');

      expect(refreshButton, findsOneWidget);
      expect(removeButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(refreshButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(removeButton).onPressed, isNull);
    }
  });

  testWidgets('manual trust actions disable during update package work', (
    tester,
  ) async {
    final entry = _allowlistEntry();
    await _pumpAllowlistScreen(
      tester,
      ZentorState(updateStatus: UpdateStatus.installing, allowlist: [entry]),
      localCoreClient: _FakeLocalCoreClient([entry]),
    );
    await tester.pumpAndSettle();

    final refreshButton = find.widgetWithText(OutlinedButton, 'Refresh');
    final removeButton = find.widgetWithText(OutlinedButton, 'Remove');

    expect(refreshButton, findsOneWidget);
    expect(removeButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(refreshButton).onPressed, isNotNull);
    expect(tester.widget<OutlinedButton>(removeButton).onPressed, isNull);
  });

  testWidgets('allowlist refresh button calls local core once', (tester) async {
    final entry = _allowlistEntry();
    final localCore = _FakeLocalCoreClient([entry]);
    final controller = await _pumpAllowlistScreen(
      tester,
      const ZentorState(),
      localCoreClient: localCore,
    );
    await tester.pumpAndSettle();

    expect(localCore.listAllowlistCalls, 1);
    expect(controller.state.allowlist.single.id, entry.id);

    await tester.tap(find.widgetWithText(OutlinedButton, 'Refresh'));
    await tester.pumpAndSettle();

    expect(localCore.listAllowlistCalls, 2);
    expect(controller.state.allowlist.single.id, entry.id);
    expect(controller.state.allowlistRefreshInFlight, isFalse);
    expect(find.text(entry.path), findsOneWidget);
  });

  testWidgets('allowlist remove dialog cancel does not call local core', (
    tester,
  ) async {
    final entry = _allowlistEntry();
    final localCore = _FakeLocalCoreClient([entry]);
    final controller = await _pumpAllowlistScreen(
      tester,
      ZentorState(allowlist: [entry]),
      localCoreClient: localCore,
    );
    await tester.pumpAndSettle();

    await tester.tap(find.widgetWithText(OutlinedButton, 'Remove'));
    await tester.pumpAndSettle();

    expect(find.text('Remove allowlist entry?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.removeAllowlistEntryCalls, 0);
    expect(controller.state.allowlist.single.active, isTrue);
    expect(find.text(entry.path), findsOneWidget);
  });

  testWidgets('allowlist remove dialog confirm calls local core once', (
    tester,
  ) async {
    final entry = _allowlistEntry();
    final localCore = _FakeLocalCoreClient([entry]);
    final controller = await _pumpAllowlistScreen(
      tester,
      ZentorState(allowlist: [entry]),
      localCoreClient: localCore,
    );
    await tester.pumpAndSettle();

    await tester.tap(find.widgetWithText(OutlinedButton, 'Remove'));
    await tester.pumpAndSettle();

    expect(find.text('Remove allowlist entry?'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Remove'));
    await tester.pumpAndSettle();

    expect(localCore.removeAllowlistEntryCalls, 1);
    expect(localCore.lastRemovedId, entry.id);
    expect(controller.state.allowlist.single.active, isFalse);
    expect(
      controller.state.events.map((event) => event.type),
      contains('allowlist_entry_removed'),
    );
    expect(find.text('No allowlist entries'), findsOneWidget);
  });
}

Future<ZentorController> _pumpAllowlistScreen(
  WidgetTester tester,
  ZentorState state, {
  LocalCoreClient localCoreClient = const LocalCoreClient(),
}) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pump();
  SharedPreferences.setMockInitialValues({});
  final preferences = await SharedPreferences.getInstance();
  final controller = ZentorController(
    configRepository: ConfigRepository(preferences),
    eventRepository: LocalEventRepository(preferences),
    apiClient: ZentorApiClient(),
    hashService: HashService(),
    appDetector: const _FakeAppDetector(),
    localCoreClient: localCoreClient,
    scanTargetService: const ScanTargetService(),
    updateService: ZentorUpdateService(),
  );
  controller.state = state;

  await tester.pumpWidget(
    ProviderScope(
      overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
      child: MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(
          body: SingleChildScrollView(child: AllowlistScreen()),
        ),
      ),
    ),
  );
  return controller;
}

AllowlistEntry _allowlistEntry() => AllowlistEntry(
  id: 'allow-1',
  type: AllowlistEntryType.file,
  path: r'C:\Users\Brent\Documents\trusted-tool.exe',
  reason: 'User approved trusted tool',
  createdAt: DateTime.utc(2026, 7, 5, 12),
  sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
);
