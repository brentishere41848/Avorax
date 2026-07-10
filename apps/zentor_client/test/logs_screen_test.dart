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
import 'package:zentor_client/features/logs/logs_screen.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

class _RecordingController extends ZentorController {
  _RecordingController(SharedPreferences preferences)
    : super(
        configRepository: ConfigRepository(preferences),
        eventRepository: LocalEventRepository(preferences),
        apiClient: ZentorApiClient(),
        hashService: HashService(),
        appDetector: const _FakeAppDetector(),
        localCoreClient: const LocalCoreClient(),
        scanTargetService: const ScanTargetService(),
        updateService: ZentorUpdateService(),
      );

  int exportCalls = 0;
  int supportBundleExportCalls = 0;
  String? exportPath = r'C:\Users\Brent\AppData\Local\Avorax\logs.jsonl';
  String? supportBundlePath =
      r'C:\Users\Brent\AppData\Local\Avorax\support-bundle.json';

  @override
  Future<String?> exportLogs({bool confirmed = false}) async {
    exportCalls += 1;
    expect(confirmed, isTrue);
    return exportPath;
  }

  @override
  Future<String?> exportSupportBundle({bool confirmed = false}) async {
    supportBundleExportCalls += 1;
    expect(confirmed, isTrue);
    return supportBundlePath;
  }
}

void main() {
  testWidgets('logs export dialog cancel does not export logs', (tester) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = _RecordingController(preferences);

    await _pumpLogsScreen(tester, controller);

    await tester.tap(find.widgetWithText(OutlinedButton, 'Export logs'));
    await tester.pumpAndSettle();
    expect(find.text('Export logs?'), findsOneWidget);

    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(controller.exportCalls, 0);
    expect(find.textContaining('Logs exported to'), findsNothing);
  });

  testWidgets('logs export dialog confirm exports logs once', (tester) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = _RecordingController(preferences);

    await _pumpLogsScreen(tester, controller);

    await tester.tap(find.widgetWithText(OutlinedButton, 'Export logs'));
    await tester.pumpAndSettle();
    expect(find.text('Export logs?'), findsOneWidget);

    await tester.tap(find.widgetWithText(FilledButton, 'Export'));
    await tester.pumpAndSettle();

    expect(controller.exportCalls, 1);
    expect(
      find.text(
        r'Logs exported to C:\Users\Brent\AppData\Local\Avorax\logs.jsonl',
      ),
      findsOneWidget,
    );
  });

  testWidgets('logs export button disables while export is busy', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = _RecordingController(preferences)
      ..state = const ZentorState(logExportInFlight: true);

    await _pumpLogsScreen(tester, controller);

    final busyButton = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Exporting logs'),
    );
    expect(busyButton.onPressed, isNull);
    expect(find.widgetWithText(OutlinedButton, 'Export logs'), findsNothing);
  });

  testWidgets('support bundle dialog cancel does not export bundle', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = _RecordingController(preferences);

    await _pumpLogsScreen(tester, controller);

    await tester.tap(
      find.widgetWithText(OutlinedButton, 'Export support bundle'),
    );
    await tester.pumpAndSettle();
    expect(find.text('Export support bundle?'), findsOneWidget);

    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(controller.supportBundleExportCalls, 0);
    expect(find.textContaining('Support bundle exported to'), findsNothing);
  });

  testWidgets('support bundle dialog confirm exports bundle once', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = _RecordingController(preferences);

    await _pumpLogsScreen(tester, controller);

    await tester.tap(
      find.widgetWithText(OutlinedButton, 'Export support bundle'),
    );
    await tester.pumpAndSettle();
    expect(find.text('Export support bundle?'), findsOneWidget);

    await tester.tap(find.widgetWithText(FilledButton, 'Export'));
    await tester.pumpAndSettle();

    expect(controller.supportBundleExportCalls, 1);
    expect(
      find.text(
        r'Support bundle exported to C:\Users\Brent\AppData\Local\Avorax\support-bundle.json',
      ),
      findsOneWidget,
    );
  });

  testWidgets('support bundle button disables while export is busy', (
    tester,
  ) async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final controller = _RecordingController(preferences)
      ..state = const ZentorState(supportBundleExportInFlight: true);

    await _pumpLogsScreen(tester, controller);

    final busyButton = tester.widget<OutlinedButton>(
      find.widgetWithText(OutlinedButton, 'Exporting bundle'),
    );
    expect(busyButton.onPressed, isNull);
    expect(
      find.widgetWithText(OutlinedButton, 'Export support bundle'),
      findsNothing,
    );
  });
}

Future<void> _pumpLogsScreen(
  WidgetTester tester,
  _RecordingController controller,
) async {
  tester.view.physicalSize = const Size(1400, 1800);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);

  await tester.pumpWidget(
    ProviderScope(
      overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
      child: MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(body: LogsScreen()),
      ),
    ),
  );
}
