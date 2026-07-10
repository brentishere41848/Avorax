import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:zentor_client/app/app_state.dart';
import 'package:zentor_client/app/theme/zentor_theme.dart';
import 'package:zentor_client/core/apps/app_detector.dart';
import 'package:zentor_client/core/config/config_repository.dart';
import 'package:zentor_client/core/files/file_selection_service.dart';
import 'package:zentor_client/core/local_core/local_core_client.dart';
import 'package:zentor_client/core/logging/local_event_repository.dart';
import 'package:zentor_client/core/network/zentor_api_client.dart';
import 'package:zentor_client/core/scanning/scan_target_service.dart';
import 'package:zentor_client/core/security/hash_service.dart';
import 'package:zentor_client/core/updates/update_service.dart';
import 'package:zentor_client/features/quarantine/quarantine_screen.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

void main() {
  testWidgets('quarantine action busy disables mutation controls', (
    tester,
  ) async {
    await _pumpQuarantineScreen(
      tester,
      ZentorState(
        quarantineActionInFlight: true,
        quarantine: [_quarantineRecord()],
      ),
    );

    final refreshButton = find.widgetWithText(OutlinedButton, 'Refresh');
    final manualButton = find.widgetWithText(OutlinedButton, 'Quarantine file');
    final restoreButton = find.widgetWithText(OutlinedButton, 'Restore / Keep');
    final deleteButton = find.widgetWithText(
      OutlinedButton,
      'Delete permanently',
    );

    expect(refreshButton, findsOneWidget);
    expect(manualButton, findsOneWidget);
    expect(restoreButton, findsOneWidget);
    expect(deleteButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(refreshButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(manualButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(restoreButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(deleteButton).onPressed, isNull);
  });

  testWidgets('quarantine controls disable while configuration state is busy', (
    tester,
  ) async {
    for (final state in const [
      ZentorState(securitySettingsActionInFlight: true),
      ZentorState(configurationResetInFlight: true),
    ]) {
      await _pumpQuarantineScreen(
        tester,
        state.copyWith(quarantine: [_quarantineRecord()]),
      );

      final refreshButton = find.widgetWithText(OutlinedButton, 'Refresh');
      final manualButton = find.widgetWithText(
        OutlinedButton,
        'Quarantine file',
      );
      final restoreButton = find.widgetWithText(
        OutlinedButton,
        'Restore / Keep',
      );
      final deleteButton = find.widgetWithText(
        OutlinedButton,
        'Delete permanently',
      );

      expect(refreshButton, findsOneWidget);
      expect(manualButton, findsOneWidget);
      expect(restoreButton, findsOneWidget);
      expect(deleteButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(refreshButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(manualButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(restoreButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(deleteButton).onPressed, isNull);
    }
  });

  testWidgets('manual trust actions disable during update package work', (
    tester,
  ) async {
    await _pumpQuarantineScreen(
      tester,
      ZentorState(
        updateStatus: UpdateStatus.installing,
        quarantine: [_quarantineRecord()],
      ),
    );

    final refreshButton = find.widgetWithText(OutlinedButton, 'Refresh');
    final manualButton = find.widgetWithText(OutlinedButton, 'Quarantine file');
    final restoreButton = find.widgetWithText(OutlinedButton, 'Restore / Keep');
    final deleteButton = find.widgetWithText(
      OutlinedButton,
      'Delete permanently',
    );

    expect(refreshButton, findsOneWidget);
    expect(manualButton, findsOneWidget);
    expect(restoreButton, findsOneWidget);
    expect(deleteButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(refreshButton).onPressed, isNotNull);
    expect(tester.widget<OutlinedButton>(manualButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(restoreButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(deleteButton).onPressed, isNull);
  });

  testWidgets('quarantine restore dialog cancel does not call local core', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpQuarantineScreen(
      tester,
      ZentorState(quarantine: [_quarantineRecord()]),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Restore / Keep'));
    await tester.pumpAndSettle();

    expect(find.text('Restore quarantined file?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.restoreQuarantineCalls, 0);
    expect(find.text('Restore quarantined file?'), findsNothing);
  });

  testWidgets('manual quarantine dialog cancel does not pick a file', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    final fileSelection = _FakeFileSelectionService(
      file: const SelectedFilePath(
        name: 'manual.bin',
        path: r'C:\tmp\manual.bin',
      ),
    );
    await _pumpQuarantineScreen(
      tester,
      const ZentorState(),
      localCoreClient: localCore,
      fileSelectionService: fileSelection,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Quarantine file'));
    await tester.pumpAndSettle();

    expect(find.text('Quarantine selected file?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(fileSelection.pickFileCalls, 0);
    expect(localCore.quarantineFileCalls, 0);
    expect(find.text('Quarantine selected file?'), findsNothing);
  });

  testWidgets('manual quarantine confirm picks and quarantines a file', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient(
      listQuarantineFailure: 'quarantine refresh unavailable',
    );
    final fileSelection = _FakeFileSelectionService(
      file: const SelectedFilePath(
        name: 'manual.bin',
        path: r'C:\tmp\manual.bin',
      ),
    );
    await _pumpQuarantineScreen(
      tester,
      const ZentorState(),
      localCoreClient: localCore,
      fileSelectionService: fileSelection,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Quarantine file'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Choose file'));
    await tester.pumpAndSettle();

    expect(fileSelection.pickFileCalls, 1);
    expect(localCore.quarantineFileCalls, 1);
    expect(localCore.lastQuarantineFilePath, r'C:\tmp\manual.bin');
    expect(localCore.lastQuarantineThreatName, 'Manual quarantine');
    expect(localCore.lastQuarantineEngine, 'avorax-ui-manual-quarantine');
  });

  testWidgets('quarantine restore dialog confirm calls local core', (
    tester,
  ) async {
    final record = _quarantineRecord();
    final localCore = _RecordingLocalCoreClient(
      listQuarantineFailure: 'quarantine refresh unavailable',
    );
    await _pumpQuarantineScreen(
      tester,
      ZentorState(quarantine: [record]),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Restore / Keep'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Restore file'));
    await tester.pumpAndSettle();

    expect(localCore.restoreQuarantineCalls, 1);
    expect(localCore.lastRestoreQuarantineId, record.quarantineId);
  });

  testWidgets('quarantine delete dialog cancel does not call local core', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpQuarantineScreen(
      tester,
      ZentorState(quarantine: [_quarantineRecord()]),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Delete permanently'));
    await tester.pumpAndSettle();

    expect(find.text('Delete quarantined file permanently?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.deleteQuarantineCalls, 0);
    expect(find.text('Delete quarantined file permanently?'), findsNothing);
  });

  testWidgets('quarantine delete dialog confirm calls local core', (
    tester,
  ) async {
    final record = _quarantineRecord();
    final localCore = _RecordingLocalCoreClient(
      listQuarantineFailure: 'quarantine refresh unavailable',
    );
    await _pumpQuarantineScreen(
      tester,
      ZentorState(quarantine: [record]),
      localCoreClient: localCore,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Delete permanently'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Delete permanently'));
    await tester.pumpAndSettle();

    expect(localCore.deleteQuarantineCalls, 1);
    expect(localCore.lastDeleteQuarantineId, record.quarantineId);
  });

  testWidgets('quarantine restored row can scan original path', (tester) async {
    final dir = Directory.systemTemp.createTempSync(
      'zentor-quarantine-rescan-',
    );
    addTearDown(() => dir.deleteSync(recursive: true));
    final original = File('${dir.path}${Platform.pathSeparator}eicar.com');
    original.writeAsBytesSync(const [1, 2, 3]);
    final record = _quarantineRecord(
      originalPath: original.path,
      status: QuarantineItemStatus.restored,
      actionTaken: 'restored',
    );
    final localCore = _RecordingLocalCoreClient();
    await _pumpQuarantineScreen(
      tester,
      ZentorState(quarantine: [record]),
      localCoreClient: localCore,
    );

    final scanButton = find.widgetWithText(
      OutlinedButton,
      'Scan original path',
    );
    expect(scanButton, findsOneWidget);
    await tester.tap(scanButton);
    await tester.pumpAndSettle();

    expect(localCore.scanCalls, 1);
    expect(localCore.lastScanPath, record.originalPath);
    expect(localCore.lastScanActionMode, ScanActionMode.detectOnly);
  });

  testWidgets(
    'quarantine original rescan disables during update package work',
    (tester) async {
      final record = _quarantineRecord(
        status: QuarantineItemStatus.restored,
        actionTaken: 'restored',
      );
      await _pumpQuarantineScreen(
        tester,
        ZentorState(
          updateStatus: UpdateStatus.installing,
          quarantine: [record],
        ),
      );

      final scanButton = find.widgetWithText(
        OutlinedButton,
        'Scan original path',
      );
      expect(scanButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(scanButton).onPressed, isNull);
    },
  );

  testWidgets('quarantine active row does not show original path rescan', (
    tester,
  ) async {
    await _pumpQuarantineScreen(
      tester,
      ZentorState(quarantine: [_quarantineRecord()]),
    );

    expect(
      find.widgetWithText(OutlinedButton, 'Scan original path'),
      findsNothing,
    );
  });
}

Future<void> _pumpQuarantineScreen(
  WidgetTester tester,
  ZentorState state, {
  LocalCoreClient? localCoreClient,
  FileSelectionService? fileSelectionService,
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
    fileSelectionService: fileSelectionService ?? const FileSelectionService(),
    localCoreClient: localCoreClient ?? const LocalCoreClient(),
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
          body: SingleChildScrollView(child: QuarantineScreen()),
        ),
      ),
    ),
  );
}

QuarantineRecord _quarantineRecord({
  String originalPath = r'C:\Users\Brent\Downloads\eicar.com',
  QuarantineItemStatus status = QuarantineItemStatus.quarantined,
  String actionTaken = 'quarantined',
}) => QuarantineRecord(
  quarantineId: 'q-1',
  originalPath: originalPath,
  quarantinePath: r'C:\ProgramData\Avorax\Quarantine\opaque-q-1',
  sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  fileSize: 68,
  detectionName: 'EICAR-Test-File',
  engine: 'local-core',
  quarantinedAt: DateTime.utc(2026, 7, 5, 12),
  status: status,
  source: 'scanner',
  blockedBeforeExecution: false,
  processStarted: false,
  actionTaken: actionTaken,
);

class _RecordingLocalCoreClient extends LocalCoreClient {
  _RecordingLocalCoreClient({this.listQuarantineFailure});

  final String? listQuarantineFailure;

  int restoreQuarantineCalls = 0;
  int deleteQuarantineCalls = 0;
  int quarantineFileCalls = 0;
  int scanCalls = 0;
  String? lastQuarantineFilePath;
  String? lastQuarantineThreatName;
  String? lastQuarantineEngine;
  String? lastRestoreQuarantineId;
  String? lastDeleteQuarantineId;
  String? lastScanPath;
  ScanActionMode? lastScanActionMode;

  @override
  Future<LocalCoreActionResult> restoreQuarantineItem(
    String quarantineId,
  ) async {
    restoreQuarantineCalls += 1;
    lastRestoreQuarantineId = quarantineId;
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<LocalCoreActionResult> deleteQuarantineItem(
    String quarantineId,
  ) async {
    deleteQuarantineCalls += 1;
    lastDeleteQuarantineId = quarantineId;
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<LocalCoreActionResult> quarantineFile(
    String path, {
    required String threatName,
    required String engine,
  }) async {
    quarantineFileCalls += 1;
    lastQuarantineFilePath = path;
    lastQuarantineThreatName = threatName;
    lastQuarantineEngine = engine;
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<List<QuarantineRecord>> listQuarantine() async {
    final failure = listQuarantineFailure;
    if (failure != null) {
      throw StateError(failure);
    }
    return const [];
  }

  @override
  Future<ScanReport> scanFile(
    String path, {
    required ScanKind kind,
    required ScanActionMode actionMode,
    void Function(ScanProgress progress)? onProgress,
  }) async {
    scanCalls += 1;
    lastScanPath = path;
    lastScanActionMode = actionMode;
    return ScanReport(
      status: ScanStatus.clean,
      kind: kind,
      actionMode: actionMode,
      filesScanned: 1,
      threatsFound: 0,
      skippedFiles: 0,
      elapsedMs: 1,
      threats: const [],
    );
  }
}

class _FakeFileSelectionService extends FileSelectionService {
  _FakeFileSelectionService({this.file});

  final SelectedFilePath? file;
  int pickFileCalls = 0;

  @override
  Future<SelectedFilePath?> pickFile() async {
    pickFileCalls += 1;
    return file;
  }
}
