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
import 'package:zentor_client/features/protected_apps/protected_apps_screen.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

class _FakeHashService extends HashService {
  _FakeHashService({this.supportsPathHashing = true});

  @override
  final bool supportsPathHashing;

  int hashCalls = 0;
  String? lastPath;

  static const hash =
      'sha256:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';

  @override
  Future<String> sha256ForFile(
    String path, {
    void Function(double progress)? onProgress,
  }) async {
    hashCalls += 1;
    lastPath = path;
    onProgress?.call(1);
    return hash;
  }
}

void main() {
  late Directory tempDir;
  late File selectedFile;
  late File detectedFile;

  setUp(() {
    tempDir = Directory.systemTemp.createTempSync('avorax-protected-app-test-');
    selectedFile = File('${tempDir.path}${Platform.pathSeparator}tool.exe')
      ..writeAsStringSync('benign protected app fixture');
    detectedFile = File(
      '${tempDir.path}${Platform.pathSeparator}detected-tool.exe',
    )..writeAsStringSync('benign detected protected app fixture');
  });

  tearDown(() {
    if (tempDir.existsSync()) {
      tempDir.deleteSync(recursive: true);
    }
  });

  testWidgets(
    'protected apps hash dialog cancel does not calculate build hash',
    (tester) async {
      final hashService = _FakeHashService();
      final controller = await _pumpProtectedAppsScreen(
        tester,
        _stateWithProtectedApp(selectedFile.path),
        hashService: hashService,
      );

      await tester.tap(
        find.widgetWithText(FilledButton, 'Calculate build hash'),
      );
      await tester.pumpAndSettle();

      expect(find.text('Calculate build hash?'), findsOneWidget);
      await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
      await tester.pumpAndSettle();

      expect(hashService.hashCalls, 0);
      expect(controller.state.config.protectedAppConfig.lastCalculatedHash, '');
      expect(find.text('Build hash calculated.'), findsNothing);
    },
  );

  testWidgets(
    'protected apps hash dialog confirm calculates and saves build hash',
    (tester) async {
      final hashService = _FakeHashService();
      final controller = await _pumpProtectedAppsScreen(
        tester,
        _stateWithProtectedApp(selectedFile.path),
        hashService: hashService,
      );

      await tester.tap(
        find.widgetWithText(FilledButton, 'Calculate build hash'),
      );
      await tester.pumpAndSettle();

      expect(find.text('Calculate build hash?'), findsOneWidget);
      await tester.tap(find.widgetWithText(FilledButton, 'Calculate'));
      await tester.pumpAndSettle();

      expect(hashService.hashCalls, 1);
      expect(hashService.lastPath, selectedFile.path);
      expect(
        controller.state.config.protectedAppConfig.lastCalculatedHash,
        _FakeHashService.hash,
      );
      expect(
        controller.state.appVerificationStatus,
        AppVerificationStatus.verified,
      );
      expect(find.text('Build hash calculated.'), findsOneWidget);
      expect(
        controller.state.events.map((event) => event.type),
        contains('file_hash_calculated'),
      );
    },
  );

  testWidgets('protected apps detected row cancel does not select app', (
    tester,
  ) async {
    final hashService = _FakeHashService();
    final controller = await _pumpProtectedAppsScreen(
      tester,
      _stateWithDetectedApp(selectedFile.path, detectedFile.path),
      hashService: hashService,
    );

    final detectedRow = find.widgetWithText(ListTile, 'Detected Tool');
    await tester.ensureVisible(detectedRow);
    await tester.tap(detectedRow);
    await tester.pumpAndSettle();

    expect(find.text('Select protected app?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(controller.state.config.protectedAppConfig.appId, 'manual-tool');
    expect(
      controller.state.config.scanPaths,
      isNot(contains(detectedFile.path)),
    );
    expect(find.text('Protected app selected.'), findsNothing);
    expect(
      controller.state.events.map((event) => event.type),
      isNot(contains('protected_app_selected')),
    );
  });

  testWidgets('protected apps detected row confirm selects app and scan path', (
    tester,
  ) async {
    final hashService = _FakeHashService();
    final controller = await _pumpProtectedAppsScreen(
      tester,
      _stateWithDetectedApp(selectedFile.path, detectedFile.path),
      hashService: hashService,
    );

    final detectedRow = find.widgetWithText(ListTile, 'Detected Tool');
    await tester.ensureVisible(detectedRow);
    await tester.tap(detectedRow);
    await tester.pumpAndSettle();

    expect(find.text('Select protected app?'), findsOneWidget);
    await tester.tap(find.widgetWithText(FilledButton, 'Select'));
    await tester.pumpAndSettle();

    final selected = controller.state.config.protectedAppConfig;
    expect(selected.appId, 'detected-tool');
    expect(selected.appName, 'Detected Tool');
    expect(selected.appPath, detectedFile.path);
    expect(selected.source, 'Known path');
    expect(controller.state.config.scanPaths, contains(detectedFile.path));
    expect(controller.state.appDetectionStatus, AppDetectionStatus.detected);
    expect(find.text('Protected app selected.'), findsOneWidget);
    expect(
      controller.state.events.map((event) => event.type),
      contains('protected_app_selected'),
    );
  });

  testWidgets('protected apps surfaces active protection process evidence', (
    tester,
  ) async {
    await _pumpProtectedAppsScreen(
      tester,
      _stateWithProtectedApp(selectedFile.path).copyWith(
        events: [
          LocalEvent(
            id: 'loop-finding',
            type: 'process_snapshot_loop_suspicious',
            message: 'Protection process snapshot reported suspicious findings',
            details: 'observed=1 skipped=0 findings=1 status=snapshotOnly',
            createdAt: DateTime.utc(2026, 7, 6, 12),
            category: 'protection',
            severity: 'warning',
          ),
        ],
      ),
      hashService: _FakeHashService(),
    );

    expect(find.text('Process snapshot evidence'), findsOneWidget);
    expect(find.text('Suspicious'), findsOneWidget);
    expect(
      find.text('Protection process snapshot reported suspicious findings'),
      findsOneWidget,
    );
    expect(
      find.text('observed=1 skipped=0 findings=1 status=snapshotOnly'),
      findsOneWidget,
    );
  });

  testWidgets('protected apps process evidence chooses newest event by time', (
    tester,
  ) async {
    await _pumpProtectedAppsScreen(
      tester,
      _stateWithProtectedApp(selectedFile.path).copyWith(
        events: [
          LocalEvent(
            id: 'older-suspicious',
            type: 'process_snapshot_suspicious',
            message: 'Older app-detection snapshot should not be shown',
            details: 'findings=1 status=older',
            createdAt: DateTime.utc(2026, 7, 6, 10),
            category: 'protection',
            severity: 'warning',
          ),
          LocalEvent(
            id: 'newer-loop-failed',
            type: 'process_snapshot_loop_failed',
            message: 'Newer active protection snapshot failed',
            details: 'process snapshot IPC denied',
            createdAt: DateTime.utc(2026, 7, 6, 12),
            category: 'protection',
            severity: 'warning',
          ),
        ],
      ),
      hashService: _FakeHashService(),
    );

    expect(find.text('Process snapshot evidence'), findsOneWidget);
    expect(find.text('Failed'), findsOneWidget);
    expect(
      find.text('Newer active protection snapshot failed'),
      findsOneWidget,
    );
    expect(
      find.text('Evidence time (UTC): 2026-07-06T12:00:00.000Z'),
      findsOneWidget,
    );
    expect(find.text('process snapshot IPC denied'), findsOneWidget);
    expect(
      find.text('Older app-detection snapshot should not be shown'),
      findsNothing,
    );
    expect(find.text('findings=1 status=older'), findsNothing);
  });

  testWidgets(
    'protected apps mutation controls disable during update package work',
    (tester) async {
      await _pumpProtectedAppsScreen(
        tester,
        _stateWithDetectedApp(
          selectedFile.path,
          detectedFile.path,
        ).copyWith(updateStatus: UpdateStatus.installing),
        hashService: _FakeHashService(),
      );

      final addFileButton = find.widgetWithText(
        OutlinedButton,
        'Add file or app',
      );
      final addFolderButton = find.widgetWithText(OutlinedButton, 'Add folder');
      final hashButton = find.widgetWithText(
        FilledButton,
        'Calculate build hash',
      );
      final detectedRow = find.widgetWithText(ListTile, 'Detected Tool');

      expect(addFileButton, findsOneWidget);
      expect(addFolderButton, findsOneWidget);
      expect(hashButton, findsOneWidget);
      expect(detectedRow, findsOneWidget);
      expect(tester.widget<OutlinedButton>(addFileButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(addFolderButton).onPressed, isNull);
      expect(tester.widget<FilledButton>(hashButton).onPressed, isNull);
      expect(tester.widget<ListTile>(detectedRow).onTap, isNull);
    },
  );

  testWidgets('protected apps add file dialog cancel does not save selection', (
    tester,
  ) async {
    final hashService = _FakeHashService();
    final controller = await _pumpProtectedAppsScreen(
      tester,
      const ZentorState(),
      hashService: hashService,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Add file or app'));
    await tester.pumpAndSettle();

    expect(find.text('Add protected app file?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(find.text('Add protected app file?'), findsNothing);
    expect(controller.state.config.protectedAppConfig.isConfigured, isFalse);
    expect(find.text('Protected app selection saved.'), findsNothing);
    expect(
      controller.state.events.map((event) => event.type),
      isNot(contains('manual_protected_app_file_unavailable')),
    );
  });

  testWidgets(
    'protected apps add file dialog confirm reports unsupported without saving',
    (tester) async {
      final hashService = _FakeHashService(supportsPathHashing: false);
      final controller = await _pumpProtectedAppsScreen(
        tester,
        const ZentorState(),
        hashService: hashService,
      );

      await tester.tap(find.widgetWithText(OutlinedButton, 'Add file or app'));
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
      await tester.pumpAndSettle();

      expect(controller.state.config.protectedAppConfig.isConfigured, isFalse);
      expect(
        controller.state.errorMessage,
        'Selected file protection is unavailable on this mobile platform.',
      );
      expect(
        controller.state.events.map((event) => event.type),
        contains('manual_protected_app_file_unavailable'),
      );
      expect(
        find.text('No protected app selection was saved.'),
        findsOneWidget,
      );
    },
  );

  testWidgets('protected apps add file dialog confirm saves picked file', (
    tester,
  ) async {
    final pickedPath =
        '${tempDir.path}${Platform.pathSeparator}picked-tool.exe';
    final pickedFile = File(pickedPath)
      ..writeAsStringSync('benign manual protected app fixture');
    final fileSelection = _FakeFileSelectionService(
      file: SelectedFilePath(name: 'picked-tool.exe', path: pickedFile.path),
    );
    final controller = await _pumpProtectedAppsScreen(
      tester,
      const ZentorState(),
      hashService: _FakeHashService(),
      fileSelectionService: fileSelection,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Add file or app'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();

    final selected = controller.state.config.protectedAppConfig;
    expect(fileSelection.pickFileCalls, 1);
    expect(fileSelection.pickDirectoryCalls, 0);
    expect(selected.appName, 'picked-tool.exe');
    expect(selected.appPath, pickedFile.path);
    expect(selected.source, 'Manual');
    expect(controller.state.config.scanPaths, contains(pickedFile.path));
    expect(controller.state.appDetectionStatus, AppDetectionStatus.manual);
    expect(find.text('Protected app selection saved.'), findsOneWidget);
    expect(
      controller.state.events.map((event) => event.type),
      contains('protected_app_added_manually'),
    );
  });

  testWidgets('protected apps add file picker cancel reports no save', (
    tester,
  ) async {
    final fileSelection = _FakeFileSelectionService();
    final controller = await _pumpProtectedAppsScreen(
      tester,
      const ZentorState(),
      hashService: _FakeHashService(),
      fileSelectionService: fileSelection,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Add file or app'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();

    expect(fileSelection.pickFileCalls, 1);
    expect(fileSelection.pickDirectoryCalls, 0);
    expect(controller.state.config.protectedAppConfig.isConfigured, isFalse);
    expect(controller.state.config.scanPaths, isEmpty);
    expect(find.text('No protected app selection was saved.'), findsOneWidget);
    expect(
      controller.state.events.map((event) => event.type),
      isNot(contains('manual_protected_app_file_failed')),
    );
    expect(
      controller.state.events.map((event) => event.type),
      isNot(contains('protected_app_added_manually')),
    );
  });

  testWidgets('protected apps add file picker failure reports error', (
    tester,
  ) async {
    final fileSelection = _FakeFileSelectionService(
      fileError: StateError('file picker failed\x00\n\twith controls'),
    );
    final controller = await _pumpProtectedAppsScreen(
      tester,
      const ZentorState(),
      hashService: _FakeHashService(),
      fileSelectionService: fileSelection,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Add file or app'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();

    expect(fileSelection.pickFileCalls, 1);
    expect(fileSelection.pickDirectoryCalls, 0);
    expect(controller.state.config.protectedAppConfig.isConfigured, isFalse);
    expect(controller.state.config.scanPaths, isEmpty);
    expect(find.text('No protected app selection was saved.'), findsOneWidget);
    expect(
      controller.state.errorMessage,
      contains('Unable to add selected file or app'),
    );
    expect(controller.state.errorMessage, contains('file picker failed'));
    expect(controller.state.errorMessage, isNot(contains('\x00')));
    final failedEvent = controller.state.events.firstWhere(
      (event) => event.type == 'manual_protected_app_file_failed',
    );
    expect(failedEvent.category, 'protection');
    expect(failedEvent.severity, 'error');
    expect(failedEvent.details, contains('file picker failed with controls'));
    expect(failedEvent.details, isNot(contains('\x00')));
  });

  testWidgets(
    'protected apps add folder dialog cancel does not save selection',
    (tester) async {
      final hashService = _FakeHashService();
      final controller = await _pumpProtectedAppsScreen(
        tester,
        const ZentorState(),
        hashService: hashService,
      );

      await tester.tap(find.widgetWithText(OutlinedButton, 'Add folder'));
      await tester.pumpAndSettle();

      expect(find.text('Add protected folder?'), findsOneWidget);
      await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
      await tester.pumpAndSettle();

      expect(find.text('Add protected folder?'), findsNothing);
      expect(controller.state.config.protectedAppConfig.isConfigured, isFalse);
      expect(find.text('Protected app selection saved.'), findsNothing);
      expect(
        controller.state.events.map((event) => event.type),
        isNot(contains('manual_protected_app_folder_unavailable')),
      );
    },
  );

  testWidgets(
    'protected apps add folder dialog confirm reports unsupported without saving',
    (tester) async {
      final hashService = _FakeHashService(supportsPathHashing: false);
      final controller = await _pumpProtectedAppsScreen(
        tester,
        const ZentorState(),
        hashService: hashService,
      );

      await tester.tap(find.widgetWithText(OutlinedButton, 'Add folder'));
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
      await tester.pumpAndSettle();

      expect(controller.state.config.protectedAppConfig.isConfigured, isFalse);
      expect(
        controller.state.errorMessage,
        'Selected folder protection is unavailable on this mobile platform.',
      );
      expect(
        controller.state.events.map((event) => event.type),
        contains('manual_protected_app_folder_unavailable'),
      );
      expect(
        find.text('No protected app selection was saved.'),
        findsOneWidget,
      );
    },
  );

  testWidgets('protected apps add folder dialog confirm saves picked folder', (
    tester,
  ) async {
    final pickedFolder = Directory(
      '${tempDir.path}${Platform.pathSeparator}PickedFolder',
    )..createSync();
    final fileSelection = _FakeFileSelectionService(
      directory: pickedFolder.path,
    );
    final controller = await _pumpProtectedAppsScreen(
      tester,
      const ZentorState(),
      hashService: _FakeHashService(),
      fileSelectionService: fileSelection,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Add folder'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();

    final selected = controller.state.config.protectedAppConfig;
    expect(fileSelection.pickFileCalls, 0);
    expect(fileSelection.pickDirectoryCalls, 1);
    expect(selected.appName, 'PickedFolder');
    expect(selected.appPath, pickedFolder.path);
    expect(selected.source, 'Manual');
    expect(controller.state.config.scanPaths, contains(pickedFolder.path));
    expect(controller.state.appDetectionStatus, AppDetectionStatus.manual);
    expect(find.text('Protected app selection saved.'), findsOneWidget);
    expect(
      controller.state.events.map((event) => event.type),
      contains('protected_app_added_manually'),
    );
  });

  testWidgets('protected apps add folder picker cancel reports no save', (
    tester,
  ) async {
    final fileSelection = _FakeFileSelectionService();
    final controller = await _pumpProtectedAppsScreen(
      tester,
      const ZentorState(),
      hashService: _FakeHashService(),
      fileSelectionService: fileSelection,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Add folder'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();

    expect(fileSelection.pickFileCalls, 0);
    expect(fileSelection.pickDirectoryCalls, 1);
    expect(controller.state.config.protectedAppConfig.isConfigured, isFalse);
    expect(controller.state.config.scanPaths, isEmpty);
    expect(find.text('No protected app selection was saved.'), findsOneWidget);
    expect(
      controller.state.events.map((event) => event.type),
      isNot(contains('manual_protected_app_folder_failed')),
    );
    expect(
      controller.state.events.map((event) => event.type),
      isNot(contains('protected_app_added_manually')),
    );
  });

  testWidgets('protected apps add folder picker failure reports error', (
    tester,
  ) async {
    final fileSelection = _FakeFileSelectionService(
      directoryError: StateError('folder picker failed\x00\n\twith controls'),
    );
    final controller = await _pumpProtectedAppsScreen(
      tester,
      const ZentorState(),
      hashService: _FakeHashService(),
      fileSelectionService: fileSelection,
    );

    await tester.tap(find.widgetWithText(OutlinedButton, 'Add folder'));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Continue'));
    await tester.pumpAndSettle();

    expect(fileSelection.pickFileCalls, 0);
    expect(fileSelection.pickDirectoryCalls, 1);
    expect(controller.state.config.protectedAppConfig.isConfigured, isFalse);
    expect(find.text('No protected app selection was saved.'), findsOneWidget);
    expect(
      controller.state.errorMessage,
      contains('Unable to add selected folder'),
    );
    expect(controller.state.errorMessage, contains('folder picker failed'));
    expect(controller.state.errorMessage, isNot(contains('\x00')));
    final failedEvent = controller.state.events.firstWhere(
      (event) => event.type == 'manual_protected_app_folder_failed',
    );
    expect(failedEvent.category, 'protection');
    expect(failedEvent.severity, 'error');
    expect(failedEvent.details, contains('folder picker failed with controls'));
    expect(failedEvent.details, isNot(contains('\x00')));
  });
}

ZentorState _stateWithProtectedApp(String appPath) => ZentorState(
  config: ZentorConfig(
    protectedAppConfig: ProtectedAppConfig(
      appId: 'manual-tool',
      appName: 'Manual Tool',
      appPath: appPath,
      source: 'Manual',
    ),
  ),
);

ZentorState _stateWithDetectedApp(String selectedPath, String detectedPath) =>
    ZentorState(
      config: ZentorConfig(
        protectedAppConfig: ProtectedAppConfig(
          appId: 'manual-tool',
          appName: 'Manual Tool',
          appPath: selectedPath,
          source: 'Manual',
        ),
      ),
      detectedApps: [
        DetectedApp(
          appId: 'detected-tool',
          displayName: 'Detected Tool',
          path: detectedPath,
          source: 'Known path',
        ),
      ],
    );

Future<ZentorController> _pumpProtectedAppsScreen(
  WidgetTester tester,
  ZentorState state, {
  required HashService hashService,
  FileSelectionService? fileSelectionService,
}) async {
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.pump();
  SharedPreferences.setMockInitialValues({});
  final preferences = await SharedPreferences.getInstance();
  final appDetector = const _FakeAppDetector();
  final controller = ZentorController(
    configRepository: ConfigRepository(preferences),
    eventRepository: LocalEventRepository(preferences),
    apiClient: ZentorApiClient(),
    hashService: hashService,
    appDetector: appDetector,
    fileSelectionService: fileSelectionService ?? const FileSelectionService(),
    localCoreClient: const LocalCoreClient(),
    scanTargetService: const ScanTargetService(),
    updateService: ZentorUpdateService(),
  );
  controller.state = state;

  await tester.pumpWidget(
    ProviderScope(
      overrides: [
        zentorControllerProvider.overrideWith((ref) => controller),
        appDetectorProvider.overrideWithValue(appDetector),
      ],
      child: MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(
          body: SingleChildScrollView(child: ProtectedAppsScreen()),
        ),
      ),
    ),
  );
  return controller;
}

class _FakeFileSelectionService extends FileSelectionService {
  _FakeFileSelectionService({
    this.file,
    this.fileError,
    this.directory,
    this.directoryError,
  });

  final SelectedFilePath? file;
  final Object? fileError;
  final String? directory;
  final Object? directoryError;
  int pickFileCalls = 0;
  int pickDirectoryCalls = 0;

  @override
  Future<SelectedFilePath?> pickFile() async {
    pickFileCalls += 1;
    final error = fileError;
    if (error != null) throw error;
    return file;
  }

  @override
  Future<String?> pickDirectory() async {
    pickDirectoryCalls += 1;
    final error = directoryError;
    if (error != null) throw error;
    return directory;
  }
}
