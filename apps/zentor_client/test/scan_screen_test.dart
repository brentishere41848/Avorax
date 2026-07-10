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
import 'package:zentor_client/features/scan/scan_screen.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

class _FakeScanTargetService extends ScanTargetService {
  const _FakeScanTargetService();

  @override
  ScanTargetPlan quickScanTargetPlan({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => const ScanTargetPlan([r'C:\AvoraxTest\Quick'], []);

  @override
  ScanTargetPlan fullScanRootPlan({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => const ScanTargetPlan([r'C:\AvoraxTest\FullRoot'], []);
}

const _engineUnavailableReport = ScanReport(
  status: ScanStatus.engineUnavailable,
  kind: ScanKind.quick,
  actionMode: ScanActionMode.detectOnly,
  filesScanned: 0,
  threatsFound: 0,
  skippedFiles: 0,
  elapsedMs: 0,
  message: 'engine unavailable',
  scanErrors: ['engine unavailable'],
  threats: [],
);

void main() {
  testWidgets('scan start busy disables action mode and scan starts', (
    tester,
  ) async {
    await _pumpScanScreen(tester, const ZentorState(scanStartInFlight: true));

    final actionModeSelector = find.byType(SegmentedButton<ScanActionMode>);
    final quickScanButton = find.widgetWithText(FilledButton, 'Quick Scan');
    final fullScanButton = find.widgetWithText(OutlinedButton, 'Full Scan');
    final customFileButton = find.widgetWithText(OutlinedButton, 'Custom File');
    final customFolderButton = find.widgetWithText(
      OutlinedButton,
      'Custom Folder',
    );

    expect(actionModeSelector, findsOneWidget);
    expect(
      tester
          .widget<SegmentedButton<ScanActionMode>>(actionModeSelector)
          .onSelectionChanged,
      isNull,
    );
    expect(quickScanButton, findsOneWidget);
    expect(fullScanButton, findsOneWidget);
    expect(customFileButton, findsOneWidget);
    expect(customFolderButton, findsOneWidget);
    expect(tester.widget<FilledButton>(quickScanButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(fullScanButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(customFileButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(customFolderButton).onPressed, isNull);
  });

  testWidgets('scan action modes label legacy quarantine honestly', (
    tester,
  ) async {
    await _pumpScanScreen(tester, const ZentorState());

    expect(find.text('Detect only'), findsOneWidget);
    expect(find.text('Auto quarantine confirmed'), findsOneWidget);
    expect(find.text('Legacy confirmed-only'), findsOneWidget);
    expect(find.text('Review non-confirmed'), findsNothing);
  });

  testWidgets('running scan disables action mode and scan starts', (
    tester,
  ) async {
    await _pumpScanScreen(
      tester,
      const ZentorState(scanStatus: ScanStatus.running),
    );

    final actionModeSelector = find.byType(SegmentedButton<ScanActionMode>);
    final quickScanButton = find.widgetWithText(FilledButton, 'Quick Scan');
    final fullScanButton = find.widgetWithText(OutlinedButton, 'Full Scan');
    final customFileButton = find.widgetWithText(OutlinedButton, 'Custom File');
    final customFolderButton = find.widgetWithText(
      OutlinedButton,
      'Custom Folder',
    );

    expect(actionModeSelector, findsOneWidget);
    expect(
      tester
          .widget<SegmentedButton<ScanActionMode>>(actionModeSelector)
          .onSelectionChanged,
      isNull,
    );
    expect(quickScanButton, findsOneWidget);
    expect(fullScanButton, findsOneWidget);
    expect(customFileButton, findsOneWidget);
    expect(customFolderButton, findsOneWidget);
    expect(tester.widget<FilledButton>(quickScanButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(fullScanButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(customFileButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(customFolderButton).onPressed, isNull);
  });

  testWidgets('scan target selection busy disables all scan start controls', (
    tester,
  ) async {
    await _pumpScanScreen(
      tester,
      const ZentorState(scanTargetSelectionInFlight: true),
    );

    final actionModeSelector = find.byType(SegmentedButton<ScanActionMode>);
    final quickScanButton = find.widgetWithText(FilledButton, 'Quick Scan');
    final fullScanButton = find.widgetWithText(OutlinedButton, 'Full Scan');
    final customFileButton = find.widgetWithText(OutlinedButton, 'Custom File');
    final customFolderButton = find.widgetWithText(
      OutlinedButton,
      'Custom Folder',
    );

    expect(actionModeSelector, findsOneWidget);
    expect(
      tester
          .widget<SegmentedButton<ScanActionMode>>(actionModeSelector)
          .onSelectionChanged,
      isNull,
    );
    expect(quickScanButton, findsOneWidget);
    expect(fullScanButton, findsOneWidget);
    expect(customFileButton, findsOneWidget);
    expect(customFolderButton, findsOneWidget);
    expect(tester.widget<FilledButton>(quickScanButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(fullScanButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(customFileButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(customFolderButton).onPressed, isNull);
  });

  testWidgets('update package work busy disables scan action mode and starts', (
    tester,
  ) async {
    await _pumpScanScreen(
      tester,
      const ZentorState(updateStatus: UpdateStatus.installing),
    );

    final actionModeSelector = find.byType(SegmentedButton<ScanActionMode>);
    final quickScanButton = find.widgetWithText(FilledButton, 'Quick Scan');
    final fullScanButton = find.widgetWithText(OutlinedButton, 'Full Scan');
    final customFileButton = find.widgetWithText(OutlinedButton, 'Custom File');
    final customFolderButton = find.widgetWithText(
      OutlinedButton,
      'Custom Folder',
    );

    expect(actionModeSelector, findsOneWidget);
    expect(
      tester
          .widget<SegmentedButton<ScanActionMode>>(actionModeSelector)
          .onSelectionChanged,
      isNull,
    );
    expect(quickScanButton, findsOneWidget);
    expect(fullScanButton, findsOneWidget);
    expect(customFileButton, findsOneWidget);
    expect(customFolderButton, findsOneWidget);
    expect(tester.widget<FilledButton>(quickScanButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(fullScanButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(customFileButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(customFolderButton).onPressed, isNull);
  });

  testWidgets('scan threat feedback and ignore busy states disable actions', (
    tester,
  ) async {
    await _pumpScanScreen(
      tester,
      ZentorState(
        detectionFeedbackInFlight: true,
        threatIgnoreActionInFlight: true,
        lastScanReport: _scanReportWithReviewThreat(),
      ),
    );

    final keepIgnoreButton = find.widgetWithText(
      OutlinedButton,
      'Keep / Ignore',
    );
    final falsePositiveButton = find.widgetWithText(
      OutlinedButton,
      'Mark false positive',
    );
    final maliciousButton = find.widgetWithText(
      OutlinedButton,
      'Mark malicious',
    );

    expect(keepIgnoreButton, findsOneWidget);
    expect(falsePositiveButton, findsOneWidget);
    expect(maliciousButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(keepIgnoreButton).onPressed, isNull);
    expect(
      tester.widget<OutlinedButton>(falsePositiveButton).onPressed,
      isNull,
    );
    expect(tester.widget<OutlinedButton>(maliciousButton).onPressed, isNull);
  });

  testWidgets('scan threat actions disable while configuration state is busy', (
    tester,
  ) async {
    for (final state in const [
      ZentorState(securitySettingsActionInFlight: true),
      ZentorState(configurationResetInFlight: true),
    ]) {
      await _pumpScanScreen(
        tester,
        state.copyWith(lastScanReport: _scanReportWithReviewThreat()),
      );

      final keepIgnoreButton = find.widgetWithText(
        OutlinedButton,
        'Keep / Ignore',
      );
      final falsePositiveButton = find.widgetWithText(
        OutlinedButton,
        'Mark false positive',
      );
      final maliciousButton = find.widgetWithText(
        OutlinedButton,
        'Mark malicious',
      );
      final allowlistButton = find.widgetWithText(
        OutlinedButton,
        'Add to allowlist',
      );

      expect(keepIgnoreButton, findsOneWidget);
      expect(falsePositiveButton, findsOneWidget);
      expect(maliciousButton, findsOneWidget);
      expect(allowlistButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(keepIgnoreButton).onPressed, isNull);
      expect(
        tester.widget<OutlinedButton>(falsePositiveButton).onPressed,
        isNull,
      );
      expect(tester.widget<OutlinedButton>(maliciousButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(allowlistButton).onPressed, isNull);

      await _pumpScanScreen(
        tester,
        state.copyWith(lastScanReport: _scanReportWithConfirmedThreat()),
      );

      final quarantineButton = find.widgetWithText(FilledButton, 'Quarantine');
      expect(quarantineButton, findsOneWidget);
      expect(tester.widget<FilledButton>(quarantineButton).onPressed, isNull);
    }
  });

  testWidgets('manual trust actions disable during update package work', (
    tester,
  ) async {
    const updateBusyState = ZentorState(updateStatus: UpdateStatus.installing);
    await _pumpScanScreen(
      tester,
      updateBusyState.copyWith(lastScanReport: _scanReportWithReviewThreat()),
    );

    final keepIgnoreButton = find.widgetWithText(
      OutlinedButton,
      'Keep / Ignore',
    );
    final falsePositiveButton = find.widgetWithText(
      OutlinedButton,
      'Mark false positive',
    );
    final maliciousButton = find.widgetWithText(
      OutlinedButton,
      'Mark malicious',
    );
    final allowlistButton = find.widgetWithText(
      OutlinedButton,
      'Add to allowlist',
    );

    expect(keepIgnoreButton, findsOneWidget);
    expect(falsePositiveButton, findsOneWidget);
    expect(maliciousButton, findsOneWidget);
    expect(allowlistButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(keepIgnoreButton).onPressed, isNull);
    expect(
      tester.widget<OutlinedButton>(falsePositiveButton).onPressed,
      isNull,
    );
    expect(tester.widget<OutlinedButton>(maliciousButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(allowlistButton).onPressed, isNull);

    await _pumpScanScreen(
      tester,
      updateBusyState.copyWith(
        lastScanReport: _scanReportWithConfirmedThreat(),
      ),
    );

    final quarantineButton = find.widgetWithText(FilledButton, 'Quarantine');
    expect(quarantineButton, findsOneWidget);
    expect(tester.widget<FilledButton>(quarantineButton).onPressed, isNull);
  });

  testWidgets(
    'scan review rows show small-threat categories without quarantine',
    (tester) async {
      await _pumpScanScreen(
        tester,
        ZentorState(
          lastScanReport: ScanReport(
            status: ScanStatus.infected,
            kind: ScanKind.quick,
            actionMode: ScanActionMode.autoQuarantineConfirmedOnly,
            filesScanned: 3,
            threatsFound: 3,
            suspiciousFound: 3,
            skippedFiles: 0,
            elapsedMs: 91,
            threats: [
              _reviewThreat(
                id: 'infostealer-review',
                fileName: 'collector.js',
                threatCategory: ThreatCategory.infostealer,
              ),
              _reviewThreat(
                id: 'miner-review',
                fileName: 'miner-config.ps1',
                threatCategory: ThreatCategory.miner,
              ),
              _reviewThreat(
                id: 'persistence-review',
                fileName: 'startup-task.ps1',
                threatCategory: ThreatCategory.persistenceIndicator,
              ),
            ],
          ),
        ),
      );

      expect(find.text('Potential infostealer'), findsOneWidget);
      expect(find.text('Potential miner'), findsOneWidget);
      expect(find.text('Persistence indicator'), findsOneWidget);
      expect(find.text('Review suggested'), findsWidgets);
      expect(find.textContaining('Review-only evidence'), findsNWidgets(3));
      expect(
        find.textContaining('will not automatically quarantine'),
        findsNWidgets(3),
      );
      expect(find.widgetWithText(FilledButton, 'Quarantine'), findsNothing);
    },
  );

  testWidgets('scan service recovery busy disables recovery controls', (
    tester,
  ) async {
    await _pumpScanScreen(
      tester,
      const ZentorState(
        serviceActionInFlight: true,
        coreServiceStatus: 'stopped',
        lastScanReport: ScanReport(
          status: ScanStatus.engineUnavailable,
          kind: ScanKind.quick,
          actionMode: ScanActionMode.detectOnly,
          filesScanned: 0,
          threatsFound: 0,
          skippedFiles: 0,
          elapsedMs: 0,
          message: 'engine unavailable',
          scanErrors: ['engine unavailable'],
          threats: [],
        ),
      ),
    );

    final startButton = find.widgetWithText(
      OutlinedButton,
      'Start Core Service',
    );
    final reportButton = find.widgetWithText(
      OutlinedButton,
      'Open install report',
    );
    final repairButton = find.widgetWithText(
      OutlinedButton,
      'Repair installation',
    );

    expect(startButton, findsOneWidget);
    expect(reportButton, findsOneWidget);
    expect(repairButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(startButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(reportButton).onPressed, isNull);
    expect(tester.widget<OutlinedButton>(repairButton).onPressed, isNull);
  });

  testWidgets(
    'scan service recovery controls disable during update package work',
    (tester) async {
      await _pumpScanScreen(
        tester,
        const ZentorState(
          updateStatus: UpdateStatus.installing,
          coreServiceStatus: 'stopped',
          lastScanReport: ScanReport(
            status: ScanStatus.engineUnavailable,
            kind: ScanKind.quick,
            actionMode: ScanActionMode.detectOnly,
            filesScanned: 0,
            threatsFound: 0,
            skippedFiles: 0,
            elapsedMs: 0,
            message: 'engine unavailable',
            scanErrors: ['engine unavailable'],
            threats: [],
          ),
        ),
      );

      final startButton = find.widgetWithText(
        OutlinedButton,
        'Start Core Service',
      );
      final reportButton = find.widgetWithText(
        OutlinedButton,
        'Open install report',
      );
      final repairButton = find.widgetWithText(
        OutlinedButton,
        'Repair installation',
      );

      expect(startButton, findsOneWidget);
      expect(reportButton, findsOneWidget);
      expect(repairButton, findsOneWidget);
      expect(tester.widget<OutlinedButton>(startButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(reportButton).onPressed, isNull);
      expect(tester.widget<OutlinedButton>(repairButton).onPressed, isNull);
    },
  );

  testWidgets(
    'scan start core service dialog cancel does not call local core',
    (tester) async {
      final localCore = _RecordingLocalCoreClient();
      await _pumpScanScreen(
        tester,
        const ZentorState(
          coreServiceStatus: 'stopped',
          lastScanReport: _engineUnavailableReport,
        ),
        localCoreClient: localCore,
      );

      final startButton = find.widgetWithText(
        OutlinedButton,
        'Start Core Service',
      );
      await tester.ensureVisible(startButton);
      await tester.tap(startButton);
      await tester.pumpAndSettle();

      expect(find.text('Start Core Service?'), findsOneWidget);
      await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
      await tester.pumpAndSettle();

      expect(localCore.startCoreServiceCalls, 0);
      expect(find.text('Start Core Service?'), findsNothing);
    },
  );

  testWidgets('scan retry engine status calls local core health once', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    final controller = await _pumpScanScreen(
      tester,
      const ZentorState(
        coreServiceStatus: 'stopped',
        lastScanReport: _engineUnavailableReport,
      ),
      localCoreClient: localCore,
    );

    final retryButton = find.widgetWithText(OutlinedButton, 'Retry');
    expect(retryButton, findsOneWidget);
    await tester.ensureVisible(retryButton);
    await tester.tap(retryButton);
    await tester.pumpAndSettle();

    expect(localCore.healthSummaryCalls, 1);
    expect(controller.state.malwareEngineStatus, MalwareEngineStatus.available);
    expect(controller.state.nativeEngineStatus, 'ready');
    expect(controller.state.malwareEngineHealthCheckInFlight, isFalse);
    expect(
      controller.state.events.map((event) => event.type),
      contains('malware_engine_available'),
    );
  });

  testWidgets('scan start core service dialog confirm calls local core', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(
        coreServiceStatus: 'stopped',
        lastScanReport: _engineUnavailableReport,
      ),
      localCoreClient: localCore,
    );

    final startButton = find.widgetWithText(
      OutlinedButton,
      'Start Core Service',
    );
    await tester.ensureVisible(startButton);
    await tester.tap(startButton);
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Start'));
    await tester.pumpAndSettle();

    expect(localCore.startCoreServiceCalls, 1);
  });

  testWidgets('scan open install report dialog confirm calls local core', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(
        coreServiceStatus: 'stopped',
        lastScanReport: _engineUnavailableReport,
      ),
      localCoreClient: localCore,
    );

    final reportButton = find.widgetWithText(
      OutlinedButton,
      'Open install report',
    );
    await tester.ensureVisible(reportButton);
    await tester.tap(reportButton);
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Open'));
    await tester.pumpAndSettle();

    expect(localCore.openInstallReportCalls, 1);
  });

  testWidgets(
    'scan open install report dialog cancel does not call local core',
    (tester) async {
      final localCore = _RecordingLocalCoreClient();
      await _pumpScanScreen(
        tester,
        const ZentorState(
          coreServiceStatus: 'stopped',
          lastScanReport: _engineUnavailableReport,
        ),
        localCoreClient: localCore,
      );

      final reportButton = find.widgetWithText(
        OutlinedButton,
        'Open install report',
      );
      await tester.ensureVisible(reportButton);
      await tester.tap(reportButton);
      await tester.pumpAndSettle();

      expect(find.text('Open install report?'), findsOneWidget);
      await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
      await tester.pumpAndSettle();

      expect(localCore.openInstallReportCalls, 0);
      expect(find.text('Open install report?'), findsNothing);
    },
  );

  testWidgets('scan repair installation dialog confirm calls local core', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(
        coreServiceStatus: 'stopped',
        lastScanReport: _engineUnavailableReport,
      ),
      localCoreClient: localCore,
    );

    final repairButton = find.widgetWithText(
      OutlinedButton,
      'Repair installation',
    );
    await tester.ensureVisible(repairButton);
    await tester.tap(repairButton);
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Repair'));
    await tester.pumpAndSettle();

    expect(localCore.repairInstallationCalls, 1);
  });

  testWidgets(
    'scan repair installation dialog cancel does not call local core',
    (tester) async {
      final localCore = _RecordingLocalCoreClient();
      await _pumpScanScreen(
        tester,
        const ZentorState(
          coreServiceStatus: 'stopped',
          lastScanReport: _engineUnavailableReport,
        ),
        localCoreClient: localCore,
      );

      final repairButton = find.widgetWithText(
        OutlinedButton,
        'Repair installation',
      );
      await tester.ensureVisible(repairButton);
      await tester.tap(repairButton);
      await tester.pumpAndSettle();

      expect(find.text('Repair installation?'), findsOneWidget);
      await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
      await tester.pumpAndSettle();

      expect(localCore.repairInstallationCalls, 0);
      expect(find.text('Repair installation?'), findsNothing);
    },
  );

  testWidgets('quick scan auto-quarantine dialog cancel does not scan', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(
        scanActionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      ),
      localCoreClient: localCore,
      scanTargetService: const _FakeScanTargetService(),
    );

    final quickScanButton = find.widgetWithText(FilledButton, 'Quick Scan');
    await tester.tap(quickScanButton);
    await tester.pumpAndSettle();

    expect(find.text('Run scan with automatic quarantine?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.scanPathsCalls, 0);
    expect(find.text('Run scan with automatic quarantine?'), findsNothing);
  });

  testWidgets('quick scan auto-quarantine dialog confirm scans once', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(
        scanActionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      ),
      localCoreClient: localCore,
      scanTargetService: const _FakeScanTargetService(),
    );

    final quickScanButton = find.widgetWithText(FilledButton, 'Quick Scan');
    await tester.tap(quickScanButton);
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Run scan'));
    await tester.pumpAndSettle();

    expect(localCore.scanPathsCalls, 1);
    expect(localCore.lastScanPaths, [r'C:\AvoraxTest\Quick']);
    expect(
      localCore.lastScanActionMode,
      ScanActionMode.autoQuarantineConfirmedOnly,
    );
  });

  testWidgets('quick scan detect-only starts without quarantine dialog', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(scanActionMode: ScanActionMode.detectOnly),
      localCoreClient: localCore,
      scanTargetService: const _FakeScanTargetService(),
    );

    final quickScanButton = find.widgetWithText(FilledButton, 'Quick Scan');
    await tester.tap(quickScanButton);
    await tester.pumpAndSettle();

    expect(find.text('Run scan with automatic quarantine?'), findsNothing);
    expect(localCore.scanPathsCalls, 1);
    expect(localCore.lastScanPaths, [r'C:\AvoraxTest\Quick']);
    expect(localCore.lastScanKind, ScanKind.quick);
    expect(localCore.lastScanActionMode, ScanActionMode.detectOnly);
  });

  testWidgets('full scan auto-quarantine dialog cancel does not scan', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(
        scanActionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      ),
      localCoreClient: localCore,
      scanTargetService: const _FakeScanTargetService(),
    );

    final fullScanButton = find.widgetWithText(OutlinedButton, 'Full Scan');
    await tester.tap(fullScanButton);
    await tester.pumpAndSettle();

    expect(find.text('Run scan with automatic quarantine?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.scanPathsCalls, 0);
    expect(find.text('Run scan with automatic quarantine?'), findsNothing);
  });

  testWidgets('full scan auto-quarantine dialog confirm scans once', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(
        scanActionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      ),
      localCoreClient: localCore,
      scanTargetService: const _FakeScanTargetService(),
    );

    final fullScanButton = find.widgetWithText(OutlinedButton, 'Full Scan');
    await tester.tap(fullScanButton);
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Run scan'));
    await tester.pumpAndSettle();

    expect(localCore.scanPathsCalls, 1);
    expect(localCore.lastScanPaths, [r'C:\AvoraxTest\FullRoot']);
    expect(localCore.lastScanKind, ScanKind.full);
    expect(
      localCore.lastScanActionMode,
      ScanActionMode.autoQuarantineConfirmedOnly,
    );
  });

  testWidgets('full scan detect-only starts without quarantine dialog', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(scanActionMode: ScanActionMode.detectOnly),
      localCoreClient: localCore,
      scanTargetService: const _FakeScanTargetService(),
    );

    final fullScanButton = find.widgetWithText(OutlinedButton, 'Full Scan');
    await tester.tap(fullScanButton);
    await tester.pumpAndSettle();

    expect(find.text('Run scan with automatic quarantine?'), findsNothing);
    expect(localCore.scanPathsCalls, 1);
    expect(localCore.lastScanPaths, [r'C:\AvoraxTest\FullRoot']);
    expect(localCore.lastScanKind, ScanKind.full);
    expect(localCore.lastScanActionMode, ScanActionMode.detectOnly);
  });

  testWidgets('custom file auto-quarantine dialog cancel does not scan', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(
        scanActionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      ),
      localCoreClient: localCore,
      scanTargetService: const _FakeScanTargetService(),
    );

    final customFileButton = find.widgetWithText(OutlinedButton, 'Custom File');
    await tester.tap(customFileButton);
    await tester.pumpAndSettle();

    expect(find.text('Run scan with automatic quarantine?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.scanPathsCalls, 0);
    expect(find.text('Run scan with automatic quarantine?'), findsNothing);
  });

  testWidgets('custom folder auto-quarantine dialog cancel does not scan', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      const ZentorState(
        scanActionMode: ScanActionMode.autoQuarantineConfirmedOnly,
      ),
      localCoreClient: localCore,
      scanTargetService: const _FakeScanTargetService(),
    );

    final customFolderButton = find.widgetWithText(
      OutlinedButton,
      'Custom Folder',
    );
    await tester.tap(customFolderButton);
    await tester.pumpAndSettle();

    expect(find.text('Run scan with automatic quarantine?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.scanPathsCalls, 0);
    expect(find.text('Run scan with automatic quarantine?'), findsNothing);
  });

  testWidgets('custom file detect-only picker selection scans chosen file', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    final fileSelection = _FakeFileSelectionService(
      file: const SelectedFilePath(
        name: 'picked-sample.txt',
        path: r'C:\AvoraxTest\picked-sample.txt',
      ),
    );
    await _pumpScanScreen(
      tester,
      const ZentorState(scanActionMode: ScanActionMode.detectOnly),
      localCoreClient: localCore,
      fileSelectionService: fileSelection,
    );

    final customFileButton = find.widgetWithText(OutlinedButton, 'Custom File');
    await tester.tap(customFileButton);
    await tester.pumpAndSettle();

    expect(fileSelection.pickFileCalls, 1);
    expect(fileSelection.pickDirectoryCalls, 0);
    expect(localCore.scanPathsCalls, 1);
    expect(localCore.lastScanPaths, [r'C:\AvoraxTest\picked-sample.txt']);
    expect(localCore.lastScanKind, ScanKind.custom);
    expect(localCore.lastScanActionMode, ScanActionMode.detectOnly);
    expect(find.text('Run scan with automatic quarantine?'), findsNothing);
  });

  testWidgets(
    'custom folder detect-only picker selection scans chosen folder',
    (tester) async {
      final localCore = _RecordingLocalCoreClient();
      final fileSelection = _FakeFileSelectionService(
        directory: r'C:\AvoraxTest\PickedFolder',
      );
      await _pumpScanScreen(
        tester,
        const ZentorState(scanActionMode: ScanActionMode.detectOnly),
        localCoreClient: localCore,
        fileSelectionService: fileSelection,
      );

      final customFolderButton = find.widgetWithText(
        OutlinedButton,
        'Custom Folder',
      );
      await tester.tap(customFolderButton);
      await tester.pumpAndSettle();

      expect(fileSelection.pickFileCalls, 0);
      expect(fileSelection.pickDirectoryCalls, 1);
      expect(localCore.scanPathsCalls, 1);
      expect(localCore.lastScanPaths, [r'C:\AvoraxTest\PickedFolder']);
      expect(localCore.lastScanKind, ScanKind.custom);
      expect(localCore.lastScanActionMode, ScanActionMode.detectOnly);
      expect(find.text('Run scan with automatic quarantine?'), findsNothing);
    },
  );

  testWidgets('scan quarantine dialog cancel does not call local core', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      ZentorState(lastScanReport: _scanReportWithConfirmedThreat()),
      localCoreClient: localCore,
    );

    final quarantineButton = find.widgetWithText(FilledButton, 'Quarantine');
    await tester.ensureVisible(quarantineButton);
    await tester.tap(quarantineButton);
    await tester.pumpAndSettle();

    expect(find.text('Quarantine this file?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.quarantineCalls, 0);
    expect(find.text('Quarantine this file?'), findsNothing);
  });

  testWidgets('scan quarantine dialog confirm calls local core', (
    tester,
  ) async {
    final threat = _confirmedThreat();
    final localCore = _RecordingLocalCoreClient(
      listQuarantineFailure: 'quarantine refresh unavailable',
    );
    await _pumpScanScreen(
      tester,
      ZentorState(lastScanReport: _scanReportWithThreat(threat)),
      localCoreClient: localCore,
    );

    final quarantineButton = find.widgetWithText(FilledButton, 'Quarantine');
    await tester.ensureVisible(quarantineButton);
    await tester.tap(quarantineButton);
    await tester.pumpAndSettle();
    await tester.tap(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.widgetWithText(FilledButton, 'Quarantine'),
      ),
    );
    await tester.pumpAndSettle();

    expect(localCore.quarantineCalls, 1);
    expect(localCore.lastQuarantineThreatId, threat.id);
  });

  testWidgets('quarantined scan row shows quarantine record evidence', (
    tester,
  ) async {
    await _pumpScanScreen(
      tester,
      ZentorState(
        lastScanReport: _scanReportWithThreat(
          _confirmedThreat(
            status: ThreatResultStatus.quarantined,
            quarantineId: 'record-eicar',
            quarantinePath:
                r'C:\ProgramData\Avorax\Quarantine\record-eicar.avoraxq',
            quarantineActionTaken: 'quarantined',
          ),
        ),
      ),
    );

    expect(find.textContaining('isolated quarantine storage'), findsOneWidget);
    expect(find.textContaining('Record: record-eicar'), findsOneWidget);
    expect(find.textContaining('.avoraxq'), findsOneWidget);
    expect(find.widgetWithText(FilledButton, 'Quarantine'), findsNothing);
  });

  testWidgets('scan allowlist dialog cancel does not call local core', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      ZentorState(lastScanReport: _scanReportWithReviewThreat()),
      localCoreClient: localCore,
    );

    final allowlistButton = find.widgetWithText(
      OutlinedButton,
      'Add to allowlist',
    );
    await tester.ensureVisible(allowlistButton);
    await tester.tap(allowlistButton);
    await tester.pumpAndSettle();

    expect(find.text('Add to allowlist?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.addAllowlistEntryCalls, 0);
    expect(find.text('Add to allowlist?'), findsNothing);
  });

  testWidgets('scan allowlist dialog confirm calls local core', (tester) async {
    final threat = _reviewThreat();
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      ZentorState(lastScanReport: _scanReportWithThreat(threat)),
      localCoreClient: localCore,
    );

    final allowlistButton = find.widgetWithText(
      OutlinedButton,
      'Add to allowlist',
    );
    await tester.ensureVisible(allowlistButton);
    await tester.tap(allowlistButton);
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(FilledButton, 'Allowlist'));
    await tester.pumpAndSettle();

    expect(localCore.addAllowlistEntryCalls, 1);
    expect(localCore.lastAllowlistPath, threat.path);
  });

  testWidgets('scan false-positive dialog cancel does not call local core', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      ZentorState(lastScanReport: _scanReportWithReviewThreat()),
      localCoreClient: localCore,
    );

    final falsePositiveButton = find.widgetWithText(
      OutlinedButton,
      'Mark false positive',
    );
    await tester.ensureVisible(falsePositiveButton);
    await tester.tap(falsePositiveButton);
    await tester.pumpAndSettle();

    expect(find.text('Mark false positive?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.labelDetectionCalls, 0);
    expect(find.text('Mark false positive?'), findsNothing);
  });

  testWidgets('scan false-positive dialog confirm calls local core', (
    tester,
  ) async {
    final threat = _reviewThreat();
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      ZentorState(lastScanReport: _scanReportWithThreat(threat)),
      localCoreClient: localCore,
    );

    final falsePositiveButton = find.widgetWithText(
      OutlinedButton,
      'Mark false positive',
    );
    await tester.ensureVisible(falsePositiveButton);
    await tester.tap(falsePositiveButton);
    await tester.pumpAndSettle();
    await tester.tap(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.widgetWithText(FilledButton, 'Mark false positive'),
      ),
    );
    await tester.pumpAndSettle();

    expect(localCore.labelDetectionCalls, 1);
    expect(localCore.lastLabelThreatId, threat.id);
    expect(localCore.lastLabel, 'falsePositive');
  });

  testWidgets('scan malicious dialog cancel does not call local core', (
    tester,
  ) async {
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      ZentorState(lastScanReport: _scanReportWithReviewThreat()),
      localCoreClient: localCore,
    );

    final maliciousButton = find.widgetWithText(
      OutlinedButton,
      'Mark malicious',
    );
    await tester.ensureVisible(maliciousButton);
    await tester.tap(maliciousButton);
    await tester.pumpAndSettle();

    expect(find.text('Submit malicious feedback?'), findsOneWidget);
    expect(
      find.textContaining('future detection decisions only'),
      findsOneWidget,
    );
    expect(
      find.textContaining('does not quarantine, delete, execute'),
      findsOneWidget,
    );
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(localCore.labelDetectionCalls, 0);
    expect(find.text('Submit malicious feedback?'), findsNothing);
  });

  testWidgets('scan malicious dialog confirm calls local core', (tester) async {
    final threat = _reviewThreat();
    final localCore = _RecordingLocalCoreClient();
    await _pumpScanScreen(
      tester,
      ZentorState(lastScanReport: _scanReportWithThreat(threat)),
      localCoreClient: localCore,
    );

    final maliciousButton = find.widgetWithText(
      OutlinedButton,
      'Mark malicious',
    );
    await tester.ensureVisible(maliciousButton);
    await tester.tap(maliciousButton);
    await tester.pumpAndSettle();
    await tester.tap(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.widgetWithText(FilledButton, 'Submit feedback'),
      ),
    );
    await tester.pumpAndSettle();

    expect(localCore.labelDetectionCalls, 1);
    expect(localCore.lastLabelThreatId, threat.id);
    expect(localCore.lastLabel, 'confirmedMalicious');
  });

  testWidgets('scan keep-ignore dialog cancel keeps threat detected', (
    tester,
  ) async {
    final threat = _reviewThreat();
    final controller = await _pumpScanScreen(
      tester,
      ZentorState(lastScanReport: _scanReportWithThreat(threat)),
    );

    final ignoreButton = find.widgetWithText(OutlinedButton, 'Keep / Ignore');
    await tester.ensureVisible(ignoreButton);
    await tester.tap(ignoreButton);
    await tester.pumpAndSettle();

    expect(find.text('Keep and ignore this detection?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Cancel'));
    await tester.pumpAndSettle();

    expect(find.text('Keep and ignore this detection?'), findsNothing);
    expect(
      controller.state.lastScanReport?.threats.single.status,
      ThreatResultStatus.detected,
    );
  });

  testWidgets('scan keep-ignore dialog confirm marks threat ignored', (
    tester,
  ) async {
    final threat = _reviewThreat();
    final controller = await _pumpScanScreen(
      tester,
      ZentorState(lastScanReport: _scanReportWithThreat(threat)),
    );

    final ignoreButton = find.widgetWithText(OutlinedButton, 'Keep / Ignore');
    await tester.ensureVisible(ignoreButton);
    await tester.tap(ignoreButton);
    await tester.pumpAndSettle();
    await tester.tap(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.widgetWithText(FilledButton, 'Keep / Ignore'),
      ),
    );
    await tester.pumpAndSettle();

    expect(
      controller.state.lastScanReport?.threats.single.status,
      ThreatResultStatus.ignored,
    );
    expect(controller.state.threatIgnoreActionInFlight, isFalse);
  });

  testWidgets(
    'scan metrics show no-report labels without scan report evidence',
    (tester) async {
      await _pumpScanScreen(tester, const ZentorState());

      expect(find.text('Files scanned'), findsOneWidget);
      expect(find.text('Threats found'), findsOneWidget);
      expect(find.text('Elapsed'), findsOneWidget);
      expect(find.text('No report'), findsNWidgets(3));
      expect(find.text('No scan report yet'), findsNWidgets(2));
      expect(find.text('Waiting for scan'), findsOneWidget);
      expect(find.text('No scan results'), findsOneWidget);
      expect(find.text('0'), findsNothing);
      expect(find.text('0s'), findsNothing);
    },
  );

  testWidgets('live scan facts show pending labels without progress evidence', (
    tester,
  ) async {
    await _pumpScanScreen(
      tester,
      const ZentorState(scanStatus: ScanStatus.running),
    );

    expect(find.text('Scan running'), findsNWidgets(2));
    expect(find.text('Preparing scan...'), findsOneWidget);
    expect(find.text('Files: Pending'), findsOneWidget);
    expect(find.text('Bytes: Pending'), findsOneWidget);
    expect(find.text('Threats: Pending'), findsOneWidget);
    expect(find.text('Suspicious: Pending'), findsOneWidget);
    expect(find.text('Skipped: Pending'), findsOneWidget);
    expect(find.text('Elapsed: Pending'), findsOneWidget);
    expect(find.text('Files: 0'), findsNothing);
    expect(find.text('Threats: 0'), findsNothing);
  });

  testWidgets('scan cancel button disables while cancellation is busy', (
    tester,
  ) async {
    await _pumpScanScreen(
      tester,
      const ZentorState(
        scanStatus: ScanStatus.running,
        scanCancelInFlight: true,
      ),
    );

    final cancelButton = find.widgetWithText(OutlinedButton, 'Cancel');

    expect(cancelButton, findsOneWidget);
    expect(tester.widget<OutlinedButton>(cancelButton).onPressed, isNull);
  });

  testWidgets(
    'scan engine diagnostics distinguish core service status labels',
    (tester) async {
      const cases = <String, String>{
        'unknown': 'Unknown',
        'unsupported': 'Unsupported on this OS',
        'error': 'Error',
        'unexpected': 'Unavailable',
      };

      for (final entry in cases.entries) {
        await _pumpScanScreen(
          tester,
          ZentorState(
            coreServiceStatus: entry.key,
            lastScanReport: const ScanReport(
              status: ScanStatus.engineUnavailable,
              kind: ScanKind.quick,
              actionMode: ScanActionMode.detectOnly,
              filesScanned: 0,
              threatsFound: 0,
              skippedFiles: 0,
              elapsedMs: 0,
              message: 'engine unavailable',
              scanErrors: ['engine unavailable'],
              threats: [],
            ),
          ),
        );

        expect(find.text('Engine unavailable'), findsOneWidget);
        expect(find.text('Core Service: ${entry.value}'), findsOneWidget);
      }
    },
  );

  testWidgets('scan engine diagnostics distinguish native ml status labels', (
    tester,
  ) async {
    const cases = <String, String>{
      'loaded': 'Found',
      'developmentModel': 'Found (development)',
      'modelMissing': 'Missing',
      'error': 'Error',
      'unexpected': 'Unknown',
    };

    for (final entry in cases.entries) {
      await _pumpScanScreen(
        tester,
        ZentorState(
          nativeMlStatus: entry.key,
          lastScanReport: const ScanReport(
            status: ScanStatus.engineUnavailable,
            kind: ScanKind.quick,
            actionMode: ScanActionMode.detectOnly,
            filesScanned: 0,
            threatsFound: 0,
            skippedFiles: 0,
            elapsedMs: 0,
            message: 'engine unavailable',
            scanErrors: ['engine unavailable'],
            threats: [],
          ),
        ),
      );

      expect(find.text('Engine unavailable'), findsOneWidget);
      expect(find.text('ML model: ${entry.value}'), findsOneWidget);
    }
  });
}

ScanReport _scanReportWithReviewThreat() => ScanReport(
  status: ScanStatus.infected,
  kind: ScanKind.custom,
  actionMode: ScanActionMode.detectOnly,
  filesScanned: 1,
  threatsFound: 1,
  skippedFiles: 0,
  elapsedMs: 42,
  threats: [_reviewThreat()],
);

ScanReport _scanReportWithConfirmedThreat() =>
    _scanReportWithThreat(_confirmedThreat());

ScanReport _scanReportWithThreat(ThreatResult threat) => ScanReport(
  status: ScanStatus.infected,
  kind: ScanKind.custom,
  actionMode: ScanActionMode.detectOnly,
  filesScanned: 1,
  threatsFound: 1,
  skippedFiles: 0,
  elapsedMs: 42,
  threats: [threat],
);

ThreatResult _reviewThreat({
  String id = 'review-threat-1',
  String fileName = 'unknown-tool.exe',
  ThreatCategory threatCategory = ThreatCategory.unknown,
}) => ThreatResult(
  id: id,
  path: 'C:\\Users\\Brent\\Downloads\\$fileName',
  fileName: fileName,
  sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  sizeBytes: 128,
  detectionType: DetectionType.heuristic,
  threatCategory: threatCategory,
  threatName: 'Suspicious test fixture',
  confidence: ThreatConfidence.medium,
  engine: 'local-core',
  detectedAt: DateTime.utc(2026, 7, 5, 12),
  recommendedAction: RecommendedAction.review,
  status: ThreatResultStatus.detected,
  reasonSummary: 'Fixture threat for Scan action busy-state verification.',
  riskScore: const RiskScore(
    score: 55,
    verdict: RiskVerdict.suspicious,
    confidence: ThreatConfidence.medium,
    reasons: [
      RiskReason(
        id: 'heuristic-test',
        title: 'Suspicious structure',
        detail: 'Benign fixture used to verify UI controls.',
        weight: 55,
        severity: RiskSeverity.medium,
        source: RiskReasonSource.heuristic,
      ),
    ],
    recommendedAction: RecommendedAction.review,
    enginesUsed: [DetectionType.heuristic],
  ),
);

ThreatResult _confirmedThreat({
  ThreatResultStatus status = ThreatResultStatus.detected,
  String? quarantineId,
  String? quarantinePath,
  String? quarantineActionTaken,
}) => ThreatResult(
  id: 'confirmed-threat-1',
  path: r'C:\Users\Brent\Downloads\eicar.com',
  fileName: 'eicar.com',
  sha256: '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f',
  sizeBytes: 68,
  detectionType: DetectionType.signature,
  threatCategory: ThreatCategory.trojan,
  threatName: 'EICAR-Test-File',
  confidence: ThreatConfidence.confirmed,
  engine: 'local-core',
  detectedAt: DateTime.utc(2026, 7, 5, 12),
  recommendedAction: RecommendedAction.quarantine,
  status: status,
  quarantineId: quarantineId,
  quarantinePath: quarantinePath,
  quarantineActionTaken: quarantineActionTaken,
  reasonSummary: 'EICAR benign test fixture for Scan quarantine UI.',
  riskScore: const RiskScore(
    score: 100,
    verdict: RiskVerdict.confirmedMalware,
    confidence: ThreatConfidence.confirmed,
    reasons: [
      RiskReason(
        id: 'eicar-signature',
        title: 'Known test signature',
        detail: 'EICAR benign antivirus test string.',
        weight: 100,
        severity: RiskSeverity.critical,
        source: RiskReasonSource.signature,
      ),
    ],
    recommendedAction: RecommendedAction.quarantine,
    enginesUsed: [DetectionType.signature],
  ),
);

Future<ZentorController> _pumpScanScreen(
  WidgetTester tester,
  ZentorState state, {
  LocalCoreClient? localCoreClient,
  ScanTargetService? scanTargetService,
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
    scanTargetService: scanTargetService ?? const ScanTargetService(),
    updateService: ZentorUpdateService(),
  );
  controller.state = state;

  await tester.pumpWidget(
    ProviderScope(
      overrides: [zentorControllerProvider.overrideWith((ref) => controller)],
      child: MaterialApp(
        theme: ZentorTheme.dark(),
        home: const Scaffold(body: SingleChildScrollView(child: ScanScreen())),
      ),
    ),
  );
  return controller;
}

class _FakeFileSelectionService extends FileSelectionService {
  _FakeFileSelectionService({this.file, this.directory});

  final SelectedFilePath? file;
  final String? directory;
  int pickFileCalls = 0;
  int pickDirectoryCalls = 0;

  @override
  Future<SelectedFilePath?> pickFile() async {
    pickFileCalls += 1;
    return file;
  }

  @override
  Future<String?> pickDirectory() async {
    pickDirectoryCalls += 1;
    return directory;
  }
}

class _RecordingLocalCoreClient extends LocalCoreClient {
  _RecordingLocalCoreClient({this.listQuarantineFailure});

  final String? listQuarantineFailure;

  int addAllowlistEntryCalls = 0;
  int labelDetectionCalls = 0;
  int quarantineCalls = 0;
  int scanPathsCalls = 0;
  int startCoreServiceCalls = 0;
  int openInstallReportCalls = 0;
  int repairInstallationCalls = 0;
  int healthSummaryCalls = 0;
  String? lastAllowlistPath;
  String? lastLabel;
  String? lastLabelThreatId;
  String? lastQuarantineThreatId;
  List<String>? lastScanPaths;
  ScanActionMode? lastScanActionMode;
  ScanKind? lastScanKind;

  @override
  Future<LocalCoreActionResult> addAllowlistEntry(String path) async {
    addAllowlistEntryCalls += 1;
    lastAllowlistPath = path;
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<List<AllowlistEntry>> listAllowlist() async {
    return const [];
  }

  @override
  Future<LocalCoreHealth> healthSummary() async {
    healthSummaryCalls += 1;
    return const LocalCoreHealth(
      malwareEngineStatus: MalwareEngineStatus.available,
      nativeEngineStatus: 'ready',
      nativeSignatureCount: 12,
      nativeRuleCount: 3,
      nativeMlStatus: 'loaded',
      coreServiceStatus: 'running',
      engineDirectory: r'C:\ProgramData\Avorax\engine',
      programDataDirectory: r'C:\ProgramData\Avorax',
    );
  }

  @override
  Future<LocalCoreActionResult> labelDetection(
    ThreatResult threat,
    String label, {
    String? note,
  }) async {
    labelDetectionCalls += 1;
    lastLabelThreatId = threat.id;
    lastLabel = label;
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<LocalCoreActionResult> quarantineThreat(ThreatResult threat) async {
    quarantineCalls += 1;
    lastQuarantineThreatId = threat.id;
    return const LocalCoreActionResult.ok();
  }

  @override
  Future<ScanReport> scanPaths(
    List<String> paths, {
    required ScanKind kind,
    required ScanActionMode actionMode,
    void Function(ScanProgress progress)? onProgress,
  }) async {
    scanPathsCalls += 1;
    lastScanPaths = List<String>.of(paths);
    lastScanActionMode = actionMode;
    lastScanKind = kind;
    return ScanReport(
      status: ScanStatus.clean,
      kind: kind,
      actionMode: actionMode,
      filesScanned: 1,
      threatsFound: 0,
      skippedFiles: 0,
      elapsedMs: 1,
      message: 'quick scan fixture complete',
      threats: const [],
    );
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
  Future<String> startCoreService() async {
    startCoreServiceCalls += 1;
    return 'Core Service start requested.';
  }

  @override
  Future<String> openInstallReport() async {
    openInstallReportCalls += 1;
    return 'Install report open requested.';
  }

  @override
  Future<String> repairInstallation() async {
    repairInstallationCalls += 1;
    return 'Installation repair requested.';
  }
}
