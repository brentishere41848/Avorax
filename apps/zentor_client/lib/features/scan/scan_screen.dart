import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_empty_state.dart';
import '../../shared/widgets/zentor_metric_card.dart';
import '../../shared/widgets/zentor_status_card.dart';
import '../update/update_mutation_guard.dart';

class ScanScreen extends ConsumerWidget {
  const ScanScreen({super.key});

  bool _scanModeMayQuarantine(ScanActionMode actionMode) {
    return actionMode != ScanActionMode.detectOnly;
  }

  Future<bool> _confirmScanAutoAction(
    BuildContext context,
    ScanActionMode actionMode,
  ) async {
    if (!_scanModeMayQuarantine(actionMode)) return true;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Run scan with automatic quarantine?'),
        content: Text(
          'Avorax may move confirmed threats into quarantine during this scan (${actionMode.label}). Non-confirmed detections remain visible for review.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Run scan'),
          ),
        ],
      ),
    );
    return confirmed == true;
  }

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final desktop = Platform.isWindows || Platform.isLinux || Platform.isMacOS;
    final updateMutationBusy = updateMutationOperationInProgress(state);
    final scanStartBusy =
        state.scanStartInFlight ||
        state.securitySettingsActionInFlight ||
        state.configurationResetInFlight ||
        state.scanStatus == ScanStatus.running ||
        updateMutationBusy;
    final scanOperationBusy =
        scanStartBusy || state.scanTargetSelectionInFlight;
    final scanStartAvailable = desktop && !scanOperationBusy;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ZentorPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('Scan', style: Theme.of(context).textTheme.headlineMedium),
              const SizedBox(height: 8),
              Text(
                desktop
                    ? 'Scan high-risk locations, all accessible local areas, or a file/folder you choose. Reports include progress, skipped files, errors, hashes, and conservative large-file handling.'
                    : 'Malware quarantine is not available on this platform because mobile OS sandboxing prevents full-device scanning.',
                style: const TextStyle(color: ZentorColors.textSecondary),
              ),
              const SizedBox(height: 20),
              SegmentedButton<ScanActionMode>(
                segments: const [
                  ButtonSegment(
                    value: ScanActionMode.detectOnly,
                    label: Text('Detect only'),
                    icon: Icon(Icons.visibility_outlined),
                  ),
                  ButtonSegment(
                    value: ScanActionMode.autoQuarantineConfirmedOnly,
                    label: Text('Auto quarantine confirmed'),
                    icon: Icon(Icons.inventory_2_outlined),
                  ),
                  ButtonSegment(
                    value: ScanActionMode.autoQuarantineAllDetections,
                    label: Text('Legacy confirmed-only'),
                    icon: Icon(Icons.lock_clock_outlined),
                  ),
                ],
                selected: {state.scanActionMode},
                onSelectionChanged: scanOperationBusy
                    ? null
                    : (selection) =>
                          controller.setScanActionMode(selection.first),
              ),
              const SizedBox(height: 18),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  ZentorButton(
                    label: 'Quick Scan',
                    icon: Icons.radar_outlined,
                    onPressed: scanStartAvailable
                        ? () async {
                            if (!await _confirmScanAutoAction(
                              context,
                              state.scanActionMode,
                            )) {
                              return;
                            }
                            await controller.runQuickScan(
                              confirmedAutoAction: _scanModeMayQuarantine(
                                state.scanActionMode,
                              ),
                            );
                          }
                        : null,
                  ),
                  ZentorButton(
                    label: 'Full Scan',
                    icon: Icons.travel_explore_outlined,
                    secondary: true,
                    onPressed: scanStartAvailable
                        ? () async {
                            if (!await _confirmScanAutoAction(
                              context,
                              state.scanActionMode,
                            )) {
                              return;
                            }
                            await controller.runFullScan(
                              confirmedAutoAction: _scanModeMayQuarantine(
                                state.scanActionMode,
                              ),
                            );
                          }
                        : null,
                  ),
                  ZentorButton(
                    label: 'Custom File',
                    icon: Icons.file_open_outlined,
                    secondary: true,
                    onPressed: scanStartAvailable
                        ? () async {
                            if (!await _confirmScanAutoAction(
                              context,
                              state.scanActionMode,
                            )) {
                              return;
                            }
                            await controller.scanSelectedFile(
                              confirmedAutoAction: _scanModeMayQuarantine(
                                state.scanActionMode,
                              ),
                            );
                          }
                        : null,
                  ),
                  ZentorButton(
                    label: 'Custom Folder',
                    icon: Icons.folder_open_outlined,
                    secondary: true,
                    onPressed: scanStartAvailable
                        ? () async {
                            if (!await _confirmScanAutoAction(
                              context,
                              state.scanActionMode,
                            )) {
                              return;
                            }
                            await controller.scanSelectedFolder(
                              confirmedAutoAction: _scanModeMayQuarantine(
                                state.scanActionMode,
                              ),
                            );
                          }
                        : null,
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        if (state.scanStatus == ScanStatus.running) ...[
          _LiveProgress(
            progress: state.scanProgress,
            cancelBusy: state.scanCancelInFlight,
            onCancel: controller.cancelScan,
          ),
          const SizedBox(height: 16),
        ],
        _ScanProgress(state: state),
        const SizedBox(height: 16),
        _ScanResults(state: state, controller: controller),
        if (state.errorMessage != null) ...[
          const SizedBox(height: 14),
          ZentorPanel(
            child: Text(
              state.errorMessage!,
              style: const TextStyle(color: ZentorColors.warning),
            ),
          ),
        ],
      ],
    );
  }
}

class _LiveProgress extends StatelessWidget {
  const _LiveProgress({
    required this.progress,
    required this.cancelBusy,
    required this.onCancel,
  });

  final ScanProgress? progress;
  final bool cancelBusy;
  final VoidCallback onCancel;

  @override
  Widget build(BuildContext context) {
    final snapshot = progress;
    final value = progress?.progressPercent == null
        ? null
        : (progress!.progressPercent! / 100).clamp(0.0, 1.0);
    return ZentorPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                progress?.scanType.label ?? 'Scan running',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const Spacer(),
              Text(
                progress?.etaLabel ?? 'ETA: calculating...',
                style: const TextStyle(color: ZentorColors.textSecondary),
              ),
            ],
          ),
          const SizedBox(height: 14),
          LinearProgressIndicator(value: value),
          const SizedBox(height: 14),
          Text(
            progress?.currentPath ?? 'Preparing scan...',
            style: const TextStyle(color: ZentorColors.textSecondary),
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 16,
            runSpacing: 8,
            children: [
              _ProgressFact(
                label: 'Files',
                value: snapshot == null
                    ? 'Pending'
                    : '${snapshot.filesScanned}',
              ),
              _ProgressFact(
                label: 'Bytes',
                value: snapshot == null
                    ? 'Pending'
                    : _formatBytes(snapshot.bytesScanned),
              ),
              _ProgressFact(
                label: 'Threats',
                value: snapshot == null
                    ? 'Pending'
                    : '${snapshot.threatsFound}',
              ),
              _ProgressFact(
                label: 'Suspicious',
                value: snapshot == null
                    ? 'Pending'
                    : '${snapshot.suspiciousFound}',
              ),
              _ProgressFact(
                label: 'Skipped',
                value: snapshot == null
                    ? 'Pending'
                    : '${snapshot.skippedFiles}',
              ),
              _ProgressFact(
                label: 'Elapsed',
                value: snapshot == null
                    ? 'Pending'
                    : _formatSeconds(snapshot.elapsedSeconds),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 10,
            children: [
              ZentorButton(
                label: 'Cancel',
                icon: Icons.close_outlined,
                secondary: true,
                onPressed: cancelBusy ? null : onCancel,
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _ProgressFact extends StatelessWidget {
  const _ProgressFact({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Text(
      '$label: $value',
      style: const TextStyle(color: ZentorColors.textSecondary),
    );
  }
}

class _ScanProgress extends StatelessWidget {
  const _ScanProgress({required this.state});

  final ZentorState state;

  @override
  Widget build(BuildContext context) {
    final report = state.lastScanReport;
    final cards = [
      ZentorMetricCard(
        title: 'Status',
        value: state.scanStatus == ScanStatus.running
            ? 'Scan running'
            : report?.status.label ?? 'Idle',
        detail: state.currentScanPath ?? report?.message ?? 'No scan running',
        icon: Icons.radar_outlined,
      ),
      ZentorMetricCard(
        title: 'Files scanned',
        value: report == null ? 'No report' : '${report.filesScanned}',
        detail: report == null
            ? 'No scan report yet'
            : 'Skipped: ${report.skippedFiles}',
        icon: Icons.article_outlined,
      ),
      ZentorMetricCard(
        title: 'Threats found',
        value: report == null ? 'No report' : '${report.threatsFound}',
        detail: report == null ? 'No scan report yet' : report.actionMode.label,
        icon: Icons.warning_amber_outlined,
      ),
      ZentorMetricCard(
        title: 'Elapsed',
        value: report == null ? 'No report' : _elapsed(report.elapsedMs),
        detail: report?.currentPath ?? 'Waiting for scan',
        icon: Icons.timer_outlined,
      ),
    ];
    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth < 900) {
          return Column(
            children: [
              for (final card in cards) ...[card, const SizedBox(height: 12)],
            ],
          );
        }
        return GridView.count(
          shrinkWrap: true,
          physics: const NeverScrollableScrollPhysics(),
          crossAxisCount: 4,
          mainAxisSpacing: 14,
          crossAxisSpacing: 14,
          childAspectRatio: 1.55,
          children: cards,
        );
      },
    );
  }

  String _elapsed(int elapsedMs) {
    if (elapsedMs <= 0) return '0s';
    final seconds = (elapsedMs / 1000).round();
    if (seconds < 60) return '${seconds}s';
    return '${seconds ~/ 60}m ${seconds % 60}s';
  }
}

class _ScanResults extends StatelessWidget {
  const _ScanResults({required this.state, required this.controller});

  final ZentorState state;
  final ZentorController controller;

  @override
  Widget build(BuildContext context) {
    final report = state.lastScanReport;
    final updateMutationBusy = updateMutationOperationInProgress(state);
    final configurationActionBusy =
        state.securitySettingsActionInFlight ||
        state.configurationResetInFlight ||
        updateMutationBusy;
    return ZentorPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Scan results', style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 16),
          if (report == null)
            const ZentorEmptyState(
              title: 'No scan results',
              message: 'Run a scan to review real detections.',
              icon: Icons.search_outlined,
            )
          else if (report.status == ScanStatus.engineUnavailable)
            _EngineUnavailableDiagnostics(
              state: state,
              onRetry: controller.unawaitedCheckMalwareEngine,
              onStartCoreService: controller.startCoreService,
              onOpenInstallReport: controller.openInstallReport,
              onRepairInstallation: controller.repairInstallation,
            )
          else if (report.threats.isEmpty && report.scanErrors.isNotEmpty)
            _ScanErrorDiagnostics(report: report)
          else if (report.threats.isEmpty)
            const ZentorEmptyState(
              title: 'No threats found',
              message: 'The completed scan did not return any detections.',
              icon: Icons.check_circle_outline,
            )
          else ...[
            if (report.scanErrors.isNotEmpty) ...[
              _ScanErrorDiagnostics(report: report),
              const SizedBox(height: 16),
            ],
            _ThreatSection(
              title: 'Confirmed threats',
              threats: report.threats
                  .where(
                    (threat) =>
                        threat.riskScore.verdict ==
                            RiskVerdict.confirmedMalware ||
                        threat.confidence == ThreatConfidence.confirmed,
                  )
                  .toList(),
              controller: controller,
              quarantineActionBusy:
                  state.quarantineActionInFlight || configurationActionBusy,
              allowlistActionBusy:
                  state.allowlistActionInFlight || configurationActionBusy,
              detectionFeedbackBusy:
                  state.detectionFeedbackInFlight || configurationActionBusy,
              threatIgnoreBusy:
                  state.threatIgnoreActionInFlight || configurationActionBusy,
            ),
            _ThreatSection(
              title: 'Probable malware',
              threats: report.threats
                  .where(
                    (threat) =>
                        threat.riskScore.verdict == RiskVerdict.probableMalware,
                  )
                  .toList(),
              controller: controller,
              quarantineActionBusy:
                  state.quarantineActionInFlight || configurationActionBusy,
              allowlistActionBusy:
                  state.allowlistActionInFlight || configurationActionBusy,
              detectionFeedbackBusy:
                  state.detectionFeedbackInFlight || configurationActionBusy,
              threatIgnoreBusy:
                  state.threatIgnoreActionInFlight || configurationActionBusy,
            ),
            _ThreatSection(
              title: 'Review suggested',
              threats: report.threats
                  .where(
                    (threat) =>
                        threat.riskScore.verdict == RiskVerdict.suspicious ||
                        threat.riskScore.verdict == RiskVerdict.unknown,
                  )
                  .toList(),
              controller: controller,
              quarantineActionBusy:
                  state.quarantineActionInFlight || configurationActionBusy,
              allowlistActionBusy:
                  state.allowlistActionInFlight || configurationActionBusy,
              detectionFeedbackBusy:
                  state.detectionFeedbackInFlight || configurationActionBusy,
              threatIgnoreBusy:
                  state.threatIgnoreActionInFlight || configurationActionBusy,
            ),
            _ThreatSection(
              title: 'Observations',
              threats: report.threats
                  .where(
                    (threat) =>
                        threat.riskScore.verdict == RiskVerdict.likelyClean &&
                        threat.riskScore.score > 0,
                  )
                  .toList(),
              controller: controller,
              quarantineActionBusy:
                  state.quarantineActionInFlight || configurationActionBusy,
              allowlistActionBusy:
                  state.allowlistActionInFlight || configurationActionBusy,
              detectionFeedbackBusy:
                  state.detectionFeedbackInFlight || configurationActionBusy,
              threatIgnoreBusy:
                  state.threatIgnoreActionInFlight || configurationActionBusy,
            ),
          ],
        ],
      ),
    );
  }
}

class _ScanErrorDiagnostics extends StatelessWidget {
  const _ScanErrorDiagnostics({required this.report});

  final ScanReport report;

  @override
  Widget build(BuildContext context) {
    final errors = report.scanErrors.take(5).toList();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ZentorEmptyState(
          title: 'Scan completed with errors',
          message:
              report.message ??
              'Some files were skipped because Avorax could not scan them. Skipped files were not reported clean.',
          icon: Icons.error_outline,
        ),
        const SizedBox(height: 14),
        for (final error in errors) ...[
          _DiagnosticChip(label: 'Scan error', value: error),
          const SizedBox(height: 8),
        ],
        if (report.scanErrors.length > errors.length)
          _DiagnosticChip(
            label: 'More errors',
            value:
                '${report.scanErrors.length - errors.length} additional error(s)',
          ),
      ],
    );
  }
}

class _EngineUnavailableDiagnostics extends StatelessWidget {
  const _EngineUnavailableDiagnostics({
    required this.state,
    required this.onRetry,
    required this.onStartCoreService,
    required this.onOpenInstallReport,
    required this.onRepairInstallation,
  });

  final ZentorState state;
  final Future<void> Function() onRetry;
  final Future<void> Function({bool confirmed}) onStartCoreService;
  final Future<void> Function({bool confirmed}) onOpenInstallReport;
  final Future<void> Function({bool confirmed}) onRepairInstallation;

  @override
  Widget build(BuildContext context) {
    final engineDir = _engineDirectoryLabel(state);
    final scanEngineDiagnostic = state.lastEngineError?.trim();
    final serviceActionBusy =
        state.serviceActionInFlight || updateMutationOperationInProgress(state);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const ZentorEmptyState(
          title: 'Engine unavailable',
          message:
              'Avorax cannot start a scan because the native engine assets or Core Service are missing. Avorax never reports files clean when the engine is unavailable.',
          icon: Icons.health_and_safety_outlined,
        ),
        const SizedBox(height: 14),
        Wrap(
          spacing: 10,
          runSpacing: 10,
          children: [
            _DiagnosticChip(
              label: 'Core Service',
              value: _serviceStatusLabel(state.coreServiceStatus),
            ),
            _DiagnosticChip(label: 'Engine directory', value: engineDir),
            _DiagnosticChip(
              label: 'Signature packs',
              value: _assetPackStatusLabel(
                count: state.nativeSignatureCount,
                nativeEngineStatus: state.nativeEngineStatus,
                engineDiagnosticVisible:
                    scanEngineDiagnostic?.isNotEmpty ?? false,
              ),
            ),
            _DiagnosticChip(
              label: 'Rule packs',
              value: _assetPackStatusLabel(
                count: state.nativeRuleCount,
                nativeEngineStatus: state.nativeEngineStatus,
                engineDiagnosticVisible:
                    scanEngineDiagnostic?.isNotEmpty ?? false,
              ),
            ),
            _DiagnosticChip(
              label: 'ML model',
              value: _nativeMlAssetLabel(state.nativeMlStatus),
            ),
            _DiagnosticChip(
              label: 'ProgramData',
              value: state.programDataDirectory ?? 'Unknown',
            ),
            if (state.enginePathsChecked.isNotEmpty)
              _DiagnosticChip(
                label: 'Paths checked',
                value: state.enginePathsChecked.take(4).join(' | '),
              ),
            if (scanEngineDiagnostic?.isNotEmpty ?? false)
              _DiagnosticChip(
                label: 'Last error',
                value: scanEngineDiagnostic!,
              ),
          ],
        ),
        const SizedBox(height: 14),
        Wrap(
          spacing: 10,
          runSpacing: 10,
          children: [
            ZentorButton(
              label: 'Retry',
              icon: Icons.refresh_outlined,
              secondary: true,
              onPressed: () => onRetry(),
            ),
            ZentorButton(
              label: 'Start Core Service',
              icon: Icons.play_arrow_outlined,
              secondary: true,
              onPressed:
                  serviceActionBusy || state.coreServiceStatus == 'running'
                  ? null
                  : () => _confirmStartCoreService(context),
            ),
            ZentorButton(
              label: 'Open install report',
              icon: Icons.description_outlined,
              secondary: true,
              onPressed: serviceActionBusy
                  ? null
                  : () => _confirmOpenInstallReport(context),
            ),
            ZentorButton(
              label: 'Repair installation',
              icon: Icons.build_outlined,
              secondary: true,
              onPressed: serviceActionBusy
                  ? null
                  : () => _confirmRepairInstallation(context),
            ),
          ],
        ),
      ],
    );
  }

  Future<void> _confirmStartCoreService(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Start Core Service?'),
        content: const Text(
          'This asks Windows to start the Avorax Core Service and may show a Windows administrator prompt. It does not install or reconfigure the service. Continue only if you trust this installed Avorax build.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Start'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await onStartCoreService(confirmed: true);
  }

  Future<void> _confirmOpenInstallReport(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Open install report?'),
        content: const Text(
          'This opens Windows Explorer to show local Avorax installation metadata such as install_report.json or install-manifest.json. Continue only if you trust this installed Avorax build.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Open'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await onOpenInstallReport(confirmed: true);
  }

  Future<void> _confirmRepairInstallation(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Repair installation?'),
        content: const Text(
          'This can register or reconfigure the Avorax Core Service as a Windows service, set it to start automatically, and show a Windows administrator prompt. Continue only if you trust this installed Avorax build.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Repair'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await onRepairInstallation(confirmed: true);
  }

  String _engineDirectoryLabel(ZentorState state) {
    final reported = state.engineDirectory?.trim();
    if (reported != null && reported.isNotEmpty) return reported;
    if (state.enginePathsChecked.isNotEmpty) {
      return 'Not reported by Core Service';
    }
    return 'Unknown';
  }

  String _serviceStatusLabel(String status) => switch (status) {
    'running' => 'Running',
    'stopped' => 'Stopped',
    'missing' => 'Missing',
    'installed' => 'Installed',
    'unknown' => 'Unknown',
    'unsupported' => 'Unsupported on this OS',
    'error' => 'Error',
    _ => 'Unavailable',
  };

  String _assetPackStatusLabel({
    required int count,
    required String nativeEngineStatus,
    required bool engineDiagnosticVisible,
  }) {
    if (count > 0) return 'Found';
    if (nativeEngineStatus == 'ready' && !engineDiagnosticVisible) {
      return 'Missing';
    }
    return 'Unknown';
  }

  String _nativeMlAssetLabel(String status) => switch (status) {
    'loaded' => 'Found',
    'developmentModel' => 'Found (development)',
    'modelMissing' => 'Missing',
    'error' => 'Error',
    _ => 'Unknown',
  };
}

class _DiagnosticChip extends StatelessWidget {
  const _DiagnosticChip({required this.label, required this.value});

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: const BoxConstraints(maxWidth: 520),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
      decoration: BoxDecoration(
        border: Border.all(color: ZentorColors.border),
        borderRadius: BorderRadius.circular(8),
        color: ZentorColors.elevatedSurface,
      ),
      child: Text(
        '$label: $value',
        style: const TextStyle(color: ZentorColors.textSecondary),
      ),
    );
  }
}

class _ThreatSection extends StatelessWidget {
  const _ThreatSection({
    required this.title,
    required this.threats,
    required this.controller,
    required this.quarantineActionBusy,
    required this.allowlistActionBusy,
    required this.detectionFeedbackBusy,
    required this.threatIgnoreBusy,
  });

  final String title;
  final List<ThreatResult> threats;
  final ZentorController controller;
  final bool quarantineActionBusy;
  final bool allowlistActionBusy;
  final bool detectionFeedbackBusy;
  final bool threatIgnoreBusy;

  @override
  Widget build(BuildContext context) {
    if (threats.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(title, style: Theme.of(context).textTheme.titleMedium),
          const SizedBox(height: 10),
          for (final threat in threats)
            _ThreatRow(
              threat: threat,
              controller: controller,
              quarantineActionBusy: quarantineActionBusy,
              allowlistActionBusy: allowlistActionBusy,
              detectionFeedbackBusy: detectionFeedbackBusy,
              threatIgnoreBusy: threatIgnoreBusy,
            ),
        ],
      ),
    );
  }
}

class _ThreatRow extends StatelessWidget {
  const _ThreatRow({
    required this.threat,
    required this.controller,
    required this.quarantineActionBusy,
    required this.allowlistActionBusy,
    required this.detectionFeedbackBusy,
    required this.threatIgnoreBusy,
  });

  final ThreatResult threat;
  final ZentorController controller;
  final bool quarantineActionBusy;
  final bool allowlistActionBusy;
  final bool detectionFeedbackBusy;
  final bool threatIgnoreBusy;

  @override
  Widget build(BuildContext context) {
    final title = threat.fileName.isEmpty ? threat.path : threat.fileName;
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: ZentorColors.elevatedSurface,
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: ZentorColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(_iconFor(threat), color: _colorFor(threat)),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  title,
                  style: Theme.of(context).textTheme.titleMedium,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              ZentorStatusPill(
                label: _badgeLabel(threat),
                color: _colorFor(threat),
                icon: Icons.circle_outlined,
              ),
            ],
          ),
          const SizedBox(height: 10),
          Text(
            threat.path,
            style: const TextStyle(color: ZentorColors.textSecondary),
            overflow: TextOverflow.ellipsis,
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _Chip(label: threat.riskScore.verdict.label),
              _Chip(label: threat.threatCategory.label),
              _Chip(label: '${threat.confidence.label} confidence'),
              _Chip(label: 'Risk ${threat.riskScore.score}/100'),
              _Chip(label: _engines(threat)),
              _Chip(label: threat.recommendedAction.label),
            ],
          ),
          const SizedBox(height: 12),
          Material(
            type: MaterialType.transparency,
            child: ExpansionTile(
              tilePadding: EdgeInsets.zero,
              collapsedIconColor: ZentorColors.textSecondary,
              iconColor: ZentorColors.primaryAccent,
              title: const Text('Why was this flagged?'),
              children: [
                Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                    threat.reasonSummary,
                    style: const TextStyle(color: ZentorColors.textSecondary),
                  ),
                ),
                const SizedBox(height: 8),
                for (final reason in threat.riskScore.reasons)
                  Align(
                    alignment: Alignment.centerLeft,
                    child: Padding(
                      padding: const EdgeInsets.only(bottom: 6),
                      child: Text(
                        '${reason.title}: ${reason.detail}',
                        style: const TextStyle(
                          color: ZentorColors.textSecondary,
                        ),
                      ),
                    ),
                  ),
                Align(
                  alignment: Alignment.centerLeft,
                  child: Text(
                    _recommendation(threat),
                    style: const TextStyle(color: ZentorColors.textSecondary),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 14),
          if (_isReviewOnly(threat)) ...[
            _ReviewOnlyNotice(path: threat.path),
            const SizedBox(height: 14),
          ],
          if (threat.status == ThreatResultStatus.quarantined) ...[
            _QuarantinedNotice(threat: threat),
            const SizedBox(height: 14),
          ],
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              if (_canQuarantineByDefault(threat))
                ZentorButton(
                  label: 'Quarantine',
                  icon: Icons.inventory_2_outlined,
                  onPressed:
                      threat.status == ThreatResultStatus.detected &&
                          !quarantineActionBusy
                      ? () => _confirmQuarantine(context)
                      : null,
                ),
              ZentorButton(
                label: 'Keep / Ignore',
                icon: Icons.visibility_outlined,
                secondary: true,
                onPressed:
                    threat.status == ThreatResultStatus.detected &&
                        !threatIgnoreBusy
                    ? () => _confirmIgnoreThreat(context)
                    : null,
              ),
              ZentorButton(
                label: 'Mark false positive',
                icon: Icons.thumb_up_alt_outlined,
                secondary: true,
                onPressed:
                    threat.status == ThreatResultStatus.detected &&
                        !detectionFeedbackBusy
                    ? () => _confirmFalsePositive(context)
                    : null,
              ),
              ZentorButton(
                label: 'Mark malicious',
                icon: Icons.report_outlined,
                secondary: true,
                onPressed:
                    threat.status == ThreatResultStatus.detected &&
                        threat.recommendedAction !=
                            RecommendedAction.quarantine &&
                        !detectionFeedbackBusy
                    ? () => _confirmMaliciousFeedback(context)
                    : null,
              ),
              ZentorButton(
                label: 'Add to allowlist',
                icon: Icons.fact_check_outlined,
                secondary: true,
                onPressed:
                    threat.status == ThreatResultStatus.detected &&
                        !allowlistActionBusy
                    ? () => _confirmAddToAllowlist(context)
                    : null,
              ),
            ],
          ),
        ],
      ),
    );
  }

  Future<void> _confirmAddToAllowlist(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Add to allowlist?'),
        content: Text(
          'Avorax will stop automatically quarantining this path if it is detected again. Only continue if you trust this file:\n${threat.path}',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Allowlist'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await controller.addThreatToAllowlist(threat, confirmed: true);
  }

  Future<void> _confirmQuarantine(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Quarantine this file?'),
        content: Text(
          'Avorax will move this file into isolated quarantine storage and keep a record for restore or deletion review:\n${threat.path}',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Quarantine'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await controller.quarantineThreat(threat, confirmed: true);
  }

  Future<void> _confirmFalsePositive(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Mark false positive?'),
        content: Text(
          'Avorax may use this feedback to suppress future detections for the same file hash. Only continue if you trust this file:\n${threat.path}',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Mark false positive'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await controller.markThreatFalsePositive(threat, confirmed: true);
  }

  Future<void> _confirmIgnoreThreat(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Keep and ignore this detection?'),
        content: Text(
          'Avorax will leave this file in place and hide this detection in the current scan results. Only continue if you trust this file:\n${threat.path}',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Keep / Ignore'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await controller.ignoreThreat(threat, confirmed: true);
  }

  Future<void> _confirmMaliciousFeedback(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Submit malicious feedback?'),
        content: Text(
          'This saves local feedback for future detection decisions only. It does not quarantine, delete, execute, or change the current file. Use Quarantine separately if that action is available and you want to isolate the file:\n${threat.path}',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Submit feedback'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await controller.markThreatMalicious(threat, confirmed: true);
  }

  bool _canQuarantineByDefault(ThreatResult threat) {
    return threat.status == ThreatResultStatus.detected &&
        (threat.riskScore.verdict == RiskVerdict.confirmedMalware ||
            threat.riskScore.verdict == RiskVerdict.probableMalware) &&
        (threat.confidence == ThreatConfidence.confirmed ||
            threat.confidence == ThreatConfidence.high);
  }

  bool _isReviewOnly(ThreatResult threat) {
    return threat.status == ThreatResultStatus.detected &&
        (threat.riskScore.verdict == RiskVerdict.suspicious ||
            threat.riskScore.verdict == RiskVerdict.unknown ||
            threat.confidence == ThreatConfidence.low ||
            threat.confidence == ThreatConfidence.medium) &&
        !_canQuarantineByDefault(threat);
  }

  String _badgeLabel(ThreatResult threat) {
    if (threat.status != ThreatResultStatus.detected) {
      return threat.status.label;
    }
    return switch (threat.riskScore.verdict) {
      RiskVerdict.confirmedMalware => 'Confirmed threat',
      RiskVerdict.probableMalware => 'Probable malware',
      RiskVerdict.suspicious || RiskVerdict.unknown => 'Review suggested',
      RiskVerdict.likelyClean => 'Observation',
      RiskVerdict.clean => 'Trusted',
    };
  }

  IconData _iconFor(ThreatResult threat) =>
      threat.confidence == ThreatConfidence.confirmed
      ? Icons.dangerous_outlined
      : Icons.report_problem_outlined;

  String _engines(ThreatResult threat) {
    final engines = threat.riskScore.enginesUsed.isEmpty
        ? [threat.detectionType.label]
        : threat.riskScore.enginesUsed.map((engine) => engine.label).toList();
    return engines.join(', ');
  }

  String _recommendation(ThreatResult threat) {
    if (threat.riskScore.verdict == RiskVerdict.confirmedMalware) {
      return 'Recommended action: quarantine. Avorax never permanently deletes automatically.';
    }
    if (threat.riskScore.verdict == RiskVerdict.probableMalware) {
      return 'Recommended action: review and quarantine if you do not recognize this file.';
    }
    if (threat.riskScore.verdict == RiskVerdict.unknown ||
        threat.riskScore.verdict == RiskVerdict.suspicious) {
      return 'Recommended action: review. This result is not eligible for automatic quarantine because the evidence is not confirmed.';
    }
    return 'Recommended action: keep unless you do not recognize this file. Unknown files are not treated as malware automatically.';
  }

  Color _colorFor(ThreatResult threat) {
    if (threat.status == ThreatResultStatus.quarantined) {
      return ZentorColors.success;
    }
    if (threat.confidence == ThreatConfidence.confirmed) {
      return ZentorColors.danger;
    }
    return ZentorColors.warning;
  }
}

class _ReviewOnlyNotice extends StatelessWidget {
  const _ReviewOnlyNotice({required this.path});

  final String path;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: ZentorColors.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: ZentorColors.warning.withValues(alpha: 0.5)),
      ),
      child: Text(
        'Review-only evidence. Avorax will not automatically quarantine this file; inspect it before choosing an action: $path',
        style: Theme.of(
          context,
        ).textTheme.bodySmall?.copyWith(color: ZentorColors.textSecondary),
      ),
    );
  }
}

class _QuarantinedNotice extends StatelessWidget {
  const _QuarantinedNotice({required this.threat});

  final ThreatResult threat;

  @override
  Widget build(BuildContext context) {
    final id = threat.quarantineId?.trim();
    final path = threat.quarantinePath?.trim();
    final detail = [
      'This file was moved into isolated quarantine storage.',
      if (id != null && id.isNotEmpty) 'Record: $id',
      if (path != null && path.isNotEmpty) 'Payload: $path',
    ].join('\n');
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: ZentorColors.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: ZentorColors.success.withValues(alpha: 0.5)),
      ),
      child: Text(
        detail,
        style: Theme.of(
          context,
        ).textTheme.bodySmall?.copyWith(color: ZentorColors.textSecondary),
      ),
    );
  }
}

class _Chip extends StatelessWidget {
  const _Chip({required this.label});

  final String label;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: ZentorColors.surface,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: ZentorColors.border),
      ),
      child: Text(
        label,
        style: Theme.of(
          context,
        ).textTheme.labelMedium?.copyWith(color: ZentorColors.textSecondary),
      ),
    );
  }
}

String _formatSeconds(int seconds) {
  if (seconds < 60) return '${seconds}s';
  return '${seconds ~/ 60}m ${seconds % 60}s';
}

String _formatBytes(int bytes) {
  if (bytes < 1024) return '$bytes B';
  final kib = bytes / 1024;
  if (kib < 1024) return '${kib.toStringAsFixed(1)} KB';
  final mib = kib / 1024;
  if (mib < 1024) return '${mib.toStringAsFixed(1)} MB';
  return '${(mib / 1024).toStringAsFixed(1)} GB';
}
