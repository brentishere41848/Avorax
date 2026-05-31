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

class ScanScreen extends ConsumerWidget {
  const ScanScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final desktop = Platform.isWindows || Platform.isLinux || Platform.isMacOS;
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
                    ? 'Scan high-risk locations, all accessible local areas, or a file/folder you choose.'
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
                    label: Text('Auto quarantine all'),
                    icon: Icon(Icons.warning_amber_outlined),
                  ),
                ],
                selected: {state.scanActionMode},
                onSelectionChanged: (selection) =>
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
                    onPressed: desktop && state.scanStatus != ScanStatus.running
                        ? () => controller.runQuickScan(
                            actionMode:
                                ScanActionMode.autoQuarantineConfirmedOnly,
                          )
                        : null,
                  ),
                  ZentorButton(
                    label: 'Full Scan',
                    icon: Icons.travel_explore_outlined,
                    secondary: true,
                    onPressed: desktop && state.scanStatus != ScanStatus.running
                        ? controller.runFullScan
                        : null,
                  ),
                  ZentorButton(
                    label: 'Custom File',
                    icon: Icons.file_open_outlined,
                    secondary: true,
                    onPressed: desktop && state.scanStatus != ScanStatus.running
                        ? controller.scanSelectedFile
                        : null,
                  ),
                  ZentorButton(
                    label: 'Custom Folder',
                    icon: Icons.folder_open_outlined,
                    secondary: true,
                    onPressed: desktop && state.scanStatus != ScanStatus.running
                        ? controller.scanSelectedFolder
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
  const _LiveProgress({required this.progress, required this.onCancel});

  final ScanProgress? progress;
  final VoidCallback onCancel;

  @override
  Widget build(BuildContext context) {
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
                value: '${progress?.filesScanned ?? 0}',
              ),
              _ProgressFact(
                label: 'Bytes',
                value: _formatBytes(progress?.bytesScanned ?? 0),
              ),
              _ProgressFact(
                label: 'Threats',
                value: '${progress?.threatsFound ?? 0}',
              ),
              _ProgressFact(
                label: 'Suspicious',
                value: '${progress?.suspiciousFound ?? 0}',
              ),
              _ProgressFact(
                label: 'Skipped',
                value: '${progress?.skippedFiles ?? 0}',
              ),
              _ProgressFact(
                label: 'Elapsed',
                value: _formatSeconds(progress?.elapsedSeconds ?? 0),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 10,
            children: [
              ZentorButton(
                label: 'Pause',
                icon: Icons.pause_outlined,
                secondary: true,
                onPressed: null,
              ),
              ZentorButton(
                label: 'Cancel',
                icon: Icons.close_outlined,
                secondary: true,
                onPressed: onCancel,
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
        value: '${report?.filesScanned ?? 0}',
        detail: 'Skipped: ${report?.skippedFiles ?? 0}',
        icon: Icons.article_outlined,
      ),
      ZentorMetricCard(
        title: 'Threats found',
        value: '${report?.threatsFound ?? 0}',
        detail: report?.actionMode.label ?? state.scanActionMode.label,
        icon: Icons.warning_amber_outlined,
      ),
      ZentorMetricCard(
        title: 'Elapsed',
        value: _elapsed(report?.elapsedMs ?? 0),
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
            const ZentorEmptyState(
              title: 'Zentor Native Engine unavailable',
              message:
                  'Native engine assets are missing or failed to load. Zentor never reports files clean when the engine is unavailable.',
              icon: Icons.health_and_safety_outlined,
            )
          else if (report.threats.isEmpty)
            const ZentorEmptyState(
              title: 'No threats found',
              message: 'The completed scan did not return any detections.',
              icon: Icons.check_circle_outline,
            )
          else ...[
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
            ),
          ],
        ],
      ),
    );
  }
}

class _ThreatSection extends StatelessWidget {
  const _ThreatSection({
    required this.title,
    required this.threats,
    required this.controller,
  });

  final String title;
  final List<ThreatResult> threats;
  final ZentorController controller;

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
            _ThreatRow(threat: threat, controller: controller),
        ],
      ),
    );
  }
}

class _ThreatRow extends StatelessWidget {
  const _ThreatRow({required this.threat, required this.controller});

  final ThreatResult threat;
  final ZentorController controller;

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
              _Chip(label: '${threat.confidence.label} confidence'),
              _Chip(label: 'Risk ${threat.riskScore.score}/100'),
              _Chip(label: _engines(threat)),
              _Chip(label: threat.recommendedAction.label),
            ],
          ),
          const SizedBox(height: 12),
          ExpansionTile(
            tilePadding: EdgeInsets.zero,
            collapsedIconColor: ZentorColors.textSecondary,
            iconColor: ZentorColors.primaryAccent,
            title: const Text('Why was this flagged?'),
            children: [
              Align(
                alignment: Alignment.centerLeft,
                child: Text(
                  threat.reasonSummary.isEmpty
                      ? 'Zentor found multiple local signals that need review. No cloud reputation was used.'
                      : threat.reasonSummary,
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
                      style: const TextStyle(color: ZentorColors.textSecondary),
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
          const SizedBox(height: 14),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: [
              if (_canQuarantineByDefault(threat))
                ZentorButton(
                  label: 'Quarantine',
                  icon: Icons.inventory_2_outlined,
                  onPressed: threat.status == ThreatResultStatus.detected
                      ? () => controller.quarantineThreat(threat)
                      : null,
                ),
              ZentorButton(
                label: 'Keep / Ignore',
                icon: Icons.visibility_outlined,
                secondary: true,
                onPressed: threat.status == ThreatResultStatus.detected
                    ? () => controller.ignoreThreat(threat)
                    : null,
              ),
              ZentorButton(
                label: 'Mark false positive',
                icon: Icons.thumb_up_alt_outlined,
                secondary: true,
                onPressed: threat.status == ThreatResultStatus.detected
                    ? () => controller.markThreatFalsePositive(threat)
                    : null,
              ),
              ZentorButton(
                label: 'Mark malicious',
                icon: Icons.report_outlined,
                secondary: true,
                onPressed: threat.status == ThreatResultStatus.detected
                    ? () => controller.markThreatMalicious(threat)
                    : null,
              ),
              if (_canQuarantineByDefault(threat))
                ZentorButton(
                  label: 'Delete permanently',
                  icon: Icons.delete_outline,
                  secondary: true,
                  onPressed: () => controller.deleteThreatPermanently(threat),
                ),
              ZentorButton(
                label: 'Add to allowlist',
                icon: Icons.fact_check_outlined,
                secondary: true,
                onPressed: threat.status == ThreatResultStatus.detected
                    ? () => controller.addThreatToAllowlist(threat)
                    : null,
              ),
            ],
          ),
        ],
      ),
    );
  }

  bool _canQuarantineByDefault(ThreatResult threat) {
    return threat.status == ThreatResultStatus.detected &&
        (threat.riskScore.verdict == RiskVerdict.confirmedMalware ||
            threat.riskScore.verdict == RiskVerdict.probableMalware) &&
        (threat.confidence == ThreatConfidence.confirmed ||
            threat.confidence == ThreatConfidence.high);
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
      return 'Recommended action: quarantine. Zentor never permanently deletes automatically.';
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
