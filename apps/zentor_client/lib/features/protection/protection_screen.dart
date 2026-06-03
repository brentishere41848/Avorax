import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_metric_card.dart';
import '../../shared/widgets/zentor_status_card.dart';

class ProtectionScreen extends ConsumerWidget {
  const ProtectionScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    return Column(
      children: [
        ZentorPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const ZentorMark(size: 58),
                  const SizedBox(width: 18),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Protection',
                          style: Theme.of(context).textTheme.headlineMedium,
                        ),
                        const SizedBox(height: 6),
                        Text(
                          state.protectionStatus.label,
                          style: const TextStyle(
                            color: ZentorColors.textSecondary,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 18),
              Text(
                _protectionExplanation(state),
                style: TextStyle(
                  color: ZentorColors.textSecondary,
                  height: 1.45,
                ),
              ),
              const SizedBox(height: 22),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  ZentorButton(
                    label:
                        state.protectionStatus == ProtectionStatus.idle ||
                            state.protectionStatus == ProtectionStatus.error
                        ? 'Enable Protection'
                        : 'Protection Enabled',
                    icon: Icons.play_arrow_rounded,
                    onPressed:
                        state.loading ||
                            (state.protectionStatus != ProtectionStatus.idle &&
                                state.protectionStatus !=
                                    ProtectionStatus.error)
                        ? null
                        : controller.startProtection,
                  ),
                  ZentorButton(
                    label: 'Stop Protection',
                    icon: Icons.stop_rounded,
                    secondary: true,
                    onPressed: state.protectionStatus == ProtectionStatus.idle
                        ? null
                        : controller.stopProtection,
                  ),
                  ZentorButton(
                    label: state.loading
                        ? 'Running self-test...'
                        : 'Run protection self-test',
                    icon: Icons.health_and_safety_outlined,
                    secondary: true,
                    onPressed: state.loading
                        ? null
                        : controller.runProtectionSelfTest,
                  ),
                  ZentorButton(
                    label: 'Run Quick Scan',
                    icon: Icons.radar_outlined,
                    secondary: true,
                    onPressed: state.scanStatus == ScanStatus.running
                        ? null
                        : () => controller.runQuickScan(),
                  ),
                ],
              ),
              const SizedBox(height: 22),
              _ProtectionChecklist(state: state),
              if (state.protectionSelfTestResult != null) ...[
                const SizedBox(height: 16),
                _SelfTestResultPanel(result: state.protectionSelfTestResult!),
              ],
              if (state.errorMessage != null) ...[
                const SizedBox(height: 16),
                Text(
                  state.errorMessage!,
                  style: const TextStyle(color: ZentorColors.warning),
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 16),
        LayoutBuilder(
          builder: (context, constraints) {
            final report = state.lastScanReport;
            final cards = [
              ZentorMetricCard(
                title: 'Protection profile',
                value: state.config.protectionMode.label,
                detail: state.config.protectionMode == ProtectionMode.lockdown
                    ? 'Unknown apps are blocked by policy until approved. Driver self-test determines whether this happens before launch.'
                    : state.config.protectionMode.description,
                icon: Icons.admin_panel_settings_outlined,
              ),
              ZentorMetricCard(
                title: 'Real-time protection',
                value: state.protectionStatus.label,
                detail: state.protectionStatus == ProtectionStatus.localOnly
                    ? 'Cloud is optional; local protection remains available.'
                    : state.guardStatus == 'running'
                    ? 'Avorax Guard Service is running. Confirmed threats can be stopped after launch.'
                    : state.coreServiceStatus == 'running'
                    ? 'Core service is running. Start Guard Service for background monitoring.'
                    : 'Core/Guard services are not running. Manual scans and quarantine remain available.',
                icon: Icons.shield_outlined,
              ),
              ZentorMetricCard(
                title: 'User-mode monitor',
                value: _watcherLabel(state.realtimeWatcherMode),
                detail: state.realtimeWatchedPaths.isEmpty
                    ? 'Best-effort folder monitoring is off. Manual scans and quarantine remain available.'
                    : 'Running best-effort folder monitoring for ${state.realtimeWatchedPaths.length} protected location(s). No kernel pre-execution blocking is claimed.',
                icon: Icons.folder_special_outlined,
              ),
              ZentorMetricCard(
                title: 'Guard Service',
                value: _guardLabel(state.guardStatus),
                detail: state.guardStatus == 'running'
                    ? 'Background post-launch monitoring is active.'
                    : 'Install/start the MSI service for background post-launch monitoring.',
                icon: Icons.security_outlined,
              ),
              ZentorMetricCard(
                title: 'Pre-execution blocking',
                value: state.driverStatus == 'running'
                    ? 'Driver active'
                    : 'Not active',
                detail: state.driverStatus == 'running'
                    ? 'Driver-assisted blocking can be used for verdict requests.'
                    : 'Current release uses post-launch user-mode stopping when confirmed threats are observed.',
                icon: Icons.block_outlined,
              ),
              ZentorMetricCard(
                title: 'Avorax Native Engine',
                value: state.nativeEngineStatus == 'ready'
                    ? 'Ready'
                    : 'Unavailable',
                detail: state.nativeEngineStatus == 'ready'
                    ? 'Primary offline scanner for native signatures, rules, ML, and heuristics.'
                    : 'Native engine assets are missing or failed to load.',
                icon: Icons.health_and_safety_outlined,
              ),
              ZentorMetricCard(
                title: 'Native rules',
                value: '${state.nativeRuleCount} rules',
                detail:
                    'Avorax-owned rules supplement native signatures, ML, and heuristic analysis.',
                icon: Icons.rule_folder_outlined,
              ),
              ZentorMetricCard(
                title: 'Cloud',
                value: state.cloudStatus.label,
                detail: 'Optional reporting and updates.',
                icon: Icons.cloud_outlined,
              ),
              ZentorMetricCard(
                title: 'Last scan',
                value: report == null ? 'Never scanned' : report.status.label,
                detail: report == null
                    ? 'No scan has completed yet.'
                    : '${report.filesScanned} files scanned, ${report.threatsFound} threats found.',
                icon: Icons.radar_outlined,
              ),
              ZentorMetricCard(
                title: 'Quarantine',
                value: state.quarantine.isEmpty
                    ? 'No quarantined files'
                    : '${state.quarantine.length} items',
                detail: 'Nothing is permanently deleted automatically.',
                icon: Icons.inventory_2_outlined,
              ),
            ];
            if (constraints.maxWidth < 900) {
              return Column(
                children: [
                  for (final card in cards) ...[
                    card,
                    const SizedBox(height: 12),
                  ],
                ],
              );
            }
            return GridView.count(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              crossAxisCount: 2,
              mainAxisSpacing: 14,
              crossAxisSpacing: 14,
              childAspectRatio: 2.3,
              children: cards,
            );
          },
        ),
      ],
    );
  }
}

class _SelfTestResultPanel extends StatelessWidget {
  const _SelfTestResultPanel({required this.result});

  final String result;

  @override
  Widget build(BuildContext context) {
    final failed =
        result.contains('FAIL') ||
        result.toLowerCase().contains('failed') ||
        result.toLowerCase().contains('not active');
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: failed
            ? ZentorColors.warning.withValues(alpha: 0.08)
            : ZentorColors.success.withValues(alpha: 0.08),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(
          color: failed ? ZentorColors.warning : ZentorColors.success,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                failed ? Icons.warning_amber_rounded : Icons.check_circle,
                color: failed ? ZentorColors.warning : ZentorColors.success,
              ),
              const SizedBox(width: 8),
              Text(
                failed
                    ? 'Protection self-test found issues'
                    : 'Protection self-test passed',
                style: Theme.of(context).textTheme.titleMedium,
              ),
            ],
          ),
          const SizedBox(height: 10),
          SelectableText(
            result,
            style: const TextStyle(
              color: ZentorColors.textSecondary,
              height: 1.35,
            ),
          ),
        ],
      ),
    );
  }
}

class _ProtectionChecklist extends StatelessWidget {
  const _ProtectionChecklist({required this.state});

  final ZentorState state;

  @override
  Widget build(BuildContext context) {
    final rows = [
      _CheckRow(
        'Native Engine',
        state.nativeEngineStatus == 'ready' ? 'Ready' : 'Error',
      ),
      _CheckRow('Signature Pack', '${state.nativeSignatureCount} loaded'),
      _CheckRow('Rule Pack', '${state.nativeRuleCount} loaded'),
      _CheckRow('Quarantine', 'Ready'),
      _CheckRow('Core Service', _serviceLabel(state.coreServiceStatus)),
      _CheckRow('Guard Service', _guardLabel(state.guardStatus)),
      _CheckRow(
        'Pre-execution Driver',
        state.driverStatus == 'running' ? 'Running' : 'Missing',
      ),
      _CheckRow('Local AI', _mlLabel(state.nativeMlStatus)),
      const _CheckRow('Cloud', 'Disabled, optional'),
    ];
    return Wrap(
      spacing: 10,
      runSpacing: 10,
      children: rows
          .map(
            (row) => Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
              decoration: BoxDecoration(
                color: ZentorColors.elevatedSurface,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: ZentorColors.border),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    row.label,
                    style: Theme.of(context).textTheme.labelMedium,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    row.value,
                    style: const TextStyle(color: ZentorColors.textSecondary),
                  ),
                ],
              ),
            ),
          )
          .toList(),
    );
  }
}

class _CheckRow {
  const _CheckRow(this.label, this.value);

  final String label;
  final String value;
}

String _protectionExplanation(ZentorState state) {
  if (state.protectionStatus == ProtectionStatus.protected) {
    return 'Local scans, quarantine, Guard Service, and native engine assets are ready. Pre-execution blocking is shown as active only when the Windows driver is running and self-tested.';
  }
  if (state.nativeEngineStatus == 'ready' && state.driverStatus != 'running') {
    return 'Local scans and quarantine are ready. Real-time pre-execution blocking is not active because the Windows driver is not installed or has not passed self-test.';
  }
  if (state.nativeEngineStatus != 'ready') {
    return 'Action required: Avorax Native Engine assets are missing or failed to load. Avorax does not report files clean while the engine is unavailable.';
  }
  return 'Avorax shows exactly which local protection components are ready, degraded, or unavailable. Cloud disabled is optional and does not reduce local scan protection.';
}

String _watcherLabel(String mode) => switch (mode) {
  'userModeBestEffort' => 'Best-effort',
  'off' => 'Off',
  _ => 'Unavailable',
};

String _guardLabel(String status) => switch (status) {
  'running' => 'Running',
  'stopped' => 'Stopped',
  'installed' => 'Installed',
  'monitorOnly' => 'Monitor only',
  'blockConfirmedThreats' => 'Block confirmed threats',
  'aggressive' => 'Aggressive',
  _ => 'Off',
};

String _serviceLabel(String status) => switch (status) {
  'running' => 'Running',
  'installed' => 'Installed',
  'stopped' => 'Stopped',
  'missing' => 'Missing',
  _ => 'Unknown',
};

String _mlLabel(String status) => switch (status) {
  'active' => 'Production',
  'developmentModel' => 'Development',
  'modelMissing' => 'Missing',
  _ => 'Unavailable',
};
