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
              const Text(
                'Zentor protects this device with visible local scanning, quarantine controls, real-time guard status, and optional cloud reporting.',
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
                    label: 'Enable Protection',
                    icon: Icons.play_arrow_rounded,
                    onPressed: state.loading
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
                    label: 'Check Engine',
                    icon: Icons.health_and_safety_outlined,
                    secondary: true,
                    onPressed: controller.unawaitedCheckMalwareEngine,
                  ),
                ],
              ),
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
                    ? 'Zentor Guard Service is running. Confirmed threats can be stopped after launch.'
                    : 'Guard Service is not running. Manual scans and quarantine remain available.',
                icon: Icons.shield_outlined,
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
                title: 'Zentor Native Engine',
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
                    'Zentor-owned rules supplement native signatures, ML, and heuristic analysis.',
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

String _guardLabel(String status) => switch (status) {
  'running' => 'Running',
  'stopped' => 'Stopped',
  'installed' => 'Installed',
  'monitorOnly' => 'Monitor only',
  'blockConfirmedThreats' => 'Block confirmed threats',
  'aggressive' => 'Aggressive',
  _ => 'Off',
};
