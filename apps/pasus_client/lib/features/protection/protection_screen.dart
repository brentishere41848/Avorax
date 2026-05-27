import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:pasus_protocol/pasus_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/pasus_colors.dart';
import '../../shared/widgets/pasus_button.dart';
import '../../shared/widgets/pasus_metric_card.dart';
import '../../shared/widgets/pasus_status_card.dart';

class ProtectionScreen extends ConsumerWidget {
  const ProtectionScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(pasusControllerProvider);
    final controller = ref.read(pasusControllerProvider.notifier);
    return Column(
      children: [
        PasusPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const PasusMark(size: 58),
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
                            color: PasusColors.textSecondary,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 18),
              const Text(
                'Pasus protects this device with visible local scanning, quarantine controls, and optional cloud reporting. Gaming protection is available separately and is not required.',
                style: TextStyle(
                  color: PasusColors.textSecondary,
                  height: 1.45,
                ),
              ),
              const SizedBox(height: 22),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  PasusButton(
                    label: 'Enable Protection',
                    icon: Icons.play_arrow_rounded,
                    onPressed: state.loading
                        ? null
                        : controller.startProtection,
                  ),
                  PasusButton(
                    label: 'Stop Protection',
                    icon: Icons.stop_rounded,
                    secondary: true,
                    onPressed: state.protectionStatus == ProtectionStatus.idle
                        ? null
                        : controller.stopProtection,
                  ),
                  PasusButton(
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
                  style: const TextStyle(color: PasusColors.warning),
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
              PasusMetricCard(
                title: 'Protection profile',
                value: state.config.protectionMode.label,
                detail: state.config.protectionMode == ProtectionMode.lockdown
                    ? 'Unknown apps are blocked by policy until approved. Driver self-test determines whether this happens before launch.'
                    : state.config.protectionMode.description,
                icon: Icons.admin_panel_settings_outlined,
              ),
              PasusMetricCard(
                title: 'Real-time protection',
                value: state.protectionStatus.label,
                detail: state.protectionStatus == ProtectionStatus.localOnly
                    ? 'Cloud is optional; local protection remains available.'
                    : 'Visible protection only.',
                icon: Icons.shield_outlined,
              ),
              PasusMetricCard(
                title: 'Pre-execution blocking',
                value: state.driverStatus == 'running'
                    ? 'Driver active'
                    : 'Not active',
                detail: state.driverStatus == 'running'
                    ? 'Driver-assisted blocking can be used for verdict requests.'
                    : 'Current release uses post-launch user-mode stopping when confirmed threats are observed.',
                icon: Icons.block_outlined,
              ),
              PasusMetricCard(
                title: 'Malware engine',
                value: state.malwareEngineStatus.label,
                detail:
                    state.malwareEngineStatus == MalwareEngineStatus.unavailable
                    ? 'Install the Pasus MSI with bundled ClamAV, or configure ClamAV for development.'
                    : 'Ready for local scans.',
                icon: Icons.health_and_safety_outlined,
              ),
              PasusMetricCard(
                title: 'YARA rules',
                value: state.yaraStatus == 'available'
                    ? '${state.yaraRuleCount} rules'
                    : 'Unavailable',
                detail:
                    'Conservative local rules supplement signature, AI, and heuristic analysis.',
                icon: Icons.rule_folder_outlined,
              ),
              PasusMetricCard(
                title: 'Cloud',
                value: state.cloudStatus.label,
                detail: 'Optional reporting and updates.',
                icon: Icons.cloud_outlined,
              ),
              PasusMetricCard(
                title: 'Last scan',
                value: report == null ? 'Never scanned' : report.status.label,
                detail: report == null
                    ? 'No scan has completed yet.'
                    : '${report.filesScanned} files scanned, ${report.threatsFound} threats found.',
                icon: Icons.radar_outlined,
              ),
              PasusMetricCard(
                title: 'Quarantine',
                value: state.quarantine.isEmpty
                    ? 'No quarantined files'
                    : '${state.quarantine.length} items',
                detail: 'Nothing is permanently deleted automatically.',
                icon: Icons.inventory_2_outlined,
              ),
              PasusMetricCard(
                title: 'Gaming protection',
                value: state.config.gameConfig.isConfigured
                    ? state.config.gameConfig.gameName
                    : 'Optional',
                detail:
                    'Game verification does not block antivirus protection.',
                icon: Icons.sports_esports_outlined,
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
