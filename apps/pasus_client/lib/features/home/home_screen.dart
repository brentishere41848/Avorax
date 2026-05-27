import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:pasus_protocol/pasus_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/pasus_colors.dart';
import '../../shared/widgets/pasus_button.dart';
import '../../shared/widgets/pasus_empty_state.dart';
import '../../shared/widgets/pasus_metric_card.dart';
import '../../shared/widgets/pasus_status_card.dart';

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(pasusControllerProvider);
    final controller = ref.read(pasusControllerProvider.notifier);
    final isDesktop = MediaQuery.sizeOf(context).width >= 1000;
    final hero = PasusPanel(
      padding: const EdgeInsets.all(28),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const PasusMark(size: 72),
              const Spacer(),
              PasusStatusPill(
                label: _mainStatus(state),
                color: _mainColor(state),
                icon: Icons.security_outlined,
              ),
            ],
          ),
          const SizedBox(height: 24),
          Text(
            _headline(state),
            style: Theme.of(context).textTheme.displaySmall,
          ),
          const SizedBox(height: 10),
          Text(
            _heroCopy(state),
            style: Theme.of(context).textTheme.bodyLarge?.copyWith(
              color: PasusColors.textSecondary,
              height: 1.45,
            ),
          ),
          const SizedBox(height: 24),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              PasusButton(
                label: 'Run Quick Scan',
                icon: Icons.radar_outlined,
                onPressed: state.scanStatus == ScanStatus.running
                    ? null
                    : controller.runQuickScan,
              ),
              PasusButton(
                label: 'Run Full Scan',
                icon: Icons.travel_explore_outlined,
                secondary: true,
                onPressed: state.scanStatus == ScanStatus.running
                    ? null
                    : controller.runFullScan,
              ),
              PasusButton(
                label:
                    state.protectionStatus == ProtectionStatus.idle ||
                        state.protectionStatus == ProtectionStatus.error
                    ? 'Enable Protection'
                    : 'Stop Protection',
                icon:
                    state.protectionStatus == ProtectionStatus.idle ||
                        state.protectionStatus == ProtectionStatus.error
                    ? Icons.shield_outlined
                    : Icons.stop_rounded,
                secondary: true,
                onPressed: state.loading
                    ? null
                    : state.protectionStatus == ProtectionStatus.idle ||
                          state.protectionStatus == ProtectionStatus.error
                    ? controller.startProtection
                    : controller.stopProtection,
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
    );

    final report = state.lastScanReport;
    final cards = [
      PasusMetricCard(
        title: 'Protection profile',
        value: state.config.protectionMode.label,
        detail: state.config.protectionMode == ProtectionMode.lockdown
            ? 'Unknown app blocking is enabled by policy. True before-launch blocking still requires a running driver.'
            : state.config.protectionMode.description,
        icon: Icons.admin_panel_settings_outlined,
      ),
      PasusMetricCard(
        title: 'Real-time protection',
        value:
            state.protectionStatus == ProtectionStatus.protected ||
                state.protectionStatus == ProtectionStatus.localOnly
            ? 'Enabled'
            : 'Disabled',
        detail: state.protectionStatus == ProtectionStatus.localOnly
            ? 'Local protection is active. Pasus Cloud is offline.'
            : state.protectionStatus.label,
        icon: Icons.shield_outlined,
      ),
      PasusMetricCard(
        title: 'Malware engine',
        value: state.malwareEngineStatus.label,
        detail: state.malwareEngineStatus == MalwareEngineStatus.unavailable
            ? 'Install the Pasus MSI with bundled ClamAV, or configure ClamAV for development.'
            : 'Signature and heuristic scanning use real local results.',
        icon: Icons.health_and_safety_outlined,
      ),
      PasusMetricCard(
        title: 'Local AI Engine',
        value: state.aiModelInfo.status.label,
        detail: state.aiModelInfo.productionReady
            ? 'Model ${state.aiModelInfo.modelVersion} is loaded for offline inference.'
            : '${state.aiModelInfo.message} AI-only detections stay review-only.',
        icon: Icons.psychology_alt_outlined,
      ),
      PasusMetricCard(
        title: 'Pre-execution Blocking',
        value: state.driverStatus == 'running'
            ? state.config.protectionMode == ProtectionMode.lockdown
                  ? 'Known-threat blocking'
                  : 'Driver active'
            : 'Driver missing',
        detail: state.driverStatus == 'running'
            ? 'Before-launch claims require the protection self-test to pass.'
            : 'Post-launch user-mode stopping is available; true pre-execution blocking needs the signed driver.',
        icon: Icons.block_outlined,
      ),
      PasusMetricCard(
        title: 'YARA Rules',
        value: state.yaraStatus == 'available'
            ? '${state.yaraRuleCount} rules loaded'
            : 'Rules unavailable',
        detail:
            'YARA detections use packaged local rules. Review-only rules do not auto-quarantine.',
        icon: Icons.rule_folder_outlined,
      ),
      PasusMetricCard(
        title: 'Behavior Guard',
        value: _guardLabel(state.guardStatus),
        detail: state.driverStatus == 'running'
            ? 'Driver-assisted guard path is available.'
            : 'User-mode guard can stop confirmed threats after launch.',
        icon: Icons.policy_outlined,
      ),
      const PasusMetricCard(
        title: 'Ransomware Guard',
        value: 'Recovery-aware',
        detail:
            'Stops ransomware-like mass changes when detected and uses local recovery data when available.',
        icon: Icons.lock_reset_outlined,
      ),
      const PasusMetricCard(
        title: 'Recovery Vault',
        value: 'Local only',
        detail:
            'Recovery can restore protected copies when available. It cannot decrypt without a backup or key.',
        icon: Icons.restore_outlined,
      ),
      PasusMetricCard(
        title: 'Last scan',
        value: report == null
            ? 'Never scanned'
            : report.threatsFound > 0
            ? '${report.threatsFound} threats found'
            : report.status.label,
        detail: report == null
            ? 'Run a scan to check this device.'
            : '${report.filesScanned} files scanned, ${report.skippedFiles} skipped.',
        icon: Icons.fact_check_outlined,
      ),
      PasusMetricCard(
        title: 'Quarantine',
        value: state.quarantine.isEmpty
            ? 'No quarantined files'
            : '${state.quarantine.length} items',
        detail: state.quarantine.isEmpty
            ? 'Confirmed detections are isolated here.'
            : 'Review quarantined files.',
        icon: Icons.inventory_2_outlined,
      ),
      PasusMetricCard(
        title: 'Updates',
        value: state.cloudStatus.label,
        detail: 'Scanning still runs locally when the malware engine is ready.',
        icon: Icons.system_update_alt_outlined,
      ),
      PasusMetricCard(
        title: 'Gaming Protection',
        value: 'Optional',
        detail: state.config.gameConfig.isConfigured
            ? state.config.gameConfig.gameName
            : 'Game verification is available when you need it.',
        icon: Icons.sports_esports_outlined,
      ),
    ];

    final recent = PasusPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                'Security events',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const Spacer(),
              TextButton(
                onPressed: () => context.go('/logs'),
                child: const Text('View all'),
              ),
            ],
          ),
          const SizedBox(height: 16),
          if (state.events.isEmpty)
            const PasusEmptyState(
              title: 'No activity yet',
              message: 'Events appear here when Pasus performs real work.',
              icon: Icons.receipt_long_outlined,
            )
          else
            for (final event in state.events.take(7))
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(
                  Icons.circle,
                  size: 9,
                  color: PasusColors.primaryAccent,
                ),
                title: Text(event.message),
                subtitle: Text(
                  event.details ?? event.type,
                  style: const TextStyle(color: PasusColors.textSecondary),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
        ],
      ),
    );

    if (isDesktop) {
      return Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            flex: 2,
            child: Column(
              children: [
                hero,
                const SizedBox(height: 16),
                GridView.count(
                  shrinkWrap: true,
                  physics: const NeverScrollableScrollPhysics(),
                  crossAxisCount: 2,
                  mainAxisSpacing: 14,
                  crossAxisSpacing: 14,
                  childAspectRatio: 2.35,
                  children: cards,
                ),
              ],
            ),
          ),
          const SizedBox(width: 16),
          Expanded(child: recent),
        ],
      );
    }
    return Column(
      children: [
        hero,
        const SizedBox(height: 14),
        for (final card in cards) ...[card, const SizedBox(height: 12)],
        recent,
      ],
    );
  }

  String _mainStatus(PasusState state) {
    if (state.scanStatus == ScanStatus.running) return 'Scan Running';
    if ((state.lastScanReport?.threatsFound ?? 0) > 0) return 'Threats Found';
    if (state.protectionStatus == ProtectionStatus.protected ||
        state.protectionStatus == ProtectionStatus.localOnly) {
      return 'Protected';
    }
    if (state.protectionStatus == ProtectionStatus.error ||
        state.malwareEngineStatus == MalwareEngineStatus.unavailable) {
      return 'Protection Disabled';
    }
    return 'Action Required';
  }

  String _headline(PasusState state) {
    final status = _mainStatus(state);
    if (status == 'Protected') return 'Your device is protected';
    if (status == 'Scan Running') return 'Scan running';
    if (status == 'Threats Found') return 'Review threats';
    return 'Run a scan';
  }

  String _heroCopy(PasusState state) {
    if (state.scanStatus == ScanStatus.running) {
      return 'Pasus is scanning accessible files and will show real results when the scan completes.';
    }
    if ((state.lastScanReport?.threatsFound ?? 0) > 0) {
      return 'Review detected suspicious files before choosing quarantine, allowlist, restore, or delete actions.';
    }
    if (state.protectionStatus == ProtectionStatus.localOnly) {
      return 'Local protection is active. Pasus Cloud is offline and does not block scanning or quarantine.';
    }
    return 'Antivirus protection and optional gaming verification, visible and under your control.';
  }

  Color _mainColor(PasusState state) {
    final status = _mainStatus(state);
    if (status == 'Protected') return PasusColors.success;
    if (status == 'Threats Found') return PasusColors.danger;
    if (status == 'Scan Running') return PasusColors.primaryAccent;
    return PasusColors.warning;
  }

  String _guardLabel(String status) => switch (status) {
    'blockConfirmedThreats' => 'Block confirmed threats',
    'monitorOnly' => 'Monitor only',
    'aggressive' => 'Aggressive',
    _ => 'Off',
  };
}
