import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../core/updates/update_service.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_empty_state.dart';
import '../../shared/widgets/zentor_metric_card.dart';
import '../../shared/widgets/zentor_status_card.dart';

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final isDesktop = MediaQuery.sizeOf(context).width >= 1000;
    final hero = ZentorPanel(
      padding: const EdgeInsets.all(28),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const ZentorMark(size: 72),
              const Spacer(),
              ZentorStatusPill(
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
              color: ZentorColors.textSecondary,
              height: 1.45,
            ),
          ),
          const SizedBox(height: 24),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              ZentorButton(
                label: 'Run Quick Scan',
                icon: Icons.radar_outlined,
                onPressed: state.scanStatus == ScanStatus.running
                    ? null
                    : controller.runQuickScan,
              ),
              ZentorButton(
                label: 'Run Full Scan',
                icon: Icons.travel_explore_outlined,
                secondary: true,
                onPressed: state.scanStatus == ScanStatus.running
                    ? null
                    : controller.runFullScan,
              ),
              ZentorButton(
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
              if (state.updateStatus == UpdateStatus.updateAvailable)
                ZentorButton(
                  label: 'Download Update',
                  icon: Icons.system_update_alt_outlined,
                  secondary: true,
                  onPressed: controller.openUpdateDownload,
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
    );

    final report = state.lastScanReport;
    final cards = [
      ZentorMetricCard(
        title: 'Protection profile',
        value: state.config.protectionMode.label,
        detail: state.config.protectionMode == ProtectionMode.lockdown
            ? 'Unknown app blocking is enabled by policy. True before-launch blocking still requires a running driver.'
            : state.config.protectionMode.description,
        icon: Icons.admin_panel_settings_outlined,
      ),
      ZentorMetricCard(
        title: 'Real-time protection',
        value:
            state.protectionStatus == ProtectionStatus.protected ||
                state.protectionStatus == ProtectionStatus.localOnly
            ? 'Enabled'
            : 'Disabled',
        detail: state.protectionStatus == ProtectionStatus.localOnly
            ? 'Local protection is active. Zentor Cloud is offline.'
            : state.protectionStatus.label,
        icon: Icons.shield_outlined,
      ),
      ZentorMetricCard(
        title: 'Zentor Native Engine',
        value: state.nativeEngineStatus == 'ready' ? 'Ready' : 'Unavailable',
        detail: state.nativeEngineStatus == 'ready'
            ? 'Native signatures, rules, heuristics, and ML run locally without cloud.'
            : 'Native engine assets are missing or failed self-test.',
        icon: Icons.health_and_safety_outlined,
      ),
      ZentorMetricCard(
        title: 'Native ML',
        value: state.nativeMlStatus == 'developmentModel'
            ? 'Development model'
            : state.nativeMlStatus,
        detail: state.nativeMlModelVersion == null
            ? 'Native ML model is not loaded.'
            : 'Model ${state.nativeMlModelVersion} is local; development ML cannot auto-quarantine by itself.',
        icon: Icons.psychology_alt_outlined,
      ),
      ZentorMetricCard(
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
      ZentorMetricCard(
        title: 'Native Rules',
        value: '${state.nativeRuleCount} rules loaded',
        detail:
            'Zentor-owned deterministic rules are bounded and review-only unless strong evidence supports action.',
        icon: Icons.rule_folder_outlined,
      ),
      ZentorMetricCard(
        title: 'Behavior Guard',
        value: _guardLabel(state.guardStatus),
        detail: state.driverStatus == 'running'
            ? 'Driver-assisted guard path is available.'
            : 'User-mode guard can stop confirmed threats after launch.',
        icon: Icons.policy_outlined,
      ),
      const ZentorMetricCard(
        title: 'Ransomware Guard',
        value: 'Recovery-aware',
        detail:
            'Stops ransomware-like mass changes when detected and uses local recovery data when available.',
        icon: Icons.lock_reset_outlined,
      ),
      const ZentorMetricCard(
        title: 'Recovery Vault',
        value: 'Local only',
        detail:
            'Recovery can restore protected copies when available. It cannot decrypt without a backup or key.',
        icon: Icons.restore_outlined,
      ),
      ZentorMetricCard(
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
      ZentorMetricCard(
        title: 'Quarantine',
        value: state.quarantine.isEmpty
            ? 'No quarantined files'
            : '${state.quarantine.length} items',
        detail: state.quarantine.isEmpty
            ? 'Confirmed detections are isolated here.'
            : 'Review quarantined files.',
        icon: Icons.inventory_2_outlined,
      ),
      ZentorMetricCard(
        title: 'Updates',
        value: state.updateStatus.label,
        detail: _updateDetail(state),
        icon: Icons.system_update_alt_outlined,
      ),
    ];

    final recent = ZentorPanel(
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
            const ZentorEmptyState(
              title: 'No activity yet',
              message: 'Events appear here when Zentor performs real work.',
              icon: Icons.receipt_long_outlined,
            )
          else
            for (final event in state.events.take(7))
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: const Icon(
                  Icons.circle,
                  size: 9,
                  color: ZentorColors.primaryAccent,
                ),
                title: Text(event.message),
                subtitle: Text(
                  event.details ?? event.type,
                  style: const TextStyle(color: ZentorColors.textSecondary),
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

  String _mainStatus(ZentorState state) {
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

  String _headline(ZentorState state) {
    final status = _mainStatus(state);
    if (status == 'Protected') return 'Your device is protected';
    if (status == 'Scan Running') return 'Scan running';
    if (status == 'Threats Found') return 'Review threats';
    return 'Run a scan';
  }

  String _heroCopy(ZentorState state) {
    if (state.scanStatus == ScanStatus.running) {
      return 'Zentor is scanning accessible files and will show real results when the scan completes.';
    }
    if ((state.lastScanReport?.threatsFound ?? 0) > 0) {
      return 'Review detected suspicious files before choosing quarantine, allowlist, restore, or delete actions.';
    }
    if (state.protectionStatus == ProtectionStatus.localOnly) {
      return 'Local protection is active. Zentor Cloud is offline and does not block scanning or quarantine.';
    }
    return 'Anti-malware protection, quarantine, and local threat review, visible and under your control.';
  }

  Color _mainColor(ZentorState state) {
    final status = _mainStatus(state);
    if (status == 'Protected') return ZentorColors.success;
    if (status == 'Threats Found') return ZentorColors.danger;
    if (status == 'Scan Running') return ZentorColors.primaryAccent;
    return ZentorColors.warning;
  }

  String _guardLabel(String status) => switch (status) {
    'running' => 'Running',
    'stopped' => 'Stopped',
    'installed' => 'Installed',
    'blockConfirmedThreats' => 'Block confirmed threats',
    'monitorOnly' => 'Monitor only',
    'aggressive' => 'Aggressive',
    _ => 'Off',
  };

  String _updateDetail(ZentorState state) {
    final update = state.updateInfo;
    if (state.updateStatus == UpdateStatus.updateAvailable && update != null) {
      return 'Zentor ${update.latestVersion} is available. ${update.assetName ?? 'Open release'} to update.';
    }
    if (state.updateStatus == UpdateStatus.upToDate) {
      return 'Zentor ${state.currentAppVersion} is installed.';
    }
    if (state.updateStatus == UpdateStatus.failed) {
      return 'Could not check GitHub Releases. Scanning still works offline.';
    }
    return 'Zentor checks GitHub Releases and asks before opening an installer.';
  }
}
