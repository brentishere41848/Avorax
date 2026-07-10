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
import '../protection/protection_confirmation.dart';
import '../update/update_confirmation.dart';
import '../update/update_mutation_guard.dart';

class HomeScreen extends ConsumerWidget {
  const HomeScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final protectionOperationBusy = state.protectionOperationInFlight;
    final protectionSelfTestBusy = state.protectionSelfTestInFlight;
    final updateMutationBusy = updateMutationOperationInProgress(state);
    final scanStartBusy =
        state.scanStartInFlight ||
        state.scanTargetSelectionInFlight ||
        state.securitySettingsActionInFlight ||
        state.configurationResetInFlight ||
        state.scanStatus == ScanStatus.running ||
        updateMutationBusy;
    final updateBusy =
        state.updateOperationInFlight ||
        state.updateStatus == UpdateStatus.checking ||
        state.updateStatus == UpdateStatus.downloading ||
        state.updateStatus == UpdateStatus.verifying ||
        state.updateStatus == UpdateStatus.installing ||
        state.updateStatus == UpdateStatus.rollingBack;
    final updateMutationBlocked = updateMutationBlockedByActiveWork(state);
    final isDesktop = MediaQuery.sizeOf(context).width >= 1000;
    final hero = ZentorPanel(
      padding: const EdgeInsets.all(28),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: 16,
            runSpacing: 12,
            children: [
              const ZentorMark(size: 72),
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
                onPressed: scanStartBusy
                    ? null
                    : () => controller.runQuickScan(
                        actionMode: ScanActionMode.detectOnly,
                      ),
              ),
              ZentorButton(
                label: 'Run Full Scan',
                icon: Icons.travel_explore_outlined,
                secondary: true,
                onPressed: scanStartBusy
                    ? null
                    : () => controller.runFullScan(
                        actionMode: ScanActionMode.detectOnly,
                      ),
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
                onPressed:
                    state.loading ||
                        protectionOperationBusy ||
                        protectionSelfTestBusy ||
                        updateMutationBusy
                    ? null
                    : state.protectionStatus == ProtectionStatus.idle ||
                          state.protectionStatus == ProtectionStatus.error
                    ? () async {
                        if (!await confirmStartProtection(context)) return;
                        await controller.startProtection(confirmed: true);
                      }
                    : () async {
                        if (!await confirmStopProtection(context)) return;
                        await controller.stopProtection(confirmed: true);
                      },
              ),
              if (state.updateStatus == UpdateStatus.updateAvailable ||
                  state.updateStatus == UpdateStatus.downloading ||
                  state.updateStatus == UpdateStatus.verifying ||
                  state.updateStatus == UpdateStatus.installing)
                ZentorButton(
                  label: state.updateStatus == UpdateStatus.updateAvailable
                      ? 'Download, verify, install'
                      : state.updateStatus.label,
                  icon: Icons.system_update_alt_outlined,
                  secondary: true,
                  onPressed: updateBusy || updateMutationBlocked
                      ? null
                      : () async {
                          if (!await confirmInstallUpdate(context)) return;
                          await controller.installUpdateInApp(confirmed: true);
                        },
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
        value: _realTimeProtectionValue(state),
        detail: _realTimeProtectionDetail(state),
        icon: Icons.shield_outlined,
      ),
      ZentorMetricCard(
        title: 'Avorax Native Engine',
        value: _nativeEngineLabel(state),
        detail: _nativeEngineDetail(state),
        icon: Icons.health_and_safety_outlined,
      ),
      ZentorMetricCard(
        title: 'Native ML',
        value: _nativeMlLabel(state.nativeMlStatus),
        detail: _nativeMlDetail(state),
        icon: Icons.psychology_alt_outlined,
      ),
      ZentorMetricCard(
        title: 'Pre-execution Blocking',
        value: _preExecutionDriverValue(state),
        detail: state.driverStatus == 'running'
            ? 'Before-launch claims require the protection self-test to pass.'
            : 'Post-launch user-mode stopping is available; true pre-execution blocking needs the signed driver.',
        icon: Icons.block_outlined,
      ),
      ZentorMetricCard(
        title: 'Native Rules',
        value: _nativeRuleCountLabel(state),
        detail:
            'Avorax-owned deterministic rules are bounded and review-only unless strong evidence supports action.',
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
            : _lastScanDetail(report),
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
              Expanded(
                child: Text(
                  'Security events',
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: Theme.of(context).textTheme.titleLarge,
                ),
              ),
              const SizedBox(width: 12),
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
              message: 'Events appear here when Avorax performs real work.',
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
    if (state.scanStatus == ScanStatus.running) return 'Scan running';
    if (_hasThreatFindings(state)) return 'Threats found';
    if (state.updateStatus == UpdateStatus.updateAvailable) {
      return 'Update required';
    }
    if (_engineNeedsAttention(state)) {
      return 'Attention needed';
    }
    if (state.protectionStatus == ProtectionStatus.protected ||
        state.protectionStatus == ProtectionStatus.localOnly) {
      return 'Protected';
    }
    if (state.protectionStatus == ProtectionStatus.idle) {
      return 'Protection disabled';
    }
    if (state.protectionStatus == ProtectionStatus.error) {
      return 'Attention needed';
    }
    return 'Attention needed';
  }

  bool _hasThreatFindings(ZentorState state) {
    final report = state.lastScanReport;
    return report != null && report.threatsFound > 0;
  }

  bool _engineNeedsAttention(ZentorState state) {
    return state.malwareEngineStatus != MalwareEngineStatus.available ||
        state.nativeEngineStatus != 'ready' ||
        (state.lastEngineError?.trim().isNotEmpty ?? false);
  }

  String _realTimeProtectionValue(ZentorState state) {
    if (_engineNeedsAttention(state)) return 'Attention needed';
    if (state.protectionStatus == ProtectionStatus.protected ||
        state.protectionStatus == ProtectionStatus.localOnly) {
      return 'Enabled';
    }
    if (state.protectionStatus == ProtectionStatus.partiallyProtected) {
      return 'Limited';
    }
    if (state.protectionStatus == ProtectionStatus.starting) return 'Starting';
    if (state.protectionStatus == ProtectionStatus.stopping) return 'Stopping';
    if (state.protectionStatus == ProtectionStatus.error) return 'Error';
    return 'Disabled';
  }

  String _realTimeProtectionDetail(ZentorState state) {
    if (_engineNeedsAttention(state)) {
      return 'Engine evidence is not ready, so Avorax cannot report this device as protected.';
    }
    if (state.protectionStatus == ProtectionStatus.localOnly) {
      return 'Local protection is active. Avorax Cloud is offline.';
    }
    if (state.protectionStatus == ProtectionStatus.partiallyProtected) {
      return 'Local protection is available, but driver self-test is required before pre-execution claims.';
    }
    return state.protectionStatus.label;
  }

  String _headline(ZentorState state) {
    final status = _mainStatus(state);
    if (status == 'Protected') return 'Protected';
    if (status == 'Scan running') return 'Scan running';
    if (status == 'Threats found') return 'Review threats';
    if (status == 'Update required') return 'Update required';
    if (status == 'Protection disabled') return 'Protection disabled';
    return 'Attention needed';
  }

  String _heroCopy(ZentorState state) {
    final status = _mainStatus(state);
    if (status == 'Scan running') {
      return 'Avorax is scanning accessible files and will show real results when the scan completes.';
    }
    if (status == 'Threats found') {
      return 'Review detected suspicious files before choosing quarantine, allowlist, restore, or delete actions.';
    }
    if (status == 'Update required') {
      return 'An update is available. Download and verify it before installation to receive current app and protection improvements.';
    }
    if (status == 'Protection disabled') {
      return 'Real-time protection is off. Run a scan or enable protection to improve this device status.';
    }
    if (status == 'Attention needed') {
      return 'Avorax needs attention before it can report this device as protected. Check engine and protection status.';
    }
    if (state.protectionStatus == ProtectionStatus.localOnly) {
      return 'Local protection is active. Avorax Cloud is offline and does not block scanning or quarantine.';
    }
    return 'Anti-malware protection, quarantine, and local threat review, visible and under your control.';
  }

  Color _mainColor(ZentorState state) {
    final status = _mainStatus(state);
    if (status == 'Protected') return ZentorColors.success;
    if (status == 'Threats found') return ZentorColors.danger;
    if (status == 'Scan running') return ZentorColors.primaryAccent;
    return ZentorColors.warning;
  }

  String _nativeMlLabel(String status) => switch (status) {
    'loaded' => 'Loaded',
    'developmentModel' => 'Development model',
    'modelMissing' => 'Missing',
    'error' => 'Error',
    _ => 'Unavailable',
  };

  String _nativeMlDetail(ZentorState state) {
    final version = state.nativeMlModelVersion;
    if (version == null) return 'Native ML model is not loaded.';
    if (state.nativeMlProductionReady) {
      return 'Model $version is production-ready according to native metadata.';
    }
    return 'Model $version is local; development ML cannot auto-quarantine by itself.';
  }

  String _nativeEngineLabel(ZentorState state) {
    if (state.lastEngineError?.trim().isNotEmpty ?? false) {
      return 'Attention needed';
    }
    return switch (state.nativeEngineStatus) {
      'ready' => 'Ready',
      'error' => 'Error',
      'unavailable' => 'Unavailable',
      _ => 'Unknown',
    };
  }

  String _nativeEngineDetail(ZentorState state) {
    final diagnostic = state.lastEngineError?.trim();
    if (diagnostic != null && diagnostic.isNotEmpty) {
      return 'Engine diagnostic: $diagnostic';
    }
    if (state.nativeEngineStatus == 'ready') {
      return 'Native signatures, rules, heuristics, and ML run locally without cloud.';
    }
    return 'Native engine assets are missing or failed self-test.';
  }

  String _guardLabel(String status) => switch (status) {
    'running' => 'Running',
    'stopped' => 'Stopped',
    'missing' => 'Missing',
    'installed' => 'Installed',
    'unknown' => 'Unknown',
    'off' => 'Off',
    'blockConfirmedThreats' => 'Block confirmed threats',
    'monitorOnly' => 'Monitor only',
    'aggressive' => 'Aggressive',
    _ => 'Unavailable',
  };

  String _nativeRuleCountLabel(ZentorState state) {
    final engineDiagnosticVisible =
        state.lastEngineError?.trim().isNotEmpty ?? false;
    if (state.nativeRuleCount > 0 ||
        (state.nativeEngineStatus == 'ready' && !engineDiagnosticVisible)) {
      return '${state.nativeRuleCount} rules loaded';
    }
    return 'Unknown';
  }

  String _preExecutionDriverValue(ZentorState state) {
    if (state.driverStatus == 'running') {
      return state.config.protectionMode == ProtectionMode.lockdown
          ? 'Known-threat blocking'
          : 'Driver active';
    }
    return _driverStatusLabel(state.driverStatus);
  }

  String _driverStatusLabel(String status) => switch (status) {
    'stopped' => 'Driver stopped',
    'installed' => 'Driver installed',
    'missing' => 'Driver missing',
    'unknown' => 'Driver status unknown',
    _ => 'Driver unavailable',
  };

  String _updateDetail(ZentorState state) {
    final update = state.updateInfo;
    if (state.updateStatus == UpdateStatus.updateAvailable && update != null) {
      return 'Avorax ${update.latestVersion} is available. Download, verify, and install it from inside Avorax.';
    }
    if (state.updateStatus == UpdateStatus.notConfigured) {
      return 'Update source not configured. Scanning still works offline.';
    }
    if (state.updateStatus == UpdateStatus.downloading ||
        state.updateStatus == UpdateStatus.verifying) {
      return state.updateStatus.label;
    }
    if (state.updateStatus == UpdateStatus.installing) {
      return 'Avorax Update Service is applying the verified update package.';
    }
    if (state.updateStatus == UpdateStatus.upToDate) {
      return 'Avorax ${state.currentAppVersion} is installed.';
    }
    if (state.updateStatus == UpdateStatus.failed) {
      return 'Could not check the Avorax update feed. Scanning still works offline.';
    }
    return 'Avorax installs signed .aup updates inside the app.';
  }
}

String _lastScanDetail(ScanReport report) {
  final base =
      '${report.filesScanned} files scanned, ${report.skippedFiles} skipped.';
  final message = report.message?.trim();
  if (message != null && message.isNotEmpty) {
    return '$base\n$message';
  }
  if (report.scanErrors.isNotEmpty) {
    return '$base\nScan completed with ${report.scanErrors.length} file error(s); skipped files were not reported clean.';
  }
  return base;
}
