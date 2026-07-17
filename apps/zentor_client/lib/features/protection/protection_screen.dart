import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../core/local_core/local_core_client.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_metric_card.dart';
import '../../shared/widgets/zentor_status_card.dart';
import '../update/update_mutation_guard.dart';
import 'protection_confirmation.dart';

class ProtectionScreen extends ConsumerWidget {
  const ProtectionScreen({super.key});

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
                    label: _startProtectionButtonLabel(state.protectionStatus),
                    icon: Icons.play_arrow_rounded,
                    onPressed:
                        state.loading ||
                            protectionSelfTestBusy ||
                            protectionOperationBusy ||
                            updateMutationBusy ||
                            (state.protectionStatus != ProtectionStatus.idle &&
                                state.protectionStatus !=
                                    ProtectionStatus.error)
                        ? null
                        : () async {
                            if (!await confirmStartProtection(context)) return;
                            await controller.startProtection(confirmed: true);
                          },
                  ),
                  ZentorButton(
                    label: 'Stop Protection',
                    icon: Icons.stop_rounded,
                    secondary: true,
                    onPressed:
                        state.protectionStatus == ProtectionStatus.idle ||
                            protectionOperationBusy ||
                            protectionSelfTestBusy ||
                            updateMutationBusy
                        ? null
                        : () async {
                            if (!await confirmStopProtection(context)) return;
                            await controller.stopProtection(confirmed: true);
                          },
                  ),
                  ZentorButton(
                    label: protectionSelfTestBusy
                        ? 'Running self-test...'
                        : 'Run protection self-test',
                    icon: Icons.health_and_safety_outlined,
                    secondary: true,
                    onPressed:
                        state.loading ||
                            protectionOperationBusy ||
                            protectionSelfTestBusy ||
                            updateMutationBusy
                        ? null
                        : controller.runProtectionSelfTest,
                  ),
                  ZentorButton(
                    label: 'Run Quick Scan',
                    icon: Icons.radar_outlined,
                    secondary: true,
                    onPressed: scanStartBusy
                        ? null
                        : () => controller.runQuickScan(
                            actionMode: ScanActionMode.detectOnly,
                          ),
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
                detail: _serviceProtectionDetail(state),
                icon: Icons.shield_outlined,
              ),
              ZentorMetricCard(
                title: 'User-mode monitor',
                value: _watcherLabel(state.realtimeWatcherMode),
                detail: state.realtimeWatchedPaths.isEmpty
                    ? 'Best-effort folder monitoring is off. Manual scans and quarantine remain available.'
                    : _watcherDetail(state),
                icon: Icons.folder_special_outlined,
              ),
              ZentorMetricCard(
                title: 'Process monitors',
                value:
                    '${_monitorStatusLabel(state.processMonitorStatus)} / ${_monitorStatusLabel(state.behaviorMonitorStatus)}',
                detail: _monitorDetail(state),
                icon: Icons.manage_search_outlined,
              ),
              ZentorMetricCard(
                title: 'Guard Service',
                value: _guardLabel(state.guardStatus),
                detail: _guardServiceDetail(state),
                icon: Icons.security_outlined,
              ),
              ZentorMetricCard(
                title: 'Pre-execution blocking',
                value: _preExecutionDriverValue(state.driverStatus),
                detail: state.driverStatus == 'running'
                    ? 'Driver-assisted blocking can be used for verdict requests.'
                    : 'Current release uses post-launch user-mode stopping when confirmed threats are observed.',
                icon: Icons.block_outlined,
              ),
              ZentorMetricCard(
                title: 'Avorax Native Engine',
                value: _nativeEngineChecklistLabel(state),
                detail: _nativeEngineProtectionDetail(state),
                icon: Icons.health_and_safety_outlined,
              ),
              ZentorMetricCard(
                title: 'Native rules',
                value: _nativeRuleCountLabel(state),
                detail:
                    'Avorax-owned rules supplement native signatures, ML, and heuristic analysis.',
                icon: Icons.rule_folder_outlined,
              ),
              ZentorMetricCard(
                title: 'Reputation',
                value: _reputationLabel(state.reputationStatus),
                detail: _reputationDetail(state),
                icon: Icons.travel_explore_outlined,
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
      _CheckRow('Native Engine', _nativeEngineChecklistLabel(state)),
      _CheckRow(
        'Signature Pack',
        _nativePackCountLabel(count: state.nativeSignatureCount, state: state),
      ),
      _CheckRow(
        'Rule Pack',
        _nativePackCountLabel(count: state.nativeRuleCount, state: state),
      ),
      _CheckRow('Quarantine', _quarantineReadinessLabel(state)),
      _CheckRow('Core Service', _serviceLabel(state.coreServiceStatus)),
      _CheckRow(
        'Core Service IPC',
        _serviceBoundaryLabel(state.coreServiceBoundaryHealth),
      ),
      _CheckRow('Guard Service', _guardLabel(state.guardStatus)),
      _CheckRow(
        'Process Monitor',
        _monitorStatusLabel(state.processMonitorStatus),
      ),
      _CheckRow(
        'Behavior Monitor',
        _monitorStatusLabel(state.behaviorMonitorStatus),
      ),
      _CheckRow('Pre-execution Driver', _driverLabel(state.driverStatus)),
      _CheckRow('Local AI', _localAiLabel(state.aiStatus)),
      _CheckRow('Reputation', _reputationLabel(state.reputationStatus)),
      const _CheckRow('Cloud', 'Disabled, optional'),
    ];
    return LayoutBuilder(
      builder: (context, constraints) {
        final compact = constraints.maxWidth < 600;
        return Wrap(
          spacing: 10,
          runSpacing: 10,
          children: rows
              .map(
                (row) => Container(
                  width: compact ? constraints.maxWidth : null,
                  padding: const EdgeInsets.symmetric(
                    horizontal: 12,
                    vertical: 10,
                  ),
                  decoration: BoxDecoration(
                    color: ZentorColors.elevatedSurface,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: ZentorColors.border),
                  ),
                  child: compact
                      ? Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              row.label,
                              style: Theme.of(context).textTheme.labelMedium,
                            ),
                            const SizedBox(height: 4),
                            Text(
                              row.value,
                              style: const TextStyle(
                                color: ZentorColors.textSecondary,
                              ),
                            ),
                          ],
                        )
                      : Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              row.label,
                              style: Theme.of(context).textTheme.labelMedium,
                            ),
                            const SizedBox(width: 8),
                            Text(
                              row.value,
                              style: const TextStyle(
                                color: ZentorColors.textSecondary,
                              ),
                            ),
                          ],
                        ),
                ),
              )
              .toList(),
        );
      },
    );
  }
}

class _CheckRow {
  const _CheckRow(this.label, this.value);

  final String label;
  final String value;
}

String _protectionExplanation(ZentorState state) {
  if (_protectionEngineNeedsAttention(state)) {
    return 'Action required: Avorax malware engine, native engine, or authenticated Core Service evidence is not ready. Avorax does not report files clean while local engine evidence is unavailable.';
  }
  if (state.protectionStatus == ProtectionStatus.protected) {
    return 'Local scans, quarantine workflows, Guard Service, native engine assets, and the authenticated Core Service boundary are available. Pre-execution blocking is shown as active only when the Windows driver is running and self-tested.';
  }
  if (state.nativeEngineStatus == 'ready' && state.driverStatus != 'running') {
    return 'Local scans are ready, and quarantine workflows remain available for confirmed detections. Real-time pre-execution blocking is not active because the Windows driver is not installed or has not passed self-test.';
  }
  return 'Avorax shows exactly which local protection components are ready, degraded, or unavailable. Cloud disabled is optional and does not reduce local scan protection.';
}

String _serviceProtectionDetail(ZentorState state) {
  final details = [
    state.protectionStatus == ProtectionStatus.localOnly
        ? 'Cloud is optional; local protection remains available.'
        : state.guardStatus == 'running'
        ? 'Avorax Guard Service is running. Confirmed threats can be stopped after launch.'
        : state.coreServiceStatus == 'running'
        ? 'Core service is running. Start Guard Service for background monitoring.'
        : 'Core/Guard services are not running. Manual scans and quarantine remain available.',
    if (state.coreServiceStatusError?.trim().isNotEmpty ?? false)
      'Core Service detail: ${state.coreServiceStatusError}',
    'Core Service IPC: ${_serviceBoundaryLabel(state.coreServiceBoundaryHealth)}',
    if (state.coreServiceBoundaryHealth.diagnostic?.trim().isNotEmpty ?? false)
      'Core Service IPC detail: ${state.coreServiceBoundaryHealth.diagnostic}',
    if (state.guardStatusError?.trim().isNotEmpty ?? false)
      'Guard Service detail: ${state.guardStatusError}',
  ];
  return details.join('\n');
}

String _guardServiceDetail(ZentorState state) {
  final details = [
    state.guardStatus == 'running'
        ? 'Background post-launch monitoring is active.'
        : 'Install/start the MSI service for background post-launch monitoring.',
    if (state.guardStatusError?.trim().isNotEmpty ?? false)
      'Guard Service detail: ${state.guardStatusError}',
  ];
  return details.join('\n');
}

bool _protectionEngineNeedsAttention(ZentorState state) {
  return state.malwareEngineStatus != MalwareEngineStatus.available ||
      state.nativeEngineStatus != 'ready' ||
      state.coreServiceBoundaryHealth.status ==
          CoreServiceBoundaryStatus.unavailable ||
      state.coreServiceBoundaryHealth.status ==
          CoreServiceBoundaryStatus.degraded ||
      (state.lastEngineError?.trim().isNotEmpty ?? false);
}

String _serviceBoundaryLabel(CoreServiceBoundaryHealth health) =>
    switch (health.status) {
      CoreServiceBoundaryStatus.notChecked => 'Not checked',
      CoreServiceBoundaryStatus.unsupported => 'Unsupported on this platform',
      CoreServiceBoundaryStatus.unavailable => 'Unavailable',
      CoreServiceBoundaryStatus.degraded =>
        'Authenticated; native engine degraded',
      CoreServiceBoundaryStatus.ready => 'Authenticated and ready',
    };

String _startProtectionButtonLabel(ProtectionStatus status) {
  if (status == ProtectionStatus.idle || status == ProtectionStatus.error) {
    return 'Enable Protection';
  }
  if (status == ProtectionStatus.partiallyProtected) return status.label;
  if (status == ProtectionStatus.protected ||
      status == ProtectionStatus.localOnly) {
    return 'Protection Enabled';
  }
  return status.label;
}

String _nativeEngineProtectionDetail(ZentorState state) {
  final engineDiagnostic = state.lastEngineError?.trim();
  final details = [
    if (engineDiagnostic != null && engineDiagnostic.isNotEmpty)
      'Engine diagnostic: $engineDiagnostic'
    else if (state.nativeEngineStatus == 'ready')
      'Primary offline scanner for native signatures, rules, ML, and heuristics.'
    else
      'Native engine assets are missing or failed to load.',
    if (state.nativeEngineError?.trim().isNotEmpty ?? false)
      'Native engine detail: ${state.nativeEngineError}',
    'Native self-test: ${_selfTestEvidenceLabel(state.nativeSelfTestPassed)}',
    if (state.nativeSelfTestError?.trim().isNotEmpty ?? false)
      'Native self-test detail: ${state.nativeSelfTestError}',
    'AI self-test: ${_selfTestEvidenceLabel(state.aiSelfTestPassed)}',
    if (state.aiSelfTestError?.trim().isNotEmpty ?? false)
      'AI self-test detail: ${state.aiSelfTestError}',
    if (state.programDataDirectoryError?.trim().isNotEmpty ?? false)
      'ProgramData root: ${state.programDataDirectoryError}',
  ];
  return details.join('\n');
}

String _selfTestEvidenceLabel(bool? passed) => switch (passed) {
  true => 'passed',
  false => 'failed',
  null => 'unknown',
};

String _nativeEngineChecklistLabel(ZentorState state) {
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

String _nativeRuleCountLabel(ZentorState state) {
  final engineDiagnosticVisible =
      state.lastEngineError?.trim().isNotEmpty ?? false;
  if (state.nativeRuleCount > 0 ||
      (state.nativeEngineStatus == 'ready' && !engineDiagnosticVisible)) {
    return '${state.nativeRuleCount} rules';
  }
  return 'Unknown';
}

String _nativePackCountLabel({required int count, required ZentorState state}) {
  final engineDiagnosticVisible =
      state.lastEngineError?.trim().isNotEmpty ?? false;
  if (count > 0 ||
      (state.nativeEngineStatus == 'ready' && !engineDiagnosticVisible)) {
    return '$count loaded';
  }
  return 'Unknown';
}

String _quarantineReadinessLabel(ZentorState state) {
  final engineDiagnosticVisible =
      state.lastEngineError?.trim().isNotEmpty ?? false;
  if (!engineDiagnosticVisible &&
      (state.malwareEngineStatus == MalwareEngineStatus.available ||
          state.nativeEngineStatus == 'ready')) {
    return 'Available';
  }
  return 'Unknown';
}

String _preExecutionDriverValue(String status) {
  if (status == 'running') return 'Driver active';
  return _driverLabel(status);
}

String _driverLabel(String status) => switch (status) {
  'running' => 'Running',
  'stopped' => 'Stopped',
  'installed' => 'Installed',
  'missing' => 'Missing',
  'unknown' => 'Unknown',
  _ => 'Unavailable',
};

String _watcherLabel(String mode) => switch (mode) {
  'userModeBestEffort' => 'Best-effort',
  'stopped' => 'Stopped',
  'off' => 'Off',
  'unknown' => 'Unknown',
  _ => 'Unavailable',
};

String _watcherDetail(ZentorState state) {
  final limits = state.realtimeWatcherLimitations.isEmpty
      ? ''
      : ' Limits: ${state.realtimeWatcherLimitations.join(', ')}.';
  final pollReason = state.watchPollLoopStatusReason?.trim();
  final pollDetail = [
    'Finite scan loop: ${_watchPollLoopStatusLabel(state.watchPollLoopStatus)}.',
    if (pollReason != null && pollReason.isNotEmpty) pollReason,
  ].join(' ');
  return 'Best-effort folder watch roots prepared for ${state.realtimeWatchedPaths.length} protected location(s). Local-core IPC validates roots only; finite user-mode polling is post-write detection only; persistent service monitoring and kernel pre-execution blocking are not claimed. $pollDetail$limits';
}

String _monitorStatusLabel(String status) => switch (status) {
  'active' => 'Active',
  'notActive' => 'Not active',
  'unavailable' => 'Unavailable',
  'unknown' => 'Unknown',
  'error' => 'Error',
  _ => 'Unavailable',
};

String _processSnapshotLoopStatusLabel(String status) => switch (status) {
  'active' => 'Active',
  'attention' => 'Attention',
  'limited' => 'Limited',
  'off' => 'Off',
  _ => 'Unknown',
};

String _watchPollLoopStatusLabel(String status) => switch (status) {
  'active' => 'Active',
  'attention' => 'Attention',
  'limited' => 'Limited',
  'off' => 'Off',
  _ => 'Unknown',
};

String _processCapabilityLabel(String capability) => switch (capability) {
  'userModePolling' => 'user-mode polling',
  'endpointSecurityWhenEntitled' => 'Endpoint Security entitlement',
  'fanotifyOrInotifyWhenAvailable' => 'fanotify/inotify',
  'unavailable' => 'unavailable',
  'unknown' => 'unknown',
  _ => 'unknown',
};

String _monitorDetail(ZentorState state) {
  final processReason = state.processMonitorStatusReason?.trim();
  final behaviorReason = state.behaviorMonitorStatusReason?.trim();
  final snapshotLoopReason = state.processSnapshotLoopStatusReason?.trim();
  final details = [
    'Process monitor: ${_monitorStatusLabel(state.processMonitorStatus)} (${_processCapabilityLabel(state.processMonitorCapability)}).',
    if (processReason != null && processReason.isNotEmpty)
      'Process reason: $processReason',
    'Behavior monitor: ${_monitorStatusLabel(state.behaviorMonitorStatus)}.',
    if (behaviorReason != null && behaviorReason.isNotEmpty)
      'Behavior reason: $behaviorReason',
    'App snapshot loop: ${_processSnapshotLoopStatusLabel(state.processSnapshotLoopStatus)}.',
    if (snapshotLoopReason != null && snapshotLoopReason.isNotEmpty)
      'Snapshot loop detail: $snapshotLoopReason',
  ];
  return details.join(' ');
}

String _reputationLabel(String status) => switch (status) {
  'available' => 'Available',
  'unavailable' => 'Unavailable',
  'disabled' => 'Disabled',
  'unknown' => 'Unknown',
  'error' => 'Error',
  _ => 'Unavailable',
};

String _reputationDetail(ZentorState state) {
  final reason = state.reputationStatusReason?.trim();
  if (reason != null && reason.isNotEmpty) return reason;
  if (state.reputationStatus == 'available') {
    return 'Reputation backend is configured.';
  }
  return 'No local or cloud reputation backend is configured.';
}

String _guardLabel(String status) => switch (status) {
  'running' => 'Running',
  'stopped' => 'Stopped',
  'missing' => 'Missing',
  'installed' => 'Installed',
  'unknown' => 'Unknown',
  'off' => 'Off',
  'monitorOnly' => 'Monitor only',
  'blockConfirmedThreats' => 'Block confirmed threats',
  'aggressive' => 'Aggressive',
  _ => 'Unavailable',
};

String _serviceLabel(String status) => switch (status) {
  'running' => 'Running',
  'installed' => 'Installed',
  'stopped' => 'Stopped',
  'missing' => 'Missing',
  'unknown' => 'Unknown',
  'unsupported' => 'Unsupported on this OS',
  'error' => 'Error',
  _ => 'Unavailable',
};

String _localAiLabel(AiModelStatus status) => switch (status) {
  AiModelStatus.active => 'Active',
  AiModelStatus.developmentModel => 'Development',
  AiModelStatus.modelMissing => 'Missing',
  AiModelStatus.error => 'Error',
};
