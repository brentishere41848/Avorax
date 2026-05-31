import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_loading_state.dart';
import '../../shared/widgets/zentor_metric_card.dart';
import '../../shared/widgets/zentor_status_card.dart';

class DeviceScreen extends ConsumerWidget {
  const DeviceScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final summary = ref.watch(deviceSummaryProvider);
    return summary.when(
      loading: () =>
          const ZentorLoadingState(message: 'Reading platform info...'),
      error: (error, _) => ZentorMetricCard(
        title: 'Device & Protection Health',
        value: 'Unable to read platform info',
        detail: '$error',
        icon: Icons.error_outline,
      ),
      data: (value) => LayoutBuilder(
        builder: (context, constraints) {
          final state = ref.watch(zentorControllerProvider);
          final cards = [
            ZentorMetricCard(
              title: 'System',
              value: value.platform,
              detail: value.osVersion,
              icon: Icons.devices_outlined,
            ),
            ZentorMetricCard(
              title: 'App version',
              value: value.appVersion,
              icon: Icons.info_outline,
            ),
            ZentorMetricCard(
              title: 'Privacy',
              value: value.deviceIdentifierHashStatus,
              detail:
                  'Raw identifiers are not stored. Cloud is optional; file upload is disabled unless the user consents.',
              icon: Icons.fingerprint,
            ),
            ZentorMetricCard(
              title: 'Avorax Services',
              value: value.localCoreStatus,
              detail:
                  'Guard Service: ${_serviceLabel(state.guardStatus)}. Last heartbeat is local-only in this build.',
              icon: Icons.memory_outlined,
            ),
            ZentorMetricCard(
              title: 'Avorax Native Engine',
              value: state.nativeEngineStatus == 'ready'
                  ? 'Ready'
                  : 'Unavailable',
              detail:
                  '${state.nativeSignatureCount} signatures, ${state.nativeRuleCount} rules. Native ML: ${_mlLabel(state.nativeMlStatus)}.',
              icon: Icons.health_and_safety_outlined,
            ),
            ZentorMetricCard(
              title: 'Real-time Protection',
              value: _serviceLabel(state.guardStatus),
              detail:
                  'Driver: ${_driverLabel(state.driverStatus)}. Pre-execution blocking is active only after driver self-test passes.',
              icon: Icons.security_outlined,
            ),
            ZentorMetricCard(
              title: 'Permissions',
              value: value.permissionsStatus,
              detail:
                  'Admin or elevated status is reported by service self-tests when available.',
              icon: Icons.lock_outline,
            ),
          ];
          final header = ZentorPanel(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Device & Protection Health',
                  style: Theme.of(context).textTheme.headlineMedium,
                ),
                const SizedBox(height: 8),
                const Text(
                  'Local system details, Avorax service readiness, native engine state, real-time protection, and privacy posture.',
                  style: TextStyle(
                    color: ZentorColors.textSecondary,
                    height: 1.45,
                  ),
                ),
              ],
            ),
          );
          if (constraints.maxWidth < 900) {
            return Column(
              children: [
                header,
                const SizedBox(height: 12),
                for (final card in cards) ...[card, const SizedBox(height: 12)],
              ],
            );
          }
          return Column(
            children: [
              header,
              const SizedBox(height: 16),
              GridView.count(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                crossAxisCount: 2,
                childAspectRatio: 2.45,
                mainAxisSpacing: 16,
                crossAxisSpacing: 16,
                children: cards,
              ),
            ],
          );
        },
      ),
    );
  }
}

String _serviceLabel(String status) => switch (status) {
  'running' => 'Running',
  'stopped' => 'Not running',
  'installed' => 'Installed',
  'monitorOnly' => 'Monitor only',
  'blockConfirmedThreats' => 'Block confirmed threats',
  _ => 'Not running',
};

String _driverLabel(String status) => switch (status) {
  'running' => 'Running',
  'selfTestPassed' => 'Self-test passed',
  'inactive' => 'Inactive',
  _ => 'Missing',
};

String _mlLabel(String status) => switch (status) {
  'active' => 'Production',
  'developmentModel' => 'Development',
  'modelMissing' => 'Missing',
  _ => 'Unavailable',
};
