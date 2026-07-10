import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_loading_state.dart';
import '../../shared/widgets/zentor_metric_card.dart';
import '../../shared/widgets/zentor_status_card.dart';

const int _maxDeviceDiagnosticChars = 4096;

String _boundedDeviceDiagnostic(Object error) {
  final text = '$error'.replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ').trim();
  if (text.isEmpty) return 'unknown error';
  if (text.length <= _maxDeviceDiagnosticChars) return text;
  return '${text.substring(0, _maxDeviceDiagnosticChars - 3)}...';
}

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
        detail: _boundedDeviceDiagnostic(error),
        icon: Icons.error_outline,
      ),
      data: (value) => LayoutBuilder(
        builder: (context, constraints) {
          final state = ref.watch(zentorControllerProvider);
          final cards = [
            ZentorMetricCard(
              title: 'System',
              value: value.platform,
              detail: '${value.osVersion}\nHost: ${value.hostName}',
              icon: Icons.devices_outlined,
            ),
            ZentorMetricCard(
              title: 'Hardware',
              value: value.systemArchitecture,
              detail:
                  '${value.processorCount} logical CPU(s). Memory: ${value.totalPhysicalMemory}.',
              icon: Icons.developer_board_outlined,
            ),
            ZentorMetricCard(
              title: 'App version',
              value: value.appVersion,
              detail: 'Executable: ${_shortPath(value.executablePath)}',
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
              detail: _serviceDetails(value.serviceStates),
              icon: Icons.memory_outlined,
            ),
            ZentorMetricCard(
              title: 'Avorax Native Engine',
              value: _nativeEngineLabel(state),
              detail: _nativeEngineDetail(state),
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
              detail: 'Current user: ${value.userName}',
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
  'stopped' => 'Stopped',
  'missing' => 'Missing',
  'installed' => 'Installed',
  'unknown' => 'Unknown',
  'off' => 'Off',
  _ => 'Unavailable',
};

String _driverLabel(String status) => switch (status) {
  'running' => 'Running',
  'stopped' => 'Stopped',
  'installed' => 'Installed',
  'missing' => 'Missing',
  'unknown' => 'Unknown',
  _ => 'Unavailable',
};

String _mlLabel(String status) => switch (status) {
  'loaded' => 'Loaded',
  'developmentModel' => 'Development',
  'modelMissing' => 'Missing',
  'error' => 'Error',
  _ => 'Unavailable',
};

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
  final details = [
    if (diagnostic != null && diagnostic.isNotEmpty)
      'Engine diagnostic: $diagnostic',
    '${state.nativeSignatureCount} signatures, ${state.nativeRuleCount} rules. Native ML: ${_mlLabel(state.nativeMlStatus)}.',
    'Native ML production-ready: ${state.nativeMlProductionReady ? 'yes' : 'no'}.',
    if (state.nativeSelfTestError?.trim().isNotEmpty ?? false)
      'Native self-test: ${state.nativeSelfTestError}',
    if (state.aiSelfTestError?.trim().isNotEmpty ?? false)
      'AI self-test: ${state.aiSelfTestError}',
  ];
  return details.join('\n');
}

String _serviceDetails(Map<String, String> states) {
  if (states.isEmpty) {
    return 'No Avorax Windows service information was returned.';
  }
  final warnings = states['avorax_service_probe_warnings']?.trim();
  return [
    'Core: ${_serviceState(states, 'avorax_core_service')}',
    'Guard: ${_serviceState(states, 'avorax_guard_service')}',
    'Update: ${_serviceState(states, 'avorax_update_service')}',
    if (warnings != null && warnings.isNotEmpty) 'Probe warnings: $warnings',
  ].join('\n');
}

String _serviceState(Map<String, String> states, String name) {
  final state = states[name]?.trim();
  if (state == null || state.isEmpty) {
    return 'unknown; service evidence missing';
  }
  return state;
}

String _shortPath(String path) {
  if (path.length <= 80) return path;
  return '...${path.substring(path.length - 77)}';
}
