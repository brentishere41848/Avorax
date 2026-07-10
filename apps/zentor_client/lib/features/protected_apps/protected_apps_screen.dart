import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_empty_state.dart';
import '../../shared/widgets/zentor_status_card.dart';
import '../update/update_mutation_guard.dart';

class ProtectedAppsScreen extends ConsumerWidget {
  const ProtectedAppsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final autoDetectionSupported = ref
        .watch(appDetectorProvider)
        .supportsAutomaticDetection;
    final selected = state.config.protectedAppConfig;
    final protectedAppActionBusy = state.protectedAppActionInFlight;
    final protectedAppMutationBusy =
        protectedAppActionBusy || updateMutationOperationInProgress(state);
    final appDetectionBusy = state.appDetectionInFlight;
    final processSnapshotEvent = _latestProcessSnapshotEvent(state.events);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ZentorPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Advanced App Control',
                style: Theme.of(context).textTheme.headlineMedium,
              ),
              const SizedBox(height: 8),
              const Text(
                'Optional legacy app allowlisting tools. Antivirus scanning and quarantine do not require this setup.',
                style: TextStyle(color: ZentorColors.textSecondary),
              ),
              const SizedBox(height: 18),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  ZentorButton(
                    label: appDetectionBusy ? 'Rescanning' : 'Rescan',
                    icon: Icons.refresh,
                    secondary: true,
                    onPressed: autoDetectionSupported && !appDetectionBusy
                        ? controller.unawaitedDetectApps
                        : null,
                  ),
                  ZentorButton(
                    label: 'Add file or app',
                    icon: Icons.file_open_outlined,
                    secondary: true,
                    onPressed: protectedAppMutationBusy
                        ? null
                        : () => _confirmManualProtectedApp(
                            context,
                            controller,
                            folder: false,
                          ),
                  ),
                  ZentorButton(
                    label: 'Add folder',
                    icon: Icons.folder_open_outlined,
                    secondary: true,
                    onPressed: protectedAppMutationBusy
                        ? null
                        : () => _confirmManualProtectedApp(
                            context,
                            controller,
                            folder: true,
                          ),
                  ),
                  ZentorButton(
                    label: 'Calculate build hash',
                    icon: Icons.tag_outlined,
                    onPressed:
                        selected.isConfigured && !protectedAppMutationBusy
                        ? () => _confirmCalculateProtectedAppHash(
                            context,
                            controller,
                          )
                        : null,
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        ZentorPanel(
          child: _ProcessSnapshotEvidence(event: processSnapshotEvent),
        ),
        const SizedBox(height: 16),
        ZentorPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Selected protected app',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 14),
              if (!selected.isConfigured)
                const ZentorEmptyState(
                  title: 'No protected app selected',
                  message:
                      'Application protection is optional. Start a supported app or add one manually when needed.',
                  icon: Icons.apps_outlined,
                )
              else
                _AppRow(
                  title: selected.appName,
                  path: selected.appPath,
                  source: selected.source.isEmpty ? 'Manual' : selected.source,
                  profile: selected.protectionProfile,
                  trailing: selected.lastCalculatedHash.isEmpty
                      ? 'Build not verified'
                      : selected.lastCalculatedHash,
                ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        ZentorPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Auto-detected apps',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 14),
              if (state.detectedApps.isEmpty)
                ZentorEmptyState(
                  title: 'No supported app detected',
                  message: autoDetectionSupported
                      ? 'Avorax found no supported apps in known launcher metadata or running processes.'
                      : 'Automatic app detection has no configured supported-app registry. '
                            'Add a file or folder manually when needed.',
                  icon: Icons.search_off_outlined,
                )
              else
                for (final app in state.detectedApps)
                  _AppRow(
                    title: app.displayName,
                    path: app.path,
                    source: app.source,
                    profile: app.protectionProfile,
                    trailing: 'Select',
                    onTap: protectedAppMutationBusy
                        ? null
                        : () => _confirmSelectDetectedApp(
                            context,
                            controller,
                            app,
                          ),
                  ),
            ],
          ),
        ),
      ],
    );
  }
}

LocalEvent? _latestProcessSnapshotEvent(List<LocalEvent> events) {
  LocalEvent? latest;
  for (final event in events) {
    if (!_processSnapshotEventTypes.contains(event.type)) continue;
    if (latest == null || event.createdAt.isAfter(latest.createdAt)) {
      latest = event;
    }
  }
  return latest;
}

const _processSnapshotEventTypes = {
  'process_snapshot_evaluated',
  'process_snapshot_suspicious',
  'process_snapshot_empty',
  'process_snapshot_failed',
  'process_snapshot_loop_evaluated',
  'process_snapshot_loop_suspicious',
  'process_snapshot_loop_empty',
  'process_snapshot_loop_failed',
};

class _ProcessSnapshotEvidence extends StatelessWidget {
  const _ProcessSnapshotEvidence({required this.event});

  final LocalEvent? event;

  @override
  Widget build(BuildContext context) {
    final event = this.event;
    final color = _processSnapshotColor(event);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            const Icon(
              Icons.manage_search_outlined,
              color: ZentorColors.primaryAccent,
            ),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                'Process snapshot evidence',
                style: Theme.of(context).textTheme.titleLarge,
              ),
            ),
            ZentorStatusPill(
              label: _processSnapshotLabel(event),
              color: color,
              icon: _processSnapshotIcon(event),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Text(
          event == null
              ? 'No process snapshot has been evaluated during app detection or active protection in this local event history.'
              : event.message,
          style: const TextStyle(color: ZentorColors.textSecondary),
        ),
        if (event != null) ...[
          const SizedBox(height: 8),
          Text(
            _processSnapshotTimestampLabel(event),
            style: const TextStyle(color: ZentorColors.textSecondary),
          ),
        ],
        if (event?.details != null && event!.details!.isNotEmpty) ...[
          const SizedBox(height: 8),
          Text(
            event.details!,
            maxLines: 3,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(color: ZentorColors.textSecondary),
          ),
        ],
      ],
    );
  }
}

String _processSnapshotLabel(LocalEvent? event) => switch (event?.type) {
  'process_snapshot_suspicious' => 'Suspicious',
  'process_snapshot_loop_suspicious' => 'Suspicious',
  'process_snapshot_evaluated' => 'Evaluated',
  'process_snapshot_loop_evaluated' => 'Evaluated',
  'process_snapshot_empty' => 'No observations',
  'process_snapshot_loop_empty' => 'No observations',
  'process_snapshot_failed' => 'Failed',
  'process_snapshot_loop_failed' => 'Failed',
  _ => 'Not evaluated',
};

String _processSnapshotTimestampLabel(LocalEvent event) =>
    'Evidence time (UTC): ${event.createdAt.toUtc().toIso8601String()}';

Color _processSnapshotColor(LocalEvent? event) => switch (event?.severity) {
  'error' => ZentorColors.danger,
  'warning' => ZentorColors.warning,
  'info' => ZentorColors.success,
  _ => ZentorColors.textSecondary,
};

IconData _processSnapshotIcon(LocalEvent? event) => switch (event?.type) {
  'process_snapshot_suspicious' => Icons.warning_amber_rounded,
  'process_snapshot_loop_suspicious' => Icons.warning_amber_rounded,
  'process_snapshot_evaluated' => Icons.check_circle_outline,
  'process_snapshot_loop_evaluated' => Icons.check_circle_outline,
  'process_snapshot_empty' => Icons.info_outline,
  'process_snapshot_loop_empty' => Icons.info_outline,
  'process_snapshot_failed' => Icons.error_outline,
  'process_snapshot_loop_failed' => Icons.error_outline,
  _ => Icons.hourglass_empty,
};

Future<void> _confirmCalculateProtectedAppHash(
  BuildContext context,
  ZentorController controller,
) async {
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Calculate build hash?'),
      content: const Text(
        'This reads the selected file and saves its SHA-256 as local verification evidence. It can mark the selected protected app as verified when no expected build hash is configured.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Calculate'),
        ),
      ],
    ),
  );
  if (confirmed != true) return;
  final saved = await controller.calculateProtectedAppHash(confirmed: true);
  if (!context.mounted) return;
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text(
        saved
            ? 'Build hash calculated.'
            : 'Unable to calculate build hash. See the error banner.',
      ),
    ),
  );
}

Future<void> _confirmManualProtectedApp(
  BuildContext context,
  ZentorController controller, {
  required bool folder,
}) async {
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: Text(folder ? 'Add protected folder?' : 'Add protected app file?'),
      content: Text(
        folder
            ? 'This changes the protected app configuration and scan scope. After confirming, choose the exact folder in the system picker.'
            : 'This changes the protected app configuration and scan scope. After confirming, choose the exact file or app in the system picker.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Continue'),
        ),
      ],
    ),
  );
  if (confirmed != true) return;
  final saved = folder
      ? await controller.addManualProtectedAppFolder(confirmed: true)
      : await controller.addManualProtectedAppFile(confirmed: true);
  if (!context.mounted) return;
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text(
        saved
            ? 'Protected app selection saved.'
            : 'No protected app selection was saved.',
      ),
    ),
  );
}

Future<void> _confirmSelectDetectedApp(
  BuildContext context,
  ZentorController controller,
  DetectedApp app,
) async {
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Select protected app?'),
      content: Text(
        'This changes the selected protected app and adds its path to the scan scope.\n\n${app.displayName}\n${app.path}',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Select'),
        ),
      ],
    ),
  );
  if (confirmed != true) return;
  final saved = await controller.selectDetectedApp(app, confirmed: true);
  if (!context.mounted) return;
  ScaffoldMessenger.of(context).showSnackBar(
    SnackBar(
      content: Text(
        saved
            ? 'Protected app selected.'
            : 'Unable to select protected app. See the error banner.',
      ),
    ),
  );
}

class _AppRow extends StatelessWidget {
  const _AppRow({
    required this.title,
    required this.path,
    required this.source,
    required this.profile,
    required this.trailing,
    this.onTap,
  });

  final String title;
  final String path;
  final String source;
  final String profile;
  final String trailing;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    return Material(
      type: MaterialType.transparency,
      child: ListTile(
        contentPadding: EdgeInsets.zero,
        onTap: onTap,
        leading: const Icon(
          Icons.apps_outlined,
          color: ZentorColors.primaryAccent,
        ),
        title: Text(title),
        subtitle: Text(
          '$source - $profile\n$path',
          style: const TextStyle(color: ZentorColors.textSecondary),
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
        ),
        trailing: SizedBox(
          width: 180,
          child: Text(
            trailing,
            textAlign: TextAlign.end,
            style: const TextStyle(color: ZentorColors.textSecondary),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ),
      ),
    );
  }
}
