import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_empty_state.dart';
import '../../shared/widgets/zentor_status_card.dart';

class LogsScreen extends ConsumerWidget {
  const LogsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final logExportBusy = state.logExportInFlight;
    final supportBundleExportBusy = state.supportBundleExportInFlight;
    return ZentorPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            spacing: 12,
            runSpacing: 12,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              Text(
                'Local events',
                style: Theme.of(context).textTheme.headlineMedium,
              ),
              Wrap(
                spacing: 10,
                runSpacing: 10,
                children: [
                  ZentorButton(
                    label: logExportBusy ? 'Exporting logs' : 'Export logs',
                    icon: Icons.download_outlined,
                    secondary: true,
                    onPressed: logExportBusy
                        ? null
                        : () async {
                            if (!await _confirmExportLogs(context)) return;
                            final path = await controller.exportLogs(
                              confirmed: true,
                            );
                            if (context.mounted && path != null) {
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(
                                  content: Text('Logs exported to $path'),
                                ),
                              );
                            }
                          },
                  ),
                  ZentorButton(
                    label: supportBundleExportBusy
                        ? 'Exporting bundle'
                        : 'Export support bundle',
                    icon: Icons.inventory_2_outlined,
                    secondary: true,
                    onPressed: supportBundleExportBusy
                        ? null
                        : () async {
                            if (!await _confirmExportSupportBundle(context)) {
                              return;
                            }
                            final path = await controller.exportSupportBundle(
                              confirmed: true,
                            );
                            if (context.mounted && path != null) {
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(
                                  content: Text(
                                    'Support bundle exported to $path',
                                  ),
                                ),
                              );
                            }
                          },
                  ),
                ],
              ),
            ],
          ),
          const SizedBox(height: 18),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              _EventSummaryCard(
                label: 'Protection events',
                value: state.events
                    .where((event) => event.category == 'protection')
                    .length
                    .toString(),
                icon: Icons.shield_outlined,
              ),
              _EventSummaryCard(
                label: 'Warnings',
                value: state.events
                    .where((event) => event.severity == 'warning')
                    .length
                    .toString(),
                icon: Icons.warning_amber_outlined,
              ),
            ],
          ),
          const SizedBox(height: 18),
          if (state.events.isEmpty)
            const ZentorEmptyState(
              title: 'No local events',
              message: 'Avorax records only real local app actions here.',
              icon: Icons.receipt_long_outlined,
            )
          else
            for (final event in state.events)
              Container(
                margin: const EdgeInsets.only(bottom: 12),
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: ZentorColors.elevatedSurface,
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: ZentorColors.border),
                ),
                child: Row(
                  children: [
                    const Icon(
                      Icons.circle,
                      size: 10,
                      color: ZentorColors.primaryAccent,
                    ),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            event.message,
                            style: const TextStyle(fontWeight: FontWeight.w700),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            _eventDetail(event),
                            style: const TextStyle(
                              color: ZentorColors.textSecondary,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
        ],
      ),
    );
  }
}

Future<bool> _confirmExportLogs(BuildContext context) async {
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Export logs?'),
      content: const Text(
        'This writes local Avorax event history to a file. The export can include file paths, protection actions, update diagnostics, and error details.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Export'),
        ),
      ],
    ),
  );
  return confirmed == true;
}

Future<bool> _confirmExportSupportBundle(BuildContext context) async {
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Export support bundle?'),
      content: const Text(
        'This writes a local diagnostic JSON file with Avorax status summaries and event history. It does not include file contents or quarantine payloads, but events can include local paths and error details.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Export'),
        ),
      ],
    ),
  );
  return confirmed == true;
}

String _eventDetail(LocalEvent event) {
  final details = event.details == null ? '' : ' | ${event.details}';
  return '${event.category}/${event.severity} | ${event.type} | ${event.createdAt.toLocal()}$details';
}

class _EventSummaryCard extends StatelessWidget {
  const _EventSummaryCard({
    required this.label,
    required this.value,
    required this.icon,
  });

  final String label;
  final String value;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return Container(
      constraints: const BoxConstraints(minWidth: 190),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: ZentorColors.elevatedSurface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: ZentorColors.border),
      ),
      child: Row(
        children: [
          Icon(icon, color: ZentorColors.primaryAccent),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  value,
                  style: Theme.of(
                    context,
                  ).textTheme.titleLarge?.copyWith(fontWeight: FontWeight.w800),
                ),
                Text(
                  label,
                  style: const TextStyle(color: ZentorColors.textSecondary),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
