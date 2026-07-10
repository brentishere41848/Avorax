import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_empty_state.dart';
import '../../shared/widgets/zentor_status_card.dart';
import '../update/update_mutation_guard.dart';

class QuarantineScreen extends ConsumerWidget {
  const QuarantineScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final configurationActionBusy =
        state.securitySettingsActionInFlight ||
        state.configurationResetInFlight;
    final updateMutationBusy = updateMutationOperationInProgress(state);
    final quarantineActionBusy =
        state.quarantineActionInFlight || configurationActionBusy;
    final quarantineMutationBusy = quarantineActionBusy || updateMutationBusy;
    final scanOriginalPathBusy = quarantineMutationBusy;
    final quarantineRefreshBusy = state.quarantineRefreshInFlight;
    return ZentorPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            spacing: 8,
            runSpacing: 8,
            crossAxisAlignment: WrapCrossAlignment.center,
            children: [
              Text(
                'Quarantine',
                style: Theme.of(context).textTheme.headlineMedium,
              ),
              ZentorButton(
                label: state.scanTargetSelectionInFlight
                    ? 'Choosing file'
                    : 'Quarantine file',
                icon: Icons.add_box_outlined,
                secondary: true,
                onPressed:
                    quarantineMutationBusy ||
                        state.scanTargetSelectionInFlight ||
                        state.scanStartInFlight ||
                        state.scanStatus == ScanStatus.running
                    ? null
                    : () async {
                        final confirmed = await _confirmQuarantineAction(
                          context,
                          title: 'Quarantine selected file?',
                          message:
                              'Avorax will ask you to choose one file, then move that file into isolated quarantine storage. Only quarantine files you intend to isolate.',
                          confirmLabel: 'Choose file',
                          destructive: true,
                        );
                        if (!confirmed) return;
                        await controller.quarantineSelectedFile(
                          confirmed: true,
                        );
                      },
              ),
              ZentorButton(
                label: quarantineRefreshBusy ? 'Refreshing' : 'Refresh',
                icon: Icons.refresh,
                secondary: true,
                onPressed: quarantineActionBusy || quarantineRefreshBusy
                    ? null
                    : controller.unawaitedRefreshQuarantine,
              ),
            ],
          ),
          const SizedBox(height: 8),
          const Text(
            'Quarantined files are isolated and renamed by the local core. Delete and restore actions require explicit user choice.',
            style: TextStyle(color: ZentorColors.textSecondary),
          ),
          const SizedBox(height: 20),
          if (state.quarantine.isEmpty)
            const ZentorEmptyState(
              title: 'No quarantined files',
              message:
                  'Avorax only lists files actually quarantined by the local core.',
              icon: Icons.inventory_2_outlined,
            )
          else
            for (final item in state.quarantine)
              Container(
                margin: const EdgeInsets.only(bottom: 14),
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: ZentorColors.elevatedSurface,
                  borderRadius: BorderRadius.circular(18),
                  border: Border.all(color: ZentorColors.border),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(
                        Icons.warning_amber,
                        color: ZentorColors.warning,
                      ),
                      title: Text(item.detectionName),
                      subtitle: Text(
                        '${item.originalPath}\n${item.sha256}',
                        style: const TextStyle(
                          color: ZentorColors.textSecondary,
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                      trailing: Text(item.status.label),
                    ),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        _MetaChip('Source', _sourceLabel(item.source)),
                        _MetaChip('Action', item.actionTaken),
                        _MetaChip(
                          'Pre-exec',
                          item.blockedBeforeExecution ? 'yes' : 'no',
                        ),
                        _MetaChip(
                          'Process',
                          item.processStarted ? 'started' : 'not started',
                        ),
                      ],
                    ),
                    const SizedBox(height: 12),
                    Wrap(
                      spacing: 10,
                      runSpacing: 10,
                      children: [
                        ZentorButton(
                          label: 'Restore / Keep',
                          icon: Icons.restore_outlined,
                          secondary: true,
                          onPressed:
                              item.status == QuarantineItemStatus.quarantined &&
                                  !quarantineMutationBusy
                              ? () async {
                                  final confirmed = await _confirmQuarantineAction(
                                    context,
                                    title: 'Restore quarantined file?',
                                    message:
                                        'Avorax will move this file back to its original location when possible. Only restore files you trust.',
                                    confirmLabel: 'Restore file',
                                  );
                                  if (!confirmed) return;
                                  await controller.restoreQuarantineItem(
                                    item,
                                    confirmed: true,
                                  );
                                }
                              : null,
                        ),
                        ZentorButton(
                          label: 'Delete permanently',
                          icon: Icons.delete_outline,
                          secondary: true,
                          onPressed:
                              item.status == QuarantineItemStatus.quarantined &&
                                  !quarantineMutationBusy
                              ? () async {
                                  final confirmed = await _confirmQuarantineAction(
                                    context,
                                    title:
                                        'Delete quarantined file permanently?',
                                    message:
                                        'This permanently deletes the isolated quarantine payload. This cannot be undone by Avorax.',
                                    confirmLabel: 'Delete permanently',
                                    destructive: true,
                                  );
                                  if (!confirmed) return;
                                  await controller.deleteQuarantineItem(
                                    item,
                                    confirmed: true,
                                  );
                                }
                              : null,
                        ),
                        if (item.status != QuarantineItemStatus.quarantined)
                          ZentorButton(
                            label: 'Scan original path',
                            icon: Icons.manage_search_outlined,
                            secondary: true,
                            onPressed: scanOriginalPathBusy
                                ? null
                                : () =>
                                      controller.rescanQuarantineOriginal(item),
                          ),
                        const _MetaChip('Default', 'kept isolated'),
                      ],
                    ),
                  ],
                ),
              ),
          if (state.errorMessage != null) ...[
            const SizedBox(height: 12),
            Text(
              state.errorMessage!,
              style: const TextStyle(color: ZentorColors.warning),
            ),
          ],
        ],
      ),
    );
  }
}

Future<bool> _confirmQuarantineAction(
  BuildContext context, {
  required String title,
  required String message,
  required String confirmLabel,
  bool destructive = false,
}) async {
  final result = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: Text(title),
      content: Text(message),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          style: destructive
              ? FilledButton.styleFrom(backgroundColor: ZentorColors.danger)
              : null,
          onPressed: () => Navigator.of(context).pop(true),
          child: Text(confirmLabel),
        ),
      ],
    ),
  );
  return result ?? false;
}

class _MetaChip extends StatelessWidget {
  const _MetaChip(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: ZentorColors.surface,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: ZentorColors.border),
      ),
      child: Text(
        '$label: $value',
        style: const TextStyle(color: ZentorColors.textSecondary, fontSize: 12),
      ),
    );
  }
}

String _sourceLabel(String source) => switch (source) {
  'scanner' => 'Scanner',
  'guard_service' => 'Guard Service',
  'minifilter_driver' => 'Minifilter Driver',
  'process_guard' => 'Process Guard',
  _ => 'Unknown source',
};
