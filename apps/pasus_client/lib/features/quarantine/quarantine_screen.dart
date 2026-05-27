import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:pasus_protocol/pasus_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/pasus_colors.dart';
import '../../shared/widgets/pasus_button.dart';
import '../../shared/widgets/pasus_empty_state.dart';
import '../../shared/widgets/pasus_status_card.dart';

class QuarantineScreen extends ConsumerWidget {
  const QuarantineScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(pasusControllerProvider);
    final controller = ref.read(pasusControllerProvider.notifier);
    return PasusPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  'Quarantine',
                  style: Theme.of(context).textTheme.headlineMedium,
                ),
              ),
              PasusButton(
                label: 'Refresh',
                icon: Icons.refresh,
                secondary: true,
                onPressed: controller.unawaitedRefreshQuarantine,
              ),
            ],
          ),
          const SizedBox(height: 8),
          const Text(
            'Quarantined files are isolated and renamed by the local core. Delete and restore actions require explicit user choice.',
            style: TextStyle(color: PasusColors.textSecondary),
          ),
          const SizedBox(height: 20),
          if (state.quarantine.isEmpty)
            const PasusEmptyState(
              title: 'No quarantined files',
              message:
                  'Pasus only lists files actually quarantined by the local core.',
              icon: Icons.inventory_2_outlined,
            )
          else
            for (final item in state.quarantine)
              Container(
                margin: const EdgeInsets.only(bottom: 14),
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: PasusColors.elevatedSurface,
                  borderRadius: BorderRadius.circular(18),
                  border: Border.all(color: PasusColors.border),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    ListTile(
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(
                        Icons.warning_amber,
                        color: PasusColors.warning,
                      ),
                      title: Text(item.detectionName),
                      subtitle: Text(
                        '${item.originalPath}\n${item.sha256}',
                        style: const TextStyle(
                          color: PasusColors.textSecondary,
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
                        PasusButton(
                          label: 'Restore / Keep',
                          icon: Icons.restore_outlined,
                          secondary: true,
                          onPressed:
                              item.status == QuarantineItemStatus.quarantined
                              ? () => controller.restoreQuarantineItem(item)
                              : null,
                        ),
                        PasusButton(
                          label: 'Delete permanently',
                          icon: Icons.delete_outline,
                          secondary: true,
                          onPressed:
                              item.status == QuarantineItemStatus.quarantined
                              ? () => controller.deleteQuarantineItem(item)
                              : null,
                        ),
                        PasusButton(
                          label: 'Keep quarantined',
                          icon: Icons.inventory_2_outlined,
                          secondary: true,
                          onPressed: null,
                        ),
                      ],
                    ),
                  ],
                ),
              ),
          if (state.errorMessage != null) ...[
            const SizedBox(height: 12),
            Text(
              state.errorMessage!,
              style: const TextStyle(color: PasusColors.warning),
            ),
          ],
        ],
      ),
    );
  }
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
        color: PasusColors.surface,
        borderRadius: BorderRadius.circular(999),
        border: Border.all(color: PasusColors.border),
      ),
      child: Text(
        '$label: $value',
        style: const TextStyle(color: PasusColors.textSecondary, fontSize: 12),
      ),
    );
  }
}

String _sourceLabel(String source) => switch (source) {
  'guard_service' => 'Guard Service',
  'minifilter_driver' => 'Minifilter Driver',
  'process_guard' => 'Process Guard',
  _ => 'Scanner',
};
