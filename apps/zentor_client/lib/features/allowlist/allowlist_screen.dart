import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_empty_state.dart';
import '../../shared/widgets/zentor_status_card.dart';
import '../update/update_mutation_guard.dart';

class AllowlistScreen extends ConsumerStatefulWidget {
  const AllowlistScreen({super.key});

  @override
  ConsumerState<AllowlistScreen> createState() => _AllowlistScreenState();
}

class _AllowlistScreenState extends ConsumerState<AllowlistScreen> {
  @override
  void initState() {
    super.initState();
    Future.microtask(
      () => ref
          .read(zentorControllerProvider.notifier)
          .unawaitedRefreshAllowlist(),
    );
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final configurationActionBusy =
        state.securitySettingsActionInFlight ||
        state.configurationResetInFlight;
    final updateMutationBusy = updateMutationOperationInProgress(state);
    final allowlistActionBusy =
        state.allowlistActionInFlight || configurationActionBusy;
    final allowlistMutationBusy = allowlistActionBusy || updateMutationBusy;
    final allowlistRefreshBusy = state.allowlistRefreshInFlight;
    final activeEntries = state.allowlist
        .where((entry) => entry.active)
        .toList();
    return ZentorPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  'Allowlist',
                  style: Theme.of(context).textTheme.headlineMedium,
                ),
              ),
              ZentorButton(
                label: allowlistRefreshBusy ? 'Refreshing' : 'Refresh',
                icon: Icons.refresh_outlined,
                secondary: true,
                onPressed: allowlistActionBusy || allowlistRefreshBusy
                    ? null
                    : controller.unawaitedRefreshAllowlist,
              ),
            ],
          ),
          const SizedBox(height: 8),
          const Text(
            'Allowlisted files will not be automatically quarantined. Only allowlist software you trust.',
            style: TextStyle(color: ZentorColors.warning, height: 1.45),
          ),
          const SizedBox(height: 20),
          if (activeEntries.isEmpty)
            const ZentorEmptyState(
              title: 'No allowlist entries',
              message:
                  'Avorax will never silently add an allowlist entry. Unsafe root folders are blocked by the local core.',
              icon: Icons.fact_check_outlined,
            )
          else
            for (final entry in activeEntries) ...[
              _AllowlistRow(
                entry: entry,
                onRemove: () => _confirmRemove(context, controller, entry),
                allowlistActionBusy: allowlistMutationBusy,
              ),
              const SizedBox(height: 12),
            ],
        ],
      ),
    );
  }

  Future<void> _confirmRemove(
    BuildContext context,
    ZentorController controller,
    AllowlistEntry entry,
  ) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Remove allowlist entry?'),
        content: Text(
          'Avorax will resume normal scan and quarantine policy for:\n${entry.path}',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await controller.removeAllowlistEntry(entry, confirmed: true);
    }
  }
}

class _AllowlistRow extends StatelessWidget {
  const _AllowlistRow({
    required this.entry,
    required this.onRemove,
    required this.allowlistActionBusy,
  });

  final AllowlistEntry entry;
  final VoidCallback onRemove;
  final bool allowlistActionBusy;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: ZentorColors.elevatedSurface,
        border: Border.all(color: ZentorColors.border),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(_icon(entry.type), color: ZentorColors.primaryAccent),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      entry.path,
                      style: Theme.of(context).textTheme.titleMedium,
                      overflow: TextOverflow.ellipsis,
                    ),
                    const SizedBox(height: 6),
                    Text(
                      '${entry.type.label} - ${entry.reason.isEmpty ? 'No reason recorded' : entry.reason}',
                      style: const TextStyle(color: ZentorColors.textSecondary),
                    ),
                    if (entry.sha256 != null && entry.sha256!.isNotEmpty) ...[
                      const SizedBox(height: 6),
                      Text(
                        entry.sha256!,
                        style: const TextStyle(
                          color: ZentorColors.textSecondary,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ],
                ),
              ),
              const SizedBox(width: 12),
              ZentorButton(
                label: 'Remove',
                icon: Icons.remove_circle_outline,
                secondary: true,
                onPressed: allowlistActionBusy ? null : onRemove,
              ),
            ],
          ),
        ],
      ),
    );
  }

  IconData _icon(AllowlistEntryType type) => switch (type) {
    AllowlistEntryType.folder => Icons.folder_outlined,
    AllowlistEntryType.hash => Icons.tag_outlined,
    AllowlistEntryType.app ||
    AllowlistEntryType.executable => Icons.apps_outlined,
    AllowlistEntryType.file => Icons.insert_drive_file_outlined,
  };
}
