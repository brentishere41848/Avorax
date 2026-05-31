import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

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
    return ZentorPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  'Local events',
                  style: Theme.of(context).textTheme.headlineMedium,
                ),
              ),
              ZentorButton(
                label: 'Export logs',
                icon: Icons.download_outlined,
                secondary: true,
                onPressed: () async {
                  final path = await controller.exportLogs();
                  if (context.mounted && path != null) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(content: Text('Logs exported to $path')),
                    );
                  }
                },
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
                            '${event.type} â€¢ ${event.createdAt.toLocal()}${event.details == null ? '' : ' â€¢ ${event.details}'}',
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
