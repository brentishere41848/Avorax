import 'package:flutter/material.dart';

import '../../../app/theme/zentor_colors.dart';
import '../update_models.dart';

class UpdateStatusRows extends StatelessWidget {
  const UpdateStatusRows({required this.model, super.key});

  final UpdateViewModel model;

  @override
  Widget build(BuildContext context) {
    final rows = <(String, String)>[
      ('Current version', model.currentVersion),
      ('Status', model.status.label),
      if (model.latestVersion != null) ('Latest version', model.latestVersion!),
      if (model.channel != null) ('Channel', model.channel!),
      if (model.packageName != null) ('Package', model.packageName!),
      ('Rollback', _rollbackLabel(model.rollbackSupported)),
      if (model.error != null) ('Last error', model.error!),
    ];
    return Wrap(
      spacing: 10,
      runSpacing: 10,
      children: [
        for (final row in rows)
          Container(
            constraints: const BoxConstraints(maxWidth: 420),
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: ZentorColors.elevatedSurface,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: ZentorColors.border),
            ),
            child: Text(
              '${row.$1}: ${row.$2}',
              style: const TextStyle(color: ZentorColors.textSecondary),
            ),
          ),
      ],
    );
  }
}

String _rollbackLabel(bool? supported) {
  if (supported == true) return 'Available';
  if (supported == false) return 'Unavailable';
  return 'Unknown';
}
