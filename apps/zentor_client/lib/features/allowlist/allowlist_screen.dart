import 'package:flutter/material.dart';

import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_empty_state.dart';
import '../../shared/widgets/zentor_status_card.dart';

class AllowlistScreen extends StatelessWidget {
  const AllowlistScreen({super.key});

  @override
  Widget build(BuildContext context) {
    return ZentorPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Allowlist', style: Theme.of(context).textTheme.headlineMedium),
          const SizedBox(height: 8),
          const Text(
            'Allowlisted files will not be automatically quarantined. Only allowlist software you trust.',
            style: TextStyle(color: ZentorColors.warning, height: 1.45),
          ),
          const SizedBox(height: 20),
          const ZentorEmptyState(
            title: 'No allowlist entries',
            message:
                'Avorax will never silently add an allowlist entry. Unsafe root folders are blocked by the local core.',
            icon: Icons.fact_check_outlined,
          ),
        ],
      ),
    );
  }
}
