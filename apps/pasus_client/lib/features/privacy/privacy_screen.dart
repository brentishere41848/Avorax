import 'package:flutter/material.dart';

import '../../app/theme/pasus_colors.dart';
import '../../shared/widgets/pasus_status_card.dart';

class PrivacyScreen extends StatelessWidget {
  const PrivacyScreen({super.key});

  static const points = [
    'Pasus scans common high-risk locations during Quick Scan.',
    'Pasus scans accessible local files during Full Scan and skips paths denied by the OS.',
    'Pasus scans only the file or folder you choose during Custom Scan.',
    'Pasus can automatically quarantine confirmed detections when scan mode allows it.',
    'Pasus never permanently deletes files automatically.',
    'Pasus does not steal credentials.',
    'Pasus does not read browser cookies.',
    'Pasus does not hide from the user.',
    'Pasus does not silently install kernel drivers. Windows driver protection is optional and user-visible.',
    'Pasus does not disable other security tools.',
    'Pasus logs local security events visibly.',
  ];

  @override
  Widget build(BuildContext context) {
    return PasusPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Privacy-first by design',
            style: Theme.of(context).textTheme.headlineMedium,
          ),
          const SizedBox(height: 12),
          Text(
            'Pasus is a visible antivirus and security client. It is not a hidden system monitor and does not claim perfect detection.',
            style: Theme.of(
              context,
            ).textTheme.bodyLarge?.copyWith(color: PasusColors.textSecondary),
          ),
          const SizedBox(height: 24),
          for (final point in points)
            Padding(
              padding: const EdgeInsets.only(bottom: 14),
              child: Row(
                children: [
                  const Icon(
                    Icons.check_circle_outline,
                    color: PasusColors.success,
                  ),
                  const SizedBox(width: 12),
                  Expanded(child: Text(point)),
                ],
              ),
            ),
        ],
      ),
    );
  }
}
