import 'package:flutter/material.dart';

import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_status_card.dart';

class PrivacyScreen extends StatelessWidget {
  const PrivacyScreen({super.key});

  static const points = [
    'Avorax scans common high-risk locations during Quick Scan.',
    'Avorax scans accessible local files during Full Scan and skips paths denied by the OS.',
    'Avorax scans only the file or folder you choose during Custom Scan.',
    'Avorax can automatically quarantine confirmed detections when scan mode allows it.',
    'Avorax never permanently deletes files automatically.',
    'Avorax does not steal credentials.',
    'Avorax does not read browser cookies.',
    'Avorax does not hide from the user.',
    'Avorax does not silently install kernel drivers. Windows driver protection is optional and user-visible.',
    'Avorax does not disable other security tools.',
    'Avorax logs local security events visibly.',
  ];

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      child: ZentorPanel(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Privacy-first by design',
              style: Theme.of(context).textTheme.headlineMedium,
            ),
            const SizedBox(height: 12),
            Text(
              'Avorax is a visible antivirus and security client. It is not a hidden system monitor and does not claim perfect detection.',
              style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                color: ZentorColors.textSecondary,
              ),
            ),
            const SizedBox(height: 24),
            for (final point in points)
              Padding(
                padding: const EdgeInsets.only(bottom: 14),
                child: Row(
                  children: [
                    const Icon(
                      Icons.check_circle_outline,
                      color: ZentorColors.success,
                    ),
                    const SizedBox(width: 12),
                    Expanded(child: Text(point)),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }
}
