import 'package:flutter/material.dart';

import '../../app/theme/zentor_colors.dart';
import 'zentor_status_card.dart';

class ZentorMetricCard extends StatelessWidget {
  const ZentorMetricCard({
    required this.title,
    required this.value,
    required this.icon,
    this.detail,
    super.key,
  });

  final String title;
  final String value;
  final String? detail;
  final IconData icon;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final textScale = MediaQuery.textScalerOf(context).scale(14) / 14;
        final stacked = textScale > 1.3 || constraints.maxWidth < 320;
        final content = Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              maxLines: stacked ? null : 1,
              overflow: stacked ? null : TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.labelMedium?.copyWith(
                color: ZentorColors.textSecondary,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              value,
              maxLines: stacked ? null : 2,
              overflow: stacked ? null : TextOverflow.ellipsis,
              style: Theme.of(context).textTheme.titleMedium,
            ),
            if (detail != null) ...[
              const SizedBox(height: 6),
              Text(
                detail!,
                maxLines: stacked ? null : 2,
                overflow: stacked ? null : TextOverflow.ellipsis,
                style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                  color: ZentorColors.textSecondary,
                ),
              ),
            ],
          ],
        );
        final iconWidget = Container(
          width: 44,
          height: 44,
          decoration: BoxDecoration(
            color: ZentorColors.elevatedSurface,
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: ZentorColors.border),
          ),
          child: Icon(icon, color: ZentorColors.primaryAccent),
        );
        return ZentorPanel(
          child: stacked
              ? Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [iconWidget, const SizedBox(height: 14), content],
                )
              : Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    iconWidget,
                    const SizedBox(width: 14),
                    Expanded(child: content),
                  ],
                ),
        );
      },
    );
  }
}
