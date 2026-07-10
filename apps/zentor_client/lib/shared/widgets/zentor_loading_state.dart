import 'package:flutter/material.dart';

import '../../app/theme/zentor_colors.dart';

class ZentorLoadingState extends StatelessWidget {
  const ZentorLoadingState({this.message = 'Working...', super.key});

  final String message;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        const SizedBox(
          width: 18,
          height: 18,
          child: CircularProgressIndicator(strokeWidth: 2),
        ),
        const SizedBox(width: 12),
        Flexible(
          child: Text(
            message,
            style: const TextStyle(color: ZentorColors.textSecondary),
          ),
        ),
      ],
    );
  }
}
