import 'package:flutter/material.dart';

Future<bool> confirmStartProtection(BuildContext context) async {
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Enable protection?'),
      content: const Text(
        'This enables Avorax real-time monitoring for configured locations, asks the local engine to apply Guard policy, and may start best-effort user-mode folder monitoring. Manual scans and quarantine remain available if startup is partial.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Enable'),
        ),
      ],
    ),
  );
  return confirmed == true;
}

Future<bool> confirmStopProtection(BuildContext context) async {
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Stop protection?'),
      content: const Text(
        'This turns off Avorax real-time monitoring and asks the local engine to disable Guard policy. Manual scans and quarantine remain available.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Stop'),
        ),
      ],
    ),
  );
  return confirmed == true;
}
