import 'package:flutter/material.dart';

Future<bool> confirmInstallUpdate(BuildContext context) async {
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Download, verify, and install update?'),
      content: const Text(
        'Avorax will download the signed .aup package, verify its hash and signature, then ask Avorax Update Service to apply it. Applying an update changes installed Avorax files and may show a Windows administrator prompt.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Continue'),
        ),
      ],
    ),
  );
  return confirmed == true;
}

Future<bool> confirmRollbackUpdate(BuildContext context) async {
  final confirmed = await showDialog<bool>(
    context: context,
    builder: (context) => AlertDialog(
      title: const Text('Rollback previous version?'),
      content: const Text(
        'Avorax will ask Avorax Update Service to restore the previous version from the local rollback snapshot. This changes installed Avorax files and may show a Windows administrator prompt.',
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () => Navigator.of(context).pop(true),
          child: const Text('Rollback'),
        ),
      ],
    ),
  );
  return confirmed == true;
}
