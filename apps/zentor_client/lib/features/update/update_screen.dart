import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../core/updates/update_service.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_status_card.dart';
import 'update_controller.dart';
import 'update_state.dart';
import 'widgets/update_status_rows.dart';

class UpdateScreen extends ConsumerWidget {
  const UpdateScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final model = updateViewModelFromState(state);
    final busy = {
      UpdateStatus.checking,
      UpdateStatus.downloading,
      UpdateStatus.verifying,
      UpdateStatus.installing,
    }.contains(model.status);
    return ZentorPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Updates', style: Theme.of(context).textTheme.headlineMedium),
          const SizedBox(height: 8),
          const Text(
            'Normal Avorax updates use signed .aup packages and are applied by Avorax Update Service. '
            'MSI and EXE installers are only for first install, repair, recovery, and offline manual installs.',
            style: TextStyle(color: ZentorColors.textSecondary, height: 1.4),
          ),
          const SizedBox(height: 18),
          UpdateStatusRows(model: model),
          if (model.releaseNotes != null) ...[
            const SizedBox(height: 18),
            Text('Release notes', style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 8),
            Text(
              model.releaseNotes!,
              style: const TextStyle(color: ZentorColors.textSecondary),
            ),
          ],
          const SizedBox(height: 18),
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              ZentorButton(
                label: model.status == UpdateStatus.checking
                    ? 'Checking'
                    : 'Check for updates',
                icon: Icons.update_outlined,
                secondary: true,
                onPressed: busy ? null : controller.checkForInAppUpdate,
              ),
              if (model.status == UpdateStatus.updateAvailable ||
                  model.status == UpdateStatus.downloading ||
                  model.status == UpdateStatus.verifying ||
                  model.status == UpdateStatus.installing)
                ZentorButton(
                  label: switch (model.status) {
                    UpdateStatus.downloading => 'Downloading',
                    UpdateStatus.verifying => 'Verifying',
                    UpdateStatus.installing => 'Installing',
                    _ => 'Download, verify, install',
                  },
                  icon: Icons.system_update_alt_outlined,
                  onPressed: busy
                      ? null
                      : controller.downloadVerifyAndInstallUpdate,
                ),
              ZentorButton(
                label: 'Rollback previous version',
                icon: Icons.history_outlined,
                secondary: true,
                onPressed: model.rollbackSupported ? null : null,
              ),
            ],
          ),
        ],
      ),
    );
  }
}
