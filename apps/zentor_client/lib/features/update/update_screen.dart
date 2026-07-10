import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../core/updates/update_service.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_status_card.dart';
import 'update_confirmation.dart';
import 'update_controller.dart';
import 'update_mutation_guard.dart';
import 'update_state.dart';
import 'widgets/update_status_rows.dart';

class UpdateScreen extends ConsumerWidget {
  const UpdateScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final model = updateViewModelFromState(state);
    final busy =
        state.updateOperationInFlight ||
        {
          UpdateStatus.checking,
          UpdateStatus.downloading,
          UpdateStatus.verifying,
          UpdateStatus.installing,
          UpdateStatus.rollingBack,
        }.contains(model.status);
    final updateMutationBlocked = updateMutationBlockedByActiveWork(state);
    final packageMutationSupported = model.packageMutationSupported;
    final rollbackSupported = model.rollbackSupported == true;
    final rollbackAllowedByState =
        rollbackSupported && !busy && !updateMutationBlocked;
    final rollbackEnabled = packageMutationSupported && rollbackAllowedByState;
    return ZentorPanel(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Updates', style: Theme.of(context).textTheme.headlineMedium),
          const SizedBox(height: 8),
          Text(
            packageMutationSupported
                ? 'Normal Avorax updates use signed .aup packages and are applied by Avorax Update Service. '
                      'MSI and EXE installers are for first install, repair, recovery, and offline manual installs.'
                : 'Avorax can check for new releases on this platform. Package verification, installation, and rollback '
                      'require a manual reinstall with the matching macOS or Linux package.',
            style: TextStyle(color: ZentorColors.textSecondary, height: 1.4),
          ),
          const SizedBox(height: 18),
          UpdateStatusRows(model: model),
          if (model.status == UpdateStatus.readyToRestart) ...[
            const SizedBox(height: 18),
            const Text(
              'Update is installed. Restart Avorax to finish switching versions.',
              style: TextStyle(color: ZentorColors.success),
            ),
          ],
          if (model.releaseNotes != null) ...[
            const SizedBox(height: 18),
            Text(
              'Release notes',
              style: Theme.of(context).textTheme.titleMedium,
            ),
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
              if (packageMutationSupported &&
                  (model.status == UpdateStatus.updateAvailable ||
                      model.status == UpdateStatus.downloading ||
                      model.status == UpdateStatus.verifying ||
                      model.status == UpdateStatus.installing))
                ZentorButton(
                  label: switch (model.status) {
                    UpdateStatus.downloading => 'Downloading',
                    UpdateStatus.verifying => 'Verifying',
                    UpdateStatus.installing => 'Installing',
                    _ => 'Download, verify, install',
                  },
                  icon: Icons.system_update_alt_outlined,
                  onPressed: busy || updateMutationBlocked
                      ? null
                      : () async {
                          if (!await confirmInstallUpdate(context)) return;
                          await controller.downloadVerifyAndInstallUpdate(
                            confirmed: true,
                          );
                        },
                ),
              if (packageMutationSupported)
                ZentorButton(
                  label: model.status == UpdateStatus.rollingBack
                      ? 'Rolling back'
                      : rollbackSupported
                      ? 'Rollback previous version'
                      : model.rollbackSupported == false
                      ? 'Rollback unavailable'
                      : 'Rollback status unknown',
                  icon: Icons.history_outlined,
                  secondary: true,
                  onPressed: rollbackEnabled
                      ? () async {
                          if (!await confirmRollbackUpdate(context)) return;
                          await controller.rollbackUpdateInApp(confirmed: true);
                        }
                      : null,
                )
              else
                const Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      Icons.install_desktop_outlined,
                      color: ZentorColors.textSecondary,
                    ),
                    SizedBox(width: 8),
                    Text(
                      'Manual package reinstall required',
                      style: TextStyle(color: ZentorColors.textSecondary),
                    ),
                  ],
                ),
            ],
          ),
        ],
      ),
    );
  }
}
