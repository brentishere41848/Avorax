import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_empty_state.dart';
import '../../shared/widgets/zentor_status_card.dart';

class ProtectedAppsScreen extends ConsumerWidget {
  const ProtectedAppsScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final selected = state.config.protectedAppConfig;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        ZentorPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Advanced App Control',
                style: Theme.of(context).textTheme.headlineMedium,
              ),
              const SizedBox(height: 8),
              const Text(
                'Optional legacy app allowlisting tools. Antivirus scanning and quarantine do not require this setup.',
                style: TextStyle(color: ZentorColors.textSecondary),
              ),
              const SizedBox(height: 18),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  ZentorButton(
                    label: 'Rescan',
                    icon: Icons.refresh,
                    secondary: true,
                    onPressed: controller.unawaitedDetectApps,
                  ),
                  ZentorButton(
                    label: 'Add file or app',
                    icon: Icons.file_open_outlined,
                    secondary: true,
                    onPressed: controller.addManualProtectedAppFile,
                  ),
                  ZentorButton(
                    label: 'Add folder',
                    icon: Icons.folder_open_outlined,
                    secondary: true,
                    onPressed: controller.addManualProtectedAppFolder,
                  ),
                  ZentorButton(
                    label: 'Calculate build hash',
                    icon: Icons.tag_outlined,
                    onPressed: selected.isConfigured
                        ? controller.calculateProtectedAppHash
                        : null,
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        ZentorPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Selected protected app',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 14),
              if (!selected.isConfigured)
                const ZentorEmptyState(
                  title: 'No protected app selected',
                  message:
                      'Application protection is optional. Start a supported app or add one manually when needed.',
                  icon: Icons.apps_outlined,
                )
              else
                _AppRow(
                  title: selected.appName,
                  path: selected.appPath,
                  source: selected.source.isEmpty ? 'Manual' : selected.source,
                  profile: selected.protectionProfile,
                  trailing: selected.lastCalculatedHash.isEmpty
                      ? 'Build not verified'
                      : selected.lastCalculatedHash,
                ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        ZentorPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Auto-detected apps',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 14),
              if (state.detectedApps.isEmpty)
                const ZentorEmptyState(
                  title: 'No supported app detected',
                  message:
                      'Avorax found no supported apps in known launcher metadata or running processes.',
                  icon: Icons.search_off_outlined,
                )
              else
                for (final app in state.detectedApps)
                  _AppRow(
                    title: app.displayName,
                    path: app.path,
                    source: app.source,
                    profile: app.protectionProfile,
                    trailing: 'Select',
                    onTap: () => controller.selectDetectedApp(app),
                  ),
            ],
          ),
        ),
      ],
    );
  }
}

class _AppRow extends StatelessWidget {
  const _AppRow({
    required this.title,
    required this.path,
    required this.source,
    required this.profile,
    required this.trailing,
    this.onTap,
  });

  final String title;
  final String path;
  final String source;
  final String profile;
  final String trailing;
  final VoidCallback? onTap;

  @override
  Widget build(BuildContext context) {
    return ListTile(
      contentPadding: EdgeInsets.zero,
      onTap: onTap,
      leading: const Icon(
        Icons.apps_outlined,
        color: ZentorColors.primaryAccent,
      ),
      title: Text(title),
      subtitle: Text(
        '$source â€¢ $profile\n$path',
        style: const TextStyle(color: ZentorColors.textSecondary),
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
      trailing: Text(
        trailing,
        style: const TextStyle(color: ZentorColors.textSecondary),
        overflow: TextOverflow.ellipsis,
      ),
    );
  }
}
