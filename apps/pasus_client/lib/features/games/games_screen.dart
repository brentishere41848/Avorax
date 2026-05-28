import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../app/app_state.dart';
import '../../app/theme/pasus_colors.dart';
import '../../shared/widgets/pasus_button.dart';
import '../../shared/widgets/pasus_empty_state.dart';
import '../../shared/widgets/pasus_status_card.dart';

class GamesScreen extends ConsumerWidget {
  const GamesScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(pasusControllerProvider);
    final controller = ref.read(pasusControllerProvider.notifier);
    final selected = state.config.gameConfig;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        PasusPanel(
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
                style: TextStyle(color: PasusColors.textSecondary),
              ),
              const SizedBox(height: 18),
              Wrap(
                spacing: 12,
                runSpacing: 12,
                children: [
                  PasusButton(
                    label: 'Rescan',
                    icon: Icons.refresh,
                    secondary: true,
                    onPressed: controller.unawaitedDetectGames,
                  ),
                  PasusButton(
                    label: 'Add file or app',
                    icon: Icons.file_open_outlined,
                    secondary: true,
                    onPressed: controller.addManualGameFile,
                  ),
                  PasusButton(
                    label: 'Add folder',
                    icon: Icons.folder_open_outlined,
                    secondary: true,
                    onPressed: controller.addManualGameFolder,
                  ),
                  PasusButton(
                    label: 'Calculate build hash',
                    icon: Icons.tag_outlined,
                    onPressed: selected.isConfigured
                        ? controller.calculateGameHash
                        : null,
                  ),
                ],
              ),
            ],
          ),
        ),
        const SizedBox(height: 16),
        PasusPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Selected protected game',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 14),
              if (!selected.isConfigured)
                const PasusEmptyState(
                  title: 'No game selected',
                  message:
                      'Gaming protection is optional. Start a supported game or add one manually when needed.',
                  icon: Icons.sports_esports_outlined,
                )
              else
                _GameRow(
                  title: selected.gameName,
                  path: selected.gamePath,
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
        PasusPanel(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Auto-detected games',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 14),
              if (state.detectedGames.isEmpty)
                const PasusEmptyState(
                  title: 'No supported game detected',
                  message:
                      'Pasus found no supported games in known launcher metadata or running processes.',
                  icon: Icons.search_off_outlined,
                )
              else
                for (final game in state.detectedGames)
                  _GameRow(
                    title: game.displayName,
                    path: game.path,
                    source: game.source,
                    profile: game.protectionProfile,
                    trailing: 'Select',
                    onTap: () => controller.selectDetectedGame(game),
                  ),
            ],
          ),
        ),
      ],
    );
  }
}

class _GameRow extends StatelessWidget {
  const _GameRow({
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
        Icons.sports_esports_outlined,
        color: PasusColors.primaryAccent,
      ),
      title: Text(title),
      subtitle: Text(
        '$source • $profile\n$path',
        style: const TextStyle(color: PasusColors.textSecondary),
        maxLines: 2,
        overflow: TextOverflow.ellipsis,
      ),
      trailing: Text(
        trailing,
        style: const TextStyle(color: PasusColors.textSecondary),
        overflow: TextOverflow.ellipsis,
      ),
    );
  }
}
