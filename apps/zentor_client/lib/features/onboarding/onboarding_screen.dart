import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_status_card.dart';

class OnboardingScreen extends ConsumerWidget {
  const OnboardingScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final onboardingCompletionBusy = state.onboardingCompletionInFlight;
    return Scaffold(
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 880),
              child: ZentorPanel(
                padding: const EdgeInsets.all(34),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const ZentorMark(size: 72),
                    const SizedBox(height: 26),
                    Text(
                      'Avorax protects your device.',
                      style: Theme.of(context).textTheme.displaySmall,
                    ),
                    const SizedBox(height: 18),
                    Text(
                      'Avorax scans, reviews, blocks, and quarantines threats while keeping protection visible and under your control.',
                      style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                        color: ZentorColors.textSecondary,
                      ),
                    ),
                    const SizedBox(height: 28),
                    const _OnboardingPoint(
                      icon: Icons.verified_user_outlined,
                      text: 'Avorax checks local files and protection status.',
                    ),
                    const _OnboardingPoint(
                      icon: Icons.folder_off_outlined,
                      text: 'Avorax does not scan unrelated personal files.',
                    ),
                    const _OnboardingPoint(
                      icon: Icons.visibility_outlined,
                      text: 'Avorax does not run hidden surveillance.',
                    ),
                    const _OnboardingPoint(
                      icon: Icons.touch_app_outlined,
                      text: 'You control when protection starts.',
                    ),
                    const SizedBox(height: 30),
                    Wrap(
                      spacing: 12,
                      runSpacing: 12,
                      children: [
                        ZentorButton(
                          label: onboardingCompletionBusy
                              ? 'Saving setup'
                              : 'Continue',
                          icon: Icons.arrow_forward,
                          onPressed: onboardingCompletionBusy
                              ? null
                              : () async {
                                  final saved = await controller
                                      .completeOnboarding();
                                  if (!context.mounted) return;
                                  if (saved) {
                                    context.go('/home');
                                    return;
                                  }
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    const SnackBar(
                                      content: Text(
                                        'Unable to save setup. See the error banner.',
                                      ),
                                    ),
                                  );
                                },
                        ),
                        ZentorButton(
                          label: 'Privacy details',
                          icon: Icons.privacy_tip_outlined,
                          secondary: true,
                          onPressed: () => context.go('/privacy'),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class _OnboardingPoint extends StatelessWidget {
  const _OnboardingPoint({required this.icon, required this.text});

  final IconData icon;
  final String text;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 14),
      child: Row(
        children: [
          Icon(icon, color: ZentorColors.primaryAccent),
          const SizedBox(width: 14),
          Expanded(child: Text(text)),
        ],
      ),
    );
  }
}
