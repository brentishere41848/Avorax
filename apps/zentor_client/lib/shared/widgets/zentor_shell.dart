import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import 'zentor_bottom_nav.dart';
import 'zentor_sidebar.dart';
import 'zentor_status_card.dart';

class ZentorShell extends ConsumerWidget {
  const ZentorShell({required this.child, required this.location, super.key});

  final Widget child;
  final String location;

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final state = ref.watch(zentorControllerProvider);
    final isDesktop = MediaQuery.sizeOf(context).width >= 900;
    final content = Column(
      children: [
        Container(
          height: 72,
          padding: const EdgeInsets.symmetric(horizontal: 24),
          decoration: const BoxDecoration(
            border: Border(bottom: BorderSide(color: ZentorColors.border)),
          ),
          child: Row(
            children: [
              if (!isDesktop) ...[
                const ZentorMark(size: 36),
                const SizedBox(width: 12),
                const Text(
                  'Avorax',
                  style: TextStyle(fontWeight: FontWeight.w800, fontSize: 18),
                ),
              ] else
                Text(
                  _titleFor(location),
                  style: Theme.of(context).textTheme.titleLarge,
                ),
              const Spacer(),
              Wrap(
                spacing: 10,
                children: [
                  ZentorStatusPill(
                    label: state.cloudStatus.label,
                    color: _cloudColor(state.cloudStatus),
                    icon: Icons.cloud_outlined,
                  ),
                  ZentorStatusPill(
                    label: state.protectionStatus.label,
                    color: _protectionColor(state.protectionStatus),
                    icon: Icons.shield_outlined,
                  ),
                ],
              ),
            ],
          ),
        ),
        Expanded(
          child: SafeArea(
            top: false,
            child: SingleChildScrollView(
              padding: EdgeInsets.all(isDesktop ? 28 : 18),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 1280),
                child: child,
              ),
            ),
          ),
        ),
      ],
    );

    return Scaffold(
      backgroundColor: ZentorColors.background,
      body: ColoredBox(
        color: ZentorColors.background,
        child: isDesktop
            ? Row(
                children: [
                  ZentorSidebar(location: location),
                  Expanded(child: content),
                ],
              )
            : content,
      ),
      bottomNavigationBar: isDesktop
          ? null
          : ZentorBottomNav(location: location),
    );
  }

  String _titleFor(String location) {
    if (location.startsWith('/scan')) return 'Scan';
    if (location.startsWith('/quarantine')) return 'Quarantine';
    if (location.startsWith('/allowlist')) return 'Allowlist';
    if (location.startsWith('/protection')) return 'Protection';
    if (location.startsWith('/device')) return 'Device Integrity';
    if (location.startsWith('/logs')) return 'Security Events';
    if (location.startsWith('/settings')) return 'Settings';
    if (location.startsWith('/updates')) return 'Updates';
    if (location.startsWith('/privacy')) return 'Privacy';
    return 'Protection Overview';
  }

  Color _cloudColor(CloudStatus status) => switch (status) {
    CloudStatus.online => ZentorColors.success,
    CloudStatus.checking => ZentorColors.primaryAccent,
    CloudStatus.disabled => ZentorColors.textSecondary,
    CloudStatus.offline => ZentorColors.warning,
    CloudStatus.misconfigured => ZentorColors.danger,
  };

  Color _protectionColor(ProtectionStatus status) => switch (status) {
    ProtectionStatus.protected => ZentorColors.success,
    ProtectionStatus.localOnly ||
    ProtectionStatus.partiallyProtected => ZentorColors.warning,
    ProtectionStatus.starting ||
    ProtectionStatus.stopping => ZentorColors.primaryAccent,
    ProtectionStatus.error => ZentorColors.danger,
    ProtectionStatus.idle => ZentorColors.textSecondary,
  };
}
