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
    final pageTitle = _titleFor(location);
    final notification = _notificationEvent(state.events);
    final title = Semantics(
      header: true,
      liveRegion: true,
      label: 'Page title, $pageTitle',
      child: ExcludeSemantics(
        child: isDesktop
            ? Text(pageTitle, style: Theme.of(context).textTheme.titleLarge)
            : const Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  ZentorMark(size: 36),
                  SizedBox(width: 12),
                  Flexible(
                    child: Text(
                      'Avorax',
                      overflow: TextOverflow.ellipsis,
                      style: TextStyle(
                        fontWeight: FontWeight.w800,
                        fontSize: 18,
                      ),
                    ),
                  ),
                ],
              ),
      ),
    );
    final statuses = Wrap(
      spacing: 10,
      runSpacing: 8,
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
    );
    final content = FocusTraversalGroup(
      policy: ReadingOrderTraversalPolicy(),
      child: Column(
        children: [
          Container(
            constraints: const BoxConstraints(minHeight: 72),
            padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
            decoration: const BoxDecoration(
              border: Border(bottom: BorderSide(color: ZentorColors.border)),
            ),
            child: LayoutBuilder(
              builder: (context, constraints) {
                final textScale =
                    MediaQuery.textScalerOf(context).scale(14) / 14;
                final stackHeader =
                    !isDesktop || constraints.maxWidth < 720 || textScale > 1.3;
                if (stackHeader) {
                  return Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [title, const SizedBox(height: 10), statuses],
                  );
                }
                return Row(
                  children: [
                    title,
                    const Spacer(),
                    Flexible(child: statuses),
                  ],
                );
              },
            ),
          ),
          if (notification != null) _InAppNotification(event: notification),
          Expanded(
            child: SafeArea(
              top: false,
              child: SingleChildScrollView(
                padding: EdgeInsets.all(isDesktop ? 28 : 18),
                child: Semantics(
                  container: true,
                  explicitChildNodes: true,
                  label: 'Main content, $pageTitle',
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 1280),
                    child: child,
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
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

  LocalEvent? _notificationEvent(List<LocalEvent> events) {
    LocalEvent? selected;
    var selectedPriority = -1;
    for (final event in events.take(20)) {
      if (!_isNotificationEvent(event)) continue;
      final priority = _notificationPriority(event);
      if (selected == null ||
          priority > selectedPriority ||
          (priority == selectedPriority &&
              event.createdAt.isAfter(selected.createdAt))) {
        selected = event;
        selectedPriority = priority;
      }
    }
    return selected;
  }

  bool _isNotificationEvent(LocalEvent event) {
    if (event.severity == 'warning' || event.severity == 'error') return true;
    return {
      'scan_completed',
      'scan_failed',
      'scan_cancelled',
      'file_quarantined',
      'quarantine_item_restored',
      'quarantine_item_deleted',
      'update_available',
      'update_install_ready',
      'update_install_failed',
      'update_rollback_failed',
      'scheduled_quick_scan_started',
    }.contains(event.type);
  }

  int _notificationPriority(LocalEvent event) {
    if (event.severity == 'error') return 3;
    if (event.severity == 'warning') return 2;
    return 1;
  }
}

class _InAppNotification extends StatelessWidget {
  const _InAppNotification({required this.event});

  final LocalEvent event;

  @override
  Widget build(BuildContext context) {
    final color = switch (event.severity) {
      'error' => ZentorColors.danger,
      'warning' => ZentorColors.warning,
      _ => ZentorColors.primaryAccent,
    };
    final notificationText = _notificationText(event);
    return Semantics(
      container: true,
      liveRegion: true,
      label: 'Security notification, $notificationText',
      child: ExcludeSemantics(
        child: Container(
          width: double.infinity,
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 10),
          decoration: BoxDecoration(
            color: ZentorColors.elevatedSurface,
            border: Border(bottom: BorderSide(color: color)),
          ),
          child: Row(
            children: [
              Icon(_iconFor(event), color: color, size: 18),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  notificationText,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(color: ZentorColors.textPrimary),
                ),
              ),
              const SizedBox(width: 10),
              Flexible(
                child: Text(
                  event.category,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(
                    color: ZentorColors.textSecondary,
                    fontSize: 12,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  IconData _iconFor(LocalEvent event) {
    if (event.severity == 'error') return Icons.error_outline;
    if (event.severity == 'warning') return Icons.warning_amber_outlined;
    if (event.type.contains('quarantine')) return Icons.inventory_2_outlined;
    if (event.type.contains('update')) return Icons.system_update_alt_outlined;
    if (event.type.contains('scan')) return Icons.radar_outlined;
    return Icons.notifications_outlined;
  }

  String _notificationText(LocalEvent event) {
    final details = event.details == null ? '' : ': ${event.details}';
    final text = '${event.message}$details'
        .replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ')
        .replaceAll(RegExp(r'\s+'), ' ')
        .trim();
    const maxNotificationChars = 220;
    if (text.length <= maxNotificationChars) return text;
    return '${text.substring(0, maxNotificationChars - 3)}...';
  }
}
