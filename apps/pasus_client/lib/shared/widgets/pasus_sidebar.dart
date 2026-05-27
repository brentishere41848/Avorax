import 'package:flutter/material.dart';
import 'package:go_router/go_router.dart';

import '../../app/theme/pasus_colors.dart';
import 'pasus_status_card.dart';

class PasusNavDestination {
  const PasusNavDestination(this.path, this.label, this.icon);

  final String path;
  final String label;
  final IconData icon;
}

const pasusDestinations = [
  PasusNavDestination('/home', 'Home', Icons.shield_outlined),
  PasusNavDestination('/scan', 'Scan', Icons.radar_outlined),
  PasusNavDestination(
    '/protection',
    'Protection',
    Icons.verified_user_outlined,
  ),
  PasusNavDestination('/quarantine', 'Quarantine', Icons.inventory_2_outlined),
  PasusNavDestination('/allowlist', 'Allowlist', Icons.fact_check_outlined),
  PasusNavDestination('/logs', 'Security Events', Icons.receipt_long_outlined),
  PasusNavDestination('/device', 'Device', Icons.devices_outlined),
  PasusNavDestination('/settings', 'Settings', Icons.settings_outlined),
  PasusNavDestination(
    '/gaming',
    'Gaming Protection',
    Icons.sports_esports_outlined,
  ),
];

class PasusSidebar extends StatelessWidget {
  const PasusSidebar({required this.location, super.key});

  final String location;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 280,
      padding: const EdgeInsets.fromLTRB(20, 24, 20, 20),
      decoration: const BoxDecoration(
        color: Color(0xFF080D16),
        border: Border(right: BorderSide(color: PasusColors.border)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              PasusMark(size: 42),
              SizedBox(width: 12),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Pasus',
                    style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800),
                  ),
                  Text(
                    'Security client',
                    style: TextStyle(color: PasusColors.textSecondary),
                  ),
                ],
              ),
            ],
          ),
          const SizedBox(height: 30),
          for (final destination in pasusDestinations)
            _SidebarItem(
              destination: destination,
              active: location.startsWith(destination.path),
            ),
          const Spacer(),
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: PasusColors.elevatedSurface,
              borderRadius: BorderRadius.circular(18),
              border: Border.all(color: PasusColors.border),
            ),
            child: const Text(
              'Visible protection only. Pasus scans local files, quarantines confirmed detections, and only uses driver protection when explicitly installed.',
              style: TextStyle(color: PasusColors.textSecondary, height: 1.45),
            ),
          ),
        ],
      ),
    );
  }
}

class _SidebarItem extends StatelessWidget {
  const _SidebarItem({required this.destination, required this.active});

  final PasusNavDestination destination;
  final bool active;

  @override
  Widget build(BuildContext context) {
    final color = active
        ? PasusColors.primaryAccent
        : PasusColors.textSecondary;
    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: InkWell(
        borderRadius: BorderRadius.circular(16),
        onTap: () => context.go(destination.path),
        child: Container(
          height: 48,
          padding: const EdgeInsets.symmetric(horizontal: 14),
          decoration: BoxDecoration(
            color: active
                ? PasusColors.primaryAccent.withValues(alpha: 0.1)
                : Colors.transparent,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(
              color: active
                  ? PasusColors.primaryAccent.withValues(alpha: 0.25)
                  : Colors.transparent,
            ),
          ),
          child: Row(
            children: [
              Icon(destination.icon, color: color, size: 20),
              const SizedBox(width: 12),
              Text(
                destination.label,
                style: TextStyle(color: color, fontWeight: FontWeight.w700),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
