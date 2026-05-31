import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../features/allowlist/allowlist_screen.dart';
import '../features/device/device_screen.dart';
import '../features/home/home_screen.dart';
import '../features/logs/logs_screen.dart';
import '../features/onboarding/onboarding_screen.dart';
import '../features/privacy/privacy_screen.dart';
import '../features/protection/protection_screen.dart';
import '../features/quarantine/quarantine_screen.dart';
import '../features/scan/scan_screen.dart';
import '../features/settings/settings_screen.dart';
import '../features/update/update_screen.dart';
import '../shared/widgets/zentor_shell.dart';

final routerProvider = Provider<GoRouter>((ref) {
  return GoRouter(
    initialLocation: '/home',
    routes: [
      GoRoute(
        path: '/onboarding',
        builder: (context, state) => const OnboardingScreen(),
      ),
      ShellRoute(
        builder: (context, state, child) =>
            ZentorShell(location: state.uri.path, child: child),
        routes: [
          GoRoute(path: '/home', builder: (_, _) => const HomeScreen()),
          GoRoute(path: '/scan', builder: (_, _) => const ScanScreen()),
          GoRoute(
            path: '/quarantine',
            builder: (_, _) => const QuarantineScreen(),
          ),
          GoRoute(
            path: '/allowlist',
            builder: (_, _) => const AllowlistScreen(),
          ),
          GoRoute(
            path: '/protection',
            builder: (_, _) => const ProtectionScreen(),
          ),
          GoRoute(path: '/device', builder: (_, _) => const DeviceScreen()),
          GoRoute(path: '/logs', builder: (_, _) => const LogsScreen()),
          GoRoute(path: '/settings', builder: (_, _) => const SettingsScreen()),
          GoRoute(path: '/updates', builder: (_, _) => const UpdateScreen()),
          GoRoute(path: '/privacy', builder: (_, _) => const PrivacyScreen()),
        ],
      ),
    ],
  );
});
