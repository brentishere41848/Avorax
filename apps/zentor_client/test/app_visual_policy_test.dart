import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zentor_client/app/theme/zentor_colors.dart';
import 'package:zentor_client/app/theme/zentor_theme.dart';

void main() {
  test('app background is the flat Avorax dark color', () {
    final theme = ZentorTheme.dark();

    expect(theme.scaffoldBackgroundColor, ZentorColors.background);
    expect(ZentorColors.background, const Color(0xFF070B12));
  });

  test('device tab does not expose implementation wording', () {
    final deviceScreen = File(
      'lib/features/device/device_screen.dart',
    ).readAsStringSync();
    final platformInfo = File(
      'lib/core/platform/platform_info_service.dart',
    ).readAsStringSync();

    expect(deviceScreen, contains('Device & Protection Health'));
    expect(deviceScreen, isNot(contains('Flutter local core active')));
    expect(platformInfo, isNot(contains('Flutter local core active')));
  });

  test('protection UI labels best-effort watcher honestly', () {
    final protectionScreen = File(
      'lib/features/protection/protection_screen.dart',
    ).readAsStringSync();

    expect(protectionScreen, contains('User-mode monitor'));
    expect(protectionScreen, contains('best-effort folder monitoring'));
    expect(
      protectionScreen,
      contains('No kernel pre-execution blocking is claimed'),
    );
  });

  test(
    'weak scan results do not show default quarantine or detected badge',
    () {
      final scanScreen = File(
        'lib/features/scan/scan_screen.dart',
      ).readAsStringSync();

      expect(scanScreen, contains('Review suggested'));
      expect(scanScreen, contains('_canQuarantineByDefault'));
      expect(scanScreen, contains('_badgeLabel'));
    },
  );

  test(
    'quarantine destructive actions require confirmation and no dead keep button',
    () {
      final quarantineScreen = File(
        'lib/features/quarantine/quarantine_screen.dart',
      ).readAsStringSync();

      expect(quarantineScreen, contains('Restore quarantined file?'));
      expect(
        quarantineScreen,
        contains('Delete quarantined file permanently?'),
      );
      expect(quarantineScreen, contains('This cannot be undone by Avorax.'));
      expect(quarantineScreen, isNot(contains("label: 'Keep quarantined'")));
      expect(
        quarantineScreen,
        contains("const _MetaChip('Default', 'kept isolated')"),
      );
    },
  );

  test('protection UI does not hard-code service running states', () {
    final protectionScreen = File(
      'lib/features/protection/protection_screen.dart',
    ).readAsStringSync();

    expect(
      protectionScreen,
      contains('_serviceLabel(state.coreServiceStatus)'),
    );
    expect(protectionScreen, contains('Protection Enabled'));
    expect(
      protectionScreen,
      isNot(contains("_CheckRow('Core Service', 'Running')")),
    );
  });
  test('protection preference is restored after app restart', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();

    expect(appState, contains('config.realtimeProtectionEnabled'));
    expect(appState, contains('_restoreProtectionAfterStartup'));
    expect(appState, contains('persistPreference: false'));
  });

  test('local events are scoped to this device', () {
    final repo = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();

    expect(repo, contains('Platform.localHostname'));
    expect(repo, contains('zentor.local_events.v1'));
  });
  test('protection self-test button has visible result panel', () {
    final protectionScreen = File(
      'lib/features/protection/protection_screen.dart',
    ).readAsStringSync();
    final appState = File('lib/app/app_state.dart').readAsStringSync();

    expect(protectionScreen, contains('_SelfTestResultPanel'));
    expect(protectionScreen, contains('Protection self-test found issues'));
    expect(protectionScreen, contains('protectionSelfTestResult'));
    expect(appState, contains('Protection self-test completed with issues'));
  });

  test('device tab renders real local system and service fields', () {
    final deviceScreen = File(
      'lib/features/device/device_screen.dart',
    ).readAsStringSync();
    final platformInfo = File(
      'lib/core/platform/platform_info_service.dart',
    ).readAsStringSync();

    expect(deviceScreen, contains('value.hostName'));
    expect(deviceScreen, contains('value.serviceStates'));
    expect(deviceScreen, contains('value.totalPhysicalMemory'));
    expect(platformInfo, contains('Get-CimInstance Win32_Service'));
    expect(platformInfo, contains('WindowsIdentity'));
    expect(platformInfo, isNot(contains('Avorax Core Service: Running')));
    expect(platformInfo, isNot(contains('No elevated permissions requested')));
  });
}
