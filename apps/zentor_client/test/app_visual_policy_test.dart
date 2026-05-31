import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zentor_client/app/theme/zentor_colors.dart';
import 'package:zentor_client/app/theme/zentor_theme.dart';

void main() {
  test('app background is the flat Zentor dark color', () {
    final theme = ZentorTheme.dark();

    expect(theme.scaffoldBackgroundColor, ZentorColors.background);
    expect(ZentorColors.background, const Color(0xFF070B12));
  });

  test('device tab does not expose implementation wording', () {
    final deviceScreen = File('lib/features/device/device_screen.dart').readAsStringSync();
    final platformInfo = File('lib/core/platform/platform_info_service.dart').readAsStringSync();

    expect(deviceScreen, contains('Device & Protection Health'));
    expect(deviceScreen, isNot(contains('Flutter local core active')));
    expect(platformInfo, isNot(contains('Flutter local core active')));
  });

  test('weak scan results do not show default quarantine or detected badge', () {
    final scanScreen = File('lib/features/scan/scan_screen.dart').readAsStringSync();

    expect(scanScreen, contains('Review suggested'));
    expect(scanScreen, contains('_canQuarantineByDefault'));
    expect(scanScreen, contains('_badgeLabel'));
  });
}
