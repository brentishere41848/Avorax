import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zentor_client/app/theme/zentor_colors.dart';
import 'package:zentor_client/app/theme/zentor_theme.dart';

import 'source_text.dart';

void main() {
  test('app background is the flat Avorax dark color', () {
    final theme = ZentorTheme.dark();

    expect(theme.scaffoldBackgroundColor, ZentorColors.background);
    expect(ZentorColors.background, const Color(0xFF070B12));
  });

  test(
    'dark theme text and status colors keep AA contrast on app surfaces',
    () {
      const surfaces = {
        'background': ZentorColors.background,
        'surface': ZentorColors.surface,
        'elevatedSurface': ZentorColors.elevatedSurface,
      };
      const foregrounds = {
        'textPrimary': ZentorColors.textPrimary,
        'textSecondary': ZentorColors.textSecondary,
        'primaryAccent': ZentorColors.primaryAccent,
        'secondaryAccent': ZentorColors.secondaryAccent,
        'success': ZentorColors.success,
        'warning': ZentorColors.warning,
        'danger': ZentorColors.danger,
      };

      for (final surface in surfaces.entries) {
        for (final foreground in foregrounds.entries) {
          expect(
            _contrastRatio(foreground.value, surface.value),
            greaterThanOrEqualTo(4.5),
            reason:
                '${foreground.key} should remain readable on ${surface.key}.',
          );
        }
      }
    },
  );

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

  test('device native engine metric shows engine diagnostics', () {
    final deviceScreen = File(
      'lib/features/device/device_screen.dart',
    ).readAsStringSync();
    final metric = deviceScreen.substring(
      deviceScreen.indexOf("title: 'Avorax Native Engine'"),
      deviceScreen.indexOf('String _serviceLabel'),
    );
    final helper = deviceScreen.substring(
      deviceScreen.indexOf('String _nativeEngineLabel'),
      deviceScreen.indexOf('String _serviceDetails'),
    );

    expect(metric, contains('value: _nativeEngineLabel(state)'));
    expect(
      helper,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(helper, contains("return 'Attention needed'"));
    expect(
      helper,
      contains('final diagnostic = state.lastEngineError?.trim()'),
    );
    expect(helper, contains(r'Engine diagnostic: $diagnostic'));
    expect(
      helper.indexOf('lastEngineError'),
      lessThan(helper.indexOf('state.nativeEngineStatus')),
    );
  });

  test('protection UI labels best-effort watcher honestly', () {
    final protectionScreen = File(
      'lib/features/protection/protection_screen.dart',
    ).readAsStringSync();

    expect(protectionScreen, contains('User-mode monitor'));
    expect(
      protectionScreen,
      contains('Best-effort folder watch roots prepared'),
    );
    expect(protectionScreen, contains('persistent service monitoring'));
    expect(
      protectionScreen,
      contains('kernel pre-execution blocking are not claimed'),
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

  test('engine unavailable UI does not invent install paths', () {
    final scanScreen = File(
      'lib/features/scan/scan_screen.dart',
    ).readAsStringSync();
    final diagnostics = scanScreen.substring(
      scanScreen.indexOf('class _EngineUnavailableDiagnostics'),
      scanScreen.indexOf('class _DiagnosticChip'),
    );

    expect(diagnostics, contains('_engineDirectoryLabel(state)'));
    expect(
      scanScreen,
      contains('final scanEngineDiagnostic = state.lastEngineError?.trim();'),
    );
    expect(diagnostics, contains('scanEngineDiagnostic?.isNotEmpty ?? false'));
    expect(diagnostics, contains('value: scanEngineDiagnostic!'));
    expect(diagnostics, contains('required bool engineDiagnosticVisible'));
    expect(
      diagnostics,
      contains("nativeEngineStatus == 'ready' && !engineDiagnosticVisible"),
    );
    expect(diagnostics, contains('engineDiagnosticVisible:'));
    expect(diagnostics, contains('Not reported by Core Service'));
    expect(diagnostics, contains("'Unknown'"));
    expect(diagnostics, isNot(contains(r'C:\Program Files\Avorax')));
    expect(diagnostics, isNot(contains('installed Avorax engine directory')));
  });

  test('manual quarantine action requires explicit confirmation', () {
    final scanScreen = File(
      'lib/features/scan/scan_screen.dart',
    ).readAsStringSync();
    final threatRow = scanScreen.substring(
      scanScreen.indexOf('class _ThreatRow'),
      scanScreen.indexOf('class _Chip'),
    );

    expect(threatRow, contains('Quarantine this file?'));
    expect(threatRow, contains('move this file into isolated quarantine'));
    expect(threatRow, contains('restore or deletion review'));
    expect(threatRow, contains('_confirmQuarantine(context)'));
    expect(threatRow, contains('quarantineThreat(threat, confirmed: true)'));
    expect(threatRow, isNot(contains('controller.quarantineThreat(threat)')));
  });

  test('keep ignore action requires explicit confirmation', () {
    final scanScreen = File(
      'lib/features/scan/scan_screen.dart',
    ).readAsStringSync();
    final threatRow = scanScreen.substring(
      scanScreen.indexOf('class _ThreatRow'),
      scanScreen.indexOf('class _Chip'),
    );

    expect(threatRow, contains('Keep and ignore this detection?'));
    expect(threatRow, contains('leave this file in place'));
    expect(threatRow, contains('hide this detection'));
    expect(threatRow, contains('_confirmIgnoreThreat(context)'));
    expect(threatRow, contains('ignoreThreat(threat, confirmed: true)'));
    expect(threatRow, isNot(contains('controller.ignoreThreat(threat)')));
  });

  test('auto-action scan starts require explicit confirmation', () {
    final scanScreen = readNormalizedSource(
      'lib/features/scan/scan_screen.dart',
    );

    expect(scanScreen, contains('Run scan with automatic quarantine?'));
    expect(scanScreen, contains('may move confirmed threats into quarantine'));
    expect(
      scanScreen,
      contains(
        '_confirmScanAutoAction(\n                              context,\n                              state.scanActionMode,',
      ),
    );
    expect(scanScreen, contains('confirmedAutoAction:'));
    expect(
      scanScreen,
      contains(
        '_scanModeMayQuarantine(\n                                state.scanActionMode,',
      ),
    );
    expect(
      scanScreen,
      isNot(
        contains(
          'actionMode:\n                                ScanActionMode.autoQuarantineConfirmedOnly',
        ),
      ),
    );
  });

  test(
    'quarantine destructive actions require confirmation and no dead keep button',
    () {
      final quarantineScreen = readNormalizedSource(
        'lib/features/quarantine/quarantine_screen.dart',
      );

      expect(quarantineScreen, contains('Restore quarantined file?'));
      expect(
        quarantineScreen,
        contains('Delete quarantined file permanently?'),
      );
      expect(quarantineScreen, contains('This cannot be undone by Avorax.'));
      expect(
        quarantineScreen,
        contains(
          'restoreQuarantineItem(\n                                    item,\n                                    confirmed: true,',
        ),
      );
      expect(
        quarantineScreen,
        contains(
          'deleteQuarantineItem(\n                                    item,\n                                    confirmed: true,',
        ),
      );
      expect(
        quarantineScreen,
        isNot(contains('controller.restoreQuarantineItem(item);')),
      );
      expect(
        quarantineScreen,
        isNot(contains('controller.deleteQuarantineItem(item);')),
      );
      expect(quarantineScreen, isNot(contains("label: 'Keep quarantined'")));
      expect(
        quarantineScreen,
        contains("const _MetaChip('Default', 'kept isolated')"),
      );
    },
  );

  test('scan results do not expose dead destructive delete controls', () {
    final scanScreen = File(
      'lib/features/scan/scan_screen.dart',
    ).readAsStringSync();
    final appState = File('lib/app/app_state.dart').readAsStringSync();

    expect(scanScreen, isNot(contains('Delete from quarantine only')));
    expect(scanScreen, isNot(contains('deleteThreatPermanently')));
    expect(appState, isNot(contains('deleteThreatPermanently')));
  });

  test('repair installation action requires explicit confirmation', () {
    final scanScreen = File(
      'lib/features/scan/scan_screen.dart',
    ).readAsStringSync();
    final diagnostics = scanScreen.substring(
      scanScreen.indexOf('class _EngineUnavailableDiagnostics'),
      scanScreen.indexOf('class _DiagnosticChip'),
    );

    expect(diagnostics, contains('Future<void> _confirmRepairInstallation'));
    expect(diagnostics, contains('showDialog<bool>'));
    expect(diagnostics, contains('Avorax Core Service'));
    expect(diagnostics, contains('Windows administrator prompt'));
    expect(diagnostics, contains('trust this installed Avorax build'));
    expect(
      diagnostics,
      contains('Future<void> Function({bool confirmed}) onRepairInstallation'),
    );
    expect(
      diagnostics,
      contains('await onRepairInstallation(confirmed: true);'),
    );
    expect(
      diagnostics,
      isNot(contains('onPressed: () => onRepairInstallation()')),
    );
  });

  test('start core service action requires explicit confirmation', () {
    final scanScreen = File(
      'lib/features/scan/scan_screen.dart',
    ).readAsStringSync();
    final diagnostics = scanScreen.substring(
      scanScreen.indexOf('class _EngineUnavailableDiagnostics'),
      scanScreen.indexOf('class _DiagnosticChip'),
    );

    expect(diagnostics, contains('Future<void> _confirmStartCoreService'));
    expect(diagnostics, contains('Start Core Service?'));
    expect(diagnostics, contains('Windows administrator prompt'));
    expect(diagnostics, contains('does not install or reconfigure'));
    expect(
      diagnostics,
      contains('Future<void> Function({bool confirmed}) onStartCoreService'),
    );
    expect(diagnostics, contains('await onStartCoreService(confirmed: true);'));
    expect(
      diagnostics,
      isNot(contains('onPressed: () => onStartCoreService()')),
    );
  });

  test('open install report action requires explicit confirmation', () {
    final scanScreen = File(
      'lib/features/scan/scan_screen.dart',
    ).readAsStringSync();
    final diagnostics = scanScreen.substring(
      scanScreen.indexOf('class _EngineUnavailableDiagnostics'),
      scanScreen.indexOf('class _DiagnosticChip'),
    );

    expect(diagnostics, contains('Future<void> _confirmOpenInstallReport'));
    expect(diagnostics, contains('Open install report?'));
    expect(diagnostics, contains('Windows Explorer'));
    expect(diagnostics, contains('local Avorax installation metadata'));
    expect(diagnostics, contains('trust this installed Avorax build'));
    expect(
      diagnostics,
      contains('Future<void> Function({bool confirmed}) onOpenInstallReport'),
    );
    expect(
      diagnostics,
      contains('await onOpenInstallReport(confirmed: true);'),
    );
    expect(
      diagnostics,
      isNot(contains('onPressed: () => onOpenInstallReport()')),
    );
  });

  test('scan malicious feedback is disabled after quarantine recommendation', () {
    final scanScreen = readNormalizedSource(
      'lib/features/scan/scan_screen.dart',
    );

    expect(scanScreen, contains("label: 'Mark malicious'"));
    expect(
      scanScreen,
      contains(
        'threat.recommendedAction !=\n                            RecommendedAction.quarantine',
      ),
    );
  });

  test('malicious feedback requires explicit confirmation', () {
    final scanScreen = File(
      'lib/features/scan/scan_screen.dart',
    ).readAsStringSync();
    final threatRow = scanScreen.substring(
      scanScreen.indexOf('class _ThreatRow'),
      scanScreen.indexOf('class _Chip'),
    );

    expect(threatRow, contains('Submit malicious feedback?'));
    expect(threatRow, contains('future detection decisions only'));
    expect(threatRow, contains('does not quarantine, delete, execute'));
    expect(threatRow, contains('_confirmMaliciousFeedback(context)'));
    expect(threatRow, contains('markThreatMalicious(threat, confirmed: true)'));
    expect(
      threatRow,
      isNot(contains('controller.markThreatMalicious(threat)')),
    );
  });

  test('allowlist add action requires explicit confirmation', () {
    final scanScreen = File(
      'lib/features/scan/scan_screen.dart',
    ).readAsStringSync();
    final threatRow = scanScreen.substring(
      scanScreen.indexOf('class _ThreatRow'),
      scanScreen.indexOf('class _Chip'),
    );

    expect(threatRow, contains('Add to allowlist?'));
    expect(threatRow, contains('automatically quarantining this path'));
    expect(threatRow, contains('Only continue if you trust this file'));
    expect(threatRow, contains('_confirmAddToAllowlist(context)'));
    expect(
      threatRow,
      contains('addThreatToAllowlist(threat, confirmed: true)'),
    );
    expect(
      threatRow,
      isNot(contains('controller.addThreatToAllowlist(threat)')),
    );
  });

  test('allowlist remove action requires explicit confirmation', () {
    final allowlistScreen = File(
      'lib/features/allowlist/allowlist_screen.dart',
    ).readAsStringSync();

    expect(allowlistScreen, contains('Remove allowlist entry?'));
    expect(
      allowlistScreen,
      contains('resume normal scan and quarantine policy'),
    );
    expect(
      allowlistScreen,
      contains('_confirmRemove(context, controller, entry)'),
    );
    expect(
      allowlistScreen,
      contains('removeAllowlistEntry(entry, confirmed: true)'),
    );
    expect(allowlistScreen, isNot(contains('removeAllowlistEntry(entry);')));
  });

  test('false-positive feedback requires explicit confirmation', () {
    final scanScreen = File(
      'lib/features/scan/scan_screen.dart',
    ).readAsStringSync();
    final threatRow = scanScreen.substring(
      scanScreen.indexOf('class _ThreatRow'),
      scanScreen.indexOf('class _Chip'),
    );

    expect(threatRow, contains('Mark false positive?'));
    expect(threatRow, contains('suppress future detections'));
    expect(threatRow, contains('Only continue if you trust this file'));
    expect(threatRow, contains('_confirmFalsePositive(context)'));
    expect(
      threatRow,
      contains('markThreatFalsePositive(threat, confirmed: true)'),
    );
    expect(
      threatRow,
      isNot(contains('controller.markThreatFalsePositive(threat)')),
    );
  });

  test('settings scheduled scan copy is honest about app lifetime limits', () {
    final settingsScreen = File(
      'lib/features/settings/settings_screen.dart',
    ).readAsStringSync();

    expect(settingsScreen, contains('Scan scheduling'));
    expect(settingsScreen, contains('Runs detect-only quick scans'));
    expect(
      settingsScreen,
      contains('does not install a Windows scheduled task'),
    );
    expect(settingsScreen, contains('Best-effort app-lifetime schedule'));
    expect(settingsScreen, contains('scheduledIntervalPreset'));
    expect(settingsScreen, contains('Change scheduled quick scan?'));
    expect(settingsScreen, contains('recurring detect-only quick scans'));
    expect(settingsScreen, contains('_confirmScheduledQuickScanSettings('));
    expect(settingsScreen, contains('updateScheduledQuickScanSettings('));
    expect(settingsScreen, contains('confirmed: true'));
    expect(
      settingsScreen,
      isNot(
        contains(
          'onChanged: (enabled) =>\n                    controller.updateScheduledQuickScanSettings',
        ),
      ),
    );
  });

  test('settings reset configuration requires explicit confirmation', () {
    final settingsScreen = File(
      'lib/features/settings/settings_screen.dart',
    ).readAsStringSync();

    expect(settingsScreen, contains('Reset configuration?'));
    expect(settingsScreen, contains('local Avorax settings back to defaults'));
    expect(settingsScreen, contains('_confirmResetConfiguration(controller)'));
    expect(settingsScreen, contains('resetConfiguration(confirmed: true)'));
    expect(settingsScreen, isNot(contains('controller.resetConfiguration();')));
  });

  test('settings protection mode changes require explicit confirmation', () {
    final settingsScreen = File(
      'lib/features/settings/settings_screen.dart',
    ).readAsStringSync();

    expect(settingsScreen, contains('Change protection mode?'));
    expect(settingsScreen, contains('Avorax Guard behavior'));
    expect(
      settingsScreen,
      contains('_confirmProtectionMode(controller, mode)'),
    );
    expect(
      settingsScreen,
      contains('setProtectionMode(mode, confirmed: true)'),
    );
    expect(
      settingsScreen,
      isNot(contains('controller.setProtectionMode(mode)')),
    );
  });

  test('developer cloud override requires explicit confirmation', () {
    final settingsScreen = File(
      'lib/features/settings/settings_screen.dart',
    ).readAsStringSync();

    expect(settingsScreen, contains('Save developer cloud override?'));
    expect(settingsScreen, contains('Disable developer cloud override?'));
    expect(
      settingsScreen,
      contains('developer cloud endpoint and client credentials'),
    );
    expect(settingsScreen, contains('confirmed: true'));
    expect(
      settingsScreen,
      isNot(contains('publicClientKey: _publicKey.text,\n    );')),
    );
  });

  test('ransomware guard settings require explicit confirmation', () {
    final settingsScreen = File(
      'lib/features/settings/settings_screen.dart',
    ).readAsStringSync();

    expect(settingsScreen, contains('Save ransomware protection settings?'));
    expect(settingsScreen, contains('trusted process allowlist'));
    expect(
      settingsScreen,
      contains('_confirmRansomwareGuardSettings(controller)'),
    );
    expect(settingsScreen, contains('updateRansomwareGuardSettings('));
    expect(settingsScreen, contains('confirmed: true'));
  });

  test('detected protected app selection requires explicit confirmation', () {
    final protectedAppsScreen = File(
      'lib/features/protected_apps/protected_apps_screen.dart',
    ).readAsStringSync();

    expect(protectedAppsScreen, contains('Select protected app?'));
    expect(protectedAppsScreen, contains('adds its path to the scan scope'));
    expect(protectedAppsScreen, contains('_confirmSelectDetectedApp('));
    expect(
      protectedAppsScreen,
      contains('selectDetectedApp(app, confirmed: true)'),
    );
    expect(
      protectedAppsScreen,
      isNot(contains('onTap: () => controller.selectDetectedApp(app)')),
    );
  });

  test('manual protected app selection requires explicit confirmation', () {
    final protectedAppsScreen = File(
      'lib/features/protected_apps/protected_apps_screen.dart',
    ).readAsStringSync();

    expect(protectedAppsScreen, contains('Add protected app file?'));
    expect(protectedAppsScreen, contains('Add protected folder?'));
    expect(
      protectedAppsScreen,
      contains('choose the exact file or app in the system picker'),
    );
    expect(
      protectedAppsScreen,
      contains('choose the exact folder in the system picker'),
    );
    expect(
      protectedAppsScreen,
      contains('addManualProtectedAppFile(confirmed: true)'),
    );
    expect(
      protectedAppsScreen,
      contains('addManualProtectedAppFolder(confirmed: true)'),
    );
    expect(
      protectedAppsScreen,
      isNot(contains('onPressed: controller.addManualProtectedAppFile')),
    );
    expect(
      protectedAppsScreen,
      isNot(contains('onPressed: controller.addManualProtectedAppFolder')),
    );
  });

  test('protected app build hash requires explicit confirmation', () {
    final protectedAppsScreen = File(
      'lib/features/protected_apps/protected_apps_screen.dart',
    ).readAsStringSync();

    expect(protectedAppsScreen, contains('Calculate build hash?'));
    expect(protectedAppsScreen, contains('local verification evidence'));
    expect(protectedAppsScreen, contains('_confirmCalculateProtectedAppHash('));
    expect(
      protectedAppsScreen,
      contains('calculateProtectedAppHash(confirmed: true)'),
    );
    expect(
      protectedAppsScreen,
      isNot(
        contains(
          'onPressed: selected.isConfigured\n                        ? controller.calculateProtectedAppHash',
        ),
      ),
    );
  });

  test('shell exposes in-app notifications from real local events', () {
    final shell = File(
      'lib/shared/widgets/zentor_shell.dart',
    ).readAsStringSync();

    expect(shell, contains('_InAppNotification'));
    expect(shell, contains('_notificationEvent(state.events)'));
    expect(shell, contains('scan_completed'));
    expect(shell, contains('file_quarantined'));
    expect(shell, contains('update_install_ready'));
    expect(shell, contains('_notificationText'));
    expect(shell, contains('_notificationPriority'));
    expect(shell, contains('events.take(20)'));
    expect(shell, contains('maxLines: 1'));
    expect(shell, contains('maxNotificationChars'));
    expect(shell, contains(r"RegExp(r'[\x00-\x1F\x7F]+')"));
    expect(shell, contains('substring(0, maxNotificationChars - 3)'));
  });

  test('logs event details use readable separators', () {
    final logsScreen = File(
      'lib/features/logs/logs_screen.dart',
    ).readAsStringSync();

    expect(logsScreen, contains("_eventDetail"));
    expect(logsScreen, contains("' | "));
    expect(logsScreen, isNot(contains('â€¢')));
  });

  test('protection UI does not hard-code service running states', () {
    final protectionScreen = File(
      'lib/features/protection/protection_screen.dart',
    ).readAsStringSync();

    expect(
      protectionScreen,
      contains('_serviceLabel(state.coreServiceStatus)'),
    );
    expect(protectionScreen, contains('_startProtectionButtonLabel('));
    expect(protectionScreen, contains("return 'Protection Enabled'"));
    expect(protectionScreen, contains('return status.label'));
    expect(protectionScreen, contains('ProtectionStatus.partiallyProtected'));
    final explanation = protectionScreen.substring(
      protectionScreen.indexOf('String _protectionExplanation'),
      protectionScreen.indexOf('String _startProtectionButtonLabel'),
    );
    final nativeEngineHelper = protectionScreen.substring(
      protectionScreen.indexOf('String _nativeEngineChecklistLabel'),
      protectionScreen.indexOf('String _nativeRuleCountLabel'),
    );
    final nativePackHelpers = protectionScreen.substring(
      protectionScreen.indexOf('String _nativeRuleCountLabel'),
      protectionScreen.indexOf('String _quarantineReadinessLabel'),
    );
    final quarantineReadinessHelper = protectionScreen.substring(
      protectionScreen.indexOf('String _quarantineReadinessLabel'),
      protectionScreen.indexOf('String _preExecutionDriverValue'),
    );
    final nativeEngineDetail = protectionScreen.substring(
      protectionScreen.indexOf('String _nativeEngineProtectionDetail'),
      protectionScreen.indexOf('String _selfTestEvidenceLabel'),
    );
    expect(
      explanation,
      contains('if (_protectionEngineNeedsAttention(state))'),
    );
    expect(
      explanation,
      contains('state.malwareEngineStatus != MalwareEngineStatus.available'),
    );
    expect(
      explanation,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(nativeEngineDetail, contains('final engineDiagnostic'));
    expect(
      nativeEngineDetail,
      contains(r'Engine diagnostic: $engineDiagnostic'),
    );
    expect(
      nativeEngineDetail.indexOf('Engine diagnostic:'),
      lessThan(nativeEngineDetail.indexOf('Primary offline scanner')),
    );
    expect(
      protectionScreen,
      contains('value: _nativeEngineChecklistLabel(state)'),
    );
    expect(protectionScreen, contains("'Native Engine',"));
    expect(protectionScreen, contains('_nativeEngineChecklistLabel(state)'));
    expect(
      nativeEngineHelper,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(nativeEngineHelper, contains("return 'Attention needed'"));
    expect(
      nativeEngineHelper.indexOf('lastEngineError'),
      lessThan(nativeEngineHelper.indexOf('state.nativeEngineStatus')),
    );
    expect(nativePackHelpers, contains('required ZentorState state'));
    expect(nativePackHelpers, contains('final engineDiagnosticVisible'));
    expect(
      nativePackHelpers,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(
      nativePackHelpers,
      contains(
        "state.nativeEngineStatus == 'ready' && !engineDiagnosticVisible",
      ),
    );
    expect(
      quarantineReadinessHelper,
      contains('final engineDiagnosticVisible'),
    );
    expect(
      quarantineReadinessHelper,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(
      quarantineReadinessHelper,
      contains('if (!engineDiagnosticVisible &&'),
    );
    expect(
      explanation.indexOf('if (_protectionEngineNeedsAttention(state))'),
      lessThan(
        explanation.indexOf(
          'state.protectionStatus == ProtectionStatus.protected',
        ),
      ),
    );
    expect(
      protectionScreen,
      isNot(contains("_CheckRow('Core Service', 'Running')")),
    );
  });
  test('start and stop protection actions require explicit confirmation', () {
    final confirmation = File(
      'lib/features/protection/protection_confirmation.dart',
    ).readAsStringSync();
    final protectionScreen = File(
      'lib/features/protection/protection_screen.dart',
    ).readAsStringSync();
    final homeScreen = File(
      'lib/features/home/home_screen.dart',
    ).readAsStringSync();

    expect(confirmation, contains('Enable protection?'));
    expect(confirmation, contains('enables Avorax real-time monitoring'));
    expect(confirmation, contains('apply Guard policy'));
    expect(confirmation, contains('Stop protection?'));
    expect(confirmation, contains('turns off Avorax real-time monitoring'));
    expect(confirmation, contains('disable Guard policy'));
    expect(protectionScreen, contains('confirmStartProtection(context)'));
    expect(homeScreen, contains('confirmStartProtection(context)'));
    expect(protectionScreen, contains('startProtection(confirmed: true)'));
    expect(homeScreen, contains('startProtection(confirmed: true)'));
    expect(protectionScreen, contains('confirmStopProtection(context)'));
    expect(homeScreen, contains('confirmStopProtection(context)'));
    expect(protectionScreen, contains('stopProtection(confirmed: true)'));
    expect(homeScreen, contains('stopProtection(confirmed: true)'));
    expect(protectionScreen, isNot(contains(': controller.stopProtection')));
    expect(homeScreen, isNot(contains(': controller.stopProtection')));
  });
  test('protection preference is restored after app restart', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();

    expect(appState, contains('config.realtimeProtectionEnabled'));
    expect(appState, contains('_restoreProtectionAfterStartup'));
    expect(appState, contains('persistPreference: false'));
    expect(appState, contains('restoringSavedPreference: true'));
  });

  test('protection quick scan shortcut is detect only', () {
    final protectionScreen = File(
      'lib/features/protection/protection_screen.dart',
    ).readAsStringSync();

    expect(protectionScreen, contains("label: 'Run Quick Scan'"));
    expect(protectionScreen, contains('actionMode: ScanActionMode.detectOnly'));
    expect(protectionScreen, contains('state.scanTargetSelectionInFlight'));
    expect(protectionScreen, isNot(contains('controller.runQuickScan()')));
  });

  test('home protected headline requires ready engine evidence', () {
    final homeScreen = File(
      'lib/features/home/home_screen.dart',
    ).readAsStringSync();
    final mainStatus = homeScreen.substring(
      homeScreen.indexOf('String _mainStatus'),
      homeScreen.indexOf('String _headline'),
    );
    final heroCopy = homeScreen.substring(
      homeScreen.indexOf('String _heroCopy'),
      homeScreen.indexOf('Color _mainColor'),
    );
    final metricHelpers = homeScreen.substring(
      homeScreen.indexOf('String _realTimeProtectionValue'),
      homeScreen.indexOf('String _headline'),
    );
    final nativeEngineHelpers = homeScreen.substring(
      homeScreen.indexOf('String _nativeEngineLabel'),
      homeScreen.indexOf('String _guardLabel'),
    );
    final nativeRuleHelper = homeScreen.substring(
      homeScreen.indexOf('String _nativeRuleCountLabel'),
      homeScreen.indexOf('String _preExecutionDriverValue'),
    );

    expect(mainStatus, contains('if (_engineNeedsAttention(state))'));
    expect(mainStatus, contains("state.nativeEngineStatus != 'ready'"));
    expect(
      mainStatus,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(
      mainStatus.indexOf('if (_engineNeedsAttention(state))'),
      lessThan(
        mainStatus.indexOf(
          'state.protectionStatus == ProtectionStatus.protected',
        ),
      ),
    );
    expect(homeScreen, contains('value: _realTimeProtectionValue(state)'));
    expect(homeScreen, contains('detail: _realTimeProtectionDetail(state)'));
    expect(
      metricHelpers,
      contains("if (_engineNeedsAttention(state)) return 'Attention needed'"),
    );
    expect(homeScreen, contains('value: _nativeEngineLabel(state)'));
    expect(homeScreen, contains('detail: _nativeEngineDetail(state)'));
    expect(
      nativeEngineHelpers,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(nativeEngineHelpers, contains("return 'Attention needed'"));
    expect(nativeEngineHelpers, contains(r'Engine diagnostic: $diagnostic'));
    expect(
      nativeEngineHelpers.indexOf('lastEngineError'),
      lessThan(nativeEngineHelpers.indexOf("state.nativeEngineStatus")),
    );
    expect(nativeRuleHelper, contains('final engineDiagnosticVisible'));
    expect(
      nativeRuleHelper,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(
      nativeRuleHelper,
      contains(
        "state.nativeEngineStatus == 'ready' && !engineDiagnosticVisible",
      ),
    );
    expect(
      nativeRuleHelper.indexOf('final engineDiagnosticVisible'),
      lessThan(
        nativeRuleHelper.indexOf(
          "state.nativeEngineStatus == 'ready' && !engineDiagnosticVisible",
        ),
      ),
    );
    expect(metricHelpers, contains('ProtectionStatus.partiallyProtected'));
    expect(metricHelpers, contains("return 'Limited'"));
    expect(
      heroCopy.indexOf("if (status == 'Attention needed')"),
      lessThan(
        heroCopy.indexOf(
          'state.protectionStatus == ProtectionStatus.localOnly',
        ),
      ),
    );
  });

  test('settings antivirus label requires ready engine evidence', () {
    final settingsScreen = File(
      'lib/features/settings/settings_screen.dart',
    ).readAsStringSync();
    final helperSource = settingsScreen.substring(
      settingsScreen.indexOf('String _settingsProtectionStatusLabel'),
      settingsScreen.indexOf('String _guardLabel'),
    );
    final nativeStatusHelper = settingsScreen.substring(
      settingsScreen.indexOf('String _nativeEngineLabel'),
      settingsScreen.indexOf('String _ipcModeLabel'),
    );
    final nativePackagedHelper = settingsScreen.substring(
      settingsScreen.indexOf('String _nativePackagedCountLabel'),
      settingsScreen.indexOf('String _featureSchemaLabel'),
    );

    expect(
      settingsScreen,
      contains("_ValueRow('Antivirus', _settingsProtectionStatusLabel(state))"),
    );
    expect(helperSource, contains('if (_settingsEngineNeedsAttention(state))'));
    expect(
      helperSource,
      contains('state.malwareEngineStatus != MalwareEngineStatus.available'),
    );
    expect(helperSource, contains("state.nativeEngineStatus != 'ready'"));
    expect(
      helperSource,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(
      settingsScreen,
      contains('final engineDiagnostic = state.lastEngineError?.trim();'),
    );
    expect(
      settingsScreen,
      contains("_ValueRow('Engine diagnostic', engineDiagnostic!)"),
    );
    expect(settingsScreen, contains("_nativeEngineLabel(state)"));
    expect(
      nativeStatusHelper,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(nativeStatusHelper, contains("return 'Attention needed'"));
    expect(
      nativeStatusHelper.indexOf('lastEngineError'),
      lessThan(nativeStatusHelper.indexOf('state.nativeEngineStatus')),
    );
    expect(settingsScreen, contains('state: state'));
    expect(nativePackagedHelper, contains('final engineDiagnosticVisible'));
    expect(
      nativePackagedHelper,
      contains("state.lastEngineError?.trim().isNotEmpty ?? false"),
    );
    expect(
      nativePackagedHelper,
      contains(
        "state.nativeEngineStatus == 'ready' && !engineDiagnosticVisible",
      ),
    );
    expect(
      helperSource.indexOf('if (_settingsEngineNeedsAttention(state))'),
      lessThan(helperSource.indexOf('return state.protectionStatus.label')),
    );
  });

  test('controller protected state requires ready engine evidence', () {
    final appState = readNormalizedSource('lib/app/app_state.dart');
    final startProtection = appState.substring(
      appState.indexOf('Future<void> startProtection'),
      appState.indexOf('Future<void> stopProtection'),
    );

    expect(startProtection, contains('final engineFullyReady'));
    expect(startProtection, contains('final engineDiagnosticWarning'));
    expect(
      startProtection,
      contains('final nativeEngineReadyWithoutDiagnostic'),
    );
    expect(startProtection, contains('Engine diagnostics require attention:'));
    expect(
      startProtection,
      contains('state.malwareEngineStatus == MalwareEngineStatus.available'),
    );
    expect(startProtection, contains("state.nativeEngineStatus == 'ready'"));
    expect(startProtection, contains('engineDiagnosticWarning == null'));
    expect(startProtection, contains('nativeEngineReadyWithoutDiagnostic ||'));
    expect(
      startProtection,
      contains(
        'state.malwareEngineStatus == MalwareEngineStatus.available &&\n'
        '              nativeEngineReadyWithoutDiagnostic',
      ),
    );
    expect(startProtection, contains('final preventionFailureDetails'));
    expect(startProtection, contains('?engineDiagnosticWarning'));
    expect(startProtection, contains('final serviceBoundaryReady'));
    expect(startProtection, contains('!Platform.isWindows ||'));
    expect(
      startProtection,
      contains('state.coreServiceBoundaryHealth.fullProtectionReady'),
    );
    expect(
      startProtection,
      contains(
        "state.driverStatus == 'running' &&\n"
        '                    engineFullyReady &&\n'
        '                    serviceBoundaryReady',
      ),
    );
    expect(
      startProtection.indexOf('final engineDiagnosticWarning'),
      lessThan(startProtection.indexOf('final hasLocalPrevention')),
    );
    expect(
      startProtection.indexOf('final engineFullyReady'),
      lessThan(startProtection.indexOf('ProtectionStatus.protected')),
    );
    expect(
      startProtection.indexOf('final serviceBoundaryReady'),
      lessThan(startProtection.indexOf('ProtectionStatus.protected')),
    );
  });

  test('controller logs limited protection starts distinctly', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final startProtection = appState.substring(
      appState.indexOf('Future<void> startProtection'),
      appState.indexOf('Future<void> stopProtection'),
    );
    final limitedLogStart = startProtection.indexOf(
      'await logEvent(',
      startProtection.indexOf('final startWarning'),
    );

    expect(startProtection, contains('final startWarning'));
    expect(startProtection, contains('final engineDiagnosticWarning'));
    expect(startProtection, contains("'protection_start_limited'"));
    expect(startProtection, contains("'Protection started with limitations'"));
    expect(
      startProtection,
      contains("severity: startWarning.isEmpty ? 'info' : 'warning'"),
    );
    expect(
      startProtection.indexOf('final startWarning'),
      lessThan(startProtection.indexOf("'protection_start_limited'")),
    );
    expect(
      startProtection.indexOf('final engineDiagnosticWarning'),
      lessThan(startProtection.indexOf('final startWarning')),
    );
    expect(
      limitedLogStart,
      greaterThan(startProtection.indexOf('final modeWarning')),
    );
    final restoreStart = startProtection.substring(
      startProtection.indexOf("'protection_restore_start_requested'"),
      startProtection.indexOf('var configForStart'),
    );
    expect(restoreStart, contains("category: 'protection'"));
    expect(
      restoreStart,
      contains("severity: restoringSavedPreference ? 'warning' : 'info'"),
    );
    final engineUnavailableFailure = startProtection.substring(
      startProtection.lastIndexOf("'protection_start_failed'"),
      startProtection.indexOf(
        'state = state.copyWith(',
        startProtection.lastIndexOf("'protection_start_failed'"),
      ),
    );
    expect(engineUnavailableFailure, contains("category: 'protection'"));
    expect(engineUnavailableFailure, contains("severity: 'error'"));
  });

  test('controller logs successful protection stops as protection events', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final stopProtection = appState.substring(
      appState.indexOf('Future<void> stopProtection'),
      appState.indexOf('Future<bool> setProtectionMode'),
    );
    final stoppedEventStart = stopProtection.indexOf("'protection_stopped'");
    final stoppedEvent = stopProtection.substring(
      stoppedEventStart,
      stopProtection.indexOf('state = state.copyWith(', stoppedEventStart),
    );

    expect(stoppedEvent, contains("'Protection stopped'"));
    expect(
      stoppedEvent,
      contains(
        'Guard mode disabled and real-time folder monitoring stopped locally.',
      ),
    );
    expect(stoppedEvent, contains("category: 'protection'"));
    expect(stoppedEvent, contains("severity: 'info'"));
  });

  test(
    'controller protection restore and mode-change events are categorized',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final restore = appState.substring(
        appState.indexOf('Future<void> _restoreProtectionAfterStartup'),
        appState.indexOf('Future<void> logEvent'),
      );
      final modeChange = appState.substring(
        appState.indexOf('Future<bool> setProtectionMode'),
        appState.indexOf('Future<bool> updateRansomwareGuardSettings'),
      );
      final restoreEvent = restore.substring(
        restore.indexOf("'protection_restore_requested'"),
        restore.indexOf(
          ');',
          restore.indexOf("'protection_restore_requested'"),
        ),
      );
      expect(restoreEvent, contains("category: 'protection'"));
      expect(restoreEvent, contains("severity: 'warning'"));
      final changedEvent = modeChange.substring(
        modeChange.indexOf("'protection_mode_changed'"),
        modeChange.indexOf(
          'state = state.copyWith(',
          modeChange.indexOf("'protection_mode_changed'"),
        ),
      );
      expect(changedEvent, contains("category: 'protection'"));
      expect(changedEvent, contains("severity: 'warning'"));
    },
  );

  test('controller scheduled scan and heartbeat events are categorized', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final scheduledSettings = appState.substring(
      appState.indexOf('Future<bool> updateScheduledQuickScanSettings({'),
      appState.indexOf(
        'void _configureScheduledQuickScan(ZentorConfig config)',
      ),
    );
    final scheduledRun = appState.substring(
      appState.indexOf('Future<void> _runScheduledQuickScan() async {'),
      appState.indexOf('List<String> _normalizeUserPaths'),
    );
    final heartbeat = appState.substring(
      appState.indexOf('Future<void> sendHeartbeat'),
      appState.indexOf('Future<void> scanSelectedFile'),
    );

    final changed = scheduledSettings.substring(
      scheduledSettings.indexOf("'scheduled_quick_scan_settings_changed'"),
      scheduledSettings.indexOf(
        'state = state.copyWith(',
        scheduledSettings.indexOf("'scheduled_quick_scan_settings_changed'"),
      ),
    );
    expect(changed, contains("category: 'scan'"));
    expect(changed, contains("severity: 'warning'"));
    final started = scheduledRun.substring(
      scheduledRun.indexOf("'scheduled_quick_scan_started'"),
      scheduledRun.indexOf(
        ');',
        scheduledRun.indexOf("'scheduled_quick_scan_started'"),
      ),
    );
    expect(started, contains("category: 'scan'"));
    expect(scheduledRun, contains('final scheduledScanDiagnostic'));
    expect(
      scheduledRun,
      contains('state.lastEngineError?.trim().isEmpty ?? true'),
    );
    expect(scheduledRun, contains('Engine diagnostics require attention:'));
    expect(started, contains('details: scheduledScanDiagnostic'));
    expect(
      started,
      contains(
        "severity: scheduledScanDiagnostic == null ? 'info' : 'warning'",
      ),
    );
    expect(
      scheduledRun.indexOf('final scheduledScanDiagnostic'),
      lessThan(scheduledRun.indexOf("'scheduled_quick_scan_started'")),
    );
    final sent = heartbeat.substring(
      heartbeat.indexOf("'heartbeat_sent'"),
      heartbeat.indexOf(');', heartbeat.indexOf("'heartbeat_sent'")),
    );
    expect(sent, contains("category: 'protection'"));
    expect(sent, contains("severity: 'info'"));
    final failed = heartbeat.substring(
      heartbeat.indexOf("'heartbeat_failed'"),
      heartbeat.indexOf(');', heartbeat.indexOf("'heartbeat_failed'")),
    );
    expect(failed, contains("category: 'protection'"));
    expect(failed, contains("severity: 'warning'"));
  });

  test('controller onboarding and cloud events are categorized', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final onboarding = appState.substring(
      appState.indexOf('Future<bool> completeOnboarding'),
      appState.indexOf('Future<void> unawaitedCheckCloud'),
    );
    final cloud = appState.substring(
      appState.indexOf('Future<void> unawaitedCheckCloud'),
      appState.indexOf('Future<void> testCloudConnection'),
    );

    final onboardingFailed = onboarding.substring(
      onboarding.indexOf("'onboarding_save_failed'"),
      onboarding.indexOf(');', onboarding.indexOf("'onboarding_save_failed'")),
    );
    expect(onboardingFailed, contains("category: 'app'"));
    expect(onboardingFailed, contains("severity: 'error'"));
    for (final eventName in ['cloud_health_check_started', 'cloud_online']) {
      final eventSource = cloud.substring(
        cloud.indexOf("'$eventName'"),
        cloud.indexOf(');', cloud.indexOf("'$eventName'")),
      );
      expect(eventSource, contains("category: 'settings'"));
      expect(eventSource, contains("severity: 'info'"));
    }
    final offline = cloud.substring(
      cloud.indexOf("'cloud_offline'"),
      cloud.indexOf(');', cloud.indexOf("'cloud_offline'")),
    );
    expect(offline, contains("category: 'settings'"));
    expect(offline, contains("severity: 'warning'"));
  });

  test('controller local event calls declare category and severity', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final matches = RegExp(r'\blogEvent\(').allMatches(appState);

    for (final match in matches) {
      final prefixStart = match.start < 24 ? 0 : match.start - 24;
      final prefix = appState.substring(prefixStart, match.start);
      if (prefix.contains('Future<void> ')) continue;
      final eventSource = appState.substring(
        match.start,
        appState.indexOf(');', match.start),
      );
      expect(eventSource, contains('category:'));
      expect(eventSource, contains('severity:'));
    }
  });

  test('controller update events are categorized by outcome severity', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final updateSource = appState.substring(
      appState.indexOf('Future<void> unawaitedCheckForUpdates'),
      appState.indexOf('bool _isUpdateOperationBusy'),
    );

    for (final eventName in [
      'update_check_failed',
      'update_install_failed',
      'update_rollback_failed',
    ]) {
      final eventSource = updateSource.substring(
        updateSource.indexOf("'$eventName'"),
        updateSource.indexOf(');', updateSource.indexOf("'$eventName'")),
      );
      expect(eventSource, contains("category: 'update'"));
      expect(eventSource, contains("severity: 'error'"));
    }
    for (final eventName in [
      'update_action_busy',
      'update_available',
      'update_install_started',
      'update_install_confirmation_required',
      'update_install_ready',
      'update_rollback_unavailable',
      'update_rollback_confirmation_required',
      'update_rollback_started',
      'update_rollback_ready',
    ]) {
      final eventSource = updateSource.substring(
        updateSource.indexOf("'$eventName'"),
        updateSource.indexOf(');', updateSource.indexOf("'$eventName'")),
      );
      expect(eventSource, contains("category: 'update'"));
      expect(eventSource, contains("severity: 'warning'"));
    }
    for (final eventName in [
      'update_check_started',
      'update_check_completed',
    ]) {
      final eventSource = updateSource.substring(
        updateSource.indexOf("'$eventName'"),
        updateSource.indexOf(');', updateSource.indexOf("'$eventName'")),
      );
      expect(eventSource, contains("category: 'update'"));
      expect(eventSource, contains("severity: 'info'"));
    }
    expect(updateSource, contains("category: 'update'"));
  });

  test('controller scan events are categorized by outcome severity', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final scanSource = appState.substring(
      appState.indexOf('Future<void> _scanPaths'),
      appState.indexOf('String _engineUnavailableMessage'),
    );

    expect(scanSource, contains("'scan_started'"));
    final startedEvent = scanSource.substring(
      scanSource.indexOf("'scan_started'"),
      scanSource.indexOf('_scanCancelled = false'),
    );
    expect(startedEvent, contains("category: 'scan'"));
    expect(startedEvent, contains("'scan_started_with_limitations'"));
    expect(scanSource, contains('final engineDiagnosticLimitation'));
    expect(
      scanSource,
      contains('state.lastEngineError?.trim().isEmpty ?? true'),
    );
    expect(scanSource, contains('Engine diagnostics require attention:'));
    expect(scanSource, contains('?engineDiagnosticLimitation'));
    expect(
      startedEvent,
      contains("severity: scanStartLimitations.isEmpty ? 'info' : 'warning'"),
    );
    expect(
      scanSource.indexOf('final engineDiagnosticLimitation'),
      lessThan(scanSource.indexOf('final scanStartLimitations')),
    );
    expect(
      scanSource.indexOf('?engineDiagnosticLimitation'),
      lessThan(scanSource.indexOf("'scan_started'")),
    );
    for (final eventName in ['scan_failed']) {
      final matches = RegExp("'$eventName'").allMatches(scanSource);
      expect(matches, isNotEmpty);
      for (final match in matches) {
        final eventSource = scanSource.substring(
          match.start,
          scanSource.indexOf(');', match.start),
        );
        expect(eventSource, contains("category: 'scan'"));
        expect(eventSource, contains("severity: 'error'"));
      }
    }
    final completedEvent = scanSource.substring(
      scanSource.indexOf("'scan_completed'"),
      scanSource.indexOf(
        'state = state.copyWith(',
        scanSource.indexOf("'scan_completed'"),
      ),
    );
    expect(
      scanSource.indexOf(
        'final scanErrorMessage = _scanCoverageWarning(report)',
      ),
      lessThan(scanSource.indexOf("'scan_completed'")),
    );
    expect(completedEvent, contains("'Scan completed with errors'"));
    expect(completedEvent, contains("category: 'scan'"));
    expect(
      completedEvent,
      contains("severity: scanErrorMessage == null ? 'info' : 'warning'"),
    );
    expect(
      completedEvent,
      contains(
        'details: _scanEventDetails(report, coverageWarning: scanErrorMessage)',
      ),
    );
    expect(appState, contains('coverageWarning ?? report.message'));
  });

  test(
    'controller custom scan picker and no-target events are categorized',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final filePicker = appState.substring(
        appState.indexOf('Future<void> scanSelectedFile'),
        appState.indexOf('Future<void> scanSelectedFolder'),
      );
      final folderPicker = appState.substring(
        appState.indexOf('Future<void> scanSelectedFolder'),
        appState.indexOf('Future<void> runQuickScan'),
      );
      final quickScan = appState.substring(
        appState.indexOf('Future<void> runQuickScan'),
        appState.indexOf('Future<void> runFullScan'),
      );

      for (final eventName in [
        'scan_file_picker_failed',
        'scan_folder_picker_failed',
      ]) {
        final source = eventName == 'scan_file_picker_failed'
            ? filePicker
            : folderPicker;
        final eventSource = source.substring(
          source.indexOf("'$eventName'"),
          source.indexOf(');', source.indexOf("'$eventName'")),
        );
        expect(eventSource, contains("category: 'scan'"));
        expect(eventSource, contains("severity: 'error'"));
      }
      final noTargetCompleted = quickScan.substring(
        quickScan.indexOf("'scan_completed'"),
        quickScan.indexOf('state = state.copyWith('),
      );
      expect(
        noTargetCompleted,
        contains('No quick scan locations were accessible.'),
      );
      expect(noTargetCompleted, contains("category: 'scan'"));
      expect(noTargetCompleted, contains("severity: 'warning'"));
    },
  );

  test('controller scan cancellation events are categorized', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final cancelScan = appState.substring(
      appState.indexOf('Future<void> cancelScan'),
      appState.indexOf('void _replaceThreat'),
    );

    final ignoredEvent = cancelScan.substring(
      cancelScan.indexOf("'scan_cancel_ignored'"),
      cancelScan.indexOf(');', cancelScan.indexOf("'scan_cancel_ignored'")),
    );
    expect(ignoredEvent, contains("category: 'scan'"));
    expect(ignoredEvent, contains("severity: 'warning'"));

    final cancelledEvent = cancelScan.substring(
      cancelScan.indexOf("'scan_cancelled'"),
      cancelScan.indexOf(');', cancelScan.indexOf("'scan_cancelled'")),
    );
    expect(cancelledEvent, contains("category: 'scan'"));
    expect(
      cancelledEvent,
      contains("severity: warning == null ? 'info' : 'warning'"),
    );

    final failedEvent = cancelScan.substring(
      cancelScan.indexOf("'scan_cancel_failed'"),
      cancelScan.indexOf(');', cancelScan.indexOf("'scan_cancel_failed'")),
    );
    expect(failedEvent, contains("category: 'scan'"));
    expect(failedEvent, contains("severity: 'error'"));
  });

  test('controller settings events are categorized', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final developerCloud = appState.substring(
      appState.indexOf('Future<bool> saveDeveloperCloudOverride'),
      appState.indexOf('Future<void> unawaitedDetectApps'),
    );
    final exportLogs = appState.substring(
      appState.indexOf('Future<String?> exportLogs'),
      appState.indexOf('Future<bool> resetConfiguration'),
    );
    final resetConfiguration = appState.substring(
      appState.indexOf('Future<bool> resetConfiguration'),
      appState.indexOf('AppVerificationStatus _verificationStatusFor'),
    );

    void expectEventMetadata(String source, String eventName, String severity) {
      final matches = RegExp("'$eventName'").allMatches(source);
      expect(matches, isNotEmpty);
      for (final match in matches) {
        final eventSource = source.substring(
          match.start,
          source.indexOf(');', match.start),
        );
        expect(eventSource, contains("category: 'settings'"));
        expect(eventSource, contains("severity: '$severity'"));
      }
    }

    expectEventMetadata(
      developerCloud,
      'developer_cloud_override_confirmation_required',
      'warning',
    );
    expectEventMetadata(developerCloud, 'configuration_saved', 'warning');
    expectEventMetadata(developerCloud, 'configuration_save_failed', 'error');
    expectEventMetadata(
      exportLogs,
      'logs_export_confirmation_required',
      'warning',
    );
    expectEventMetadata(exportLogs, 'logs_exported', 'info');
    expectEventMetadata(exportLogs, 'logs_export_failed', 'error');
    expectEventMetadata(
      resetConfiguration,
      'configuration_reset_confirmation_required',
      'warning',
    );
    expectEventMetadata(resetConfiguration, 'configuration_reset', 'warning');
    expectEventMetadata(
      resetConfiguration,
      'configuration_reset_failed',
      'error',
    );
  });

  test(
    'controller app detection and malware health events are categorized',
    () {
      final appState = File('lib/app/app_state.dart').readAsStringSync();
      final appDetection = appState.substring(
        appState.indexOf('Future<void> unawaitedDetectApps'),
        appState.indexOf('Future<void> unawaitedCheckMalwareEngine'),
      );
      final malwareHealth = appState.substring(
        appState.indexOf('Future<void> unawaitedCheckMalwareEngine'),
        appState.indexOf('Future<void> unawaitedRefreshQuarantine'),
      );
      final processSnapshotHelper = appState.substring(
        appState.indexOf('Future<void> _evaluateProcessSnapshot({'),
        appState.indexOf('String? _startProcessSnapshotLoop'),
      );

      void expectEventMetadata(
        String source,
        String eventName,
        String severity,
      ) {
        final matches = RegExp("'$eventName'").allMatches(source);
        expect(matches, isNotEmpty);
        for (final match in matches) {
          final eventSource = source.substring(
            match.start,
            source.indexOf(');', match.start),
          );
          expect(eventSource, contains("category: 'protection'"));
          expect(eventSource, contains("severity: '$severity'"));
        }
      }

      expectEventMetadata(appDetection, 'app_detection_disabled', 'warning');
      expectEventMetadata(appDetection, 'app_detection_started', 'info');
      expectEventMetadata(appDetection, 'no_supported_app_detected', 'warning');
      expectEventMetadata(appDetection, 'protected_app_detected', 'info');
      expectEventMetadata(appDetection, 'app_detection_failed', 'error');
      expect(appDetection, contains("emptyType: 'process_snapshot_empty'"));
      expect(appDetection, contains("emptySeverity: 'warning'"));
      expect(appDetection, contains('process_snapshot_suspicious'));
      expect(appDetection, contains('process_snapshot_evaluated'));
      expect(appDetection, contains("failedType: 'process_snapshot_failed'"));
      expect(processSnapshotHelper, contains("category: 'protection'"));
      expect(processSnapshotHelper, contains('severity: emptySeverity'));
      expect(processSnapshotHelper, contains('final eventSeverity'));
      expect(processSnapshotHelper, contains("findingCount > 0 ? 'warning'"));
      expect(processSnapshotHelper, contains('severity: eventSeverity'));
      expect(
        processSnapshotHelper,
        contains('_shouldSkipRepeatedProcessSnapshotRoutineEvent'),
      );
      expect(processSnapshotHelper, contains("severity: 'warning'"));

      final engineEventStart = malwareHealth.indexOf(
        'final healthEventSeverity',
      );
      final engineEventEnd = engineEventStart + 1400 > malwareHealth.length
          ? malwareHealth.length
          : engineEventStart + 1400;
      final engineEvent = malwareHealth.substring(
        engineEventStart,
        engineEventEnd,
      );
      expect(engineEvent, contains("category: 'protection'"));
      expect(
        engineEvent,
        contains(
          "status == MalwareEngineStatus.available && healthDetails.isEmpty",
        ),
      );
      expect(malwareHealth, contains('.map((detail) => detail.trim())'));
      expect(malwareHealth, contains('lastEngineError: healthDetails'));
      expect(
        malwareHealth,
        contains('clearLastEngineError: healthDetails.isEmpty'),
      );
      expect(engineEvent, contains("severity: healthEventSeverity"));
      expectEventMetadata(
        malwareHealth,
        'malware_engine_health_failed',
        'error',
      );
    },
  );

  test('protected apps screen surfaces process snapshot event evidence', () {
    final protectedAppsScreen = File(
      'lib/features/protected_apps/protected_apps_screen.dart',
    ).readAsStringSync();

    expect(protectedAppsScreen, contains('Process snapshot evidence'));
    expect(
      protectedAppsScreen,
      contains('_latestProcessSnapshotEvent(state.events)'),
    );
    expect(protectedAppsScreen, contains('event.createdAt.isAfter'));
    expect(
      protectedAppsScreen,
      contains("'process_snapshot_suspicious' => 'Suspicious'"),
    );
    expect(
      protectedAppsScreen,
      contains("'process_snapshot_loop_suspicious' => 'Suspicious'"),
    );
    expect(
      protectedAppsScreen,
      contains("'process_snapshot_evaluated' => 'Evaluated'"),
    );
    expect(
      protectedAppsScreen,
      contains("'process_snapshot_loop_evaluated' => 'Evaluated'"),
    );
    expect(
      protectedAppsScreen,
      contains("'process_snapshot_failed' => 'Failed'"),
    );
    expect(
      protectedAppsScreen,
      contains("'process_snapshot_loop_failed' => 'Failed'"),
    );
    expect(
      protectedAppsScreen,
      contains('active protection in this local event history'),
    );
    expect(protectedAppsScreen, contains('maxLines: 3'));
  });

  test('controller service recovery events are categorized', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final startCoreService = appState.substring(
      appState.indexOf('Future<void> startCoreService'),
      appState.indexOf('Future<void> openInstallReport'),
    );
    final installReport = appState.substring(
      appState.indexOf('Future<void> openInstallReport'),
      appState.indexOf('Future<void> repairInstallation'),
    );
    final repair = appState.substring(
      appState.indexOf('Future<void> repairInstallation'),
      appState.indexOf('Future<bool> addManualProtectedAppFile'),
    );

    void expectEventMetadata(String source, String eventName, String severity) {
      final matches = RegExp("'$eventName'").allMatches(source);
      expect(matches, isNotEmpty);
      for (final match in matches) {
        final end = match.start + 900 > source.length
            ? source.length
            : match.start + 900;
        final eventSource = source.substring(match.start, end);
        expect(eventSource, contains("category: 'protection'"));
        expect(eventSource, contains("severity: '$severity'"));
      }
    }

    expectEventMetadata(
      startCoreService,
      'core_service_start_confirmation_required',
      'warning',
    );
    expectEventMetadata(
      startCoreService,
      'core_service_start_requested',
      'warning',
    );
    expectEventMetadata(startCoreService, 'core_service_start_failed', 'error');
    expectEventMetadata(
      installReport,
      'install_report_open_confirmation_required',
      'warning',
    );
    expectEventMetadata(
      installReport,
      'install_report_open_requested',
      'warning',
    );
    expectEventMetadata(installReport, 'install_report_open_failed', 'error');
    expectEventMetadata(
      repair,
      'installation_repair_confirmation_required',
      'warning',
    );
    expectEventMetadata(repair, 'installation_repair_requested', 'warning');
    expectEventMetadata(repair, 'installation_repair_failed', 'error');
  });

  test('controller protected app mutation events are categorized', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final manualFile = appState.substring(
      appState.indexOf('Future<bool> addManualProtectedAppFile'),
      appState.indexOf('Future<bool> addManualProtectedAppFolder'),
    );
    final manualFolder = appState.substring(
      appState.indexOf('Future<bool> addManualProtectedAppFolder'),
      appState.indexOf('Future<bool> selectDetectedApp'),
    );
    final selectDetected = appState.substring(
      appState.indexOf('Future<bool> selectDetectedApp'),
      appState.indexOf('Future<bool> _saveManualAppPath'),
    );
    final saveManual = appState.substring(
      appState.indexOf('Future<bool> _saveManualAppPath'),
      appState.indexOf('Future<bool> calculateProtectedAppHash'),
    );
    final hash = appState.substring(
      appState.indexOf('Future<bool> calculateProtectedAppHash'),
      appState.indexOf('Future<void> startProtection'),
    );

    void expectEventMetadata(String source, String eventName, String severity) {
      final matches = RegExp("'$eventName'").allMatches(source);
      expect(matches, isNotEmpty);
      for (final match in matches) {
        final eventSource = source.substring(
          match.start,
          source.indexOf(');', match.start),
        );
        expect(eventSource, contains("category: 'protection'"));
        expect(eventSource, contains("severity: '$severity'"));
      }
    }

    expectEventMetadata(
      manualFile,
      'manual_protected_app_selection_confirmation_required',
      'warning',
    );
    expectEventMetadata(
      manualFile,
      'manual_protected_app_file_unavailable',
      'warning',
    );
    expectEventMetadata(
      manualFile,
      'manual_protected_app_file_failed',
      'error',
    );
    expectEventMetadata(
      manualFolder,
      'manual_protected_app_selection_confirmation_required',
      'warning',
    );
    expectEventMetadata(
      manualFolder,
      'manual_protected_app_folder_unavailable',
      'warning',
    );
    expectEventMetadata(
      manualFolder,
      'manual_protected_app_folder_failed',
      'error',
    );
    expectEventMetadata(
      selectDetected,
      'protected_app_selection_confirmation_required',
      'warning',
    );
    expectEventMetadata(selectDetected, 'protected_app_selected', 'warning');
    expectEventMetadata(selectDetected, 'protected_app_select_failed', 'error');
    expectEventMetadata(saveManual, 'protected_app_added_manually', 'warning');
    expectEventMetadata(
      hash,
      'protected_app_hash_confirmation_required',
      'warning',
    );
    expectEventMetadata(hash, 'protected_app_hash_no_target', 'warning');
    expectEventMetadata(hash, 'protected_app_hash_path_probe_failed', 'error');
    expectEventMetadata(hash, 'protected_app_hash_unavailable', 'warning');
    expectEventMetadata(hash, 'file_hash_calculated', 'warning');
    expectEventMetadata(hash, 'file_hash_failed', 'error');
  });

  test('controller quarantine and allowlist events are categorized', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final quarantineThreat = appState.substring(
      appState.indexOf('Future<void> quarantineThreat'),
      appState.indexOf('Future<void> ignoreThreat'),
    );
    final addAllowlist = appState.substring(
      appState.indexOf('Future<void> addThreatToAllowlist'),
      appState.indexOf('Future<void> removeAllowlistEntry'),
    );
    final removeAllowlist = appState.substring(
      appState.indexOf('Future<void> removeAllowlistEntry'),
      appState.indexOf('Future<void> restoreQuarantineItem'),
    );
    final restore = appState.substring(
      appState.indexOf('Future<void> restoreQuarantineItem'),
      appState.indexOf('Future<void> deleteQuarantineItem'),
    );
    final delete = appState.substring(
      appState.indexOf('Future<void> deleteQuarantineItem'),
      appState.indexOf('void _replaceQuarantineRecordStatus'),
    );

    void expectEventMetadata(
      String source,
      String eventName,
      String category,
      String severity,
    ) {
      final matches = RegExp("'$eventName'").allMatches(source);
      expect(matches, isNotEmpty);
      for (final match in matches) {
        final eventSource = source.substring(
          match.start,
          source.indexOf(');', match.start),
        );
        expect(eventSource, contains("category: '$category'"));
        expect(eventSource, contains("severity: '$severity'"));
      }
    }

    expectEventMetadata(
      quarantineThreat,
      'quarantine_failed',
      'quarantine',
      'error',
    );
    expectEventMetadata(
      quarantineThreat,
      'file_quarantined',
      'quarantine',
      'warning',
    );
    expectEventMetadata(
      addAllowlist,
      'allowlist_entry_add_failed',
      'protection',
      'error',
    );
    expectEventMetadata(
      addAllowlist,
      'allowlist_entry_added',
      'protection',
      'warning',
    );
    expectEventMetadata(
      removeAllowlist,
      'allowlist_entry_remove_failed',
      'protection',
      'error',
    );
    expectEventMetadata(
      removeAllowlist,
      'allowlist_entry_removed',
      'protection',
      'warning',
    );
    expectEventMetadata(
      restore,
      'quarantine_restore_requested',
      'quarantine',
      'warning',
    );
    expectEventMetadata(
      restore,
      'quarantine_restore_failed',
      'quarantine',
      'error',
    );
    expectEventMetadata(
      restore,
      'quarantine_item_restored',
      'quarantine',
      'warning',
    );
    expectEventMetadata(
      delete,
      'quarantine_delete_failed',
      'quarantine',
      'error',
    );
    expectEventMetadata(
      delete,
      'quarantine_item_deleted',
      'quarantine',
      'warning',
    );
  });

  test('controller detection feedback events are categorized', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final falsePositive = appState.substring(
      appState.indexOf('Future<void> markThreatFalsePositive'),
      appState.indexOf('Future<void> markThreatMalicious'),
    );
    final malicious = appState.substring(
      appState.indexOf('Future<void> markThreatMalicious'),
      appState.indexOf('Future<void> addThreatToAllowlist'),
    );

    void expectEventMetadata(
      String source,
      String eventName,
      String category,
      String severity,
    ) {
      final matches = RegExp("'$eventName'").allMatches(source);
      expect(matches, isNotEmpty);
      for (final match in matches) {
        final eventSource = source.substring(
          match.start,
          source.indexOf(');', match.start),
        );
        expect(eventSource, contains("category: '$category'"));
        expect(eventSource, contains("severity: '$severity'"));
      }
    }

    expectEventMetadata(
      falsePositive,
      'false_positive_label_confirmation_required',
      'protection',
      'warning',
    );
    expectEventMetadata(
      falsePositive,
      'false_positive_label_failed',
      'protection',
      'error',
    );
    expectEventMetadata(
      falsePositive,
      'false_positive_label_saved',
      'protection',
      'warning',
    );
    expectEventMetadata(
      malicious,
      'malicious_label_confirmation_required',
      'protection',
      'warning',
    );
    expectEventMetadata(
      malicious,
      'malicious_label_failed',
      'protection',
      'error',
    );
    expectEventMetadata(
      malicious,
      'malicious_label_saved',
      'protection',
      'warning',
    );
  });

  test('controller threat ignore event is categorized', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final ignoreThreat = appState.substring(
      appState.indexOf('Future<void> ignoreThreat'),
      appState.indexOf('Future<void> markThreatFalsePositive'),
    );

    for (final eventName in [
      'threat_ignore_confirmation_required',
      'threat_ignored',
    ]) {
      final eventSource = ignoreThreat.substring(
        ignoreThreat.indexOf("'$eventName'"),
        ignoreThreat.indexOf(');', ignoreThreat.indexOf("'$eventName'")),
      );
      expect(eventSource, contains("category: 'scan'"));
      expect(eventSource, contains("severity: 'warning'"));
    }
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

  test('protection self-test completion event reflects issues', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final selfTest = appState.substring(
      appState.indexOf('Future<void> runProtectionSelfTest'),
      appState.indexOf('Future<void> sendHeartbeat'),
    );
    final completedEvent = selfTest.substring(
      selfTest.indexOf("'protection_self_test_completed'"),
      selfTest.indexOf(
        'state = state.copyWith(',
        selfTest.indexOf("'protection_self_test_completed'"),
      ),
    );
    final startedEvent = selfTest.substring(
      selfTest.indexOf("'protection_self_test_started'"),
      selfTest.indexOf(
        'state = state.copyWith(',
        selfTest.indexOf("'protection_self_test_started'"),
      ),
    );

    expect(startedEvent, contains("category: 'protection'"));
    expect(startedEvent, contains("severity: 'info'"));
    expect(
      selfTest.indexOf('final failed'),
      lessThan(selfTest.indexOf("'protection_self_test_completed'")),
    );
    expect(completedEvent, contains("category: 'protection'"));
    expect(completedEvent, contains("severity: failed ? 'warning' : 'info'"));
    expect(
      completedEvent,
      contains("'Protection self-test completed with issues'"),
    );
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

double _contrastRatio(Color foreground, Color background) {
  final foregroundLuminance = foreground.computeLuminance();
  final backgroundLuminance = background.computeLuminance();
  final lighter = foregroundLuminance > backgroundLuminance
      ? foregroundLuminance
      : backgroundLuminance;
  final darker = foregroundLuminance > backgroundLuminance
      ? backgroundLuminance
      : foregroundLuminance;
  return (lighter + 0.05) / (darker + 0.05);
}
