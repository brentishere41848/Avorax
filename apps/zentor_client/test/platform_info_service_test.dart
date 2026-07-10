import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:zentor_client/core/platform/platform_info_service.dart';
import 'package:zentor_client/core/security/device_hash_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  setUp(() {
    PackageInfo.setMockInitialValues(
      appName: 'Avorax',
      packageName: 'com.avorax.client',
      version: '1.2.3',
      buildNumber: '45',
      buildSignature: 'test-signature',
      installerStore: null,
    );
  });

  test('Windows platform info parser bounds PowerShell JSON fields', () {
    final source = File(
      'lib/core/platform/platform_info_service.dart',
    ).readAsStringSync();

    expect(source, contains('_maxPlatformTextChars'));
    expect(source, contains('_maxPlatformDiagnosticChars'));
    expect(source, contains('_maxServiceStateEntries'));
    expect(source, contains('String? _boundedPlatformString'));
    expect(source, contains('String? _platformJsonStringField'));
    expect(
      source,
      contains('String _platformPermissionsStatusWithDiagnostics'),
    );
    expect(source, contains('String _boundedPlatformDiagnostic(Object error)'));
    expect(source, contains('platform info parse warnings'));
    expect(source, contains(r"diagnostics.add('malformed $fieldName')"));
    expect(source, contains('states.length >= _maxServiceStateEntries'));
    expect(source, contains('trimmed.substring(0, maxLength)'));
    expect(source, isNot(contains('decoded[\'hostName\']?.toString()')));
    expect(
      source,
      isNot(contains("_boundedPlatformString(decoded['hostName']) ?? ''")),
    );
    expect(
      source,
      isNot(contains("_boundedPlatformString(decoded['userName']) ?? ''")),
    );
    expect(
      source,
      isNot(contains("_boundedPlatformString(decoded['architecture']) ?? ''")),
    );
    expect(
      source,
      isNot(
        contains(
          "_boundedPlatformString(decoded['totalPhysicalMemory']) ?? 'Unknown'",
        ),
      ),
    );
  });

  test('Windows service probe failures are explicit unknown states', () {
    final source = File(
      'lib/core/platform/platform_info_service.dart',
    ).readAsStringSync();
    final serviceMethod = source.substring(
      source.indexOf('Future<Map<String, String>> _loadWindowsServiceStates'),
      source.indexOf('Future<_SystemInfo> _loadWindowsSystemInfo'),
    );

    expect(serviceMethod, contains('_serviceProbeFailureStates'));
    expect(serviceMethod, contains('_attachServiceProbeWarnings'));
    expect(serviceMethod, contains('service-state probe returned no output'));
    expect(
      serviceMethod,
      contains('service-state probe returned non-object JSON'),
    );
    expect(serviceMethod, contains('service-state probe failed'));
    expect(serviceMethod, contains('service-state JSON entry limit reached'));
    expect(serviceMethod, contains('malformed service-state name'));
    expect(serviceMethod, contains(r'malformed service-state value for $key'));
    expect(serviceMethod, contains('unknown; service-state value malformed'));
    expect(source, contains('avorax_service_probe_warnings'));
    expect(source, contains('unknown; service-state parse warnings'));
    expect(source, contains('unknown; service evidence missing'));
    expect(source, contains('states.putIfAbsent(name, () => detail)'));
    expect(serviceMethod, contains('Get-CimInstance Win32_Service'));
    expect(serviceMethod, contains('-ErrorAction Stop'));
    expect(serviceMethod, contains('unknown; service query failed'));
    expect(serviceMethod, contains('Convert-AvoraxBoundedText'));
    expect(serviceMethod, contains('_boundedPlatformDiagnostic(error)'));
    expect(source, contains('unknown; service probe failed'));
    expect(serviceMethod, isNot(contains('return const {};')));
    expect(serviceMethod, isNot(contains('if (key == null) continue;')));
    expect(serviceMethod, isNot(contains("??\n            '';")));
    expect(serviceMethod, isNot(contains(r"return '$name: Not installed'")));
    expect(serviceMethod, isNot(contains('SilentlyContinue')));
    expect(serviceMethod, isNot(contains('_boundedPlatformString(error')));
  });

  test('service-state probe failure is visible at runtime', () async {
    final service = PlatformInfoService(
      DeviceHashService(),
      powerShellRunner: (script) async {
        if (script.contains('Win32_Service')) return '';
        if (script.contains('Win32_ComputerSystem')) return _systemInfoJson();
        fail('unexpected platform script');
      },
    );

    final summary = await service.load();

    expect(summary.appVersion, '1.2.3+45');
    for (final serviceName in const [
      'avorax_core_service',
      'avorax_guard_service',
      'avorax_update_service',
    ]) {
      expect(
        summary.serviceStates[serviceName],
        contains('unknown; service probe failed'),
      );
      expect(
        summary.serviceStates[serviceName],
        contains('PowerShell service-state probe returned no output'),
      );
    }
    expect(summary.localCoreStatus, contains('unknown; service probe failed'));
  });

  test('Windows system info probe failures are explicit diagnostics', () {
    final source = File(
      'lib/core/platform/platform_info_service.dart',
    ).readAsStringSync();
    final systemMethod = source.substring(
      source.indexOf('Future<_SystemInfo> _loadWindowsSystemInfo'),
      source.indexOf('Future<String?> _runPowerShell'),
    );

    expect(systemMethod, contains('_systemInfoProbeFailure'));
    expect(systemMethod, contains('system-info probe returned no output'));
    expect(
      systemMethod,
      contains('system-info probe returned non-object JSON'),
    );
    expect(systemMethod, contains('system-info probe failed'));
    expect(systemMethod, contains('Get-CimInstance Win32_ComputerSystem'));
    expect(systemMethod, contains('Get-CimInstance Win32_OperatingSystem'));
    expect(systemMethod, contains('-ErrorAction Stop'));
    expect(systemMethod, contains('computer query failed'));
    expect(systemMethod, contains('OS query failed'));
    expect(systemMethod, contains('Convert-AvoraxBoundedText'));
    expect(systemMethod, contains('_boundedPlatformDiagnostic(error)'));
    expect(systemMethod, contains('_platformJsonStringField'));
    expect(systemMethod, contains('_platformPermissionsStatusWithDiagnostics'));
    expect(source, contains('Unknown; system info probe failed'));
    expect(systemMethod, isNot(contains('return const _SystemInfo();')));
    expect(systemMethod, isNot(contains('SilentlyContinue')));
    expect(systemMethod, isNot(contains('_boundedPlatformString(error')));
  });

  test('system-info probe failure is visible at runtime', () async {
    final service = PlatformInfoService(
      DeviceHashService(),
      powerShellRunner: (script) async {
        if (script.contains('Win32_Service')) {
          return '{"avorax_core_service":"running"}';
        }
        if (script.contains('Win32_ComputerSystem')) return '[]';
        fail('unexpected platform script');
      },
    );

    final summary = await service.load();

    expect(
      summary.permissionsStatus,
      contains('Unknown; system info probe failed'),
    );
    expect(
      summary.permissionsStatus,
      contains('PowerShell system-info probe returned non-object JSON'),
    );
    expect(summary.hostName, isNotEmpty);
    expect(summary.systemArchitecture, isNotEmpty);
  });

  test(
    'PowerShell platform probe timeout reports cleanup at runtime',
    () async {
      if (!Platform.isWindows) return;
      late Process process;
      final service = PlatformInfoService(
        DeviceHashService(),
        powerShellProcessStarter: (_, _) async {
          process = await _startSleepingDartProcess();
          return process;
        },
        powerShellTimeout: const Duration(milliseconds: 50),
        processReapTimeout: const Duration(seconds: 2),
      );

      await expectLater(
        service.load(),
        throwsA(
          isA<StateError>()
              .having(
                (error) => error.message,
                'message',
                contains('PowerShell platform probe timed out.'),
              )
              .having(
                (error) => error.message,
                'message',
                contains('Termination requested.'),
              )
              .having(
                (error) => error.message,
                'message',
                anyOf(
                  contains('Timed-out process exited with code'),
                  contains('Timed-out process did not exit within'),
                ),
              ),
        ),
      );
      await _expectProcessExited(process, 'platform timeout fixture');
    },
  );

  test('PowerShell platform probe failures preserve diagnostics', () {
    final source = File(
      'lib/core/platform/platform_info_service.dart',
    ).readAsStringSync();
    final runner = source.substring(
      source.indexOf('Future<String?> _runPowerShell'),
      source.indexOf('String? _boundedPlatformString'),
    );

    expect(runner, contains('PowerShell platform probe failed'));
    expect(runner, contains('PowerShell platform probe exited with code'));
    expect(runner, contains('Process.start'));
    expect(runner, contains('_collectBoundedPowerShellText(process.stdout)'));
    expect(runner, contains('_collectBoundedPowerShellText(process.stderr)'));
    expect(runner, contains('process.exitCode.timeout'));
    expect(runner, contains('await _platformTimeoutTerminationStatus'));
    expect(runner, contains('await _platformReapStatus(process)'));
    expect(source, contains('_windowsTaskkillExecutable()'));
    expect(source, contains('taskkill.exe'));
    expect(source, contains("'/T'"));
    expect(source, contains("'/F'"));
    expect(runner, contains('_platformProcessReapTimeout'));
    expect(runner, contains('Timed-out process did not exit within'));
    expect(runner, contains('Termination requested.'));
    expect(runner, contains('Termination request failed.'));
    expect(
      runner,
      contains('PowerShell platform probe output exceeded size limit'),
    );
    expect(runner, contains('_boundedPlatformDiagnostic(error)'));
    expect(
      runner,
      contains('_powerShellDiagnostic(stdout: stdout, stderr: stderr)'),
    );
    final runPowerShellOnly = runner.substring(
      runner.indexOf('Future<String?> _runPowerShell'),
      runner.indexOf('String _windowsPowerShellExecutable'),
    );
    expect(runner, isNot(contains('if (result.exitCode != 0) return null')));
    expect(runner, isNot(contains('Process.run')));
    expect(runner, isNot(contains('} on Object {')));
    expect(runPowerShellOnly, isNot(contains('return null;')));
    expect(runner, isNot(contains('_boundedPlatformString(error')));
  });

  test('PowerShell platform probe avoids PATH lookup and raw command text', () {
    final source = File(
      'lib/core/platform/platform_info_service.dart',
    ).readAsStringSync();
    final runner = source.substring(
      source.indexOf('Future<String?> _runPowerShell'),
      source.indexOf(
        'Future<_BoundedPowerShellText> _collectBoundedPowerShellText',
      ),
    );

    expect(runner, contains('_windowsPowerShellExecutable()'));
    expect(runner, contains("'-EncodedCommand'"));
    expect(runner, contains('_powershellEncodedCommand(script)'));
    expect(runner, isNot(contains("'powershell.exe'")));
    expect(runner, isNot(contains("'-Command'")));
    expect(runner, contains("_checkedWindowsSystemRootValue('SystemRoot')"));
    expect(runner, contains("_checkedWindowsSystemRootValue('WINDIR')"));
    expect(runner, contains('_nonEmptyEnvironmentValue(name)'));
    expect(runner, contains('SystemRoot or WINDIR is required to locate'));
    expect(
      runner,
      contains('PowerShell platform probe root must be on a local drive'),
    );
    expect(runner, isNot(contains(r'C:\Windows')));
    expect(runner, contains('WindowsPowerShell'));
    expect(runner, contains('powershell.exe'));
    expect(runner, contains('_isWindowsRemoteOrDevicePath(candidate)'));
    expect(runner, contains('_powerShellExecutableProbe(candidate)'));
    expect(runner, contains('followLinks: false'));
    expect(
      runner,
      contains('PowerShell platform probe command must be on a local drive'),
    );
    expect(runner, contains('for (final codeUnit in script.codeUnits)'));
    expect(runner, contains('base64Encode(bytes)'));
  });

  test('source marker: PowerShell platform probe output is bounded', () {
    final source = File(
      'lib/core/platform/platform_info_service.dart',
    ).readAsStringSync();

    expect(source, contains('_maxPlatformPowerShellOutputChars'));
    expect(
      source,
      contains('Future<_BoundedPowerShellText> _collectBoundedPowerShellText'),
    );
    expect(source, contains('Utf8Decoder(allowMalformed: true)'));
    expect(
      source,
      contains(
        '_BoundedPowerShellText(buffer.toString(), truncated: truncated)',
      ),
    );
    expect(source, contains('stdout.truncated'));
    expect(
      source,
      contains('PowerShell platform probe output exceeded size limit'),
    );
  });

  test('device screen platform provider errors are bounded', () {
    final source = File(
      'lib/features/device/device_screen.dart',
    ).readAsStringSync();

    expect(source, contains('_maxDeviceDiagnosticChars'));
    expect(source, contains('String _boundedDeviceDiagnostic(Object error)'));
    expect(source, contains(r"RegExp(r'[\x00-\x1F\x7F]+')"));
    expect(source, contains('substring(0, _maxDeviceDiagnosticChars - 3)'));
    expect(source, contains('detail: _boundedDeviceDiagnostic(error)'));
    expect(source, contains("states['avorax_service_probe_warnings']"));
    expect(source, contains(r'Probe warnings: $warnings'));
    expect(
      source,
      contains('String _serviceState(Map<String, String> states, String name)'),
    );
    expect(source, contains('unknown; service evidence missing'));
    expect(
      source,
      isNot(contains("states['avorax_core_service'] ?? 'not installed'")),
    );
    expect(
      source,
      isNot(contains("states['avorax_guard_service'] ?? 'not installed'")),
    );
    expect(
      source,
      isNot(contains("states['avorax_update_service'] ?? 'not installed'")),
    );
    expect(source, isNot(contains(r"detail: '$error'")));
  });
}

String _systemInfoJson() {
  return '''
{
  "hostName": "AVX-TEST",
  "userName": "Avorax\\\\Tester",
  "architecture": "x64",
  "totalPhysicalMemory": "16.0 GB",
  "permissionsStatus": "Running as standard user"
}
''';
}

Future<Process> _startSleepingDartProcess() async {
  final tempDir = await Directory.systemTemp.createTemp(
    'avorax_platform_timeout_fixture_',
  );
  addTearDown(() async {
    if (await tempDir.exists()) {
      await tempDir.delete(recursive: true);
    }
  });
  final script = File('${tempDir.path}${Platform.pathSeparator}sleep.dart');
  await script.writeAsString('''
import 'dart:async';

Future<void> main() async {
  print('fixture stdout before sleep');
  await Future<void>.delayed(const Duration(seconds: 30));
}
''');
  return Process.start(_dartExecutable(), [script.path]);
}

Future<void> _expectProcessExited(Process process, String label) async {
  try {
    await process.exitCode.timeout(const Duration(seconds: 2));
  } on Object catch (error) {
    final killed = process.kill();
    try {
      await process.exitCode.timeout(const Duration(seconds: 2));
    } on Object {
      // Best-effort cleanup before failing the test.
    }
    fail(
      '$label process ${process.pid} was still running after timeout cleanup; '
      'killRequested=$killed; observation=$error',
    );
  }
}

String _dartExecutable() {
  final flutterRoot = Platform.environment['FLUTTER_ROOT'];
  if (flutterRoot != null && flutterRoot.trim().isNotEmpty) {
    final executable = Platform.isWindows ? 'dart.exe' : 'dart';
    final candidate = File(
      '$flutterRoot${Platform.pathSeparator}bin${Platform.pathSeparator}cache'
      '${Platform.pathSeparator}dart-sdk${Platform.pathSeparator}bin'
      '${Platform.pathSeparator}$executable',
    );
    if (candidate.existsSync()) return candidate.path;
  }
  return Platform.isWindows ? 'dart.exe' : 'dart';
}
