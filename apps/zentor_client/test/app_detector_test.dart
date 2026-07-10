import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:zentor_client/core/apps/app_detector.dart';

void main() {
  test(
    'app detector returns empty when no real supported apps are found',
    () async {
      final detector = AppDetector();
      final apps = await detector.detect();
      expect(detector.supportsAutomaticDetection, isFalse);
      expect(apps, isEmpty);
    },
  );

  test('empty app registry disables automatic detection explicitly', () {
    final detectorSource = File(
      'lib/core/apps/app_detector.dart',
    ).readAsStringSync();
    final stateSource = File('lib/app/app_state.dart').readAsStringSync();
    final screenSource = File(
      'lib/features/protected_apps/protected_apps_screen.dart',
    ).readAsStringSync();
    final rescanButton = screenSource.substring(
      screenSource.indexOf("appDetectionBusy ? 'Rescanning' : 'Rescan'"),
      screenSource.indexOf("label: 'Add file or app'"),
    );

    expect(detectorSource, contains('bool get supportsAutomaticDetection'));
    expect(
      detectorSource,
      contains('if (!supportsAutomaticDetection) return const []'),
    );
    expect(stateSource, contains('app_detection_disabled'));
    expect(
      stateSource,
      contains('No supported protected-app registry entries are configured'),
    );
    expect(screenSource, contains('supportsAutomaticDetection'));
    expect(
      screenSource,
      contains(
        'Automatic app detection has no configured supported-app registry',
      ),
    );
    expect(rescanButton, contains('onPressed: autoDetectionSupported'));
    expect(rescanButton, contains('? controller.unawaitedDetectApps'));
    expect(rescanButton, contains(': null'));
  });

  test('process enumeration failures are visible', () {
    final source = File('lib/core/apps/app_detector.dart').readAsStringSync();
    final method = source.substring(
      source.indexOf(
        'Future<List<ProcessObservation>> processSnapshotObservations()',
      ),
      source.indexOf('Future<List<DetectedApp>> _detectKnownInstallPaths()'),
    );

    expect(
      method,
      contains(
        'Unable to collect process snapshot observations for protected app detection',
      ),
    );
    expect(source, contains('_maxAppDetectionDiagnosticChars'));
    expect(
      source,
      contains('String _boundedAppDetectionDiagnostic(Object error)'),
    );
    expect(
      source,
      contains('substring(0, _maxAppDetectionDiagnosticChars - 3)'),
    );
    expect(method, contains('_boundedAppDetectionDiagnostic(error)'));
    expect(source, contains(r'$executable exited with code $exitCode'));
    expect(method, contains('_runProcessListCommand'));
    expect(method, isNot(contains('} on Object {\n      return const [];')));
    expect(method, isNot(contains(r'detection: $error')));
  });

  test('process enumeration output is bounded', () {
    final source = File('lib/core/apps/app_detector.dart').readAsStringSync();

    expect(source, contains('_maxAppDetectionProcessOutputChars'));
    expect(source, contains('_maxProcessSnapshotObservations'));
    expect(
      source,
      contains('observations.length >= _maxProcessSnapshotObservations'),
    );
    expect(source, contains('(_processStarter ?? Process.start)'));
    expect(
      source,
      contains('_collectBoundedProcessListOutput(process.stdout)'),
    );
    expect(
      source,
      contains('_collectBoundedProcessListOutput(process.stderr)'),
    );
    expect(source, contains('process.exitCode.timeout'));
    expect(source, contains('await _processListTimeoutTerminationStatus'));
    expect(source, contains('_windowsTaskkillExecutable()'));
    expect(source, contains('taskkill.exe'));
    expect(source, contains("'/T'"));
    expect(source, contains("'/F'"));
    expect(source, contains('await _processListReapStatus(process)'));
    expect(source, contains('_processListReapTimeout'));
    expect(source, contains('Timed-out process did not exit within'));
    expect(source, contains('Termination requested.'));
    expect(source, contains('Termination request failed.'));
    expect(source, contains('Utf8Decoder(allowMalformed: true)'));
    expect(source, contains('output exceeded size limit'));
    expect(source, isNot(contains('Process.run')));
  });

  test('process enumeration timeout reports cleanup at runtime', () async {
    late Process process;
    final detector = AppDetector.withProcessStarter(
      processStarter: (_, _) async {
        process = await _startSleepingDartProcess();
        return process;
      },
      processListCommandTimeout: const Duration(milliseconds: 50),
      processListReapTimeout: const Duration(seconds: 2),
    );

    await expectLater(
      detector.processSnapshotObservations(),
      throwsA(
        isA<StateError>()
            .having(
              (error) => error.message,
              'message',
              contains('timed out. Termination requested.'),
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
    await _expectProcessExited(process, 'app detector timeout fixture');
  });

  test('process snapshot observations parse bounded PID evidence', () {
    final source = File('lib/core/apps/app_detector.dart').readAsStringSync();
    final windowsParser = source.substring(
      source.indexOf('List<ProcessObservation> _windowsPowerShellObservations'),
      source.indexOf('List<ProcessObservation> _posixProcessObservations'),
    );
    final posixParser = source.substring(
      source.indexOf('List<ProcessObservation> _posixProcessObservations'),
      source.indexOf('String? _processSnapshotText(String value)'),
    );

    expect(source, contains("import '../local_core/local_core_client.dart'"));
    expect(windowsParser, contains('jsonDecode(text)'));
    expect(windowsParser, contains("row['pid']"));
    expect(windowsParser, contains("row['parent_pid']"));
    expect(windowsParser, contains("row['image_path']"));
    expect(windowsParser, contains("row['command_line']"));
    expect(
      windowsParser,
      contains(
        'ProcessObservation(\n'
        '          pid: pid,\n'
        '          parentPid: parentPid,\n'
        '          imagePath: image,\n'
        '          commandLine: commandLine,',
      ),
    );
    expect(posixParser, contains("RegExp(r'\\s+').firstMatch(trimmed)"));
    expect(
      posixParser,
      contains('int.tryParse(trimmed.substring(0, separator.start))'),
    );
    expect(posixParser, contains('trimmed.substring(separator.end)'));
    expect(source, contains('String? _processSnapshotText(String value)'));
    expect(
      source,
      contains('String? _processSnapshotCommandLineText(String value)'),
    );
    expect(source, contains('int? _processSnapshotInt(Object? value)'));
    expect(
      source,
      contains("value.replaceAll(RegExp(r'[\\x00-\\x1F\\x7F]+'), ' ')"),
    );
    expect(source, contains('if (_hasParentTraversal(text)) return null'));
    expect(source, contains('String _processImageLeaf(String imagePath)'));
  });

  test('process enumeration commands avoid PATH lookup', () {
    final source = File('lib/core/apps/app_detector.dart').readAsStringSync();
    final observationsMethod = source.substring(
      source.indexOf(
        'Future<List<ProcessObservation>> processSnapshotObservations()',
      ),
      source.indexOf(
        'Future<_BoundedProcessListOutput> _runProcessListCommand',
      ),
    );
    final resolverSlice = source.substring(
      source.indexOf('String _windowsPowerShellProcessListExecutable()'),
      source.indexOf(
        'Future<_BoundedProcessListOutput> _collectBoundedProcessListOutput',
      ),
    );

    expect(
      observationsMethod,
      contains('_windowsPowerShellProcessListExecutable()'),
    );
    expect(observationsMethod, contains('_unixProcessListExecutable()'));
    expect(observationsMethod, contains('_windowsPowerShellObservations'));
    expect(observationsMethod, contains('_posixProcessObservations'));
    expect(observationsMethod, contains("'-EncodedCommand'"));
    expect(observationsMethod, isNot(contains("'-ExecutionPolicy'")));
    expect(observationsMethod, isNot(contains("'Bypass'")));
    expect(
      observationsMethod,
      contains('_powershellEncodedCommand(_windowsProcessSnapshotScript)'),
    );
    expect(
      observationsMethod,
      isNot(contains("_runProcessListCommand('tasklist'")),
    );
    expect(observationsMethod, isNot(contains("_runProcessListCommand('ps'")));
    expect(observationsMethod, isNot(contains("'tasklist.exe'")));
    expect(resolverSlice, contains('_windowsSystemRoot()'));
    expect(
      resolverSlice,
      contains("_checkedWindowsSystemRootValue('SystemRoot')"),
    );
    expect(resolverSlice, contains("_checkedWindowsSystemRootValue('WINDIR')"));
    expect(resolverSlice, contains('_nonEmptyEnvironmentValue(name)'));
    expect(
      resolverSlice,
      contains('SystemRoot or WINDIR is required to locate'),
    );
    expect(
      resolverSlice,
      contains(
        'Windows process enumeration tool root must be on a local drive',
      ),
    );
    expect(resolverSlice, isNot(contains(r"C:\Windows")));
    expect(resolverSlice, contains('System32'));
    expect(resolverSlice, contains('WindowsPowerShell'));
    expect(resolverSlice, contains('powershell.exe'));
    expect(resolverSlice, isNot(contains('tasklist.exe')));
    expect(resolverSlice, contains("const ['/bin/ps', '/usr/bin/ps']"));
    expect(resolverSlice, contains('_processListExecutableProbe(candidate)'));
    expect(resolverSlice, contains('_requireProcessListExecutable'));
    expect(resolverSlice, contains('_isWindowsRemoteOrDevicePath(candidate)'));
    expect(resolverSlice, contains('followLinks: false'));
    expect(resolverSlice, contains('FileSystemEntityType.file'));
    expect(
      resolverSlice,
      contains('Windows process enumeration command must be on a local drive'),
    );
    expect(
      resolverSlice,
      contains('POSIX process enumeration command was not found'),
    );
  });

  test('Windows process snapshot parser preserves command line evidence', () async {
    if (!Platform.isWindows) return;
    String? executable;
    List<String>? arguments;
    final detector = AppDetector.withProcessStarter(
      processStarter: (processExecutable, processArguments) {
        executable = processExecutable;
        arguments = List<String>.of(processArguments);
        return _startPrintingDartProcess(
          '[{"pid":42,"parent_pid":7,'
          '"image_path":"C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",'
          '"command_line":"powershell.exe -WindowStyle Hidden -EncodedCommand benignfixture"}]',
        );
      },
    );

    final observations = await detector.processSnapshotObservations();

    expect(executable, contains('powershell.exe'));
    expect(arguments, contains('-EncodedCommand'));
    expect(arguments, isNot(contains('-ExecutionPolicy')));
    expect(arguments, isNot(contains('Bypass')));
    expect(observations, hasLength(1));
    expect(observations.single.pid, 42);
    expect(observations.single.parentPid, 7);
    expect(
      observations.single.imagePath,
      'C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe',
    );
    expect(
      observations.single.commandLine,
      'powershell.exe -WindowStyle Hidden -EncodedCommand benignfixture',
    );
  });

  test('known install path probe failures are visible', () {
    final source = File('lib/core/apps/app_detector.dart').readAsStringSync();
    final stateSource = File('lib/app/app_state.dart').readAsStringSync();
    final detectionMethod = source.substring(
      source.indexOf('Future<List<DetectedApp>> _detectKnownInstallPaths()'),
      source.indexOf('List<DetectedApp> _dedupe'),
    );

    expect(detectionMethod, contains('_directoryExistsForAppDetection'));
    expect(detectionMethod, contains('_fileExistsForAppDetection'));
    expect(detectionMethod, contains('FileSystemEntity.type'));
    expect(detectionMethod, contains('followLinks: false'));
    expect(detectionMethod, contains('FileSystemEntityType.link'));
    expect(detectionMethod, contains('refusing to follow linked install path'));
    expect(
      detectionMethod,
      contains('refusing to follow linked executable candidate'),
    );
    expect(
      detectionMethod,
      contains('Unable to inspect protected app install path'),
    );
    expect(
      detectionMethod,
      contains('Unable to inspect protected app executable candidate'),
    );
    expect(detectionMethod, contains('_boundedAppDetectionDiagnostic(error)'));
    expect(stateSource, contains('app_detection_failed'));
    expect(
      stateSource,
      contains('final details = _boundedUiDiagnostic(error)'),
    );
    expect(stateSource, contains('Unable to detect protected apps: \$details'));
    expect(
      stateSource,
      isNot(contains('Unable to detect protected apps: \$error')),
    );
    expect(detectionMethod, isNot(contains(r'install path $error')));
    expect(detectionMethod, isNot(contains(r'executable candidate $error')));
    expect(detectionMethod, isNot(contains('directory.exists()')));
    expect(detectionMethod, isNot(contains('file.exists()')));
  });

  test('known install roots require absolute local environment values', () {
    final source = File('lib/core/apps/app_detector.dart').readAsStringSync();
    final rootsMethod = source.substring(
      source.indexOf('List<String> _knownRoots()'),
      source.indexOf('Future<bool> _directoryExistsForAppDetection'),
    );

    expect(source, contains('String? _nonEmptyEnvironmentValue(String name)'));
    expect(source, contains('String? _knownRootEnvironmentValue(String name)'));
    expect(source, contains('bool _isAbsoluteLocalInstallRoot(String path)'));
    expect(rootsMethod, contains("_knownRootEnvironmentValue('ProgramFiles')"));
    expect(
      rootsMethod,
      contains("_knownRootEnvironmentValue('ProgramFiles(x86)')"),
    );
    expect(rootsMethod, contains("_knownRootEnvironmentValue('HOME')"));
    expect(
      rootsMethod,
      isNot(contains("_nonEmptyEnvironmentValue('ProgramFiles')")),
    );
    expect(rootsMethod, isNot(contains("\${Platform.environment['HOME']}")));
    expect(rootsMethod, isNot(contains("Platform.environment['HOME'];")));
    expect(source, contains('value == null || value.isEmpty ? null : value'));
    expect(source, contains('_isWindowsRemoteOrDevicePath(path)'));
    expect(source, contains("path.startsWith('/') && !path.startsWith('//')"));
  });
}

Future<Process> _startSleepingDartProcess() async {
  final tempDir = await Directory.systemTemp.createTemp(
    'avorax_app_detector_timeout_fixture_',
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

Future<Process> _startPrintingDartProcess(String output) async {
  final tempDir = await Directory.systemTemp.createTemp(
    'avorax_app_detector_output_fixture_',
  );
  addTearDown(() async {
    if (await tempDir.exists()) {
      await tempDir.delete(recursive: true);
    }
  });
  final script = File('${tempDir.path}${Platform.pathSeparator}print.dart');
  await script.writeAsString('''
import 'dart:convert';

Future<void> main() async {
  print(utf8.decode(base64Decode('${base64Encode(utf8.encode(output))}')));
}
''');
  return Process.start(_dartExecutable(), [script.path]);
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
