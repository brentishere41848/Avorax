import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:zentor_protocol/zentor_protocol.dart';

import '../local_core/local_core_client.dart';
import 'app_registry.dart';

typedef ProcessListProcessStarter =
    Future<Process> Function(String executable, List<String> arguments);

const int _maxAppDetectionDiagnosticChars = 2048;
const int _maxAppDetectionProcessOutputChars = 256 * 1024;
const int _maxProcessSnapshotObservations = 256;
const String _processSnapshotTruncationMarker = ' ...[truncated-middle]... ';
const Duration _windowsProcessTreeKillTimeout = Duration(seconds: 5);
const String _windowsProcessSnapshotScript = r'''
$ErrorActionPreference = 'Stop'
$rows = foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object -First 256)) {
  $image = if ($process.ExecutablePath) { $process.ExecutablePath } else { $process.Name }
  if ($image) {
    $row = [ordered]@{
      pid = $process.ProcessId
      parent_pid = $process.ParentProcessId
      image_path = $image
    }
    if ($process.CommandLine) {
      $row.command_line = $process.CommandLine
    }
    [pscustomobject]$row
  }
}
ConvertTo-Json -InputObject @($rows) -Compress -Depth 4
''';

String _boundedAppDetectionDiagnostic(Object error) {
  final text = '$error'.replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ').trim();
  if (text.isEmpty) return 'unknown error';
  if (text.length <= _maxAppDetectionDiagnosticChars) return text;
  return '${text.substring(0, _maxAppDetectionDiagnosticChars - 3)}...';
}

class AppDetector {
  const AppDetector([AppRegistry registry = const AppRegistry()])
    : this._(
        registry,
        null,
        const Duration(seconds: 8),
        const Duration(seconds: 5),
      );

  const AppDetector.withProcessStarter({
    AppRegistry registry = const AppRegistry(),
    required ProcessListProcessStarter processStarter,
    Duration processListCommandTimeout = const Duration(seconds: 8),
    Duration processListReapTimeout = const Duration(seconds: 5),
  }) : this._(
         registry,
         processStarter,
         processListCommandTimeout,
         processListReapTimeout,
       );

  const AppDetector._(
    this._registry,
    this._processStarter,
    this._processListCommandTimeout,
    this._processListReapTimeout,
  );

  final AppRegistry _registry;
  final ProcessListProcessStarter? _processStarter;
  final Duration _processListCommandTimeout;
  final Duration _processListReapTimeout;

  bool get supportsAutomaticDetection => _registry.entries.isNotEmpty;

  Future<List<DetectedApp>> detect() async {
    if (!supportsAutomaticDetection) return const [];
    final found = <DetectedApp>[];
    found.addAll(await _detectRunningProcesses());
    found.addAll(await _detectKnownInstallPaths());
    return _dedupe(found);
  }

  Future<List<DetectedApp>> _detectRunningProcesses() async {
    final observations = await processSnapshotObservations();
    final names = observations
        .map((observation) => _processImageLeaf(observation.imagePath))
        .where((name) => name.isNotEmpty)
        .map((name) => name.toLowerCase())
        .toSet();
    if (names.isEmpty) return const [];
    final detected = <DetectedApp>[];
    for (final entry in _registry.entries) {
      final running = entry.processNames.any(
        (process) => names.contains(process.toLowerCase()),
      );
      if (running) {
        detected.add(
          DetectedApp(
            appId: entry.appId,
            displayName: entry.displayName,
            path: 'Running process',
            source: 'Running Process',
            protectionProfile: entry.protectionProfile,
          ),
        );
      }
    }
    return detected;
  }

  Future<List<ProcessObservation>> processSnapshotObservations() async {
    try {
      if (Platform.isWindows) {
        final output = await _runProcessListCommand(
          _windowsPowerShellProcessListExecutable(),
          [
            '-NoProfile',
            '-EncodedCommand',
            _powershellEncodedCommand(_windowsProcessSnapshotScript),
          ],
        );
        return _windowsPowerShellObservations(output.text);
      }
      if (Platform.isLinux || Platform.isMacOS) {
        final output = await _runProcessListCommand(
          _unixProcessListExecutable(),
          ['-axo', 'pid=,comm='],
        );
        return _posixProcessObservations(output.text);
      }
    } on Object catch (error) {
      throw StateError(
        'Unable to collect process snapshot observations for protected app detection: ${_boundedAppDetectionDiagnostic(error)}',
      );
    }
    return const [];
  }

  List<ProcessObservation> _windowsPowerShellObservations(String text) {
    final Object? decoded;
    try {
      decoded = jsonDecode(text);
    } on FormatException catch (error) {
      throw StateError(
        'Windows process snapshot JSON was malformed: ${_boundedAppDetectionDiagnostic(error)}',
      );
    }
    if (decoded is! List) {
      throw StateError('Windows process snapshot JSON was not an array.');
    }

    final observations = <ProcessObservation>[];
    for (final row in decoded) {
      if (observations.length >= _maxProcessSnapshotObservations) break;
      if (row is! Map) continue;
      final pid = _processSnapshotInt(row['pid']);
      final parentPid = _processSnapshotInt(row['parent_pid']);
      final image = _processSnapshotText(row['image_path']?.toString() ?? '');
      final commandLineEvidence = _processSnapshotCommandLineText(
        row['command_line']?.toString() ?? '',
      );
      if (image == null || pid == null || pid < 0) continue;
      observations.add(
        ProcessObservation(
          pid: pid,
          parentPid: parentPid,
          imagePath: image,
          commandLine: commandLineEvidence?.text,
          commandLineTruncated: commandLineEvidence?.truncated ?? false,
        ),
      );
    }
    return observations;
  }

  List<ProcessObservation> _posixProcessObservations(String text) {
    final observations = <ProcessObservation>[];
    for (final line in text.split('\n')) {
      if (observations.length >= _maxProcessSnapshotObservations) break;
      final trimmed = line.trim();
      if (trimmed.isEmpty) continue;
      final separator = RegExp(r'\s+').firstMatch(trimmed);
      if (separator == null) continue;
      final pid = int.tryParse(trimmed.substring(0, separator.start));
      final image = _processSnapshotText(trimmed.substring(separator.end));
      if (pid == null || pid < 0 || image == null) continue;
      observations.add(ProcessObservation(pid: pid, imagePath: image));
    }
    return observations;
  }

  String? _processSnapshotText(String value) {
    final text = value.replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ').trim();
    if (text.isEmpty || text.contains('\u0000')) return null;
    if (_hasParentTraversal(text)) return null;
    if (text.length <= _maxAppDetectionDiagnosticChars) return text;
    return text.substring(0, _maxAppDetectionDiagnosticChars);
  }

  ({String text, bool truncated})? _processSnapshotCommandLineText(
    String value,
  ) {
    final text = value.replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ').trim();
    if (text.isEmpty || text.contains('\u0000')) return null;
    final codePoints = text.runes.toList(growable: false);
    if (codePoints.length <= _maxAppDetectionDiagnosticChars) {
      return (text: text, truncated: false);
    }
    final retainedChars =
        _maxAppDetectionDiagnosticChars -
        _processSnapshotTruncationMarker.length;
    final headChars = retainedChars ~/ 2;
    final tailChars = retainedChars - headChars;
    return (
      text:
          '${String.fromCharCodes(codePoints.take(headChars))}'
          '$_processSnapshotTruncationMarker'
          '${String.fromCharCodes(codePoints.skip(codePoints.length - tailChars))}',
      truncated: true,
    );
  }

  int? _processSnapshotInt(Object? value) {
    if (value is int) return value;
    if (value is num && value.isFinite && value == value.roundToDouble()) {
      return value.toInt();
    }
    if (value is String) return int.tryParse(value.trim());
    return null;
  }

  String _processImageLeaf(String imagePath) {
    return imagePath
        .replaceAll(r'\', '/')
        .split('/')
        .last
        .trim()
        .replaceAll('"', '');
  }

  Future<_BoundedProcessListOutput> _runProcessListCommand(
    String executable,
    List<String> arguments,
  ) async {
    final Process process;
    try {
      process = await (_processStarter ?? Process.start)(executable, arguments);
    } on Object catch (error) {
      throw StateError(
        '$executable launch failed: ${_boundedAppDetectionDiagnostic(error)}',
      );
    }
    final stdoutFuture = _collectBoundedProcessListOutput(process.stdout);
    final stderrFuture = _collectBoundedProcessListOutput(process.stderr);
    final int exitCode;
    try {
      exitCode = await process.exitCode.timeout(_processListCommandTimeout);
    } on TimeoutException {
      final terminationStatus = await _processListTimeoutTerminationStatus(
        process,
      );
      final reapStatus = await _processListReapStatus(process);
      final stdout = await _timedOutProcessListOutput(stdoutFuture);
      final stderr = await _timedOutProcessListOutput(stderrFuture);
      throw StateError(
        '$executable timed out. $terminationStatus $reapStatus: '
        '${_processListDiagnostic(stdout: stdout, stderr: stderr)}',
      );
    }
    final stdout = await stdoutFuture;
    final stderr = await stderrFuture;
    if (exitCode != 0) {
      throw StateError(
        '$executable exited with code $exitCode: '
        '${_processListDiagnostic(stdout: stdout, stderr: stderr)}',
      );
    }
    if (stdout.truncated) {
      throw StateError('$executable output exceeded size limit.');
    }
    return stdout;
  }

  String _processListTerminationStatus(bool killed) =>
      killed ? 'Termination requested.' : 'Termination request failed.';

  Future<String> _processListTimeoutTerminationStatus(Process process) async {
    if (Platform.isWindows) {
      final treeStatus = await _windowsProcessTreeTerminationStatus(
        process.pid,
      );
      if (treeStatus.startsWith('Process tree termination requested.')) {
        return 'Termination requested. $treeStatus';
      }
      return '${_processListTerminationStatus(process.kill())} $treeStatus';
    }
    return _processListTerminationStatus(process.kill());
  }

  Future<String> _windowsProcessTreeTerminationStatus(int pid) async {
    Process? taskkillProcess;
    try {
      final taskkill = _windowsTaskkillExecutable();
      taskkillProcess = await Process.start(taskkill, [
        '/PID',
        '$pid',
        '/T',
        '/F',
      ]);
      final stdoutFuture = _collectBoundedProcessListOutput(
        taskkillProcess.stdout,
      );
      final stderrFuture = _collectBoundedProcessListOutput(
        taskkillProcess.stderr,
      );
      final exitCode = await taskkillProcess.exitCode.timeout(
        _windowsProcessTreeKillTimeout,
      );
      final stdout = await stdoutFuture;
      final stderr = await stderrFuture;
      if (exitCode == 0) return 'Process tree termination requested.';
      return 'Process tree termination failed with exit code $exitCode: '
          '${_processListDiagnostic(stdout: stdout, stderr: stderr)}.';
    } on TimeoutException {
      taskkillProcess?.kill();
      return 'Process tree termination timed out.';
    } on Object catch (error) {
      return 'Process tree termination failed: '
          '${_boundedAppDetectionDiagnostic(error)}.';
    }
  }

  Future<String> _processListReapStatus(Process process) async {
    try {
      final exitCode = await process.exitCode.timeout(_processListReapTimeout);
      return 'Timed-out process exited with code $exitCode.';
    } on TimeoutException {
      return 'Timed-out process did not exit within '
          '${_processListReapTimeout.inSeconds} seconds after termination '
          'request.';
    } on Object catch (error) {
      return 'Timed-out process exit observation failed: '
          '${_boundedAppDetectionDiagnostic(error)}.';
    }
  }

  Future<_BoundedProcessListOutput> _timedOutProcessListOutput(
    Future<_BoundedProcessListOutput> output,
  ) async {
    try {
      return await output.timeout(_processListReapTimeout);
    } on TimeoutException {
      return const _BoundedProcessListOutput(
        'stream collection did not finish after timeout cleanup',
        truncated: true,
      );
    }
  }

  String _windowsPowerShellProcessListExecutable() {
    final systemRoot = _windowsSystemRoot();
    final candidate = File(
      '$systemRoot${Platform.pathSeparator}System32${Platform.pathSeparator}WindowsPowerShell${Platform.pathSeparator}v1.0${Platform.pathSeparator}powershell.exe',
    ).absolute.path;
    if (_isWindowsRemoteOrDevicePath(candidate)) {
      throw StateError(
        'Windows process enumeration command must be on a local drive.',
      );
    }
    _requireProcessListExecutable(candidate, 'Windows process enumeration');
    return candidate;
  }

  String _windowsTaskkillExecutable() {
    final systemRoot = _windowsSystemRoot();
    final candidate = File(
      '$systemRoot${Platform.pathSeparator}System32${Platform.pathSeparator}taskkill.exe',
    ).absolute.path;
    if (_isWindowsRemoteOrDevicePath(candidate)) {
      throw StateError(
        'Windows process tree termination command must be on a local drive.',
      );
    }
    _requireProcessListExecutable(
      candidate,
      'Windows process tree termination',
    );
    return candidate;
  }

  String _powershellEncodedCommand(String script) {
    final bytes = <int>[];
    for (final codeUnit in script.codeUnits) {
      bytes
        ..add(codeUnit & 0xff)
        ..add((codeUnit >> 8) & 0xff);
    }
    return base64Encode(bytes);
  }

  String _windowsSystemRoot() {
    final systemRoot =
        _checkedWindowsSystemRootValue('SystemRoot') ??
        _checkedWindowsSystemRootValue('WINDIR');
    if (systemRoot == null) {
      throw StateError(
        'SystemRoot or WINDIR is required to locate the Windows process enumeration command.',
      );
    }
    if (_isWindowsRemoteOrDevicePath(systemRoot)) {
      throw StateError(
        'Windows process enumeration tool root must be on a local drive.',
      );
    }
    return Directory(systemRoot).absolute.path;
  }

  String? _checkedWindowsSystemRootValue(String name) {
    final value = _nonEmptyEnvironmentValue(name);
    if (value == null) return null;
    if (value.contains('\u0000')) {
      throw StateError(
        'Windows process enumeration tool root $name must not contain NUL.',
      );
    }
    if (_hasParentTraversal(value)) {
      throw StateError(
        'Windows process enumeration tool root $name must not contain parent traversal.',
      );
    }
    return value;
  }

  String _unixProcessListExecutable() {
    for (final candidate in const ['/bin/ps', '/usr/bin/ps']) {
      if (_processListExecutableProbe(candidate).isRegularFile) {
        return candidate;
      }
    }
    throw StateError(
      'POSIX process enumeration command was not found as a regular file.',
    );
  }

  void _requireProcessListExecutable(String path, String label) {
    final probe = _processListExecutableProbe(path);
    if (probe.isRegularFile) return;
    final diagnostic = probe.diagnostic == null
        ? ''
        : ' Probe failed: ${probe.diagnostic}.';
    throw StateError('$label command is not a regular file.$diagnostic');
  }

  _ProcessListExecutableProbe _processListExecutableProbe(String path) {
    try {
      final type = FileSystemEntity.typeSync(path, followLinks: false);
      return _ProcessListExecutableProbe(type == FileSystemEntityType.file);
    } on FileSystemException catch (error) {
      return _ProcessListExecutableProbe(
        false,
        'Unable to inspect $path: ${_boundedAppDetectionDiagnostic(error.message)}',
      );
    } on ArgumentError catch (error) {
      return _ProcessListExecutableProbe(
        false,
        'Unable to inspect $path: ${_boundedAppDetectionDiagnostic(error)}',
      );
    }
  }

  bool _isWindowsRemoteOrDevicePath(String path) {
    final normalized = path.replaceAll('/', r'\');
    if (normalized.startsWith(r'\\')) return true;
    return !RegExp(r'^[A-Za-z]:\\').hasMatch(normalized);
  }

  bool _hasParentTraversal(String path) {
    return path
        .replaceAll(r'\', '/')
        .split('/')
        .any((segment) => segment == '..');
  }

  Future<_BoundedProcessListOutput> _collectBoundedProcessListOutput(
    Stream<List<int>> stream,
  ) async {
    final buffer = StringBuffer();
    var truncated = false;
    await for (final chunk in stream.transform(
      const Utf8Decoder(allowMalformed: true),
    )) {
      final remaining = _maxAppDetectionProcessOutputChars - buffer.length;
      if (remaining > 0) {
        buffer.write(
          chunk.length <= remaining ? chunk : chunk.substring(0, remaining),
        );
      }
      if (chunk.length > remaining) truncated = true;
    }
    return _BoundedProcessListOutput(buffer.toString(), truncated: truncated);
  }

  String _processListDiagnostic({
    required _BoundedProcessListOutput stdout,
    required _BoundedProcessListOutput stderr,
  }) {
    final stderrText = _processListTextForDiagnostic(stderr);
    final stdoutText = _processListTextForDiagnostic(stdout);
    final diagnostic = stderrText.isNotEmpty
        ? stderrText
        : stdoutText.isNotEmpty
        ? stdoutText
        : 'no diagnostic output';
    return _boundedAppDetectionDiagnostic(diagnostic);
  }

  String _processListTextForDiagnostic(_BoundedProcessListOutput output) {
    final text = output.text.trim();
    if (!output.truncated) return text;
    if (text.isEmpty) return 'output exceeded process-list size limit';
    return '$text [truncated]';
  }

  Future<List<DetectedApp>> _detectKnownInstallPaths() async {
    final detected = <DetectedApp>[];
    for (final root in _knownRoots()) {
      final directory = Directory(root);
      if (!await _directoryExistsForAppDetection(directory)) continue;
      for (final entry in _registry.entries) {
        for (final hint in entry.allowedPathHints) {
          final candidateDir = Directory(_join(root, hint));
          if (!await _directoryExistsForAppDetection(candidateDir)) continue;
          final executable = await _firstExistingExecutable(
            candidateDir.path,
            entry.executableNames,
          );
          detected.add(
            DetectedApp(
              appId: entry.appId,
              displayName: entry.displayName,
              path: executable ?? candidateDir.path,
              source: _sourceForRoot(root),
              protectionProfile: entry.protectionProfile,
            ),
          );
        }
      }
    }
    return detected;
  }

  List<String> _knownRoots() {
    if (Platform.isWindows) {
      final programFiles = _knownRootEnvironmentValue('ProgramFiles');
      final programFilesX86 = _knownRootEnvironmentValue('ProgramFiles(x86)');
      return [
        if (programFiles != null) '$programFiles\\Steam\\steamapps\\common',
        if (programFilesX86 != null)
          '$programFilesX86\\Steam\\steamapps\\common',
        if (programFiles != null) '$programFiles\\Epic Apps',
        if (programFilesX86 != null) '$programFilesX86\\GOG Galaxy\\Apps',
      ];
    }
    if (Platform.isMacOS) {
      final home = _knownRootEnvironmentValue('HOME');
      return ['/Applications', if (home != null) '$home/Applications'];
    }
    if (Platform.isLinux) {
      final home = _knownRootEnvironmentValue('HOME');
      return [
        if (home != null) '$home/.steam/steam/steamapps/common',
        if (home != null) '$home/.local/share/Steam/steamapps/common',
        if (home != null) '$home/Apps',
        '/usr/local/apps',
      ];
    }
    return const [];
  }

  String? _knownRootEnvironmentValue(String name) {
    final value = _nonEmptyEnvironmentValue(name);
    if (value == null) return null;
    if (value.contains('\u0000')) {
      throw StateError(
        'Protected app install root $name must not contain NUL.',
      );
    }
    if (_hasParentTraversal(value)) {
      throw StateError(
        'Protected app install root $name must not contain parent traversal.',
      );
    }
    return _isAbsoluteLocalInstallRoot(value) ? value : null;
  }

  String? _nonEmptyEnvironmentValue(String name) {
    final value = Platform.environment[name]?.trim();
    return value == null || value.isEmpty ? null : value;
  }

  bool _isAbsoluteLocalInstallRoot(String path) {
    if (Platform.isWindows) return !_isWindowsRemoteOrDevicePath(path);
    return path.startsWith('/') && !path.startsWith('//');
  }

  Future<bool> _directoryExistsForAppDetection(Directory directory) async {
    try {
      final type = await FileSystemEntity.type(
        directory.path,
        followLinks: false,
      );
      if (type == FileSystemEntityType.link) {
        throw StateError('refusing to follow linked install path');
      }
      return type == FileSystemEntityType.directory;
    } on Object catch (error) {
      throw StateError(
        'Unable to inspect protected app install path ${directory.path}: ${_boundedAppDetectionDiagnostic(error)}',
      );
    }
  }

  Future<bool> _fileExistsForAppDetection(File file) async {
    try {
      final type = await FileSystemEntity.type(file.path, followLinks: false);
      if (type == FileSystemEntityType.link) {
        throw StateError('refusing to follow linked executable candidate');
      }
      return type == FileSystemEntityType.file;
    } on Object catch (error) {
      throw StateError(
        'Unable to inspect protected app executable candidate ${file.path}: ${_boundedAppDetectionDiagnostic(error)}',
      );
    }
  }

  Future<String?> _firstExistingExecutable(
    String root,
    List<String> executableNames,
  ) async {
    for (final executableName in executableNames) {
      final path = _join(root, executableName);
      final file = File(path);
      if (await _fileExistsForAppDetection(file)) return path;
    }
    return null;
  }

  List<DetectedApp> _dedupe(List<DetectedApp> apps) {
    final seen = <String>{};
    final unique = <DetectedApp>[];
    for (final app in apps) {
      final key = '${app.appId}:${app.path}';
      if (seen.add(key)) unique.add(app);
    }
    return unique;
  }

  String _sourceForRoot(String root) {
    final lower = root.toLowerCase();
    if (lower.contains('steam')) return 'Steam';
    if (lower.contains('epic')) return 'Epic';
    if (lower.contains('gog')) return 'GOG';
    return 'Known Location';
  }

  String _join(String a, String b) {
    final separator = Platform.pathSeparator;
    return a.endsWith(separator) ? '$a$b' : '$a$separator$b';
  }
}

class _ProcessListExecutableProbe {
  const _ProcessListExecutableProbe(this.isRegularFile, [this.diagnostic]);

  final bool isRegularFile;
  final String? diagnostic;
}

class _BoundedProcessListOutput {
  const _BoundedProcessListOutput(this.text, {required this.truncated});

  final String text;
  final bool truncated;
}
