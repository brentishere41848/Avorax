// ignore_for_file: prefer_initializing_formals

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:package_info_plus/package_info_plus.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../security/device_hash_service.dart';

typedef PowerShellProcessStarter =
    Future<Process> Function(String executable, List<String> arguments);

class PlatformInfoService {
  PlatformInfoService(
    this._deviceHashService, {
    Future<String?> Function(String script)? powerShellRunner,
    PowerShellProcessStarter? powerShellProcessStarter,
    Duration powerShellTimeout = const Duration(seconds: 8),
    Duration processReapTimeout = const Duration(seconds: 5),
  }) : _powerShellRunner = powerShellRunner,
       _powerShellProcessStarter = powerShellProcessStarter,
       _platformPowerShellTimeout = powerShellTimeout,
       _platformProcessReapTimeout = processReapTimeout;

  final DeviceHashService _deviceHashService;
  final Future<String?> Function(String script)? _powerShellRunner;
  final PowerShellProcessStarter? _powerShellProcessStarter;
  final Duration _platformPowerShellTimeout;
  final Duration _platformProcessReapTimeout;
  static const _windowsServiceNames = [
    'avorax_core_service',
    'avorax_guard_service',
    'avorax_update_service',
  ];
  static const _maxPlatformTextChars = 256;
  static const _maxPlatformDiagnosticChars = 2048;
  static const _maxPlatformPowerShellOutputChars = 256 * 1024;
  static const _maxServiceStateEntries = 12;
  static const _serviceProbeWarningKey = 'avorax_service_probe_warnings';
  static const _windowsProcessTreeKillTimeout = Duration(seconds: 5);

  Future<DeviceIntegritySummary> load() async {
    final packageInfo = await PackageInfo.fromPlatform();
    final windowsInfo = Platform.isWindows
        ? await _loadWindowsSystemInfo()
        : const _SystemInfo();
    final serviceStates = Platform.isWindows
        ? await _loadWindowsServiceStates()
        : const <String, String>{};
    return DeviceIntegritySummary(
      platform: _platformName(),
      appVersion: '${packageInfo.version}+${packageInfo.buildNumber}',
      osVersion: Platform.operatingSystemVersion,
      deviceIdentifierHashStatus: _deviceHashService
          .deviceIdentifierHashStatus(),
      localCoreStatus: _serviceSummary('avorax_core_service', serviceStates),
      permissionsStatus: Platform.isWindows
          ? windowsInfo.permissionsStatus
          : _nonWindowsPermissionsStatus(),
      hostName: windowsInfo.hostName.isEmpty
          ? Platform.localHostname
          : windowsInfo.hostName,
      userName: windowsInfo.userName.isEmpty
          ? _environmentUserName()
          : windowsInfo.userName,
      executablePath: Platform.resolvedExecutable,
      workingDirectory: Directory.current.path,
      systemArchitecture: windowsInfo.architecture.isEmpty
          ? _environmentArchitecture()
          : windowsInfo.architecture,
      processorCount: Platform.numberOfProcessors,
      totalPhysicalMemory: windowsInfo.totalPhysicalMemory,
      serviceStates: serviceStates,
    );
  }

  String _platformName() {
    if (Platform.isAndroid) return 'Android';
    if (Platform.isIOS) return 'iOS';
    if (Platform.isWindows) return 'Windows';
    if (Platform.isMacOS) return 'macOS';
    if (Platform.isLinux) return 'Linux';
    return Platform.operatingSystem;
  }

  String _nonWindowsPermissionsStatus() =>
      'Current user: ${_environmentValue(['USER'], fallback: 'Unknown')}';

  String _environmentUserName() => _environmentValue([
    'USERNAME',
    'USER',
    'USERDOMAIN',
  ], fallback: 'Unknown');

  String _environmentArchitecture() => _environmentValue([
    'PROCESSOR_ARCHITECTURE',
  ], fallback: Platform.operatingSystem);

  String _environmentValue(List<String> names, {required String fallback}) {
    for (final name in names) {
      final parsed = _boundedPlatformString(Platform.environment[name]);
      if (parsed != null) return parsed;
    }
    return fallback;
  }

  String _serviceSummary(String name, Map<String, String> serviceStates) {
    final state = serviceStates[name];
    if (state == null) return '$name: unknown; service evidence missing';
    return '$name: $state';
  }

  Future<Map<String, String>> _loadWindowsServiceStates() async {
    final script = r'''
function Convert-AvoraxBoundedText([object]$Value) {
  $text = [string]$Value
  if ($text.Length -gt 512) { return $text.Substring(0, 509) + '...' }
  return $text
}
$names = @('avorax_core_service','avorax_guard_service','avorax_update_service')
$result = @{}
foreach ($name in $names) {
  try {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
  } catch {
    $result[$name] = "unknown; service query failed: $(Convert-AvoraxBoundedText $_.Exception.Message)"
    continue
  }
  if ($null -eq $svc) {
    $result[$name] = 'not installed'
  } else {
    $result[$name] = "$($svc.State); start=$($svc.StartMode); path=$($svc.PathName); exit=$($svc.ExitCode)"
  }
}
$result | ConvertTo-Json -Compress
''';
    final output = await (_powerShellRunner ?? _runPowerShell)(script);
    if (output == null || output.isEmpty) {
      return _serviceProbeFailureStates(
        'PowerShell service-state probe returned no output',
      );
    }
    try {
      final decoded = jsonDecode(output);
      if (decoded is! Map) {
        return _serviceProbeFailureStates(
          'PowerShell service-state probe returned non-object JSON',
        );
      }
      final states = <String, String>{};
      final diagnostics = <String>[];
      for (final entry in decoded.entries) {
        if (states.length >= _maxServiceStateEntries) {
          diagnostics.add('service-state JSON entry limit reached');
          break;
        }
        final key = _boundedPlatformString(entry.key);
        if (key == null) {
          diagnostics.add('malformed service-state name');
          continue;
        }
        final value = _boundedPlatformString(
          entry.value,
          maxLength: _maxPlatformDiagnosticChars,
        );
        if (value == null) {
          diagnostics.add('malformed service-state value for $key');
          states[key] = 'unknown; service-state value malformed';
          continue;
        }
        states[key] = value;
      }
      _attachServiceProbeWarnings(states, diagnostics);
      return states;
    } on Object catch (error) {
      final details = _boundedPlatformDiagnostic(error);
      return _serviceProbeFailureStates(
        'PowerShell service-state probe failed: $details',
      );
    }
  }

  Map<String, String> _serviceProbeFailureStates(String reason) {
    final detail =
        _boundedPlatformString(
          'unknown; service probe failed: $reason',
          maxLength: _maxPlatformDiagnosticChars,
        ) ??
        'unknown; service probe failed';
    return {for (final name in _windowsServiceNames) name: detail};
  }

  void _attachServiceProbeWarnings(
    Map<String, String> states,
    List<String> diagnostics,
  ) {
    if (diagnostics.isEmpty) return;
    final detail =
        _boundedPlatformString(
          'unknown; service-state parse warnings: ${diagnostics.take(4).join(', ')}',
          maxLength: _maxPlatformDiagnosticChars,
        ) ??
        'unknown; service-state parse warnings';
    for (final name in _windowsServiceNames) {
      states.putIfAbsent(name, () => detail);
    }
    states[_serviceProbeWarningKey] = detail;
  }

  Future<_SystemInfo> _loadWindowsSystemInfo() async {
    final script = r'''
function Convert-AvoraxBoundedText([object]$Value) {
  $text = [string]$Value
  if ($text.Length -gt 512) { return $text.Substring(0, 509) + '...' }
  return $text
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$computer = $null
$computerError = $null
try {
  $computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
} catch {
  $computerError = Convert-AvoraxBoundedText $_.Exception.Message
}
$os = $null
$osError = $null
try {
  $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {
  $osError = Convert-AvoraxBoundedText $_.Exception.Message
}
$permissionStatus = if ($admin) { 'Running elevated as Administrator' } else { 'Running as standard user' }
if ($osError) {
  $permissionStatus = "$permissionStatus; OS query failed: $osError"
}
[ordered]@{
  hostName = $env:COMPUTERNAME
  userName = $identity.Name
  architecture = $env:PROCESSOR_ARCHITECTURE
  totalPhysicalMemory = if ($computer.TotalPhysicalMemory) { '{0:N1} GB' -f ($computer.TotalPhysicalMemory / 1GB) } elseif ($computerError) { "Unknown; computer query failed: $computerError" } else { 'Unknown' }
  permissionsStatus = $permissionStatus
  windowsBuild = if ($os.BuildNumber) { $os.BuildNumber } else { '' }
} | ConvertTo-Json -Compress
''';
    final output = await (_powerShellRunner ?? _runPowerShell)(script);
    if (output == null || output.isEmpty) {
      return _systemInfoProbeFailure(
        'PowerShell system-info probe returned no output',
      );
    }
    try {
      final decoded = jsonDecode(output);
      if (decoded is! Map) {
        return _systemInfoProbeFailure(
          'PowerShell system-info probe returned non-object JSON',
        );
      }
      final diagnostics = <String>[];
      final hostName = _platformJsonStringField(
        decoded,
        'hostName',
        diagnostics,
      );
      final userName = _platformJsonStringField(
        decoded,
        'userName',
        diagnostics,
      );
      final architecture = _platformJsonStringField(
        decoded,
        'architecture',
        diagnostics,
      );
      final totalPhysicalMemory = _platformJsonStringField(
        decoded,
        'totalPhysicalMemory',
        diagnostics,
      );
      final permissionsStatus =
          _platformJsonStringField(
            decoded,
            'permissionsStatus',
            diagnostics,
            maxLength: _maxPlatformDiagnosticChars,
          ) ??
          'Unknown';
      return _SystemInfo(
        hostName: hostName ?? '',
        userName: userName ?? '',
        architecture: architecture ?? '',
        totalPhysicalMemory: totalPhysicalMemory ?? 'Unknown',
        permissionsStatus: _platformPermissionsStatusWithDiagnostics(
          permissionsStatus,
          diagnostics,
        ),
      );
    } on Object catch (error) {
      final details = _boundedPlatformDiagnostic(error);
      return _systemInfoProbeFailure(
        'PowerShell system-info probe failed: $details',
      );
    }
  }

  _SystemInfo _systemInfoProbeFailure(String reason) {
    final detail =
        _boundedPlatformString(
          'Unknown; system info probe failed: $reason',
          maxLength: _maxPlatformDiagnosticChars,
        ) ??
        'Unknown; system info probe failed';
    return _SystemInfo(permissionsStatus: detail);
  }

  Future<String?> _runPowerShell(String script) async {
    final Process process;
    try {
      process = await (_powerShellProcessStarter ?? Process.start)(
        _windowsPowerShellExecutable(),
        [
          '-NoProfile',
          '-ExecutionPolicy',
          'Bypass',
          '-EncodedCommand',
          _powershellEncodedCommand(script),
        ],
      );
    } on Object catch (error) {
      final details = _boundedPlatformDiagnostic(error);
      throw StateError('PowerShell platform probe failed: $details');
    }
    final stdoutFuture = _collectBoundedPowerShellText(process.stdout);
    final stderrFuture = _collectBoundedPowerShellText(process.stderr);
    final int exitCode;
    try {
      exitCode = await process.exitCode.timeout(_platformPowerShellTimeout);
    } on TimeoutException {
      final terminationStatus = await _platformTimeoutTerminationStatus(
        process,
      );
      final reapStatus = await _platformReapStatus(process);
      final stdout = await _timedOutPowerShellText(stdoutFuture);
      final stderr = await _timedOutPowerShellText(stderrFuture);
      throw StateError(
        'PowerShell platform probe timed out. $terminationStatus $reapStatus: '
        '${_powerShellDiagnostic(stdout: stdout, stderr: stderr)}',
      );
    } on Object catch (error) {
      final details = _boundedPlatformDiagnostic(error);
      throw StateError('PowerShell platform probe failed: $details');
    }
    final stdout = await stdoutFuture;
    final stderr = await stderrFuture;
    if (exitCode != 0) {
      throw StateError(
        'PowerShell platform probe exited with code $exitCode: '
        '${_powerShellDiagnostic(stdout: stdout, stderr: stderr)}',
      );
    }
    if (stdout.truncated) {
      throw StateError('PowerShell platform probe output exceeded size limit.');
    }
    final output = stdout.text.trim();
    return output.isEmpty ? null : output;
  }

  String _platformTerminationStatus(bool killed) =>
      killed ? 'Termination requested.' : 'Termination request failed.';

  Future<String> _platformTimeoutTerminationStatus(Process process) async {
    if (Platform.isWindows) {
      final treeStatus = await _windowsProcessTreeTerminationStatus(
        process.pid,
      );
      if (treeStatus.startsWith('Process tree termination requested.')) {
        return 'Termination requested. $treeStatus';
      }
      return '${_platformTerminationStatus(process.kill())} $treeStatus';
    }
    return _platformTerminationStatus(process.kill());
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
      final stdoutFuture = _collectBoundedPowerShellText(
        taskkillProcess.stdout,
      );
      final stderrFuture = _collectBoundedPowerShellText(
        taskkillProcess.stderr,
      );
      final exitCode = await taskkillProcess.exitCode.timeout(
        _windowsProcessTreeKillTimeout,
      );
      final stdout = await stdoutFuture;
      final stderr = await stderrFuture;
      if (exitCode == 0) return 'Process tree termination requested.';
      return 'Process tree termination failed with exit code $exitCode: '
          '${_powerShellDiagnostic(stdout: stdout, stderr: stderr)}.';
    } on TimeoutException {
      taskkillProcess?.kill();
      return 'Process tree termination timed out.';
    } on Object catch (error) {
      return 'Process tree termination failed: '
          '${_boundedPlatformDiagnostic(error)}.';
    }
  }

  Future<String> _platformReapStatus(Process process) async {
    try {
      final exitCode = await process.exitCode.timeout(
        _platformProcessReapTimeout,
      );
      return 'Timed-out process exited with code $exitCode.';
    } on TimeoutException {
      return 'Timed-out process did not exit within '
          '${_platformProcessReapTimeout.inSeconds} seconds after termination '
          'request.';
    } on Object catch (error) {
      return 'Timed-out process exit observation failed: '
          '${_boundedPlatformDiagnostic(error)}.';
    }
  }

  Future<_BoundedPowerShellText> _timedOutPowerShellText(
    Future<_BoundedPowerShellText> output,
  ) async {
    try {
      return await output.timeout(_platformProcessReapTimeout);
    } on TimeoutException {
      return const _BoundedPowerShellText(
        'stream collection did not finish after timeout cleanup',
        truncated: true,
      );
    }
  }

  String _windowsPowerShellExecutable() {
    final systemRoot = _windowsSystemRoot();
    final candidate = File(
      '$systemRoot${Platform.pathSeparator}System32${Platform.pathSeparator}WindowsPowerShell${Platform.pathSeparator}v1.0${Platform.pathSeparator}powershell.exe',
    ).absolute.path;
    if (_isWindowsRemoteOrDevicePath(candidate)) {
      throw StateError(
        'PowerShell platform probe command must be on a local drive.',
      );
    }
    final probe = _powerShellExecutableProbe(candidate);
    if (probe.isRegularFile) return candidate;
    final diagnostic = probe.diagnostic == null
        ? ''
        : ' Probe failed: ${probe.diagnostic}.';
    throw StateError(
      'PowerShell platform probe command is not a regular file.$diagnostic',
    );
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
    final probe = _powerShellExecutableProbe(candidate);
    if (probe.isRegularFile) return candidate;
    final diagnostic = probe.diagnostic == null
        ? ''
        : ' Probe failed: ${probe.diagnostic}.';
    throw StateError(
      'Windows process tree termination command is not a regular file.$diagnostic',
    );
  }

  String _windowsSystemRoot() {
    final systemRoot =
        _checkedWindowsSystemRootValue('SystemRoot') ??
        _checkedWindowsSystemRootValue('WINDIR');
    if (systemRoot == null) {
      throw StateError(
        'SystemRoot or WINDIR is required to locate the PowerShell platform probe command.',
      );
    }
    if (_isWindowsRemoteOrDevicePath(systemRoot)) {
      throw StateError(
        'PowerShell platform probe root must be on a local drive.',
      );
    }
    return Directory(systemRoot).absolute.path;
  }

  String? _checkedWindowsSystemRootValue(String name) {
    final value = _nonEmptyEnvironmentValue(name);
    if (value == null) return null;
    if (value.contains('\u0000')) {
      throw StateError(
        'PowerShell platform probe root $name must not contain NUL.',
      );
    }
    if (_hasParentTraversal(value)) {
      throw StateError(
        'PowerShell platform probe root $name must not contain parent traversal.',
      );
    }
    return value;
  }

  _PowerShellExecutableProbe _powerShellExecutableProbe(String path) {
    try {
      final type = FileSystemEntity.typeSync(path, followLinks: false);
      return _PowerShellExecutableProbe(type == FileSystemEntityType.file);
    } on FileSystemException catch (error) {
      return _PowerShellExecutableProbe(
        false,
        'Unable to inspect $path: ${_boundedPlatformDiagnostic(error.message)}',
      );
    } on ArgumentError catch (error) {
      return _PowerShellExecutableProbe(
        false,
        'Unable to inspect $path: ${_boundedPlatformDiagnostic(error)}',
      );
    }
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

  String? _nonEmptyEnvironmentValue(String name) {
    final value = Platform.environment[name]?.trim();
    return value == null || value.isEmpty ? null : value;
  }

  Future<_BoundedPowerShellText> _collectBoundedPowerShellText(
    Stream<List<int>> stream,
  ) async {
    final buffer = StringBuffer();
    var truncated = false;
    await for (final chunk in stream.transform(
      const Utf8Decoder(allowMalformed: true),
    )) {
      final remaining = _maxPlatformPowerShellOutputChars - buffer.length;
      if (remaining > 0) {
        buffer.write(
          chunk.length <= remaining ? chunk : chunk.substring(0, remaining),
        );
      }
      if (chunk.length > remaining) truncated = true;
    }
    return _BoundedPowerShellText(buffer.toString(), truncated: truncated);
  }

  String _powerShellDiagnostic({
    required _BoundedPowerShellText stdout,
    required _BoundedPowerShellText stderr,
  }) {
    final stderrText = _powerShellTextForDiagnostic(stderr);
    final stdoutText = _powerShellTextForDiagnostic(stdout);
    final diagnostic = stderrText.isNotEmpty
        ? stderrText
        : stdoutText.isNotEmpty
        ? stdoutText
        : 'no diagnostic output';
    return _boundedPlatformString(
          diagnostic,
          maxLength: _maxPlatformDiagnosticChars,
        ) ??
        'no diagnostic output';
  }

  String _powerShellTextForDiagnostic(_BoundedPowerShellText output) {
    final text = output.text.trim();
    if (!output.truncated) return text;
    if (text.isEmpty) return 'output exceeded platform probe size limit';
    return '$text [truncated]';
  }

  String? _platformJsonStringField(
    Map<dynamic, dynamic> decoded,
    String fieldName,
    List<String> diagnostics, {
    int maxLength = _maxPlatformTextChars,
  }) {
    final value = decoded[fieldName];
    if (value == null) return null;
    final parsed = _boundedPlatformString(value, maxLength: maxLength);
    if (parsed != null) return parsed;
    diagnostics.add('malformed $fieldName');
    return null;
  }

  String _platformPermissionsStatusWithDiagnostics(
    String permissionsStatus,
    List<String> diagnostics,
  ) {
    if (diagnostics.isEmpty) return permissionsStatus;
    final detail =
        _boundedPlatformString(
          '$permissionsStatus; platform info parse warnings: ${diagnostics.take(4).join(', ')}',
          maxLength: _maxPlatformDiagnosticChars,
        ) ??
        permissionsStatus;
    return detail;
  }

  String _boundedPlatformDiagnostic(Object error) =>
      _boundedPlatformString(
        error.toString(),
        maxLength: _maxPlatformDiagnosticChars,
      ) ??
      'unknown error';

  String? _boundedPlatformString(
    Object? value, {
    int maxLength = _maxPlatformTextChars,
  }) {
    if (value is! String) return null;
    final trimmed = value.replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ').trim();
    if (trimmed.isEmpty) return null;
    if (trimmed.length <= maxLength) return trimmed;
    return trimmed.substring(0, maxLength);
  }
}

class _PowerShellExecutableProbe {
  const _PowerShellExecutableProbe(this.isRegularFile, [this.diagnostic]);

  final bool isRegularFile;
  final String? diagnostic;
}

class _BoundedPowerShellText {
  const _BoundedPowerShellText(this.text, {required this.truncated});

  final String text;
  final bool truncated;
}

class _SystemInfo {
  const _SystemInfo({
    this.hostName = '',
    this.userName = '',
    this.architecture = '',
    this.totalPhysicalMemory = 'Unknown',
    this.permissionsStatus = 'Unknown',
  });

  final String hostName;
  final String userName;
  final String architecture;
  final String totalPhysicalMemory;
  final String permissionsStatus;
}
