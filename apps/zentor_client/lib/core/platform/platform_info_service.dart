import 'dart:convert';
import 'dart:io';

import 'package:package_info_plus/package_info_plus.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../security/device_hash_service.dart';

class PlatformInfoService {
  PlatformInfoService(this._deviceHashService);

  final DeviceHashService _deviceHashService;

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
          : 'Current user: ${Platform.environment['USER'] ?? 'Unknown'}',
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

  String _environmentUserName() =>
      Platform.environment['USERNAME'] ??
      Platform.environment['USER'] ??
      Platform.environment['USERDOMAIN'] ??
      'Unknown';

  String _environmentArchitecture() =>
      Platform.environment['PROCESSOR_ARCHITECTURE'] ??
      Platform.operatingSystem;

  String _serviceSummary(String name, Map<String, String> serviceStates) {
    final state = serviceStates[name];
    if (state == null) return '$name: Not installed';
    return '$name: $state';
  }

  Future<Map<String, String>> _loadWindowsServiceStates() async {
    final script = r'''
$names = @('avorax_core_service','avorax_guard_service','avorax_update_service')
$result = @{}
foreach ($name in $names) {
  $svc = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction SilentlyContinue
  if ($null -eq $svc) {
    $result[$name] = 'not installed'
  } else {
    $result[$name] = "$($svc.State); start=$($svc.StartMode); path=$($svc.PathName); exit=$($svc.ExitCode)"
  }
}
$result | ConvertTo-Json -Compress
''';
    final output = await _runPowerShell(script);
    if (output == null || output.isEmpty) return const {};
    try {
      final decoded = jsonDecode(output);
      if (decoded is! Map) return const {};
      return decoded.map(
        (key, value) => MapEntry(key.toString(), value?.toString() ?? ''),
      );
    } on Object {
      return const {};
    }
  }

  Future<_SystemInfo> _loadWindowsSystemInfo() async {
    final script = r'''
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
[ordered]@{
  hostName = $env:COMPUTERNAME
  userName = $identity.Name
  architecture = $env:PROCESSOR_ARCHITECTURE
  totalPhysicalMemory = if ($computer.TotalPhysicalMemory) { '{0:N1} GB' -f ($computer.TotalPhysicalMemory / 1GB) } else { 'Unknown' }
  permissionsStatus = if ($admin) { 'Running elevated as Administrator' } else { 'Running as standard user' }
  windowsBuild = if ($os.BuildNumber) { $os.BuildNumber } else { '' }
} | ConvertTo-Json -Compress
''';
    final output = await _runPowerShell(script);
    if (output == null || output.isEmpty) return const _SystemInfo();
    try {
      final decoded = jsonDecode(output);
      if (decoded is! Map) return const _SystemInfo();
      return _SystemInfo(
        hostName: decoded['hostName']?.toString() ?? '',
        userName: decoded['userName']?.toString() ?? '',
        architecture: decoded['architecture']?.toString() ?? '',
        totalPhysicalMemory:
            decoded['totalPhysicalMemory']?.toString() ?? 'Unknown',
        permissionsStatus:
            decoded['permissionsStatus']?.toString() ?? 'Unknown',
      );
    } on Object {
      return const _SystemInfo();
    }
  }

  Future<String?> _runPowerShell(String script) async {
    try {
      final result = await Process.run('powershell.exe', [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        script,
      ]).timeout(const Duration(seconds: 8));
      if (result.exitCode != 0) return null;
      return result.stdout.toString().trim();
    } on Object {
      return null;
    }
  }
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
