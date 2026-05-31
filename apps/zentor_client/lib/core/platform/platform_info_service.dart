import 'dart:io';

import 'package:package_info_plus/package_info_plus.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../security/device_hash_service.dart';

class PlatformInfoService {
  PlatformInfoService(this._deviceHashService);

  final DeviceHashService _deviceHashService;

  Future<DeviceIntegritySummary> load() async {
    final packageInfo = await PackageInfo.fromPlatform();
    return DeviceIntegritySummary(
      platform: _platformName(),
      appVersion: '${packageInfo.version}+${packageInfo.buildNumber}',
      osVersion: Platform.operatingSystemVersion,
      deviceIdentifierHashStatus: _deviceHashService
          .deviceIdentifierHashStatus(),
      localCoreStatus: 'Zentor Core Service: Running',
      permissionsStatus: 'No elevated permissions requested',
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
}
