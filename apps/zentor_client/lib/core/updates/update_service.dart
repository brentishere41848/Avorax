import 'dart:convert';
import 'dart:io';

import 'package:http/http.dart' as http;
import 'package:package_info_plus/package_info_plus.dart';

import '../config/build_config.dart';

enum UpdateStatus {
  notChecked,
  checking,
  upToDate,
  updateAvailable,
  failed;

  String get label => switch (this) {
    UpdateStatus.notChecked => 'Not checked',
    UpdateStatus.checking => 'Checking',
    UpdateStatus.upToDate => 'Up to date',
    UpdateStatus.updateAvailable => 'Update available',
    UpdateStatus.failed => 'Check failed',
  };
}

class UpdateInfo {
  const UpdateInfo({
    required this.currentVersion,
    required this.latestVersion,
    required this.releaseUrl,
    this.downloadUrl,
    this.assetName,
    this.publishedAt,
    this.releaseNotes,
  });

  final String currentVersion;
  final String latestVersion;
  final Uri releaseUrl;
  final Uri? downloadUrl;
  final String? assetName;
  final DateTime? publishedAt;
  final String? releaseNotes;
}

class UpdateCheckResult {
  const UpdateCheckResult._({
    required this.status,
    required this.currentVersion,
    this.update,
    this.error,
  });

  factory UpdateCheckResult.upToDate(String currentVersion) =>
      UpdateCheckResult._(
        status: UpdateStatus.upToDate,
        currentVersion: currentVersion,
      );

  factory UpdateCheckResult.available(UpdateInfo update) => UpdateCheckResult._(
    status: UpdateStatus.updateAvailable,
    currentVersion: update.currentVersion,
    update: update,
  );

  factory UpdateCheckResult.failed(String currentVersion, String error) =>
      UpdateCheckResult._(
        status: UpdateStatus.failed,
        currentVersion: currentVersion,
        error: error,
      );

  final UpdateStatus status;
  final String currentVersion;
  final UpdateInfo? update;
  final String? error;
}

class ZentorUpdateService {
  ZentorUpdateService({
    this.buildConfig = const BuildConfig(),
    http.Client? client,
  }) : _client = client ?? http.Client();

  final BuildConfig buildConfig;
  final http.Client _client;

  Future<UpdateCheckResult> checkForUpdate({String? currentVersion}) async {
    final installedVersion = currentVersion ?? await _installedVersion();
    final releasesUri = Uri.https(
      'api.github.com',
      '/repos/'
          '${buildConfig.updatesRepoOwner}/${buildConfig.updatesRepoName}'
          '/releases',
    );
    try {
      final response = await _client.get(
        releasesUri,
        headers: const {
          'Accept': 'application/vnd.github+json',
          'User-Agent': 'Avorax-Update-Checker',
        },
      );
      if (response.statusCode != 200) {
        return UpdateCheckResult.failed(
          installedVersion,
          'GitHub returned HTTP ${response.statusCode}.',
        );
      }
      final decoded = jsonDecode(response.body);
      if (decoded is! List) {
        return UpdateCheckResult.failed(
          installedVersion,
          'GitHub release response was not a list.',
        );
      }
      final release = _latestRelease(decoded);
      if (release == null) {
        return UpdateCheckResult.failed(
          installedVersion,
          'No Avorax GitHub releases were found.',
        );
      }
      final latestVersion = _normalizeVersion(release.tagName);
      if (_compareVersions(latestVersion, installedVersion) <= 0) {
        return UpdateCheckResult.upToDate(installedVersion);
      }
      return UpdateCheckResult.available(
        UpdateInfo(
          currentVersion: installedVersion,
          latestVersion: latestVersion,
          releaseUrl: release.htmlUrl,
          downloadUrl: release.preferredAsset?.downloadUrl,
          assetName: release.preferredAsset?.name,
          publishedAt: release.publishedAt,
          releaseNotes: release.body,
        ),
      );
    } on Object catch (error) {
      return UpdateCheckResult.failed(installedVersion, '$error');
    }
  }

  Future<String> _installedVersion() async {
    try {
      final packageInfo = await PackageInfo.fromPlatform();
      return packageInfo.version;
    } on Object {
      return buildConfig.appVersion;
    }
  }

  _GitHubRelease? _latestRelease(List<Object?> releases) {
    final parsed = releases
        .whereType<Map<String, Object?>>()
        .map(_GitHubRelease.fromJson)
        .where((release) => !release.draft)
        .toList();
    if (parsed.isEmpty) return null;
    parsed.sort((a, b) => _compareVersions(b.tagName, a.tagName));
    return parsed.first;
  }

  static int _compareVersions(String left, String right) {
    final a = _versionParts(left);
    final b = _versionParts(right);
    final maxLength = a.length > b.length ? a.length : b.length;
    for (var i = 0; i < maxLength; i += 1) {
      final ai = i < a.length ? a[i] : 0;
      final bi = i < b.length ? b[i] : 0;
      if (ai != bi) return ai.compareTo(bi);
    }
    return 0;
  }

  static List<int> _versionParts(String value) {
    final normalized = _normalizeVersion(value);
    final core = normalized.split(RegExp(r'[-+]')).first;
    return core
        .split('.')
        .map((part) => int.tryParse(part) ?? 0)
        .toList(growable: false);
  }

  static String _normalizeVersion(String value) {
    return value.trim().replaceFirst(RegExp(r'^[vV]'), '');
  }
}

class _GitHubRelease {
  const _GitHubRelease({
    required this.tagName,
    required this.htmlUrl,
    required this.draft,
    required this.assets,
    this.publishedAt,
    this.body,
  });

  factory _GitHubRelease.fromJson(Map<String, Object?> json) {
    final assetsJson = json['assets'];
    final assets = assetsJson is List
        ? assetsJson
              .whereType<Map<String, Object?>>()
              .map(_GitHubAsset.fromJson)
              .toList()
        : <_GitHubAsset>[];
    return _GitHubRelease(
      tagName: json['tag_name'] as String? ?? '',
      htmlUrl: Uri.parse(json['html_url'] as String? ?? 'https://github.com'),
      draft: json['draft'] as bool? ?? false,
      assets: assets,
      publishedAt: DateTime.tryParse(json['published_at'] as String? ?? ''),
      body: json['body'] as String?,
    );
  }

  final String tagName;
  final Uri htmlUrl;
  final bool draft;
  final List<_GitHubAsset> assets;
  final DateTime? publishedAt;
  final String? body;

  _GitHubAsset? get preferredAsset {
    if (assets.isEmpty) return null;
    final lowerPriority = Platform.isWindows
        ? ['setup.exe', '.msi']
        : Platform.isMacOS
        ? ['.dmg', '.pkg', '.zip']
        : Platform.isLinux
        ? ['.appimage', '.deb', '.rpm', '.tar.gz']
        : ['.apk', '.ipa'];
    for (final suffix in lowerPriority) {
      for (final asset in assets) {
        if (asset.name.toLowerCase().endsWith(suffix)) {
          return asset;
        }
      }
    }
    return assets.first;
  }
}

class _GitHubAsset {
  const _GitHubAsset({required this.name, required this.downloadUrl});

  factory _GitHubAsset.fromJson(Map<String, Object?> json) {
    return _GitHubAsset(
      name: json['name'] as String? ?? '',
      downloadUrl: Uri.parse(
        json['browser_download_url'] as String? ?? 'https://github.com',
      ),
    );
  }

  final String name;
  final Uri downloadUrl;
}
