import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:package_info_plus/package_info_plus.dart';
import 'package:path_provider/path_provider.dart';

import '../config/build_config.dart';

enum UpdateStatus {
  notConfigured,
  notChecked,
  checking,
  upToDate,
  updateAvailable,
  downloading,
  downloaded,
  verifying,
  verified,
  installing,
  readyToRestart,
  rollingBack,
  failed;

  String get label => switch (this) {
    UpdateStatus.notConfigured => 'Update source not configured',
    UpdateStatus.notChecked => 'Not checked',
    UpdateStatus.checking => 'Checking',
    UpdateStatus.upToDate => 'Up to date',
    UpdateStatus.updateAvailable => 'Update available',
    UpdateStatus.downloading => 'Downloading update',
    UpdateStatus.downloaded => 'Update downloaded',
    UpdateStatus.verifying => 'Verifying update',
    UpdateStatus.verified => 'Update verified',
    UpdateStatus.installing => 'Installing update',
    UpdateStatus.readyToRestart => 'Ready to restart',
    UpdateStatus.rollingBack => 'Rolling back update',
    UpdateStatus.failed => 'Update failed',
  };
}

class UpdateInfo {
  const UpdateInfo({
    required this.currentVersion,
    required this.latestVersion,
    required this.feedUrl,
    required this.packageUrl,
    required this.packageSha256,
    required this.channel,
    required this.rollbackSupported,
    this.packageName,
    this.releaseNotes,
    this.publishedAt,
    this.required = false,
    this.critical = false,
    this.localPackagePath,
  });

  final String currentVersion;
  final String latestVersion;
  final Uri feedUrl;
  final Uri packageUrl;
  final String packageSha256;
  final String channel;
  final bool rollbackSupported;
  final String? packageName;
  final String? releaseNotes;
  final DateTime? publishedAt;
  final bool required;
  final bool critical;
  final String? localPackagePath;

  UpdateInfo copyWith({String? localPackagePath}) {
    return UpdateInfo(
      currentVersion: currentVersion,
      latestVersion: latestVersion,
      feedUrl: feedUrl,
      packageUrl: packageUrl,
      packageSha256: packageSha256,
      channel: channel,
      rollbackSupported: rollbackSupported,
      packageName: packageName,
      releaseNotes: releaseNotes,
      publishedAt: publishedAt,
      required: required,
      critical: critical,
      localPackagePath: localPackagePath ?? this.localPackagePath,
    );
  }
}

class UpdateCheckResult {
  const UpdateCheckResult._({
    required this.status,
    required this.currentVersion,
    this.update,
    this.error,
  });

  factory UpdateCheckResult.notConfigured(String currentVersion) =>
      UpdateCheckResult._(
        status: UpdateStatus.notConfigured,
        currentVersion: currentVersion,
        error: 'Update source not configured.',
      );

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
    final feedUrl = buildConfig.updateFeedUrl.trim();
    if (feedUrl.isEmpty) {
      return UpdateCheckResult.notConfigured(installedVersion);
    }
    final feedUri = Uri.parse(feedUrl);
    if (!_isTrustedFeedUri(feedUri)) {
      return UpdateCheckResult.failed(
        installedVersion,
        'Update source must be HTTPS or a local file feed.',
      );
    }
    try {
      final feed = await _loadFeed(feedUri);
      final update = _updateFromFeed(feed, feedUri, installedVersion);
      if (update == null) return UpdateCheckResult.upToDate(installedVersion);
      return UpdateCheckResult.available(update);
    } on Object catch (error) {
      return UpdateCheckResult.failed(installedVersion, '$error');
    }
  }

  Future<UpdateInfo> downloadUpdatePackage(UpdateInfo update) async {
    final assetName = update.packageName ?? _fileNameFromUri(update.packageUrl);
    if (!assetName.toLowerCase().endsWith('.aup')) {
      throw StateError('Normal Avorax updates require a signed .aup package.');
    }
    final cacheDir = await getTemporaryDirectory();
    final updateDir = Directory(
      '${cacheDir.path}${Platform.pathSeparator}AvoraxUpdates',
    );
    await updateDir.create(recursive: true);
    final packagePath = '${updateDir.path}${Platform.pathSeparator}$assetName';
    final packageFile = File(packagePath);
    if (update.packageUrl.scheme == 'file') {
      await File(update.packageUrl.toFilePath()).copy(packagePath);
    } else {
      final response = await _client.get(
        update.packageUrl,
        headers: const {'User-Agent': 'Avorax-In-App-Updater'},
      );
      if (response.statusCode != 200) {
        throw StateError(
          'Update package download failed with HTTP ${response.statusCode}.',
        );
      }
      await packageFile.writeAsBytes(response.bodyBytes, flush: true);
    }
    final actualHash = await _sha256File(packageFile);
    if (actualHash.toLowerCase() != update.packageSha256.toLowerCase()) {
      try {
        await packageFile.delete();
      } on Object {
        // Keep the original verification error as the user-facing failure.
      }
      throw StateError(
        'Downloaded update package SHA-256 does not match feed.',
      );
    }
    return update.copyWith(localPackagePath: packageFile.path);
  }

  Future<void> verifyDownloadedPackage(UpdateInfo update) async {
    final packagePath = update.localPackagePath;
    if (packagePath == null) {
      throw StateError('No downloaded update package is available to verify.');
    }
    final updater = _requireUpdateServiceExecutable();
    await _runUpdater(updater, [
      '--verify',
      packagePath,
      update.currentVersion,
    ], elevated: Platform.isWindows);
  }

  Future<void> installDownloadedPackage(UpdateInfo update) async {
    final packagePath = update.localPackagePath;
    if (packagePath == null) {
      throw StateError('No verified update package is available to install.');
    }
    final updater = _requireUpdateServiceExecutable();
    final args = ['--apply', packagePath, _installDir(), update.currentVersion];
    await _runUpdater(updater, args, elevated: Platform.isWindows);
  }

  Future<void> rollbackPreviousVersion() async {
    final updater = _requireUpdateServiceExecutable();
    await _runUpdater(updater, [
      '--rollback',
      _installDir(),
    ], elevated: Platform.isWindows);
  }

  String _requireUpdateServiceExecutable() {
    final updater = _updateServiceExecutable();
    if (updater == null || !File(updater).existsSync()) {
      throw StateError('Avorax Update Service executable is missing.');
    }
    return updater;
  }

  Future<void> _runUpdater(
    String updater,
    List<String> args, {
    required bool elevated,
  }) async {
    if (elevated) {
      final escapedUpdater = updater.replaceAll("'", "''");
      final escapedArgs = args
          .map((arg) => "'${arg.replaceAll("'", "''")}'")
          .join(', ');
      final process = await Process.start('powershell.exe', [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-Command',
        "\$p = Start-Process -FilePath '$escapedUpdater' -ArgumentList @($escapedArgs) -Verb RunAs -Wait -PassThru; exit \$p.ExitCode",
      ]);
      final stderr = await process.stderr.transform(utf8.decoder).join();
      final exitCode = await process.exitCode;
      if (exitCode != 0) {
        throw StateError(
          'Avorax Update Service failed. Exit code: $exitCode. $stderr',
        );
      }
      return;
    }
    final result = await Process.run(updater, args);
    if (result.exitCode != 0) {
      throw StateError('Avorax Update Service failed: ${result.stderr}');
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

  Future<Map<String, Object?>> _loadFeed(Uri feedUri) async {
    if (feedUri.scheme == 'file') {
      final text = await File(feedUri.toFilePath()).readAsString();
      final decoded = jsonDecode(text);
      if (decoded is Map<String, Object?>) return decoded;
      throw StateError('Update feed JSON root must be an object.');
    }
    final response = await _client.get(
      feedUri,
      headers: const {
        'Accept': 'application/json',
        'User-Agent': 'Avorax-Update-Checker',
      },
    );
    if (response.statusCode != 200) {
      if (_isGithubLatestDownloadFeed(feedUri) && response.statusCode == 404) {
        try {
          final releaseFeedUri = await _resolveGithubReleaseFeedAssetUri();
          if (releaseFeedUri != null) {
            return _loadFeed(releaseFeedUri);
          }
        } on Object catch (error) {
          throw StateError(
            'Update feed returned HTTP ${response.statusCode}; '
            'GitHub release feed fallback failed: $error',
          );
        }
      }
      throw StateError('Update feed returned HTTP ${response.statusCode}.');
    }
    final decoded = jsonDecode(response.body);
    if (decoded is Map<String, Object?>) return decoded;
    throw StateError('Update feed JSON root must be an object.');
  }

  bool _isGithubLatestDownloadFeed(Uri feedUri) {
    final owner = buildConfig.updatesRepoOwner.toLowerCase();
    final repo = buildConfig.updatesRepoName.toLowerCase();
    final segments = feedUri.pathSegments
        .map((part) => part.toLowerCase())
        .toList();
    return feedUri.scheme == 'https' &&
        feedUri.host.toLowerCase() == 'github.com' &&
        segments.length == 6 &&
        segments[0] == owner &&
        segments[1] == repo &&
        segments[2] == 'releases' &&
        segments[3] == 'latest' &&
        segments[4] == 'download' &&
        segments[5] == 'update-feed.json';
  }

  Future<Uri?> _resolveGithubReleaseFeedAssetUri() async {
    final apiUri = Uri.https(
      'api.github.com',
      '/repos/${buildConfig.updatesRepoOwner}/${buildConfig.updatesRepoName}/releases',
      const {'per_page': '20'},
    );
    final response = await _client.get(
      apiUri,
      headers: const {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'Avorax-Update-Checker',
      },
    );
    if (response.statusCode != 200) {
      throw StateError(
        'GitHub releases lookup returned HTTP ${response.statusCode}.',
      );
    }
    final decoded = jsonDecode(response.body);
    if (decoded is! List) {
      throw StateError('GitHub releases response JSON root must be a list.');
    }
    final allowPrerelease = buildConfig.updateChannel == 'dev';
    for (final item in decoded.whereType<Map<String, Object?>>()) {
      if (item['draft'] == true) continue;
      if (!allowPrerelease && item['prerelease'] == true) continue;
      final assets = item['assets'];
      if (assets is! List) continue;
      for (final asset in assets.whereType<Map<String, Object?>>()) {
        if (asset['name'] != 'update-feed.json') continue;
        final value = asset['browser_download_url']?.toString() ?? '';
        if (value.isEmpty) continue;
        final uri = Uri.parse(value);
        if (_isTrustedFeedUri(uri)) return uri;
      }
    }
    throw StateError('No update-feed.json asset found in GitHub releases.');
  }

  UpdateInfo? _updateFromFeed(
    Map<String, Object?> feed,
    Uri feedUri,
    String installedVersion,
  ) {
    if (feed['product'] != 'Avorax Anti-Virus') {
      throw StateError('Update feed is for the wrong product.');
    }
    final channel = feed['channel']?.toString() ?? buildConfig.updateChannel;
    if (channel != buildConfig.updateChannel) {
      throw StateError('Update feed channel does not match this build.');
    }
    final latestVersion = feed['latest_version']?.toString() ?? '';
    if (latestVersion.isEmpty) {
      throw StateError('Update feed is missing latest_version.');
    }
    if (_compareVersions(latestVersion, installedVersion) <= 0) {
      return null;
    }
    final packages = feed['packages'];
    if (packages is! List) {
      throw StateError('Update feed packages must be a list.');
    }
    final package = packages.whereType<Map<String, Object?>>().firstWhere(
      (item) =>
          item['version']?.toString() == latestVersion &&
          (item['package_url']?.toString().endsWith('.aup') ?? false),
      orElse: () =>
          throw StateError('No .aup package found for latest version.'),
    );
    final packageUrl = _resolvePackageUri(
      feedUri,
      package['package_url']?.toString() ?? '',
    );
    if (!_isTrustedPackageUri(packageUrl)) {
      throw StateError('Update package URL must be HTTPS or local file.');
    }
    final packageSha256 = package['package_sha256']?.toString() ?? '';
    if (packageSha256.isEmpty) {
      throw StateError('Update package entry is missing package_sha256.');
    }
    return UpdateInfo(
      currentVersion: installedVersion,
      latestVersion: latestVersion,
      feedUrl: feedUri,
      packageUrl: packageUrl,
      packageSha256: packageSha256,
      channel: channel,
      rollbackSupported: package['rollback_supported'] as bool? ?? false,
      packageName: _fileNameFromUri(packageUrl),
      releaseNotes: package['release_notes']?.toString(),
      publishedAt: DateTime.tryParse(package['published_at']?.toString() ?? ''),
      required: package['required'] as bool? ?? false,
      critical: package['critical'] as bool? ?? false,
    );
  }

  Uri _resolvePackageUri(Uri feedUri, String value) {
    final uri = Uri.parse(value);
    if (uri.hasScheme) return uri;
    if (feedUri.scheme == 'file') {
      final base = File(feedUri.toFilePath()).parent.uri;
      return base.resolveUri(uri);
    }
    return feedUri.resolveUri(uri);
  }

  bool _isTrustedFeedUri(Uri uri) =>
      uri.scheme == 'https' || uri.scheme == 'file';

  bool _isTrustedPackageUri(Uri uri) =>
      uri.scheme == 'https' || uri.scheme == 'file';

  String _fileNameFromUri(Uri uri) {
    final segments = uri.pathSegments;
    return segments.isEmpty ? 'update.aup' : segments.last;
  }

  Future<String> _sha256File(File file) async {
    final input = file.openRead();
    final digest = await sha256.bind(input).first;
    return digest.toString();
  }

  String? _updateServiceExecutable() {
    final name = Platform.isWindows
        ? 'avorax_update_service.exe'
        : 'avorax_update_service';
    final candidates = [
      '${File(Platform.resolvedExecutable).parent.path}${Platform.pathSeparator}$name',
      '${Directory.current.path}${Platform.pathSeparator}$name',
    ];
    for (final candidate in candidates) {
      if (File(candidate).existsSync()) return File(candidate).absolute.path;
    }
    return candidates.first;
  }

  String _installDir() {
    if (Platform.isWindows) return r'C:\Program Files\Avorax';
    return File(Platform.resolvedExecutable).parent.path;
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
    final normalized = value.trim().replaceFirst(RegExp(r'^[vV]'), '');
    final core = normalized.split(RegExp(r'[-+]')).first;
    return core
        .split('.')
        .map((part) => int.tryParse(part) ?? 0)
        .toList(growable: false);
  }
}
