import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:package_info_plus/package_info_plus.dart';
import 'package:path_provider/path_provider.dart';

import '../config/build_config.dart';

const int maxInAppUpdatePackageBytes = 512 * 1024 * 1024;
const int maxUpdateFeedBytes = 1024 * 1024;
const int maxGithubReleasesResponseBytes = 2 * 1024 * 1024;
const int maxUpdateFeedPackages = 64;
const int maxGithubReleases = 20;
const int maxGithubReleaseAssets = 64;
const int maxUpdateFeedUrlChars = 2048;
const int maxUpdateMetadataStringChars = 4096;
const int maxUpdateContentLengthHeaderChars = 32;
const int maxUpdateAssetNameChars = 128;
const int maxUpdateRedirectLocationChars = 4096;
const int maxUpdateRedirectBodyBytes = 64 * 1024;
const int maxUpdateReleaseNotesChars = 16 * 1024;
const int maxUpdateCheckErrorChars = 4096;
const int maxUpdaterDiagnosticChars = 8 * 1024;
const String _updaterDiagnosticTruncationSuffix = '...[truncated]';
const Duration updaterProcessTimeout = Duration(minutes: 30);
const Duration updaterProcessReapTimeout = Duration(seconds: 5);
const Duration updateNetworkRequestTimeout = Duration(seconds: 30);
const Duration updateNetworkReadTimeout = Duration(seconds: 30);
const Set<String> _allowedUpdateFeedFields = {
  'product',
  'channel',
  'latest_version',
  'minimum_supported_version',
  'packages',
};
const Set<String> _allowedUpdateFeedPackageFields = {
  'version',
  'package_url',
  'package_sha256',
  'release_notes',
  'published_at',
  'required',
  'critical',
  'rollback_supported',
};

final RegExp _supportedUpdateVersionPattern = RegExp(
  r'^[vV]?\d{1,6}(\.\d{1,6}){0,3}([-+][A-Za-z0-9._-]{1,64})?$',
);

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
  final bool? rollbackSupported;
  final String? packageName;
  final String? releaseNotes;
  final DateTime? publishedAt;
  final bool required;
  final bool critical;
  final String? localPackagePath;

  UpdateInfo copyWith({
    String? localPackagePath,
    bool clearLocalPackagePath = false,
  }) {
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
      localPackagePath: clearLocalPackagePath
          ? null
          : localPackagePath ?? this.localPackagePath,
    );
  }

  UpdateInfo withoutLocalPackagePath() => copyWith(clearLocalPackagePath: true);
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
        error: _boundedUpdateCheckError(error),
      );

  final UpdateStatus status;
  final String currentVersion;
  final UpdateInfo? update;
  final String? error;
}

String _boundedUpdateCheckError(String value) {
  final normalized = value.replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ').trim();
  if (normalized.isEmpty) return 'Update check failed.';
  if (normalized.length <= maxUpdateCheckErrorChars) return normalized;
  return '${normalized.substring(0, maxUpdateCheckErrorChars - 3)}...';
}

void _requireUpdateUriText(String value, String label) {
  if (_containsControlOrNul(value)) {
    throw StateError('$label must not contain control characters.');
  }
}

bool _containsControlOrNul(String value) {
  return RegExp(r'[\x00-\x1F\x7F]').hasMatch(value);
}

bool _containsUnsafeFreeTextControlOrNul(String value) {
  return value.runes.any(
    (codePoint) =>
        codePoint == 0x00 ||
        codePoint == 0x7F ||
        (codePoint < 0x20 &&
            codePoint != 0x09 &&
            codePoint != 0x0A &&
            codePoint != 0x0D),
  );
}

Duration _requirePositiveTimeout(Duration value, String label) {
  if (value <= Duration.zero) {
    throw ArgumentError.value(value, label, 'must be greater than zero');
  }
  return value;
}

int _requirePositiveByteLimit(int value, String label) {
  if (value <= 0) {
    throw ArgumentError.value(value, label, 'must be greater than zero');
  }
  return value;
}

class ZentorUpdateService {
  ZentorUpdateService({
    this.buildConfig = const BuildConfig(),
    http.Client? client,
    Duration networkRequestTimeout = updateNetworkRequestTimeout,
    Duration networkReadTimeout = updateNetworkReadTimeout,
    int maxPackageBytes = maxInAppUpdatePackageBytes,
  }) : _client = client ?? http.Client(),
       _networkRequestTimeout = _requirePositiveTimeout(
         networkRequestTimeout,
         'networkRequestTimeout',
       ),
       _networkReadTimeout = _requirePositiveTimeout(
         networkReadTimeout,
         'networkReadTimeout',
       ),
       _maxPackageBytes = _requirePositiveByteLimit(
         maxPackageBytes,
         'maxPackageBytes',
       );

  final BuildConfig buildConfig;
  final http.Client _client;
  final Duration _networkRequestTimeout;
  final Duration _networkReadTimeout;
  final int _maxPackageBytes;

  bool get packageMutationSupported => Platform.isWindows;

  Future<UpdateCheckResult> checkForUpdate({String? currentVersion}) async {
    String? installedVersion;
    try {
      installedVersion = currentVersion ?? await _installedVersion();
      final feedUrl = buildConfig.updateFeedUrl.trim();
      if (feedUrl.isEmpty) {
        return UpdateCheckResult.notConfigured(installedVersion);
      }
      if (feedUrl.length > maxUpdateFeedUrlChars) {
        return UpdateCheckResult.failed(
          installedVersion,
          'Update source URL is too long.',
        );
      }
      _requireUpdateUriText(feedUrl, 'Update source URL');
      final feedUri = Uri.parse(feedUrl);
      if (!_isTrustedFeedUri(feedUri)) {
        return UpdateCheckResult.failed(
          installedVersion,
          'Update source must be HTTPS or a local file feed.',
        );
      }
      final feed = await _loadFeed(feedUri);
      final update = _updateFromFeed(feed, feedUri, installedVersion);
      if (update == null) return UpdateCheckResult.upToDate(installedVersion);
      return UpdateCheckResult.available(update);
    } on Object catch (error) {
      return UpdateCheckResult.failed(
        installedVersion ?? currentVersion ?? _installedVersionFailureLabel(),
        _boundedUpdateCheckError('$error'),
      );
    }
  }

  Future<UpdateInfo> downloadUpdatePackage(UpdateInfo update) async {
    _requireUpdateInfoForUse(update);
    if (!_isTrustedPackageUri(update.packageUrl, update.feedUrl)) {
      throw StateError(
        'Update package URL must be HTTPS unless the update feed is local.',
      );
    }
    if (update.feedUrl.scheme == 'file' && update.packageUrl.scheme == 'file') {
      _requireExistingLocalPackageInsideFeedDirectory(
        update.feedUrl,
        update.packageUrl,
      );
    }
    final assetName = _safeUpdateAssetName(
      update.packageName ?? _fileNameFromUri(update.packageUrl),
    );
    if (!assetName.toLowerCase().endsWith('.aup')) {
      throw StateError('Normal Avorax updates require a signed .aup package.');
    }
    final updateDir = await _updateCacheDirectory();
    await _ensureSafeDirectory(updateDir, 'update cache directory');
    final packagePath = '${updateDir.path}${Platform.pathSeparator}$assetName';
    final packageFile = File(packagePath);
    _rejectLinkPath(packagePath, 'cached update package');
    final tempFile = await _temporaryPackageFile(updateDir, assetName);
    try {
      if (update.packageUrl.scheme == 'file') {
        final source = File(update.packageUrl.toFilePath());
        _requireRegularFile(source.path, 'local update package source');
        _rejectOversizedPackage(
          await source.length(),
          'Local update package source',
        );
        await _copyLocalPackageToReservedTempFile(source, tempFile);
      } else {
        final response = await _getPackageWithAllowedRedirects(
          update.packageUrl,
        );
        if (response.statusCode != 200) {
          if (response.statusCode >= 300 && response.statusCode < 400) {
            throw StateError('Update package redirects are not allowed.');
          }
          throw StateError(
            'Update package download failed with HTTP ${response.statusCode}.',
          );
        }
        _rejectOversizedPackageHeader(
          response.headers['content-length'],
          'Update package Content-Length',
        );
        await _writeStreamToReservedPackageFile(
          tempFile,
          response.stream,
          'downloaded update package',
        );
      }
      final actualHash = await _sha256File(tempFile);
      if (actualHash.toLowerCase() != update.packageSha256.toLowerCase()) {
        throw StateError(
          'Downloaded update package SHA-256 does not match feed.',
        );
      }
      await _activateDownloadedPackage(tempFile, packageFile);
    } on Object catch (error, stackTrace) {
      try {
        await _deleteTemporaryPackageFile(tempFile);
      } on Object catch (cleanupError) {
        Error.throwWithStackTrace(
          StateError(
            'Update package download failed and temporary package cleanup also failed. '
            "Original error: ${_boundedUpdateCheckError('$error')}. "
            "Cleanup error: ${_boundedUpdateCheckError('$cleanupError')}",
          ),
          stackTrace,
        );
      }
      Error.throwWithStackTrace(error, stackTrace);
    }
    return update.copyWith(localPackagePath: packageFile.path);
  }

  Future<http.StreamedResponse> _getPackageWithAllowedRedirects(
    Uri packageUri,
  ) {
    return _sendWithAllowedGithubReleaseRedirects(
      packageUri,
      label: 'Update package',
      headers: const {'User-Agent': 'Avorax-In-App-Updater'},
    );
  }

  Future<Directory> _updateCacheDirectory() async {
    final cacheDir = await getTemporaryDirectory();
    return Directory('${cacheDir.path}${Platform.pathSeparator}AvoraxUpdates');
  }

  void _rejectOversizedPackage(int sizeBytes, String label) {
    if (sizeBytes > _maxPackageBytes) {
      throw StateError(
        '$label exceeds the ${_packageSizeLimitLabel()} in-app update package limit.',
      );
    }
  }

  String _packageSizeLimitLabel() {
    if (_maxPackageBytes >= 1024 * 1024 &&
        _maxPackageBytes % (1024 * 1024) == 0) {
      return '${_maxPackageBytes ~/ (1024 * 1024)} MiB';
    }
    return _maxPackageBytes == 1 ? '1 byte' : '$_maxPackageBytes bytes';
  }

  void _rejectOversizedPackageHeader(String? value, String label) {
    final sizeBytes = _parseContentLengthHeader(value, label);
    if (sizeBytes == null) return;
    _rejectOversizedPackage(sizeBytes, label);
  }

  void _rejectOversizedJson(int sizeBytes, int limitBytes, String label) {
    if (sizeBytes > limitBytes) {
      throw StateError(
        '$label exceeds the ${limitBytes ~/ 1024} KiB update metadata limit.',
      );
    }
  }

  void _rejectOversizedJsonHeader(String? value, int limitBytes, String label) {
    final sizeBytes = _parseContentLengthHeader(value, label);
    if (sizeBytes == null) return;
    _rejectOversizedJson(sizeBytes, limitBytes, label);
  }

  int? _parseContentLengthHeader(String? value, String label) {
    if (value == null) return null;
    if (value.length > maxUpdateContentLengthHeaderChars ||
        _containsControlOrNul(value)) {
      throw StateError('$label is invalid.');
    }
    final normalized = value.trim();
    if (normalized.isEmpty || !RegExp(r'^\d{1,32}$').hasMatch(normalized)) {
      throw StateError('$label is invalid.');
    }
    final sizeBytes = int.tryParse(normalized);
    if (sizeBytes == null) {
      throw StateError('$label is invalid.');
    }
    return sizeBytes;
  }

  Future<void> verifyDownloadedPackage(UpdateInfo update) async {
    final packagePath = await _requireDownloadedPackageForUse(update, 'verify');
    final updater = _requireInstalledUpdateServiceExecutable();
    await _runUpdater(
      updater,
      _updaterArgsFor(update, ['--verify', packagePath, update.currentVersion]),
      elevated: Platform.isWindows,
    );
  }

  Future<void> installDownloadedPackage(UpdateInfo update) async {
    final packagePath = await _requireDownloadedPackageForUse(
      update,
      'install',
    );
    final updater = _requireInstalledUpdateServiceExecutable();
    final args = ['--apply', packagePath, _installDir(), update.currentVersion];
    await _runUpdater(
      updater,
      _updaterArgsFor(update, args),
      elevated: Platform.isWindows,
    );
  }

  List<String> _updaterArgsFor(UpdateInfo update, List<String> args) {
    if (update.channel == 'dev') {
      return [...args, '--allow-development-key'];
    }
    return args;
  }

  Future<String> _requireDownloadedPackageForUse(
    UpdateInfo update,
    String action,
  ) async {
    _requireUpdateInfoForUse(update);
    final packagePath = update.localPackagePath;
    if (packagePath == null || packagePath.trim().isEmpty) {
      throw StateError('No downloaded update package is available to $action.');
    }
    _safeUpdateAssetName(_fileNameFromUri(File(packagePath).uri));
    final updateDir = await _updateCacheDirectory();
    await _ensureSafeDirectory(updateDir, 'update cache directory');
    if (!_isPathInside(
      updateDir.absolute.path,
      File(packagePath).absolute.path,
    )) {
      throw StateError(
        'Downloaded update package is outside the update cache.',
      );
    }
    _requireRegularFile(packagePath, 'downloaded update package');
    final actualHash = await _sha256File(File(packagePath));
    if (actualHash.toLowerCase() != update.packageSha256.toLowerCase()) {
      throw StateError(
        'Downloaded update package SHA-256 changed before $action.',
      );
    }
    return packagePath;
  }

  void _requireUpdateInfoForUse(UpdateInfo update) {
    _requireSupportedVersion(update.currentVersion, 'current version');
    _requireSupportedVersion(update.latestVersion, 'latest version');
    if (update.channel != buildConfig.updateChannel) {
      throw StateError('Downloaded update channel does not match this build.');
    }
    if (!_isTrustedFeedUri(update.feedUrl)) {
      throw StateError('Downloaded update feed URL is not trusted.');
    }
    _requirePackageArtifactUri(update.packageUrl);
    if (!_isSha256(update.packageSha256)) {
      throw StateError('Downloaded update package SHA-256 is invalid.');
    }
  }

  Future<void> rollbackPreviousVersion() async {
    final updater = _requireInstalledUpdateServiceExecutable();
    await _runUpdater(updater, [
      '--rollback',
      _installDir(),
    ], elevated: Platform.isWindows);
  }

  String _requireInstalledUpdateServiceExecutable() {
    final updater = _updateServiceExecutable(
      includeDevelopmentCandidates: false,
    );
    if (updater == null) {
      throw StateError('Avorax Update Service executable is missing.');
    }
    final probe = _regularUpdateFileProbe(updater);
    if (probe.isRegularFile) {
      final path = File(updater).resolveSymbolicLinksSync();
      final devBlocker = _developmentUpdateServiceExecutionBlocker(path);
      if (devBlocker != null) throw StateError(devBlocker);
      return path;
    }
    final devCandidate = _firstDevelopmentUpdateServiceExecutable();
    if (devCandidate != null) {
      throw StateError(
        'Refusing to use a development checkout Avorax Update Service for in-app update verification, install, or rollback. Build and install Avorax first, then run updates from the installed app.',
      );
    }
    _requireRegularFile(updater, 'Avorax Update Service executable');
    return updater;
  }

  Future<void> _runUpdater(
    String updater,
    List<String> args, {
    required bool elevated,
  }) async {
    final Process process;
    if (elevated) {
      process = await Process.start(_windowsPowerShellExecutable(), [
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-EncodedCommand',
        _powershellEncodedCommand(_elevatedUpdaterScript(updater, args)),
      ]);
    } else {
      process = await Process.start(updater, args);
    }
    final stdoutFuture = _collectBoundedUtf8(process.stdout);
    final stderrFuture = _collectBoundedUtf8(process.stderr);
    final int exitCode;
    try {
      exitCode = await process.exitCode.timeout(updaterProcessTimeout);
    } on TimeoutException {
      final terminationStatus = _updaterTerminationStatus(process.kill());
      final reapStatus = await _updaterReapStatus(process);
      final stdout = await stdoutFuture;
      final stderr = await stderrFuture;
      throw StateError(
        'Avorax Update Service timed out.$terminationStatus$reapStatus'
        '${_formatUpdaterDiagnostics(stdout: stdout, stderr: stderr)}',
      );
    }
    final stdout = await stdoutFuture;
    final stderr = await stderrFuture;
    if (exitCode != 0) {
      throw StateError(
        'Avorax Update Service failed. Exit code: $exitCode.'
        '${_formatUpdaterDiagnostics(stdout: stdout, stderr: stderr)}',
      );
    }
  }

  String _updaterTerminationStatus(bool killed) {
    return killed ? ' Termination requested.' : ' Termination request failed.';
  }

  Future<String> _updaterReapStatus(Process process) async {
    try {
      final exitCode = await process.exitCode.timeout(
        updaterProcessReapTimeout,
      );
      return ' Timed-out process exited with code $exitCode.';
    } on TimeoutException {
      return ' Timed-out process did not exit after termination request.';
    } on Object catch (error) {
      return ' Failed to observe timed-out process exit: '
          '${_boundedUpdateCheckError('$error')}';
    }
  }

  Future<String> _collectBoundedUtf8(Stream<List<int>> stream) async {
    final buffer = StringBuffer();
    var truncated = false;
    await for (final chunk in stream.transform(
      const Utf8Decoder(allowMalformed: true),
    )) {
      final remaining = maxUpdaterDiagnosticChars - buffer.length;
      if (remaining > 0) {
        buffer.write(
          chunk.length <= remaining ? chunk : chunk.substring(0, remaining),
        );
      }
      if (chunk.length > remaining) truncated = true;
    }
    if (!truncated) return buffer.toString();
    return _updaterDiagnosticWithTruncationSuffix(buffer.toString());
  }

  String _updaterDiagnosticWithTruncationSuffix(String text) {
    if (maxUpdaterDiagnosticChars <=
        _updaterDiagnosticTruncationSuffix.length) {
      return _updaterDiagnosticTruncationSuffix.substring(
        0,
        maxUpdaterDiagnosticChars,
      );
    }
    final prefixLimit =
        maxUpdaterDiagnosticChars - _updaterDiagnosticTruncationSuffix.length;
    final prefix = text.length <= prefixLimit
        ? text
        : text.substring(0, prefixLimit);
    return '$prefix$_updaterDiagnosticTruncationSuffix';
  }

  String _boundedUpdaterDiagnosticText(String text) {
    if (text.length <= maxUpdaterDiagnosticChars) return text;
    return _updaterDiagnosticWithTruncationSuffix(text);
  }

  String _formatUpdaterDiagnostics({
    required String stdout,
    required String stderr,
  }) {
    final parts = <String>[];
    final stderrText = stderr
        .replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ')
        .trim();
    final stdoutText = stdout
        .replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ')
        .trim();
    if (stderrText.isNotEmpty) parts.add(' stderr: $stderrText');
    if (stdoutText.isNotEmpty) parts.add(' stdout: $stdoutText');
    return _boundedUpdaterDiagnosticText(parts.join());
  }

  Future<String> _installedVersion() async {
    try {
      final packageInfo = await PackageInfo.fromPlatform();
      final version = packageInfo.version.trim();
      if (version.isEmpty) {
        throw StateError('installed package version was empty');
      }
      return version;
    } on Object catch (error) {
      throw StateError(
        'Unable to determine installed Avorax version: ${_boundedUpdateCheckError('$error')}',
      );
    }
  }

  String _installedVersionFailureLabel() {
    final fallback = buildConfig.appVersion.trim();
    return fallback.isEmpty ? 'unknown' : fallback;
  }

  Future<Map<String, Object?>> _loadFeed(Uri feedUri) async {
    if (feedUri.scheme == 'file') {
      final file = File(feedUri.toFilePath());
      final text = await _readBoundedUtf8File(
        file,
        maxUpdateFeedBytes,
        'Local update feed',
      );
      final decoded = jsonDecode(text);
      if (decoded is Map<String, Object?>) return decoded;
      throw StateError('Update feed JSON root must be an object.');
    }
    final response = await _getFeedWithAllowedRedirects(feedUri);
    if (response.statusCode != 200) {
      if (response.statusCode >= 300 && response.statusCode < 400) {
        throw StateError('Update feed redirects are not allowed.');
      }
      if (_isGithubLatestDownloadFeed(feedUri) && response.statusCode == 404) {
        try {
          final releaseFeedUri = await _resolveGithubReleaseFeedAssetUri();
          if (releaseFeedUri != null) {
            return _loadFeed(releaseFeedUri);
          }
        } on Object catch (error) {
          throw StateError(
            'Update feed returned HTTP ${response.statusCode}; '
            'GitHub release feed fallback failed: ${_boundedUpdateCheckError('$error')}',
          );
        }
      }
      throw StateError('Update feed returned HTTP ${response.statusCode}.');
    }
    _rejectOversizedJsonHeader(
      response.headers['content-length'],
      maxUpdateFeedBytes,
      'Update feed Content-Length',
    );
    _rejectOversizedJson(
      response.bodyBytes.length,
      maxUpdateFeedBytes,
      'Update feed response',
    );
    final decoded = jsonDecode(response.body);
    if (decoded is Map<String, Object?>) return decoded;
    throw StateError('Update feed JSON root must be an object.');
  }

  Future<String> _readBoundedUtf8File(
    File file,
    int maxBytes,
    String label,
  ) async {
    _requireRegularFile(file.path, label);
    final bytes = <int>[];
    var totalBytes = 0;
    await for (final chunk in file.openRead()) {
      totalBytes += chunk.length;
      _rejectOversizedJson(totalBytes, maxBytes, label);
      bytes.addAll(chunk);
    }
    _requireRegularFile(file.path, label);
    return utf8.decode(bytes);
  }

  Future<http.Response> _getFeedWithAllowedRedirects(Uri feedUri) {
    return _getWithAllowedGithubReleaseRedirects(
      feedUri,
      label: 'Update feed',
      maxBytes: maxUpdateFeedBytes,
      headers: const {
        'Accept': 'application/json',
        'User-Agent': 'Avorax-Update-Checker',
      },
    );
  }

  Future<http.Response> _getWithAllowedGithubReleaseRedirects(
    Uri initialUri, {
    required String label,
    required int maxBytes,
    required Map<String, String> headers,
  }) async {
    final streamed = await _sendWithAllowedGithubReleaseRedirects(
      initialUri,
      label: label,
      headers: headers,
    );
    return _responseFromBoundedStreamedResponse(streamed, maxBytes, label);
  }

  Future<http.Response> _responseFromBoundedStreamedResponse(
    http.StreamedResponse streamed,
    int maxBytes,
    String label,
  ) async {
    final bytes = <int>[];
    var totalBytes = 0;
    try {
      await for (final chunk in streamed.stream.timeout(_networkReadTimeout)) {
        totalBytes += chunk.length;
        _rejectOversizedJson(totalBytes, maxBytes, label);
        bytes.addAll(chunk);
      }
    } on TimeoutException {
      throw StateError(_responseTimeoutMessage(label));
    }
    return http.Response.bytes(
      bytes,
      streamed.statusCode,
      request: streamed.request,
      headers: streamed.headers,
      isRedirect: streamed.isRedirect,
      persistentConnection: streamed.persistentConnection,
      reasonPhrase: streamed.reasonPhrase,
    );
  }

  String _responseTimeoutMessage(String label) {
    if (label.endsWith(' response')) return '$label timed out.';
    return '$label response timed out.';
  }

  Future<http.StreamedResponse> _sendWithAllowedGithubReleaseRedirects(
    Uri initialUri, {
    required String label,
    required Map<String, String> headers,
  }) async {
    var currentUri = initialUri;
    for (var redirectCount = 0; redirectCount < 3; redirectCount += 1) {
      final request = http.Request('GET', currentUri)
        ..followRedirects = false
        ..headers.addAll(headers);
      final http.StreamedResponse streamed;
      try {
        streamed = await _client.send(request).timeout(_networkRequestTimeout);
      } on TimeoutException {
        throw StateError('$label request timed out.');
      }
      if (streamed.statusCode < 300 || streamed.statusCode >= 400) {
        return streamed;
      }
      await _drainBoundedRedirectBody(streamed.stream, label);
      currentUri = _allowedGithubReleaseRedirectLocation(
        currentUri,
        streamed.headers,
        label,
      );
    }
    throw StateError('$label redirected too many times.');
  }

  Future<void> _drainBoundedRedirectBody(
    Stream<List<int>> stream,
    String label,
  ) async {
    var totalBytes = 0;
    try {
      await for (final chunk in stream.timeout(_networkReadTimeout)) {
        totalBytes += chunk.length;
        if (totalBytes > maxUpdateRedirectBodyBytes) {
          throw StateError('$label redirect response body is too large.');
        }
      }
    } on TimeoutException {
      throw StateError('$label redirect response timed out.');
    }
  }

  Uri _allowedGithubReleaseRedirectLocation(
    Uri currentUri,
    Map<String, String> responseHeaders,
    String label,
  ) {
    final rawLocation = responseHeaders['location'];
    if (rawLocation == null ||
        rawLocation.length > maxUpdateRedirectLocationChars) {
      throw StateError('$label redirect location is invalid.');
    }
    _requireUpdateUriText(rawLocation, '$label redirect location');
    final location = rawLocation.trim();
    if (location.isEmpty) {
      throw StateError('$label redirect location is invalid.');
    }
    final Uri redirectedUri;
    try {
      redirectedUri = currentUri.resolve(location);
    } on FormatException catch (error) {
      final details = _boundedUpdateCheckError(error.message);
      throw StateError('$label redirect location is invalid: $details');
    }
    if (!_isAllowedGithubReleaseRedirect(currentUri, redirectedUri)) {
      throw StateError('$label redirects are not allowed.');
    }
    return redirectedUri;
  }

  bool _isGithubLatestDownloadFeed(Uri feedUri) {
    final owner = _configuredGithubRepoPart(
      buildConfig.updatesRepoOwner,
      'owner',
    ).toLowerCase();
    final repo = _configuredGithubRepoPart(
      buildConfig.updatesRepoName,
      'repository',
    ).toLowerCase();
    final segments = feedUri.pathSegments
        .map((part) => part.toLowerCase())
        .toList();
    return _isTrustedHttpsUri(feedUri) &&
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
    final owner = _configuredGithubRepoPart(
      buildConfig.updatesRepoOwner,
      'owner',
    );
    final repo = _configuredGithubRepoPart(
      buildConfig.updatesRepoName,
      'repository',
    );
    final apiUri = Uri.https(
      'api.github.com',
      '/repos/$owner/$repo/releases',
      const {'per_page': '20'},
    );
    final response = await _getGithubReleasesWithoutRedirect(apiUri);
    if (response.statusCode >= 300 && response.statusCode < 400) {
      throw StateError('GitHub releases lookup redirects are not allowed.');
    }
    if (response.statusCode != 200) {
      throw StateError(
        'GitHub releases lookup returned HTTP ${response.statusCode}.',
      );
    }
    _rejectOversizedJsonHeader(
      response.headers['content-length'],
      maxGithubReleasesResponseBytes,
      'GitHub releases Content-Length',
    );
    _rejectOversizedJson(
      response.bodyBytes.length,
      maxGithubReleasesResponseBytes,
      'GitHub releases response',
    );
    final decoded = jsonDecode(response.body);
    if (decoded is! List) {
      throw StateError('GitHub releases response JSON root must be a list.');
    }
    if (decoded.length > maxGithubReleases) {
      throw StateError('GitHub releases response contains too many releases.');
    }
    final allowPrerelease = buildConfig.updateChannel == 'dev';
    for (final item in decoded) {
      if (item is! Map<String, Object?>) {
        throw StateError('GitHub release entries must be objects.');
      }
      if (_githubOptionalBool(item, 'draft') == true) continue;
      if (!allowPrerelease && _githubOptionalBool(item, 'prerelease') == true) {
        continue;
      }
      final assets = item['assets'];
      if (assets is! List) {
        throw StateError('GitHub release assets must be a list.');
      }
      if (assets.length > maxGithubReleaseAssets) {
        throw StateError('GitHub release contains too many assets.');
      }
      for (final asset in assets) {
        if (asset is! Map<String, Object?>) {
          throw StateError('GitHub release asset entries must be objects.');
        }
        if (_githubRequiredString(asset, 'name') != 'update-feed.json') {
          continue;
        }
        final value = _githubRequiredString(asset, 'browser_download_url');
        _requireUpdateUriText(value, 'GitHub release feed asset URL');
        final Uri uri;
        try {
          uri = Uri.parse(value);
        } on FormatException catch (error) {
          final details = _boundedUpdateCheckError(error.message);
          throw StateError(
            'GitHub release feed asset URL is invalid: $details',
          );
        }
        if (_isTrustedGithubReleaseFeedAssetUri(uri)) return uri;
      }
    }
    throw StateError('No update-feed.json asset found in GitHub releases.');
  }

  Future<http.Response> _getGithubReleasesWithoutRedirect(Uri apiUri) async {
    final request = http.Request('GET', apiUri)
      ..followRedirects = false
      ..headers['Accept'] = 'application/vnd.github+json'
      ..headers['User-Agent'] = 'Avorax-Update-Checker';
    final http.StreamedResponse streamed;
    try {
      streamed = await _client.send(request).timeout(_networkRequestTimeout);
    } on TimeoutException {
      throw StateError('GitHub releases request timed out.');
    }
    return _responseFromBoundedStreamedResponse(
      streamed,
      maxGithubReleasesResponseBytes,
      'GitHub releases response',
    );
  }

  bool _isTrustedGithubReleaseFeedAssetUri(Uri uri) {
    return _trustedGithubReleaseAssetName(uri) == 'update-feed.json';
  }

  bool _isAllowedGithubReleaseRedirect(Uri currentUri, Uri redirectedUri) {
    final currentAssetName = _trustedGithubReleaseAssetName(currentUri);
    if (currentAssetName == null ||
        !_isAllowedUpdateRedirectAssetName(currentAssetName)) {
      return false;
    }
    final redirectedAssetName = _trustedGithubReleaseAssetName(redirectedUri);
    if (redirectedAssetName != null) {
      return redirectedAssetName == currentAssetName;
    }
    final redirectedSegments = redirectedUri.pathSegments;
    return _isTrustedHttpsUri(redirectedUri) &&
        redirectedUri.host.toLowerCase() ==
            'release-assets.githubusercontent.com' &&
        !redirectedUri.hasFragment &&
        redirectedSegments.length >= 3 &&
        redirectedSegments.first == 'github-production-release-asset' &&
        redirectedSegments.every(
          (part) => part.isNotEmpty && part != '.' && part != '..',
        );
  }

  String? _trustedGithubReleaseAssetName(Uri uri) {
    final owner = _configuredGithubRepoPart(
      buildConfig.updatesRepoOwner,
      'owner',
    ).toLowerCase();
    final repo = _configuredGithubRepoPart(
      buildConfig.updatesRepoName,
      'repository',
    ).toLowerCase();
    final segments = uri.pathSegments
        .map((part) => part.toLowerCase())
        .toList(growable: false);
    if (!_isTrustedHttpsUri(uri) ||
        uri.host.toLowerCase() != 'github.com' ||
        segments.length < 6 ||
        segments[0] != owner ||
        segments[1] != repo ||
        segments[2] != 'releases') {
      return null;
    }
    if (segments[3] == 'latest' &&
        segments.length == 6 &&
        segments[4] == 'download') {
      return _safeTrustedGithubAssetName(segments[5]);
    }
    if (segments[3] == 'download' && segments.length == 6) {
      return _safeTrustedGithubAssetName(segments[5]);
    }
    return null;
  }

  String? _safeTrustedGithubAssetName(String value) {
    if (value == 'update-feed.json') return value;
    try {
      return _safeUpdateAssetName(value);
    } on StateError {
      return null;
    }
  }

  String _configuredGithubRepoPart(String value, String label) {
    final normalized = value.trim();
    final pattern = label == 'owner'
        ? RegExp(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$')
        : RegExp(r'^[A-Za-z0-9._-]{1,100}$');
    if (!pattern.hasMatch(normalized) ||
        normalized == '.' ||
        normalized == '..' ||
        normalized.contains('..')) {
      throw StateError('Configured GitHub update $label is invalid.');
    }
    return normalized;
  }

  UpdateInfo? _updateFromFeed(
    Map<String, Object?> feed,
    Uri feedUri,
    String installedVersion,
  ) {
    _rejectUnknownUpdateFields(feed, _allowedUpdateFeedFields, 'feed');
    final product = _requiredString(feed, 'product');
    if (product != 'Avorax Anti-Virus') {
      throw StateError('Update feed is for the wrong product.');
    }
    final channel =
        _optionalString(feed, 'channel') ?? buildConfig.updateChannel;
    if (channel != buildConfig.updateChannel) {
      throw StateError('Update feed channel does not match this build.');
    }
    final latestVersion = _requiredString(feed, 'latest_version');
    _requireSupportedVersion(latestVersion, 'latest_version');
    _requireSupportedVersion(installedVersion, 'installed version');
    final minimumSupportedVersion = _optionalString(
      feed,
      'minimum_supported_version',
    );
    if (minimumSupportedVersion != null) {
      _requireSupportedVersion(
        minimumSupportedVersion,
        'minimum_supported_version',
      );
      if (_compareVersions(installedVersion, minimumSupportedVersion) < 0) {
        throw StateError(
          'Installed version is below update feed minimum_supported_version.',
        );
      }
    }
    if (_compareVersions(latestVersion, installedVersion) <= 0) {
      return null;
    }
    final packages = feed['packages'];
    if (packages is! List) {
      throw StateError('Update feed packages must be a list.');
    }
    if (packages.length > maxUpdateFeedPackages) {
      throw StateError('Update feed contains too many packages.');
    }
    Map<String, Object?>? package;
    for (final item in packages) {
      if (item is! Map<String, Object?>) {
        throw StateError('Update feed package entries must be objects.');
      }
      _rejectUnknownUpdateFields(
        item,
        _allowedUpdateFeedPackageFields,
        'feed package',
      );
      final candidatePackageUrl = _requiredString(item, 'package_url');
      if (!candidatePackageUrl.endsWith('.aup')) {
        continue;
      }
      final candidateVersion = _requiredString(item, 'version');
      _requireSupportedVersion(candidateVersion, 'package version');
      if (candidateVersion == latestVersion) {
        package = item;
        break;
      }
    }
    if (package == null) {
      throw StateError('No .aup package found for latest version.');
    }
    final packageVersion = _requiredString(package, 'version');
    _requireSupportedVersion(packageVersion, 'package version');
    if (packageVersion != latestVersion) {
      throw StateError('Update package version does not match latest_version.');
    }
    final packageUrl = _resolvePackageUri(
      feedUri,
      _requiredString(package, 'package_url'),
    );
    _requirePackageArtifactUri(packageUrl);
    if (!_isTrustedPackageUri(packageUrl, feedUri)) {
      throw StateError(
        'Update package URL must be HTTPS unless the update feed is local.',
      );
    }
    if (feedUri.scheme == 'file' && packageUrl.scheme == 'file') {
      _requireLocalPackageInsideFeedDirectory(feedUri, packageUrl);
    }
    final packageSha256 = _requiredString(package, 'package_sha256');
    if (!_isSha256(packageSha256)) {
      throw StateError(
        'Update package entry is missing a valid package_sha256.',
      );
    }
    return UpdateInfo(
      currentVersion: installedVersion,
      latestVersion: latestVersion,
      feedUrl: feedUri,
      packageUrl: packageUrl,
      packageSha256: packageSha256,
      channel: channel,
      rollbackSupported: _optionalBool(package, 'rollback_supported'),
      packageName: _safeUpdateAssetName(_fileNameFromUri(packageUrl)),
      releaseNotes: _optionalBoundedString(
        package,
        'release_notes',
        maxUpdateReleaseNotesChars,
      ),
      publishedAt: _optionalDateTime(package, 'published_at'),
      required: _optionalBool(package, 'required') ?? false,
      critical: _optionalBool(package, 'critical') ?? false,
    );
  }

  Uri _resolvePackageUri(Uri feedUri, String value) {
    _requireUpdateUriText(value, 'Update package URL');
    final Uri uri;
    try {
      uri = Uri.parse(value);
    } on FormatException catch (error) {
      final details = _boundedUpdateCheckError(error.message);
      throw StateError('Update package URL is invalid: $details');
    }
    if (uri.hasScheme) return uri;
    if (feedUri.scheme == 'file') {
      final base = File(feedUri.toFilePath()).parent.uri;
      return base.resolveUri(uri);
    }
    return feedUri.resolveUri(uri);
  }

  void _requirePackageArtifactUri(Uri uri) {
    if (uri.hasQuery || uri.hasFragment) {
      throw StateError(
        'Update package URL must not include query or fragment.',
      );
    }
  }

  bool _isTrustedFeedUri(Uri uri) {
    if (uri.scheme == 'https') return _isTrustedHttpsUri(uri);
    if (uri.scheme != 'file') return false;
    return _isTrustedLocalFileFeedUri(uri);
  }

  bool _isTrustedHttpsUri(Uri uri) {
    return uri.hasAuthority &&
        uri.host.trim().isNotEmpty &&
        uri.userInfo.isEmpty;
  }

  bool _isTrustedLocalFileFeedUri(Uri uri) {
    if (uri.hasQuery || uri.hasFragment) return false;
    if (uri.hasAuthority && uri.authority.isNotEmpty) return false;
    final path = _fileUriToPathOrNull(uri);
    if (path == null) return false;
    return _isAbsoluteLocalPath(path) && !_hasParentTraversal(path);
  }

  String? _fileUriToPathOrNull(Uri uri) {
    try {
      return uri.toFilePath();
    } on Object {
      return null;
    }
  }

  bool _isTrustedPackageUri(Uri uri, Uri feedUri) {
    if (uri.scheme == 'https') return _isTrustedHttpsUri(uri);
    if (uri.scheme == 'file' && feedUri.scheme == 'file') {
      return _isTrustedLocalFilePackageUri(uri);
    }
    return false;
  }

  bool _isTrustedLocalFilePackageUri(Uri uri) {
    if (uri.hasAuthority && uri.authority.isNotEmpty) return false;
    final path = _fileUriToPathOrNull(uri);
    if (path == null) return false;
    return _isAbsoluteLocalPath(path) && !_hasParentTraversal(path);
  }

  void _requireLocalPackageInsideFeedDirectory(Uri feedUri, Uri packageUri) {
    final feedDirectory = File(feedUri.toFilePath()).parent.absolute.path;
    final packagePath = File(packageUri.toFilePath()).absolute.path;
    if (!_isPathInside(feedDirectory, packagePath)) {
      throw StateError(
        'Local update package must be in the local feed directory.',
      );
    }
  }

  void _requireExistingLocalPackageInsideFeedDirectory(
    Uri feedUri,
    Uri packageUri,
  ) {
    _requireLocalPackageInsideFeedDirectory(feedUri, packageUri);
    final feedDirectory = _canonicalExistingLocalDirectoryPath(
      File(feedUri.toFilePath()).parent.path,
      'local update feed directory',
    );
    final packagePath = _canonicalExistingLocalFilePath(
      File(packageUri.toFilePath()).path,
      'local update package source',
    );
    if (!_isPathInside(feedDirectory, packagePath)) {
      throw StateError(
        'Local update package must be in the local feed directory.',
      );
    }
  }

  String _canonicalExistingLocalDirectoryPath(String path, String label) {
    _rejectLinkPath(path, label);
    final type = FileSystemEntity.typeSync(path, followLinks: false);
    if (type != FileSystemEntityType.directory) {
      throw StateError('$label is not a directory.');
    }
    final resolved = _resolveExistingFileSystemPath(Directory(path), label);
    _rejectLinkPath(resolved, label);
    final resolvedType = FileSystemEntity.typeSync(
      resolved,
      followLinks: false,
    );
    if (resolvedType != FileSystemEntityType.directory) {
      throw StateError('$label canonical path is not a directory.');
    }
    return _normalizePath(resolved);
  }

  String _canonicalExistingLocalFilePath(String path, String label) {
    _requireRegularFile(path, label);
    final resolved = _resolveExistingFileSystemPath(File(path), label);
    _requireRegularFile(resolved, label);
    return _normalizePath(resolved);
  }

  String _resolveExistingFileSystemPath(FileSystemEntity entity, String label) {
    try {
      return entity.resolveSymbolicLinksSync();
    } on FileSystemException catch (error) {
      throw StateError(
        '$label canonical path could not be resolved: '
        "${_boundedUpdateCheckError('$error')}",
      );
    }
  }

  bool _isPathInside(String parentPath, String childPath) {
    final parent = _normalizePath(parentPath);
    final child = _normalizePath(childPath);
    return child == parent ||
        child.startsWith('$parent${Platform.pathSeparator}');
  }

  String _normalizePath(String path) {
    final absolute = File(path).absolute.path;
    final parts = absolute
        .split(RegExp(r'[/\\]+'))
        .where((part) => part.isNotEmpty && part != '.')
        .toList(growable: false);
    if (parts.any((part) => part == '..')) {
      throw StateError('Local update package path contains traversal.');
    }
    final withoutTrailing = parts.join(Platform.pathSeparator);
    return Platform.isWindows ? withoutTrailing.toLowerCase() : withoutTrailing;
  }

  String _fileNameFromUri(Uri uri) {
    final segments = uri.pathSegments;
    return segments.isEmpty ? 'update.aup' : segments.last;
  }

  String _safeUpdateAssetName(String value) {
    final name = value.trim();
    if (!_isSafeUpdatePackageAssetName(name)) {
      throw StateError('Update package filename is unsafe.');
    }
    return name;
  }

  bool _isSafeUpdatePackageAssetName(String name) {
    return name.length <= maxUpdateAssetNameChars &&
        RegExp(r'^[A-Za-z0-9._-]+\.aup$').hasMatch(name) &&
        !name.contains('..');
  }

  bool _isAllowedUpdateRedirectAssetName(String name) {
    return name == 'update-feed.json' || _isSafeUpdatePackageAssetName(name);
  }

  Future<String> _sha256File(File file) async {
    _requireRegularFile(file.path, 'update package hash input');
    _rejectOversizedPackage(await file.length(), 'update package hash input');
    _requireRegularFile(file.path, 'update package hash input');
    final input = file.openRead();
    final digest = await sha256.bind(input).first;
    return digest.toString();
  }

  Future<void> _activateDownloadedPackage(
    File tempFile,
    File packageFile,
  ) async {
    _requireRegularFile(
      tempFile.path,
      'temporary update package activation input',
    );
    _rejectLinkPath(packageFile.path, 'cached update package');
    final existingType = FileSystemEntity.typeSync(
      packageFile.path,
      followLinks: false,
    );
    File? backupFile;
    if (existingType == FileSystemEntityType.file) {
      backupFile = _temporaryPackageBackupFile(packageFile);
      await packageFile.rename(backupFile.path);
    } else if (existingType != FileSystemEntityType.notFound) {
      throw StateError('Cached update package path is not a regular file.');
    }
    try {
      await tempFile.rename(packageFile.path);
    } on Object catch (error, stackTrace) {
      if (backupFile != null) {
        try {
          _rejectLinkPath(
            packageFile.path,
            'cached update package restore target',
          );
          final restoreType = FileSystemEntity.typeSync(
            packageFile.path,
            followLinks: false,
          );
          if (restoreType != FileSystemEntityType.notFound) {
            throw StateError(
              'Cached update package restore target was not empty.',
            );
          }
          await backupFile.rename(packageFile.path);
        } on Object catch (restoreError) {
          Error.throwWithStackTrace(
            StateError(
              'Cached update package activation failed and restore also failed. '
              "Activation error: ${_boundedUpdateCheckError('$error')}. "
              "Restore error: ${_boundedUpdateCheckError('$restoreError')}",
            ),
            stackTrace,
          );
        }
      }
      Error.throwWithStackTrace(error, stackTrace);
    }
    if (backupFile != null) {
      await _deleteTemporaryPackageFile(backupFile);
    }
  }

  Future<void> _copyLocalPackageToReservedTempFile(
    File source,
    File tempFile,
  ) async {
    _requireRegularFile(source.path, 'local update package source');
    _requireRegularFile(
      tempFile.path,
      'temporary update package local-copy output',
    );
    final output = await tempFile.open(mode: FileMode.write);
    var totalBytes = 0;
    try {
      await output.truncate(0);
      await for (final chunk in source.openRead()) {
        totalBytes += chunk.length;
        _rejectOversizedPackage(totalBytes, 'Local update package source');
        await output.writeFrom(chunk);
      }
      await output.flush();
    } finally {
      await output.close();
    }
    _requireRegularFile(source.path, 'local update package source');
    _requireRegularFile(
      tempFile.path,
      'temporary update package local-copy output',
    );
  }

  Future<void> _writeStreamToReservedPackageFile(
    File tempFile,
    Stream<List<int>> stream,
    String label,
  ) async {
    _requireRegularFile(tempFile.path, 'temporary update package output');
    final output = await tempFile.open(mode: FileMode.write);
    var totalBytes = 0;
    try {
      await output.truncate(0);
      try {
        await for (final chunk in stream.timeout(_networkReadTimeout)) {
          totalBytes += chunk.length;
          _rejectOversizedPackage(totalBytes, label);
          await output.writeFrom(chunk);
        }
      } on TimeoutException {
        throw StateError('$label download timed out.');
      }
      await output.flush();
    } finally {
      await output.close();
    }
    _requireRegularFile(tempFile.path, 'temporary update package output');
  }

  Future<void> _deleteTemporaryPackageFile(File tempFile) async {
    final type = FileSystemEntity.typeSync(tempFile.path, followLinks: false);
    if (type == FileSystemEntityType.notFound) return;
    if (type != FileSystemEntityType.file) {
      throw StateError('Temporary update package cleanup target was unsafe.');
    }
    await tempFile.delete();
  }

  File _temporaryPackageBackupFile(File packageFile) {
    for (var attempt = 0; attempt < 16; attempt += 1) {
      final path =
          '${packageFile.path}.${DateTime.now().microsecondsSinceEpoch}.$attempt.bak';
      _rejectLinkPath(path, 'temporary cached update package backup');
      final type = FileSystemEntity.typeSync(path, followLinks: false);
      if (type == FileSystemEntityType.notFound) {
        return File(path);
      }
      if (type != FileSystemEntityType.file) {
        throw StateError(
          'Temporary cached update package backup path was unsafe.',
        );
      }
    }
    throw StateError(
      'Unable to allocate a temporary cached update package backup path.',
    );
  }

  Future<void> _ensureSafeDirectory(Directory directory, String label) async {
    _rejectLinkPath(directory.path, label);
    final existingType = FileSystemEntity.typeSync(
      directory.path,
      followLinks: false,
    );
    if (existingType == FileSystemEntityType.notFound) {
      await directory.create(recursive: true);
      _rejectLinkPath(directory.path, label);
      return;
    }
    if (existingType != FileSystemEntityType.directory) {
      throw StateError('$label path is not a directory.');
    }
  }

  Future<File> _temporaryPackageFile(
    Directory updateDir,
    String assetName,
  ) async {
    for (var attempt = 0; attempt < 16; attempt += 1) {
      final path =
          '${updateDir.path}${Platform.pathSeparator}.$assetName.${DateTime.now().microsecondsSinceEpoch}.$attempt.part';
      _rejectLinkPath(path, 'temporary update package');
      final type = FileSystemEntity.typeSync(path, followLinks: false);
      if (type == FileSystemEntityType.file) {
        continue;
      }
      if (type != FileSystemEntityType.notFound) {
        throw StateError('Temporary update package path was unsafe.');
      }
      final tempFile = File(path);
      try {
        await tempFile.create(exclusive: true);
        return tempFile;
      } on FileSystemException catch (error) {
        final racedType = FileSystemEntity.typeSync(path, followLinks: false);
        if (racedType == FileSystemEntityType.file) {
          continue;
        }
        if (racedType != FileSystemEntityType.notFound) {
          throw StateError('Temporary update package path became unsafe.');
        }
        throw StateError(
          'Failed to reserve temporary update package path: '
          '${_boundedUpdateCheckError('$error')}',
        );
      }
    }
    throw StateError(
      'Unable to allocate a safe temporary update package path.',
    );
  }

  void _requireRegularFile(String path, String label) {
    _rejectLinkPath(path, label);
    final probe = _regularUpdateFileProbe(path);
    if (!probe.isRegularFile) {
      final diagnostic = probe.diagnostic == null
          ? ''
          : ' Probe failed: ${probe.diagnostic}.';
      throw StateError('$label is not a regular file.$diagnostic');
    }
  }

  void _rejectLinkPath(String path, String label) {
    final type = FileSystemEntity.typeSync(path, followLinks: false);
    if (type == FileSystemEntityType.link) {
      throw StateError('Refusing to use symbolic link $label.');
    }
  }

  bool _isSha256(String value) {
    return RegExp(r'^[a-fA-F0-9]{64}$').hasMatch(value.trim());
  }

  void _requireSupportedVersion(String value, String label) {
    final normalized = value.trim();
    if (!_supportedUpdateVersionPattern.hasMatch(normalized)) {
      throw StateError('Update $label is not a supported version string.');
    }
  }

  bool? _optionalBool(Map<String, Object?> source, String field) {
    final value = source[field];
    if (value == null) return null;
    if (value is bool) return value;
    throw StateError('Update package field $field must be a boolean.');
  }

  void _rejectUnknownUpdateFields(
    Map<String, Object?> source,
    Set<String> allowedFields,
    String label,
  ) {
    for (final key in source.keys) {
      if (!allowedFields.contains(key)) {
        throw StateError('Update $label contains unknown field $key.');
      }
    }
  }

  String _requiredString(Map<String, Object?> source, String field) {
    final value = source[field];
    if (value is! String || value.trim().isEmpty) {
      throw StateError('Update package field $field must be a string.');
    }
    if (_containsControlOrNul(value)) {
      throw StateError(
        'Update package field $field must not contain control characters.',
      );
    }
    if (value.length > maxUpdateMetadataStringChars) {
      throw StateError('Update package field $field is too long.');
    }
    return value.trim();
  }

  String? _optionalString(Map<String, Object?> source, String field) {
    final value = source[field];
    if (value == null) return null;
    if (value is! String || value.trim().isEmpty) {
      throw StateError('Update package field $field must be a string.');
    }
    if (_containsControlOrNul(value)) {
      throw StateError(
        'Update package field $field must not contain control characters.',
      );
    }
    if (value.length > maxUpdateMetadataStringChars) {
      throw StateError('Update package field $field is too long.');
    }
    return value.trim();
  }

  bool? _githubOptionalBool(Map<String, Object?> source, String field) {
    final value = source[field];
    if (value == null) return null;
    if (value is bool) return value;
    throw StateError('GitHub release field $field must be a boolean.');
  }

  String _githubRequiredString(Map<String, Object?> source, String field) {
    final value = source[field];
    if (value is! String || value.trim().isEmpty) {
      throw StateError('GitHub release field $field must be a string.');
    }
    if (_containsControlOrNul(value)) {
      throw StateError(
        'GitHub release field $field must not contain control characters.',
      );
    }
    if (value.length > maxUpdateMetadataStringChars) {
      throw StateError('GitHub release field $field is too long.');
    }
    return value.trim();
  }

  String? _optionalBoundedString(
    Map<String, Object?> source,
    String field,
    int maxLength,
  ) {
    final value = source[field];
    if (value == null) return null;
    if (value is! String) {
      throw StateError('Update package field $field must be a string.');
    }
    if (_containsUnsafeFreeTextControlOrNul(value)) {
      throw StateError(
        'Update package field $field must not contain unsupported control characters.',
      );
    }
    if (value.length > maxLength) {
      throw StateError('Update package field $field is too long.');
    }
    return value;
  }

  DateTime? _optionalDateTime(Map<String, Object?> source, String field) {
    final value = source[field];
    if (value == null) return null;
    if (value is! String || value.trim().isEmpty) {
      throw StateError(
        'Update package field $field must be an ISO-8601 string.',
      );
    }
    if (_containsControlOrNul(value)) {
      throw StateError(
        'Update package field $field must not contain control characters.',
      );
    }
    if (value.length > maxUpdateMetadataStringChars) {
      throw StateError('Update package field $field is too long.');
    }
    final parsed = DateTime.tryParse(value.trim());
    if (parsed == null) {
      throw StateError('Update package field $field is not a valid date.');
    }
    return parsed;
  }

  String? _updateServiceExecutable({bool includeDevelopmentCandidates = true}) {
    final name = Platform.isWindows
        ? 'avorax_update_service.exe'
        : 'avorax_update_service';
    final executableParent = _updateServiceExecutableParentPath();
    final candidates = [
      _joinPath([executableParent, name]),
      if (includeDevelopmentCandidates)
        ..._developmentUpdateServiceCandidates(name),
    ];
    for (final candidate in candidates) {
      final probe = _regularUpdateFileProbe(candidate);
      if (probe.isRegularFile) {
        return File(candidate).absolute.path;
      }
      if (probe.diagnostic != null) return candidate;
    }
    return candidates.first;
  }

  String? _firstDevelopmentUpdateServiceExecutable() {
    final name = Platform.isWindows
        ? 'avorax_update_service.exe'
        : 'avorax_update_service';
    for (final candidate in _developmentUpdateServiceCandidates(name)) {
      if (_regularUpdateFileProbe(candidate).isRegularFile) {
        return File(candidate).absolute.path;
      }
    }
    return null;
  }

  String? _developmentUpdateServiceExecutionBlocker(String executablePath) {
    for (final root in _candidateDevelopmentRepoRoots()) {
      if (!_isUpdateServiceDevelopmentRepoRoot(root)) continue;
      if (_isPathInside(root.path, executablePath)) {
        return 'Refusing to use a development checkout Avorax Update Service for in-app update verification, install, or rollback. Build and install Avorax first, then run updates from the installed app.';
      }
    }
    return null;
  }

  String _updateServiceExecutableParentPath() {
    final parent = File(Platform.resolvedExecutable).parent.absolute.path;
    if (!_isAbsoluteLocalPath(parent)) {
      throw StateError(
        'Avorax Update Service executable directory must be an absolute local path.',
      );
    }
    return parent;
  }

  List<String> _developmentUpdateServiceCandidates(String executableName) {
    final candidates = <String>[];
    final seen = <String>{};
    for (final root in _candidateDevelopmentRepoRoots()) {
      if (!_isUpdateServiceDevelopmentRepoRoot(root)) continue;
      for (final candidate in [
        _joinPath([root.path, 'target', 'release', executableName]),
        _joinPath([
          root.path,
          'core',
          'avorax_update_service',
          'target',
          'release',
          executableName,
        ]),
      ]) {
        if (seen.add(candidate)) candidates.add(candidate);
      }
    }
    return candidates;
  }

  List<Directory> _candidateDevelopmentRepoRoots() {
    final roots = <Directory>[];
    final seen = <String>{};
    var cursor = Directory.current.absolute;
    for (var depth = 0; depth < 3; depth++) {
      if (seen.add(cursor.path)) roots.add(cursor);
      final parent = cursor.parent;
      if (parent.path == cursor.path) break;
      cursor = parent;
    }
    return roots;
  }

  bool _isUpdateServiceDevelopmentRepoRoot(Directory root) {
    final appMarker = _joinPath([
      root.path,
      'apps',
      'zentor_client',
      'pubspec.yaml',
    ]);
    final updateServiceMarker = _joinPath([
      root.path,
      'core',
      'avorax_update_service',
      'Cargo.toml',
    ]);
    return _regularUpdateFileProbe(appMarker).isRegularFile &&
        _regularUpdateFileProbe(updateServiceMarker).isRegularFile;
  }

  String _joinPath(List<String> segments) {
    final separator = Platform.pathSeparator;
    var path = segments.first;
    for (final segment in segments.skip(1)) {
      path = path.endsWith(separator)
          ? '$path$segment'
          : '$path$separator$segment';
    }
    return path;
  }

  _UpdateFileProbe _regularUpdateFileProbe(String path) {
    try {
      final type = FileSystemEntity.typeSync(path, followLinks: false);
      if (type == FileSystemEntityType.file) {
        return const _UpdateFileProbe(true);
      }
      if (type == FileSystemEntityType.notFound) {
        return const _UpdateFileProbe(false);
      }
      return _UpdateFileProbe(false, '$path exists but is not a regular file.');
    } on FileSystemException catch (error) {
      return _UpdateFileProbe(
        false,
        'Unable to inspect $path: ${_boundedUpdateCheckError(error.message)}',
      );
    } on ArgumentError catch (error) {
      return _UpdateFileProbe(
        false,
        'Unable to inspect $path: ${_boundedUpdateCheckError('$error')}',
      );
    } on Object catch (error) {
      return _UpdateFileProbe(
        false,
        'Unable to inspect $path: ${_boundedUpdateCheckError('$error')}',
      );
    }
  }

  String _elevatedUpdaterScript(String updater, List<String> args) {
    final quotedUpdater = _powershellSingleQuoted(updater);
    final quotedArgs = args.map(_powershellSingleQuoted).join(', ');
    return '\$process = Start-Process -FilePath $quotedUpdater '
        '-ArgumentList @($quotedArgs) -Verb RunAs -Wait -PassThru; '
        'exit \$process.ExitCode';
  }

  String _powershellSingleQuoted(String value) =>
      "'${value.replaceAll("'", "''")}'";

  String _powershellEncodedCommand(String script) {
    final bytes = <int>[];
    for (final codeUnit in script.codeUnits) {
      bytes
        ..add(codeUnit & 0xff)
        ..add((codeUnit >> 8) & 0xff);
    }
    return base64Encode(bytes);
  }

  String _windowsPowerShellExecutable() {
    final systemRoot = _windowsSystemRoot();
    final candidate = File(
      '$systemRoot${Platform.pathSeparator}System32${Platform.pathSeparator}WindowsPowerShell${Platform.pathSeparator}v1.0${Platform.pathSeparator}powershell.exe',
    ).absolute.path;
    if (_isWindowsRemoteOrDevicePath(candidate)) {
      throw StateError(
        'PowerShell update launcher command must be on a local drive.',
      );
    }
    _requireRegularFile(candidate, 'PowerShell update launcher executable');
    return candidate;
  }

  String _windowsSystemRoot() {
    final systemRoot =
        _checkedWindowsSystemRootValue('SystemRoot') ??
        _checkedWindowsSystemRootValue('WINDIR');
    if (systemRoot == null) {
      throw StateError(
        'SystemRoot or WINDIR is required to locate the PowerShell update launcher command.',
      );
    }
    if (_isWindowsRemoteOrDevicePath(systemRoot)) {
      throw StateError(
        'PowerShell update launcher root must be on a local drive.',
      );
    }
    return Directory(systemRoot).absolute.path;
  }

  String? _checkedWindowsSystemRootValue(String name) {
    final value = _nonEmptyEnvironmentValue(name);
    if (value == null) return null;
    if (value.contains('\u0000')) {
      throw StateError(
        'PowerShell update launcher root $name must not contain NUL.',
      );
    }
    if (_hasParentTraversal(value)) {
      throw StateError(
        'PowerShell update launcher root $name must not contain parent traversal.',
      );
    }
    return value;
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

  bool _isAbsoluteLocalPath(String path) {
    final normalized = path.trim();
    if (normalized.isEmpty) return false;
    if (Platform.isWindows) return !_isWindowsRemoteOrDevicePath(normalized);
    return normalized.startsWith('/') && !normalized.startsWith('//');
  }

  String? _nonEmptyEnvironmentValue(String name) {
    final value = Platform.environment[name]?.trim();
    return value == null || value.isEmpty ? null : value;
  }

  String _installDir() {
    final parent = File(Platform.resolvedExecutable).parent.absolute.path;
    if (!_isAbsoluteLocalPath(parent)) {
      throw StateError(
        'Update install directory must be an absolute local path.',
      );
    }
    return parent;
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
    if (!_supportedUpdateVersionPattern.hasMatch(value.trim())) {
      throw ArgumentError.value(
        value,
        'value',
        'Unsupported update version string',
      );
    }
    final core = normalized.split(RegExp(r'[-+]')).first;
    return core
        .split('.')
        .map((part) => int.parse(part))
        .toList(growable: false);
  }
}

class _UpdateFileProbe {
  const _UpdateFileProbe(this.isRegularFile, [this.diagnostic]);

  final bool isRegularFile;
  final String? diagnostic;
}
