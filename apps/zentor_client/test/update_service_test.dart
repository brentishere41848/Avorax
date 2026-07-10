import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:path_provider_platform_interface/path_provider_platform_interface.dart';
import 'package:zentor_client/core/config/build_config.dart';
import 'package:zentor_client/core/updates/update_service.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Directory temporaryRoot;

  setUp(() async {
    temporaryRoot = await Directory.systemTemp.createTemp(
      'avorax-update-service-test-',
    );
    PathProviderPlatform.instance = _FakePathProviderPlatform(
      temporaryRoot.path,
    );
  });

  tearDown(() async {
    if (await temporaryRoot.exists()) {
      await temporaryRoot.delete(recursive: true);
    }
  });

  test(
    'default build config uses GitHub release update feed for in-app updates',
    () {
      const config = BuildConfig();

      expect(config.updateFeedUrl, isNotEmpty);
      expect(config.updateFeedUrl, startsWith('https://'));
      expect(
        config.updateFeedUrl,
        contains('/releases/latest/download/update-feed.json'),
      );
    },
  );

  test('detects newer feed release and selects signed aup package', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        expect(request.url.path, '/update-feed.json');
        return http.Response(jsonEncode(_feed('0.1.15')), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.updateAvailable);
    expect(result.update?.latestVersion, '0.1.15');
    expect(result.update?.packageName, 'Avorax-AntiVirus-0.1.15.aup');
  });

  test('returns not configured when update feed is absent', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(updateFeedUrl: ''),
      client: MockClient((request) async => http.Response('{}', 200)),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.notConfigured);
    expect(result.error, contains('not configured'));
  });

  test(
    'installed version discovery failures fail visibly before feed handling',
    () async {
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(appVersion: '9.8.7', updateFeedUrl: ''),
        client: MockClient((request) async {
          fail('update feed should not be loaded after version failure');
        }),
      );

      final result = await service.checkForUpdate();

      expect(result.status, UpdateStatus.failed);
      expect(result.currentVersion, '9.8.7');
      expect(
        result.error,
        contains('Unable to determine installed Avorax version'),
      );
      expect(result.error, isNot(contains('\x00')));
    },
  );

  test('malformed update feed URLs return failed update checks', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(updateFeedUrl: 'http://[not-a-host'),
      client: MockClient((request) async => http.Response('{}', 200)),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('Missing end'));
  });

  test('rejects control text in configured update feed URLs', () async {
    var requested = false;
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json\x00',
      ),
      client: MockClient((request) async {
        requested = true;
        return http.Response('{}', 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(
      result.error,
      contains('Update source URL must not contain control characters'),
    );
    expect(result.error, isNot(contains('\x00')));
    expect(requested, isFalse);
  });

  test('rejects redirecting update feeds', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
      ),
      client: MockClient((request) async {
        expect(request.followRedirects, isFalse);
        return http.Response(
          '',
          302,
          headers: {'location': 'https://other.example.test/update-feed.json'},
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('Update feed redirects are not allowed'));
  });

  test('allows bounded GitHub feed redirect chains', () async {
    final requests = <http.Request>[];
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        requests.add(request);
        expect(request.followRedirects, isFalse);
        if (request.url.path ==
            '/brentishere41848/Avorax/releases/latest/download/update-feed.json') {
          return http.Response(
            '',
            302,
            headers: {
              'location':
                  'https://github.com/brentishere41848/Avorax/releases/download/v0.1.15/update-feed.json',
            },
          );
        }
        if (request.url.path ==
            '/brentishere41848/Avorax/releases/download/v0.1.15/update-feed.json') {
          return http.Response(
            '',
            302,
            headers: {
              'location':
                  'https://release-assets.githubusercontent.com/github-production-release-asset/1/2?response-content-disposition=attachment%3B%20filename%3Dupdate-feed.json',
            },
          );
        }
        if (request.url.host == 'release-assets.githubusercontent.com') {
          return http.Response(
            jsonEncode(
              _feed(
                '0.1.15',
                packageUrl:
                    'https://github.com/brentishere41848/Avorax/releases/download/v0.1.15/Avorax-AntiVirus-0.1.15.aup',
              ),
            ),
            200,
          );
        }
        return http.Response('unexpected ${request.url}', 500);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.updateAvailable);
    expect(result.update?.latestVersion, '0.1.15');
    expect(requests.map((request) => request.url.host).toList(), [
      'github.com',
      'github.com',
      'release-assets.githubusercontent.com',
    ]);
  });

  test('rejects control text in GitHub update redirect Locations', () async {
    final requests = <Uri>[];
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        requests.add(request.url);
        return http.Response(
          '',
          302,
          headers: {
            'location':
                'https://github.com/brentishere41848/Avorax/releases/download/v0.1.15/update-feed.json\x00',
          },
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(
      result.error,
      contains('Update feed redirect location must not contain control'),
    );
    expect(result.error, isNot(contains('\x00')));
    expect(requests.map((uri) => uri.host).toList(), ['github.com']);
  });

  test('rejects malformed GitHub release-assets redirect paths', () async {
    final requests = <Uri>[];
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        requests.add(request.url);
        if (request.url.host == 'github.com') {
          return http.Response(
            '',
            302,
            headers: {
              'location':
                  'https://release-assets.githubusercontent.com/github-production-release-asset/../2?response-content-disposition=attachment%3B%20filename%3Dupdate-feed.json',
            },
          );
        }
        return http.Response('unexpected ${request.url}', 500);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('Update feed redirects are not allowed'));
    expect(requests.map((uri) => uri.host).toList(), ['github.com']);
  });

  test('fails visible update checks when redirect response body stalls', () async {
    final controller = StreamController<List<int>>();
    addTearDown(controller.close);
    final requests = <Uri>[];
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: _StreamingClient((request) {
        requests.add(request.url);
        if (request.url.path ==
            '/brentishere41848/Avorax/releases/latest/download/update-feed.json') {
          return http.StreamedResponse(
            controller.stream,
            302,
            request: request,
            headers: const {
              'location':
                  'https://github.com/brentishere41848/Avorax/releases/download/v0.1.15/update-feed.json',
            },
          );
        }
        return http.StreamedResponse(
          Stream<List<int>>.value(utf8.encode('unexpected ${request.url}')),
          500,
          request: request,
        );
      }),
      networkReadTimeout: const Duration(milliseconds: 10),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('Update feed redirect response timed out'));
    expect(requests.map((uri) => uri.host).toList(), ['github.com']);
  });

  test('source marker: update feed downloads use controlled redirects', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final loadFeedMethod = source.substring(
      source.indexOf('Future<Map<String, Object?>> _loadFeed'),
      source.indexOf('Future<http.Response> _getFeedWithAllowedRedirects'),
    );
    final feedRequestMethod = source.substring(
      source.indexOf('Future<http.Response> _getFeedWithAllowedRedirects'),
      source.indexOf('bool _isGithubLatestDownloadFeed'),
    );
    final redirectLocationMethod = source.substring(
      source.indexOf('Uri _allowedGithubReleaseRedirectLocation'),
      source.indexOf('bool _isGithubLatestDownloadFeed'),
    );

    expect(loadFeedMethod, contains('_getFeedWithAllowedRedirects(feedUri)'));
    expect(loadFeedMethod, contains('Update feed redirects are not allowed'));
    expect(
      feedRequestMethod,
      contains('_getWithAllowedGithubReleaseRedirects'),
    );
    expect(
      feedRequestMethod,
      contains('_allowedGithubReleaseRedirectLocation'),
    );
    expect(feedRequestMethod, contains('followRedirects = false'));
    expect(feedRequestMethod, contains('headers: const {'));
    expect(feedRequestMethod, contains("'Accept': 'application/json'"));
    expect(feedRequestMethod, contains('..headers.addAll(headers)'));
    expect(feedRequestMethod, contains('_drainBoundedRedirectBody'));
    expect(source, contains('maxUpdateRedirectBodyBytes'));
    expect(source, contains('redirect response body is too large'));
    expect(feedRequestMethod, isNot(contains('drain<void>()')));
    expect(
      redirectLocationMethod,
      contains("final rawLocation = responseHeaders['location']"),
    );
    expect(
      redirectLocationMethod,
      contains(
        "_requireUpdateUriText(rawLocation, '\$label redirect location')",
      ),
    );
    expect(
      redirectLocationMethod.indexOf(
        "_requireUpdateUriText(rawLocation, '\$label redirect location')",
      ),
      lessThan(
        redirectLocationMethod.indexOf('final location = rawLocation.trim()'),
      ),
    );
    expect(
      redirectLocationMethod.indexOf(
        "_requireUpdateUriText(rawLocation, '\$label redirect location')",
      ),
      lessThan(redirectLocationMethod.indexOf('currentUri.resolve(location)')),
    );
  });

  test('source marker: update feed URL parsing is inside failure handling', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final checkMethod = source.substring(
      source.indexOf('Future<UpdateCheckResult> checkForUpdate'),
      source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
    );

    expect(
      checkMethod.indexOf('try {'),
      lessThan(checkMethod.indexOf('Uri.parse(feedUrl)')),
    );
    expect(
      checkMethod.indexOf('Uri.parse(feedUrl)'),
      lessThan(checkMethod.indexOf('_loadFeed(feedUri)')),
    );
    expect(checkMethod, contains('return UpdateCheckResult.failed('));
    expect(checkMethod, contains('installedVersion ?? currentVersion'));
  });

  test('source marker: installed version failures are visible', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final checkMethod = source.substring(
      source.indexOf('Future<UpdateCheckResult> checkForUpdate'),
      source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
    );
    final installedVersionMethod = source.substring(
      source.indexOf('Future<String> _installedVersion'),
      source.indexOf('Future<Map<String, Object?>> _loadFeed'),
    );

    expect(checkMethod, contains('String? installedVersion'));
    expect(checkMethod, contains('_installedVersionFailureLabel()'));
    expect(
      installedVersionMethod,
      contains('Unable to determine installed Avorax version'),
    );
    expect(
      installedVersionMethod,
      isNot(contains('return buildConfig.appVersion;')),
    );
  });

  test(
    'source marker: configured update feed URLs are bounded before parse',
    () {
      final source = File(
        'lib/core/updates/update_service.dart',
      ).readAsStringSync();
      final checkMethod = source.substring(
        source.indexOf('Future<UpdateCheckResult> checkForUpdate'),
        source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
      );

      expect(source, contains('const int maxUpdateFeedUrlChars = 2048'));
      expect(checkMethod, contains('feedUrl.length > maxUpdateFeedUrlChars'));
      expect(checkMethod, contains('Update source URL is too long.'));
      expect(
        checkMethod.indexOf('feedUrl.length > maxUpdateFeedUrlChars'),
        lessThan(checkMethod.indexOf('Uri.parse(feedUrl)')),
      );
    },
  );

  test('source marker: update URI text rejects controls before parse', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final checkMethod = source.substring(
      source.indexOf('Future<UpdateCheckResult> checkForUpdate'),
      source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
    );
    final packageResolver = source.substring(
      source.indexOf('Uri _resolvePackageUri'),
      source.indexOf('void _requirePackageArtifactUri'),
    );
    final githubResolver = source.substring(
      source.indexOf('Future<Uri?> _resolveGithubReleaseFeedAssetUri'),
      source.indexOf('Future<http.Response> _getGithubReleasesWithoutRedirect'),
    );

    expect(source, contains('void _requireUpdateUriText'));
    expect(source, contains('bool _containsControlOrNul'));
    expect(source, contains(r"RegExp(r'[\x00-\x1F\x7F]')"));
    expect(
      checkMethod,
      contains("_requireUpdateUriText(feedUrl, 'Update source URL')"),
    );
    expect(
      checkMethod.indexOf(
        "_requireUpdateUriText(feedUrl, 'Update source URL')",
      ),
      lessThan(checkMethod.indexOf('Uri.parse(feedUrl)')),
    );
    expect(
      packageResolver,
      contains("_requireUpdateUriText(value, 'Update package URL')"),
    );
    expect(
      packageResolver.indexOf(
        "_requireUpdateUriText(value, 'Update package URL')",
      ),
      lessThan(packageResolver.indexOf('Uri.parse(value)')),
    );
    expect(
      githubResolver,
      contains("_requireUpdateUriText(value, 'GitHub release feed asset URL')"),
    );
    expect(
      githubResolver.indexOf(
        "_requireUpdateUriText(value, 'GitHub release feed asset URL')",
      ),
      lessThan(githubResolver.indexOf('Uri.parse(value)')),
    );
  });

  test('source marker: update check failure text is bounded', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final resultFactory = source.substring(
      source.indexOf('factory UpdateCheckResult.failed'),
      source.indexOf('final UpdateStatus status'),
    );
    final errorHelper = source.substring(
      source.indexOf('String _boundedUpdateCheckError'),
      source.indexOf('class ZentorUpdateService'),
    );
    final checkMethod = source.substring(
      source.indexOf('Future<UpdateCheckResult> checkForUpdate'),
      source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
    );

    expect(source, contains('const int maxUpdateCheckErrorChars = 4096'));
    expect(resultFactory, contains('_boundedUpdateCheckError(error)'));
    expect(checkMethod, contains("_boundedUpdateCheckError('\$error')"));
    expect(errorHelper, contains('value.replaceAll'));
    expect(errorHelper, contains(r"RegExp(r'[\x00-\x1F\x7F]+')"));
    expect(errorHelper, contains('.trim()'));
    expect(errorHelper, contains('maxUpdateCheckErrorChars'));
    expect(errorHelper, contains("return 'Update check failed.'"));
    expect(checkMethod, isNot(contains("'\$error',")));
    expect(errorHelper, contains("substring(0, maxUpdateCheckErrorChars - 3)"));
    expect(
      errorHelper,
      isNot(contains("substring(0, maxUpdateCheckErrorChars)}...")),
    );
  });

  test('source marker: update service diagnostics are bounded', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final installedVersion = source.substring(
      source.indexOf('Future<String> _installedVersion'),
      source.indexOf('String _installedVersionFailureLabel'),
    );
    final loadFeed = source.substring(
      source.indexOf('Future<Map<String, Object?>> _loadFeed'),
      source.indexOf('Future<http.Response> _getFeedWithAllowedRedirects'),
    );
    final probe = source.substring(
      source.indexOf('_UpdateFileProbe _regularUpdateFileProbe'),
      source.indexOf('String _installDir()'),
    );

    expect(installedVersion, contains('_boundedUpdateCheckError'));
    expect(loadFeed, contains('_boundedUpdateCheckError'));
    expect(probe, contains('_boundedUpdateCheckError'));
    expect(installedVersion, isNot(contains(r'version: $error')));
    expect(loadFeed, isNot(contains(r'fallback failed: $error')));
    expect(probe, isNot(contains(r'Unable to inspect $path: $error')));
  });

  test('source marker: update URL parse diagnostics are bounded', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final redirectMethod = source.substring(
      source.indexOf('Uri _allowedGithubReleaseRedirectLocation'),
      source.indexOf('bool _isAllowedGithubReleaseRedirect'),
    );
    final githubFeedMethod = source.substring(
      source.indexOf('Future<Uri?> _resolveGithubReleaseFeedAssetUri'),
      source.indexOf('bool _isTrustedGithubReleaseFeedAssetUri'),
    );
    final packageUriMethod = source.substring(
      source.indexOf('Uri _resolvePackageUri'),
      source.indexOf('bool _isTrustedPackageUri'),
    );

    for (final method in [redirectMethod, githubFeedMethod, packageUriMethod]) {
      expect(method, contains('_boundedUpdateCheckError(error.message)'));
      expect(method, isNot(contains(r': ${error.message}')));
    }
  });

  test('rejects installer assets for normal updates', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
      ),
      client: MockClient((request) async {
        return http.Response(
          jsonEncode(_feed('0.1.15', packageName: 'setup.exe')),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('No .aup package found'));
  });

  test('rejects feed package entries with malformed SHA-256', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        return http.Response(
          jsonEncode(_feed('0.1.15', packageSha256: 'not-a-sha256')),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('valid package_sha256'));
  });

  test('rejects control text in required update metadata fields', () async {
    Future<UpdateCheckResult> check(Map<String, Object?> feed) {
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl: 'https://updates.example.test/update-feed.json',
          updateChannel: 'dev',
        ),
        client: MockClient((request) async {
          return http.Response(jsonEncode(feed), 200);
        }),
      );
      return service.checkForUpdate(currentVersion: '0.1.14');
    }

    final productFeed = _feed('0.1.15');
    productFeed['product'] = 'Avorax Anti-Virus\x00';
    final productResult = await check(productFeed);
    expect(productResult.status, UpdateStatus.failed);
    expect(
      productResult.error,
      contains('Update package field product must not contain control'),
    );
    expect(productResult.error, isNot(contains('\x00')));

    final versionFeed = _feed('0.1.15');
    versionFeed['latest_version'] = '0.1.15\x00';
    final versionResult = await check(versionFeed);
    expect(versionResult.status, UpdateStatus.failed);
    expect(
      versionResult.error,
      contains('Update package field latest_version must not contain control'),
    );
    expect(versionResult.error, isNot(contains('\x00')));

    final hashFeed = _feed('0.1.15');
    final packages = hashFeed['packages'] as List<Object?>;
    final package = Map<String, Object?>.from(
      packages.single as Map<String, Object?>,
    );
    package['package_sha256'] = '${'a' * 64}\x00';
    hashFeed['packages'] = [package];
    final hashResult = await check(hashFeed);
    expect(hashResult.status, UpdateStatus.failed);
    expect(
      hashResult.error,
      contains('Update package field package_sha256 must not contain control'),
    );
    expect(hashResult.error, isNot(contains('\x00')));
  });

  test('rejects oversized local update feeds while streaming', () async {
    final feedFile = File(
      '${temporaryRoot.path}${Platform.pathSeparator}oversized-feed.json',
    );
    await feedFile.writeAsBytes(List<int>.filled(maxUpdateFeedBytes + 1, 0x20));
    final service = ZentorUpdateService(
      buildConfig: BuildConfig(
        updateFeedUrl: feedFile.uri.toString(),
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        fail('local file feeds must not perform HTTP requests');
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('Local update feed exceeds'));
    expect(result.error, contains('update metadata limit'));
  });

  test(
    'rejects oversized remote update feeds without Content-Length while streaming',
    () async {
      var requests = 0;
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl: 'https://updates.example.test/update-feed.json',
          updateChannel: 'dev',
        ),
        client: _StreamingClient((request) {
          requests += 1;
          expect(request.url.path, '/update-feed.json');
          return http.StreamedResponse(
            Stream<List<int>>.fromIterable([
              List<int>.filled(maxUpdateFeedBytes, 0x20),
              const [0x20],
            ]),
            200,
            request: request,
            headers: const {},
          );
        }),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(requests, 1);
      expect(result.status, UpdateStatus.failed);
      expect(result.error, contains('Update feed exceeds'));
      expect(result.error, contains('update metadata limit'));
    },
  );

  test('fails visible update checks when feed request send stalls', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: _HangingClient(),
      networkRequestTimeout: const Duration(milliseconds: 10),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('Update feed request timed out'));
  });

  test(
    'fails visible update checks when feed response stream stalls',
    () async {
      final controller = StreamController<List<int>>();
      addTearDown(controller.close);
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl: 'https://updates.example.test/update-feed.json',
          updateChannel: 'dev',
        ),
        client: _StreamingClient((request) {
          return http.StreamedResponse(
            controller.stream,
            200,
            request: request,
            headers: const {},
          );
        }),
        networkReadTimeout: const Duration(milliseconds: 10),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(result.status, UpdateStatus.failed);
      expect(result.error, contains('Update feed response timed out'));
    },
  );

  test('rejects package SHA-256 values with wrong types', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        final packages = feed['packages'] as List<Object?>;
        final package = Map<String, Object?>.from(
          packages.single as Map<String, Object?>,
        );
        package['package_sha256'] = 123;
        feed['packages'] = [package];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('package_sha256 must be a string'));
  });

  test('rejects update feeds with malformed latest versions', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        return http.Response(jsonEncode(_feed('not-a-version')), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('supported version string'));
  });

  test('rejects update feeds with non-string latest versions', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        feed['latest_version'] = 15;
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('latest_version must be a string'));
  });

  test('rejects update feeds with unknown top-level fields', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        feed['install_script'] = 'run.ps1';
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('unknown field install_script'));
  });

  test(
    'rejects update feeds with malformed minimum supported versions',
    () async {
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl: 'https://updates.example.test/update-feed.json',
          updateChannel: 'dev',
        ),
        client: MockClient((request) async {
          final feed = _feed('0.1.15');
          feed['minimum_supported_version'] = 'not-a-version';
          return http.Response(jsonEncode(feed), 200);
        }),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(result.status, UpdateStatus.failed);
      expect(
        result.error,
        contains('minimum_supported_version is not a supported version string'),
      );
    },
  );

  test('rejects control text in optional update metadata fields', () async {
    Future<UpdateCheckResult> check(Map<String, Object?> feed) {
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl: 'https://updates.example.test/update-feed.json',
          updateChannel: 'dev',
        ),
        client: MockClient((request) async {
          return http.Response(jsonEncode(feed), 200);
        }),
      );
      return service.checkForUpdate(currentVersion: '0.1.14');
    }

    final channelFeed = _feed('0.1.15');
    channelFeed['channel'] = 'dev\x00';
    final channelResult = await check(channelFeed);
    expect(channelResult.status, UpdateStatus.failed);
    expect(
      channelResult.error,
      contains('Update package field channel must not contain control'),
    );
    expect(channelResult.error, isNot(contains('\x00')));

    final minimumFeed = _feed('0.1.15');
    minimumFeed['minimum_supported_version'] = '0.1.0\x00';
    final minimumResult = await check(minimumFeed);
    expect(minimumResult.status, UpdateStatus.failed);
    expect(
      minimumResult.error,
      contains(
        'Update package field minimum_supported_version must not contain control',
      ),
    );
    expect(minimumResult.error, isNot(contains('\x00')));

    final publishedFeed = _feed('0.1.15');
    final packages = publishedFeed['packages'] as List<Object?>;
    final package = Map<String, Object?>.from(
      packages.single as Map<String, Object?>,
    );
    package['published_at'] = '2026-05-31T12:00:00Z\x00';
    publishedFeed['packages'] = [package];
    final publishedResult = await check(publishedFeed);
    expect(publishedResult.status, UpdateStatus.failed);
    expect(
      publishedResult.error,
      contains('Update package field published_at must not contain control'),
    );
    expect(publishedResult.error, isNot(contains('\x00')));
  });

  test('rejects update feeds that do not support installed version', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        feed['minimum_supported_version'] = '0.1.15';
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(
      result.error,
      contains('below update feed minimum_supported_version'),
    );
  });

  test('update feed versions are validated before comparison', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final updateFromFeedMethod = source.substring(
      source.indexOf('UpdateInfo? _updateFromFeed'),
      source.indexOf('Uri _resolvePackageUri'),
    );

    expect(source, contains('_requireSupportedVersion'));
    expect(
      updateFromFeedMethod,
      contains("final product = _requiredString(feed, 'product')"),
    );
    expect(updateFromFeedMethod, contains("product != 'Avorax Anti-Virus'"));
    expect(
      updateFromFeedMethod,
      isNot(contains("feed['product'] != 'Avorax Anti-Virus'")),
    );
    expect(
      updateFromFeedMethod,
      contains("_requiredString(feed, 'latest_version')"),
    );
    expect(updateFromFeedMethod, contains("_requiredString(item, 'version')"));
    expect(
      updateFromFeedMethod,
      contains("_requiredString(package, 'version')"),
    );
    expect(
      updateFromFeedMethod,
      contains("_requiredString(package, 'package_sha256')"),
    );
    expect(
      updateFromFeedMethod,
      contains("_requireSupportedVersion(latestVersion"),
    );
    expect(
      updateFromFeedMethod,
      contains('final minimumSupportedVersion = _optionalString('),
    );
    expect(updateFromFeedMethod, contains("'minimum_supported_version'"));
    expect(updateFromFeedMethod, contains('_requireSupportedVersion'));
    expect(updateFromFeedMethod, contains('minimumSupportedVersion'));
    expect(
      updateFromFeedMethod,
      contains('_compareVersions(installedVersion, minimumSupportedVersion)'),
    );
    expect(
      updateFromFeedMethod,
      contains("_requireSupportedVersion(installedVersion"),
    );
    expect(source, contains('_supportedUpdateVersionPattern'));
    expect(source, contains('supported version string'));
    expect(source, contains(r'\d{1,6}'));
  });

  test('source marker: version comparison rejects malformed parts', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final versionPartsMethod = source.substring(
      source.indexOf('static List<int> _versionParts'),
    );

    expect(versionPartsMethod, contains('_supportedUpdateVersionPattern'));
    expect(versionPartsMethod, contains('Unsupported update version string'));
    expect(versionPartsMethod, contains('int.parse(part)'));
    expect(versionPartsMethod, isNot(contains('int.tryParse(part) ?? 0')));
  });

  test('rejects package entries with malformed package versions', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        final packages = feed['packages'] as List<Object?>;
        final package = Map<String, Object?>.from(
          packages.single as Map<String, Object?>,
        );
        package['version'] = 'not-a-version';
        package['package_url'] = 'Avorax-AntiVirus-0.1.15.aup';
        feed['packages'] = [package];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(
      result.error,
      contains('package version is not a supported version string'),
    );
  });

  test('rejects package entries with non-string package versions', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        final packages = feed['packages'] as List<Object?>;
        final package = Map<String, Object?>.from(
          packages.single as Map<String, Object?>,
        );
        package['version'] = 15;
        feed['packages'] = [package];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('version must be a string'));
  });

  test('rejects package entries that are not JSON objects', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        feed['packages'] = ['Avorax-AntiVirus-0.1.15.aup'];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(
      result.error,
      contains('Update feed package entries must be objects'),
    );
  });

  test('rejects update package boolean fields with wrong types', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        final packages = feed['packages'] as List<Object?>;
        final package = Map<String, Object?>.from(
          packages.single as Map<String, Object?>,
        );
        package['critical'] = 'yes';
        feed['packages'] = [package];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('must be a boolean'));
  });

  test('rejects update package entries with unknown fields', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        final packages = feed['packages'] as List<Object?>;
        final package = Map<String, Object?>.from(
          packages.single as Map<String, Object?>,
        );
        package['post_install'] = 'run.ps1';
        feed['packages'] = [package];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('unknown field post_install'));
  });

  test('rejects update feed package entries that are not objects', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        feed['packages'] = ['not-an-object'];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('package entries must be objects'));
  });

  test('source marker: update package entries are not silently skipped', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final updateFromFeedMethod = source.substring(
      source.indexOf('UpdateInfo? _updateFromFeed'),
      source.indexOf('Uri _resolvePackageUri'),
    );

    expect(
      updateFromFeedMethod,
      contains('Update feed package entries must be objects'),
    );
    expect(
      updateFromFeedMethod,
      isNot(contains('packages.whereType<Map<String, Object?>>()')),
    );
  });

  test(
    'source marker: update feeds and package entries reject unknown fields',
    () {
      final source = File(
        'lib/core/updates/update_service.dart',
      ).readAsStringSync();
      final updateFromFeedMethod = source.substring(
        source.indexOf('UpdateInfo? _updateFromFeed'),
        source.indexOf('Uri _resolvePackageUri'),
      );

      expect(source, contains('const Set<String> _allowedUpdateFeedFields'));
      expect(
        source,
        contains('const Set<String> _allowedUpdateFeedPackageFields'),
      );
      expect(source, contains('void _rejectUnknownUpdateFields'));
      expect(source, contains(r'Update $label contains unknown field $key.'));
      expect(updateFromFeedMethod, contains('_rejectUnknownUpdateFields(feed'));
      expect(updateFromFeedMethod, contains('_rejectUnknownUpdateFields('));
      expect(source, contains("'release_notes'"));
      expect(source, contains("'published_at'"));
      expect(source, isNot(contains('install_script')));
      expect(source, isNot(contains('post_install')));
    },
  );

  test('rejects update package URLs with wrong types', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        final packages = feed['packages'] as List<Object?>;
        final package = Map<String, Object?>.from(
          packages.single as Map<String, Object?>,
        );
        package['package_url'] = 123;
        feed['packages'] = [package];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('package_url must be a string'));
  });

  test('rejects malformed update package URLs with explicit error', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        final packages = feed['packages'] as List<Object?>;
        final package = Map<String, Object?>.from(
          packages.single as Map<String, Object?>,
        );
        package['package_url'] = 'https://[not-a-host/Avorax-AntiVirus.aup';
        feed['packages'] = [package];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('Update package URL is invalid'));
  });

  test('rejects control text in feed package URLs', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        final packages = feed['packages'] as List<Object?>;
        final package = Map<String, Object?>.from(
          packages.single as Map<String, Object?>,
        );
        package['package_url'] =
            'https://updates.example.test/Avorax-AntiVirus.aup\x00';
        feed['packages'] = [package];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(
      result.error,
      contains('Update package field package_url must not contain control'),
    );
    expect(result.error, isNot(contains('\x00')));
  });

  test('source marker: package URLs are required strings', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final updateFromFeedMethod = source.substring(
      source.indexOf('UpdateInfo? _updateFromFeed'),
      source.indexOf('Uri _resolvePackageUri'),
    );

    expect(
      updateFromFeedMethod,
      contains("_requiredString(item, 'package_url')"),
    );
    expect(
      updateFromFeedMethod,
      contains("_requiredString(package, 'package_url')"),
    );
    expect(source, contains('String _requiredString'));
    expect(source, contains('Update package URL is invalid'));
  });

  test('source marker: update package URLs are artifact-only', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final updateFromFeedMethod = source.substring(
      source.indexOf('UpdateInfo? _updateFromFeed'),
      source.indexOf('Uri _resolvePackageUri'),
    );
    final requireUpdateInfoMethod = source.substring(
      source.indexOf('void _requireUpdateInfoForUse'),
      source.indexOf('Future<void> rollbackPreviousVersion'),
    );
    final artifactUriMethod = source.substring(
      source.indexOf('void _requirePackageArtifactUri'),
      source.indexOf('bool _isTrustedFeedUri'),
    );

    expect(
      updateFromFeedMethod,
      contains('_requirePackageArtifactUri(packageUrl)'),
    );
    expect(
      requireUpdateInfoMethod,
      contains('_requirePackageArtifactUri(update.packageUrl)'),
    );
    expect(artifactUriMethod, contains('uri.hasQuery || uri.hasFragment'));
    expect(
      artifactUriMethod,
      contains('Update package URL must not include query or fragment'),
    );
  });

  test('source marker: HTTPS update URIs require host authority', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final feedTrustMethod = source.substring(
      source.indexOf('bool _isTrustedFeedUri'),
      source.indexOf('bool _isTrustedLocalFileFeedUri'),
    );
    final packageTrustMethod = source.substring(
      source.indexOf('bool _isTrustedPackageUri'),
      source.indexOf('bool _isTrustedLocalFilePackageUri'),
    );

    expect(feedTrustMethod, contains('_isTrustedHttpsUri(uri)'));
    expect(packageTrustMethod, contains('_isTrustedHttpsUri(uri)'));
    expect(feedTrustMethod, contains('bool _isTrustedHttpsUri(Uri uri)'));
    expect(feedTrustMethod, contains('uri.hasAuthority'));
    expect(feedTrustMethod, contains('uri.host.trim().isNotEmpty'));
    expect(feedTrustMethod, contains('uri.userInfo.isEmpty'));
  });

  test('source marker: GitHub update URLs share HTTPS trust gate', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final latestFeedMethod = source.substring(
      source.indexOf('bool _isGithubLatestDownloadFeed'),
      source.indexOf('Future<Uri?> _resolveGithubReleaseFeedAssetUri'),
    );
    final redirectMethod = source.substring(
      source.indexOf('bool _isAllowedGithubReleaseRedirect'),
      source.indexOf('String? _trustedGithubReleaseAssetName'),
    );
    final assetNameMethod = source.substring(
      source.indexOf('String? _trustedGithubReleaseAssetName'),
      source.indexOf('String _configuredGithubRepoPart'),
    );

    expect(latestFeedMethod, contains('_isTrustedHttpsUri(feedUri)'));
    expect(redirectMethod, contains('_isTrustedHttpsUri(redirectedUri)'));
    expect(assetNameMethod, contains('_isTrustedHttpsUri(uri)'));
    expect(
      latestFeedMethod,
      contains("feedUri.host.toLowerCase() == 'github.com'"),
    );
    expect(assetNameMethod, contains("uri.host.toLowerCase() != 'github.com'"));
    expect(
      assetNameMethod,
      contains('_safeTrustedGithubAssetName(segments[5])'),
    );
    expect(assetNameMethod, contains('String? _safeTrustedGithubAssetName'));
    expect(assetNameMethod, contains('return _safeUpdateAssetName(value);'));
    expect(assetNameMethod, contains('} on StateError {'));
    expect(assetNameMethod, contains('return null;'));
    expect(redirectMethod, contains("'release-assets.githubusercontent.com'"));
    expect(
      redirectMethod,
      contains('final redirectedSegments = redirectedUri.pathSegments'),
    );
    expect(redirectMethod, contains('redirectedSegments.length >= 3'));
    expect(
      redirectMethod,
      contains("redirectedSegments.first == 'github-production-release-asset'"),
    );
    expect(redirectMethod, contains('redirectedSegments.every'));
    expect(redirectMethod, contains('part.isNotEmpty'));
    expect(redirectMethod, contains("part != '.'"));
    expect(redirectMethod, contains("part != '..'"));
  });

  test('rejects overlong update package release notes', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        final packages = feed['packages'] as List<Object?>;
        final package = Map<String, Object?>.from(
          packages.single as Map<String, Object?>,
        );
        package['release_notes'] = 'A' * (16 * 1024 + 1);
        feed['packages'] = [package];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('too long'));
  });

  test('rejects malformed update package published dates', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        final feed = _feed('0.1.15');
        final packages = feed['packages'] as List<Object?>;
        final package = Map<String, Object?>.from(
          packages.single as Map<String, Object?>,
        );
        package['published_at'] = 'not-a-date';
        feed['packages'] = [package];
        return http.Response(jsonEncode(feed), 200);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('valid date'));
  });

  test('validates release notes free text controls at runtime', () async {
    Future<UpdateCheckResult> checkReleaseNotes(String releaseNotes) {
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl: 'https://updates.example.test/update-feed.json',
          updateChannel: 'dev',
        ),
        client: MockClient((request) async {
          final feed = _feed('0.1.15');
          final packages = feed['packages'] as List<Object?>;
          final package = Map<String, Object?>.from(
            packages.single as Map<String, Object?>,
          );
          package['release_notes'] = releaseNotes;
          feed['packages'] = [package];
          return http.Response(jsonEncode(feed), 200);
        }),
      );
      return service.checkForUpdate(currentVersion: '0.1.14');
    }

    final allowedResult = await checkReleaseNotes(
      'Line one\nLine two\tTabbed\r\nDone',
    );
    expect(allowedResult.status, UpdateStatus.updateAvailable);
    expect(allowedResult.update?.releaseNotes, contains('Line two\tTabbed'));

    final rejectedResult = await checkReleaseNotes('Unsafe\x00notes');
    expect(rejectedResult.status, UpdateStatus.failed);
    expect(
      rejectedResult.error,
      contains(
        'Update package field release_notes must not contain unsupported control',
      ),
    );
    expect(rejectedResult.error, isNot(contains('\x00')));
  });

  test('update package metadata fields are validated before use', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final updateFromFeedMethod = source.substring(
      source.indexOf('UpdateInfo? _updateFromFeed'),
      source.indexOf('Uri _resolvePackageUri'),
    );

    expect(
      updateFromFeedMethod,
      contains("_requireSupportedVersion(packageVersion"),
    );
    expect(updateFromFeedMethod, contains('package version'));
    expect(
      updateFromFeedMethod,
      contains("_optionalBool(package, 'rollback_supported')"),
    );
    expect(
      updateFromFeedMethod,
      isNot(contains("_optionalBool(package, 'rollback_supported') ?? false")),
    );
    expect(
      updateFromFeedMethod,
      contains("_optionalBool(package, 'required')"),
    );
    expect(
      updateFromFeedMethod,
      contains("_optionalBool(package, 'critical')"),
    );
    expect(updateFromFeedMethod, contains('_optionalBoundedString'));
    expect(updateFromFeedMethod, contains('_optionalDateTime'));
    expect(source, contains('maxUpdateReleaseNotesChars'));
    expect(source, contains('must be a boolean'));
    expect(source, contains('must be a string'));
    expect(source, contains('valid date'));
  });

  test('rejects unsafe update package filenames', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        return http.Response(
          jsonEncode(_feed('0.1.15', packageName: 'nested%5Cupdate.aup')),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('filename is unsafe'));
  });

  test('source marker: update package asset names are length bounded', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final downloadMethod = source.substring(
      source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
      source.indexOf(
        'Future<http.StreamedResponse> _getPackageWithAllowedRedirects',
      ),
    );
    final updateFromFeedMethod = source.substring(
      source.indexOf('UpdateInfo? _updateFromFeed'),
      source.indexOf('Uri _resolvePackageUri'),
    );
    final safeNameMethod = source.substring(
      source.indexOf('String _safeUpdateAssetName'),
      source.indexOf('Future<String> _sha256File'),
    );

    expect(source, contains('const int maxUpdateAssetNameChars = 128'));
    expect(downloadMethod, contains('_safeUpdateAssetName'));
    expect(updateFromFeedMethod, contains('_safeUpdateAssetName'));
    expect(safeNameMethod, contains('_isSafeUpdatePackageAssetName'));
    expect(safeNameMethod, contains('name.length <= maxUpdateAssetNameChars'));
    expect(safeNameMethod, contains('Update package filename is unsafe'));
  });

  test('rejects file package URLs from remote update feeds', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
        updateChannel: 'dev',
      ),
      client: MockClient((request) async {
        return http.Response(
          jsonEncode(
            _feed(
              '0.1.15',
              packageName: 'file:///C:/Avorax/Avorax-AntiVirus-0.1.15.aup',
            ),
          ),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('unless the update feed is local'));
  });

  test('source marker: remote update feeds cannot select local packages', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final trustMethod = source.substring(
      source.indexOf('bool _isTrustedPackageUri'),
      source.indexOf('String _fileNameFromUri'),
    );

    expect(source, contains('_isTrustedPackageUri(packageUrl, feedUri)'));
    expect(
      trustMethod,
      contains("uri.scheme == 'file' && feedUri.scheme == 'file'"),
    );
    expect(source, contains('unless the update feed is local'));
  });

  test('source marker: local update packages must be trusted file URIs', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final trustMethod = source.substring(
      source.indexOf('bool _isTrustedPackageUri'),
      source.indexOf('void _requireLocalPackageInsideFeedDirectory'),
    );

    expect(trustMethod, contains('_isTrustedLocalFilePackageUri(uri)'));
    expect(
      trustMethod,
      contains('bool _isTrustedLocalFilePackageUri(Uri uri)'),
    );
    expect(
      trustMethod,
      contains('uri.hasAuthority && uri.authority.isNotEmpty'),
    );
    expect(trustMethod, contains('_fileUriToPathOrNull(uri)'));
    expect(trustMethod, contains('_isAbsoluteLocalPath(path)'));
    expect(trustMethod, contains('!_hasParentTraversal(path)'));
  });

  test(
    'source marker: file update feeds must be local and revalidated before use',
    () {
      final source = File(
        'lib/core/updates/update_service.dart',
      ).readAsStringSync();
      final feedTrustMethod = source.substring(
        source.indexOf('bool _isTrustedFeedUri'),
        source.indexOf('bool _isTrustedPackageUri'),
      );
      final requireMethod = source.substring(
        source.indexOf('void _requireUpdateInfoForUse'),
        source.indexOf('Future<void> rollbackPreviousVersion'),
      );

      expect(requireMethod, contains('_isTrustedFeedUri(update.feedUrl)'));
      expect(
        requireMethod,
        contains('Downloaded update feed URL is not trusted.'),
      );
      expect(feedTrustMethod, contains('bool _isTrustedLocalFileFeedUri'));
      expect(feedTrustMethod, contains('uri.hasQuery || uri.hasFragment'));
      expect(feedTrustMethod, contains('_fileUriToPathOrNull(uri)'));
      expect(feedTrustMethod, contains('_isAbsoluteLocalPath(path)'));
      expect(feedTrustMethod, contains('!_hasParentTraversal(path)'));
      expect(feedTrustMethod, contains('String? _fileUriToPathOrNull'));
      expect(feedTrustMethod, contains('return uri.toFilePath();'));
    },
  );

  test('source marker: file update feeds reject URI authorities', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final feedTrustMethod = source.substring(
      source.indexOf('bool _isTrustedLocalFileFeedUri'),
      source.indexOf('String? _fileUriToPathOrNull'),
    );

    expect(
      feedTrustMethod,
      contains('uri.hasAuthority && uri.authority.isNotEmpty'),
    );
  });

  test('rejects local update feed paths that are not regular files', () async {
    final directory = await Directory.systemTemp.createTemp(
      'avorax-update-feed-test-',
    );
    try {
      final service = ZentorUpdateService(
        buildConfig: BuildConfig(updateFeedUrl: directory.uri.toString()),
        client: MockClient((request) async => http.Response('{}', 500)),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(result.status, UpdateStatus.failed);
      expect(result.error, contains('Local update feed is not a regular file'));
    } finally {
      if (await directory.exists()) {
        await directory.delete(recursive: true);
      }
    }
  });

  test('source marker: local update feeds are regular files', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final loadFeedMethod = source.substring(
      source.indexOf('Future<Map<String, Object?>> _loadFeed'),
      source.indexOf('bool _isGithubLatestDownloadFeed'),
    );

    expect(
      loadFeedMethod,
      contains(
        "_readBoundedUtf8File(\n        file,\n        maxUpdateFeedBytes,\n        'Local update feed'",
      ),
    );
    expect(source, contains('followLinks: false'));
    expect(source, contains('Refusing to use symbolic link'));
  });

  test('rejects local package paths outside the local feed directory', () async {
    final feedDirectory = await Directory.systemTemp.createTemp(
      'avorax-local-feed-',
    );
    final packageDirectory = await Directory.systemTemp.createTemp(
      'avorax-local-package-',
    );
    try {
      final package = File(
        '${packageDirectory.path}${Platform.pathSeparator}Avorax-AntiVirus-0.1.15.aup',
      );
      await package.writeAsString('benign package fixture', flush: true);
      final feed = File(
        '${feedDirectory.path}${Platform.pathSeparator}update-feed.json',
      );
      await feed.writeAsString(
        jsonEncode(_feed('0.1.15', packageName: package.uri.toString())),
        flush: true,
      );
      final service = ZentorUpdateService(
        buildConfig: BuildConfig(updateFeedUrl: feed.uri.toString()),
        client: MockClient((request) async => http.Response('{}', 500)),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(result.status, UpdateStatus.failed);
      expect(result.error, contains('local feed directory'));
    } finally {
      if (await feedDirectory.exists()) {
        await feedDirectory.delete(recursive: true);
      }
      if (await packageDirectory.exists()) {
        await packageDirectory.delete(recursive: true);
      }
    }
  });

  test('source marker: local packages stay under local feed directory', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();

    expect(source, contains('_requireLocalPackageInsideFeedDirectory'));
    expect(source, contains('_isPathInside(feedDirectory, packagePath)'));
    expect(
      source,
      contains('Local update package must be in the local feed directory'),
    );
    expect(source, contains('Local update package path contains traversal'));
    expect(source, contains("part == '..'"));
  });

  test(
    'source marker: local package downloads recheck canonical feed containment',
    () {
      final source = File(
        'lib/core/updates/update_service.dart',
      ).readAsStringSync();
      final downloadMethod = source.substring(
        source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
        source.indexOf(
          'Future<http.StreamedResponse> _getPackageWithAllowedRedirects',
        ),
      );
      final canonicalMethod = source.substring(
        source.indexOf('void _requireExistingLocalPackageInsideFeedDirectory'),
        source.indexOf('String _canonicalExistingLocalDirectoryPath'),
      );

      expect(
        downloadMethod,
        contains('_requireExistingLocalPackageInsideFeedDirectory('),
      );
      expect(
        downloadMethod.indexOf(
          '_requireExistingLocalPackageInsideFeedDirectory',
        ),
        lessThan(downloadMethod.indexOf('final source = File')),
      );
      expect(
        canonicalMethod,
        contains(
          '_requireLocalPackageInsideFeedDirectory(feedUri, packageUri)',
        ),
      );
      expect(canonicalMethod, contains('_canonicalExistingLocalDirectoryPath'));
      expect(canonicalMethod, contains('_canonicalExistingLocalFilePath'));
      expect(source, contains('resolveSymbolicLinksSync()'));
      expect(
        canonicalMethod,
        contains('Local update package must be in the local feed directory'),
      );
    },
  );

  test(
    'failed local package staging preserves existing cached package',
    () async {
      final feedDirectory = await Directory.systemTemp.createTemp(
        'avorax-local-feed-',
      );
      try {
        const assetName = 'Avorax-AntiVirus-0.1.15.aup';
        final sourcePackage = File(
          '${feedDirectory.path}${Platform.pathSeparator}$assetName',
        );
        await sourcePackage.writeAsString(
          'oversized benign package fixture',
          flush: true,
        );
        final feed = File(
          '${feedDirectory.path}${Platform.pathSeparator}update-feed.json',
        );
        await feed.writeAsString(
          jsonEncode(
            _feed('0.1.15', packageName: sourcePackage.uri.toString()),
          ),
          flush: true,
        );
        final updateCache = Directory(
          '${temporaryRoot.path}${Platform.pathSeparator}AvoraxUpdates',
        );
        await updateCache.create(recursive: true);
        final cachedPackage = File(
          '${updateCache.path}${Platform.pathSeparator}$assetName',
        );
        await cachedPackage.writeAsString(
          'existing cached package',
          flush: true,
        );
        final service = ZentorUpdateService(
          buildConfig: BuildConfig(updateFeedUrl: feed.uri.toString()),
          client: MockClient((request) async => http.Response('{}', 500)),
          maxPackageBytes: 4,
        );
        final update = UpdateInfo(
          currentVersion: '0.1.14',
          latestVersion: '0.1.15',
          feedUrl: feed.uri,
          packageUrl: sourcePackage.uri,
          packageSha256: 'a' * 64,
          channel: 'dev',
          rollbackSupported: true,
          packageName: assetName,
        );

        await expectLater(
          service.downloadUpdatePackage(update),
          throwsA(
            isA<StateError>().having(
              (error) => error.message,
              'message',
              contains('Local update package source exceeds'),
            ),
          ),
        );

        expect(await cachedPackage.readAsString(), 'existing cached package');
        final leftovers = updateCache
            .listSync()
            .map((entry) => entry.path)
            .where((path) => path.contains('.part'))
            .toList();
        expect(leftovers, isEmpty);
      } finally {
        if (await feedDirectory.exists()) {
          await feedDirectory.delete(recursive: true);
        }
      }
    },
  );

  test('rejects redirecting update package downloads', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(updateChannel: 'dev'),
      client: MockClient((request) async {
        expect(request.followRedirects, isFalse);
        return http.Response(
          '',
          302,
          headers: {
            'location':
                'https://other.example.test/Avorax-AntiVirus-0.1.15.aup',
          },
        );
      }),
    );
    final update = UpdateInfo(
      currentVersion: '0.1.14',
      latestVersion: '0.1.15',
      feedUrl: Uri.parse('https://updates.example.test/update-feed.json'),
      packageUrl: Uri.parse(
        'https://updates.example.test/Avorax-AntiVirus-0.1.15.aup',
      ),
      packageSha256: 'a' * 64,
      channel: 'dev',
      rollbackSupported: true,
      packageName: 'Avorax-AntiVirus-0.1.15.aup',
    );

    expect(
      () => service.downloadUpdatePackage(update),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          contains('Update package redirects are not allowed'),
        ),
      ),
    );
  });

  test('does not fake success when feed check fails', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl: 'https://updates.example.test/update-feed.json',
      ),
      client: MockClient((request) async => http.Response('rate limited', 403)),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('HTTP 403'));
  });

  test('falls back to GitHub release asset feed when latest download 404s', () async {
    final requests = <Uri>[];
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        requests.add(request.url);
        if (request.url.path ==
            '/brentishere41848/Avorax/releases/latest/download/update-feed.json') {
          return http.Response('not found', 404);
        }
        if (request.url.host == 'api.github.com' &&
            request.url.path == '/repos/brentishere41848/Avorax/releases') {
          return http.Response(
            jsonEncode([
              {
                'tag_name': 'v0.1.15',
                'draft': false,
                'prerelease': true,
                'assets': [
                  {
                    'name': 'update-feed.json',
                    'browser_download_url':
                        'https://github.com/brentishere41848/Avorax/releases/download/v0.1.15/update-feed.json',
                  },
                ],
              },
            ]),
            200,
          );
        }
        if (request.url.path ==
            '/brentishere41848/Avorax/releases/download/v0.1.15/update-feed.json') {
          return http.Response(
            jsonEncode(
              _feed(
                '0.1.15',
                packageUrl:
                    'https://github.com/brentishere41848/Avorax/releases/download/v0.1.15/Avorax-AntiVirus-0.1.15.aup',
              ),
            ),
            200,
          );
        }
        return http.Response('unexpected ${request.url}', 500);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.updateAvailable);
    expect(result.update?.latestVersion, '0.1.15');
    expect(
      requests.map((uri) => uri.host),
      containsAll(['github.com', 'api.github.com']),
    );
  });

  test('rejects redirecting GitHub release metadata lookups', () async {
    final requests = <http.Request>[];
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        requests.add(request);
        expect(request.followRedirects, isFalse);
        if (request.url.host == 'github.com') {
          return http.Response('not found', 404);
        }
        if (request.url.host == 'api.github.com') {
          return http.Response(
            '',
            302,
            headers: {
              'location':
                  'https://api.github.com/repos/brentishere41848/Avorax/releases?per_page=20',
            },
          );
        }
        return http.Response('unexpected ${request.url}', 500);
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(
      result.error,
      contains('GitHub releases lookup redirects are not allowed'),
    );
    expect(
      requests.map((request) => request.url.host),
      containsAll(['github.com', 'api.github.com']),
    );
  });

  test(
    'rejects oversized GitHub release metadata without Content-Length while streaming',
    () async {
      final requests = <Uri>[];
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl:
              'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
          updateChannel: 'dev',
          updatesRepoOwner: 'brentishere41848',
          updatesRepoName: 'Avorax',
        ),
        client: _StreamingClient((request) {
          requests.add(request.url);
          if (request.url.host == 'github.com') {
            return http.StreamedResponse(
              Stream<List<int>>.value(utf8.encode('not found')),
              404,
              request: request,
            );
          }
          if (request.url.host == 'api.github.com' &&
              request.url.path == '/repos/brentishere41848/Avorax/releases') {
            return http.StreamedResponse(
              Stream<List<int>>.fromIterable([
                List<int>.filled(maxGithubReleasesResponseBytes, 0x20),
                const [0x20],
              ]),
              200,
              request: request,
              headers: const {},
            );
          }
          return http.StreamedResponse(
            Stream<List<int>>.value(utf8.encode('unexpected ${request.url}')),
            500,
            request: request,
          );
        }),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(result.status, UpdateStatus.failed);
      expect(result.error, contains('GitHub releases response exceeds'));
      expect(result.error, contains('update metadata limit'));
      expect(
        requests.map((uri) => uri.host),
        containsAll(['github.com', 'api.github.com']),
      );
    },
  );

  test(
    'rejects control text in GitHub release metadata Content-Length at runtime',
    () async {
      final requests = <Uri>[];
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl:
              'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
          updateChannel: 'dev',
          updatesRepoOwner: 'brentishere41848',
          updatesRepoName: 'Avorax',
        ),
        client: MockClient((request) async {
          requests.add(request.url);
          if (request.url.host == 'github.com') {
            return http.Response('not found', 404);
          }
          if (request.url.host == 'api.github.com') {
            return http.Response(
              '[]',
              200,
              headers: {'content-length': '1\x00'},
            );
          }
          return http.Response('unexpected ${request.url}', 500);
        }),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(result.status, UpdateStatus.failed);
      expect(
        result.error,
        contains('GitHub releases Content-Length is invalid'),
      );
      expect(result.error, isNot(contains('\x00')));
      expect(
        requests.map((uri) => uri.host),
        containsAll(['github.com', 'api.github.com']),
      );
    },
  );

  test(
    'fails visible update checks when GitHub release metadata request stalls',
    () async {
      final requests = <Uri>[];
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl:
              'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
          updateChannel: 'dev',
          updatesRepoOwner: 'brentishere41848',
          updatesRepoName: 'Avorax',
        ),
        client: _StreamingClient((request) {
          requests.add(request.url);
          if (request.url.host == 'github.com') {
            return http.StreamedResponse(
              Stream<List<int>>.value(utf8.encode('not found')),
              404,
              request: request,
            );
          }
          if (request.url.host == 'api.github.com') {
            return Completer<http.StreamedResponse>().future;
          }
          return http.StreamedResponse(
            Stream<List<int>>.value(utf8.encode('unexpected ${request.url}')),
            500,
            request: request,
          );
        }),
        networkRequestTimeout: const Duration(milliseconds: 10),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(result.status, UpdateStatus.failed);
      expect(result.error, contains('GitHub releases request timed out'));
      expect(
        requests.map((uri) => uri.host),
        containsAll(['github.com', 'api.github.com']),
      );
    },
  );

  test(
    'fails visible update checks when GitHub release metadata stream stalls',
    () async {
      final controller = StreamController<List<int>>();
      addTearDown(controller.close);
      final requests = <Uri>[];
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl:
              'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
          updateChannel: 'dev',
          updatesRepoOwner: 'brentishere41848',
          updatesRepoName: 'Avorax',
        ),
        client: _StreamingClient((request) {
          requests.add(request.url);
          if (request.url.host == 'github.com') {
            return http.StreamedResponse(
              Stream<List<int>>.value(utf8.encode('not found')),
              404,
              request: request,
            );
          }
          if (request.url.host == 'api.github.com') {
            return http.StreamedResponse(
              controller.stream,
              200,
              request: request,
              headers: const {},
            );
          }
          return http.StreamedResponse(
            Stream<List<int>>.value(utf8.encode('unexpected ${request.url}')),
            500,
            request: request,
          );
        }),
        networkReadTimeout: const Duration(milliseconds: 10),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(result.status, UpdateStatus.failed);
      expect(result.error, contains('GitHub releases response timed out'));
      expect(
        requests.map((uri) => uri.host),
        containsAll(['github.com', 'api.github.com']),
      );
    },
  );

  test('rejects malformed GitHub release feed asset metadata', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        if (request.url.host == 'github.com') {
          return http.Response('not found', 404);
        }
        return http.Response(
          jsonEncode([
            {
              'tag_name': 'v0.1.15',
              'draft': false,
              'prerelease': true,
              'assets': [
                {'name': 'update-feed.json', 'browser_download_url': 123},
              ],
            },
          ]),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('browser_download_url must be a string'));
  });

  test('rejects control text in GitHub fallback feed asset URLs', () async {
    final requests = <Uri>[];
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        requests.add(request.url);
        if (request.url.host == 'github.com') {
          return http.Response('not found', 404);
        }
        return http.Response(
          jsonEncode([
            {
              'tag_name': 'v0.1.15',
              'draft': false,
              'prerelease': true,
              'assets': [
                {
                  'name': 'update-feed.json',
                  'browser_download_url':
                      'https://github.com/brentishere41848/Avorax/releases/download/v0.1.15/update-feed.json\x00',
                },
              ],
            },
          ]),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(
      result.error,
      contains(
        'GitHub release field browser_download_url must not contain control',
      ),
    );
    expect(result.error, isNot(contains('\x00')));
    expect(
      requests.map((uri) => uri.host),
      containsAll(['github.com', 'api.github.com']),
    );
  });

  test('rejects malformed GitHub fallback feed asset URLs', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        if (request.url.host == 'github.com') {
          return http.Response('not found', 404);
        }
        return http.Response(
          jsonEncode([
            {
              'tag_name': 'v0.1.15',
              'draft': false,
              'prerelease': true,
              'assets': [
                {
                  'name': 'update-feed.json',
                  'browser_download_url':
                      'https://[not-a-host/update-feed.json',
                },
              ],
            },
          ]),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('GitHub release feed asset URL is invalid'));
  });

  test('rejects GitHub fallback feed assets outside configured repo', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        if (request.url.host == 'github.com') {
          return http.Response('not found', 404);
        }
        return http.Response(
          jsonEncode([
            {
              'tag_name': 'v0.1.15',
              'draft': false,
              'prerelease': true,
              'assets': [
                {
                  'name': 'update-feed.json',
                  'browser_download_url':
                      'https://updates.example.test/update-feed.json',
                },
              ],
            },
          ]),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('No update-feed.json asset found'));
  });

  test('rejects nested GitHub fallback feed asset paths', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        if (request.url.host == 'github.com') {
          return http.Response('not found', 404);
        }
        return http.Response(
          jsonEncode([
            {
              'tag_name': 'v0.1.15',
              'draft': false,
              'prerelease': true,
              'assets': [
                {
                  'name': 'update-feed.json',
                  'browser_download_url':
                      'https://github.com/brentishere41848/Avorax/releases/download/v0.1.15/nested/update-feed.json',
                },
              ],
            },
          ]),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('No update-feed.json asset found'));
  });

  test('rejects unsafe decoded GitHub fallback feed asset names', () async {
    final requests = <Uri>[];
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updateFeedUrl:
            'https://github.com/brentishere41848/Avorax/releases/latest/download/update-feed.json',
        updateChannel: 'dev',
        updatesRepoOwner: 'brentishere41848',
        updatesRepoName: 'Avorax',
      ),
      client: MockClient((request) async {
        requests.add(request.url);
        if (request.url.host == 'github.com') {
          return http.Response('not found', 404);
        }
        return http.Response(
          jsonEncode([
            {
              'tag_name': 'v0.1.15',
              'draft': false,
              'prerelease': true,
              'assets': [
                {
                  'name': 'update-feed.json',
                  'browser_download_url':
                      'https://github.com/brentishere41848/Avorax/releases/download/v0.1.15/nested%5Cupdate-feed.json',
                },
              ],
            },
          ]),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('No update-feed.json asset found'));
    expect(
      requests.map((uri) => uri.host),
      containsAll(['github.com', 'api.github.com']),
    );
  });

  test('source marker: GitHub fallback metadata is typed', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final resolverMethod = source.substring(
      source.indexOf('Future<Uri?> _resolveGithubReleaseFeedAssetUri'),
      source.indexOf('UpdateInfo? _updateFromFeed'),
    );

    expect(resolverMethod, contains('GitHub release entries must be objects'));
    expect(resolverMethod, contains('_githubOptionalBool'));
    expect(resolverMethod, contains('_githubRequiredString'));
    expect(
      resolverMethod,
      contains('GitHub release feed asset URL is invalid'),
    );
    expect(
      resolverMethod,
      contains("_githubRequiredString(asset, 'browser_download_url')"),
    );
    expect(resolverMethod, contains('_isTrustedGithubReleaseFeedAssetUri'));
    expect(source, contains('_trustedGithubReleaseAssetName(uri)'));
    expect(source, contains("segments[3] == 'download'"));
    expect(source, contains('segments.length == 6'));
    expect(source, contains("== 'update-feed.json'"));
  });

  test('source marker: GitHub release metadata lookup rejects redirects', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final resolverMethod = source.substring(
      source.indexOf('Future<Uri?> _resolveGithubReleaseFeedAssetUri'),
      source.indexOf('Future<http.Response> _getGithubReleasesWithoutRedirect'),
    );
    final requestMethod = source.substring(
      source.indexOf('Future<http.Response> _getGithubReleasesWithoutRedirect'),
      source.indexOf('bool _isTrustedGithubReleaseFeedAssetUri'),
    );

    expect(
      resolverMethod,
      contains('_getGithubReleasesWithoutRedirect(apiUri)'),
    );
    expect(
      resolverMethod,
      contains('GitHub releases lookup redirects are not allowed'),
    );
    expect(requestMethod, contains("http.Request('GET', apiUri)"));
    expect(requestMethod, contains('followRedirects = false'));
    expect(requestMethod, contains("application/vnd.github+json"));
  });

  test('source marker: GitHub update repo identifiers are validated', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final latestFeedMethod = source.substring(
      source.indexOf('bool _isGithubLatestDownloadFeed'),
      source.indexOf('Future<Uri?> _resolveGithubReleaseFeedAssetUri'),
    );
    final resolverMethod = source.substring(
      source.indexOf('Future<Uri?> _resolveGithubReleaseFeedAssetUri'),
      source.indexOf('bool _isTrustedGithubReleaseFeedAssetUri'),
    );
    final trustedAssetMethod = source.substring(
      source.indexOf('bool _isTrustedGithubReleaseFeedAssetUri'),
      source.indexOf('UpdateInfo? _updateFromFeed'),
    );
    final validatorMethod = source.substring(
      source.indexOf('String _configuredGithubRepoPart'),
      source.indexOf('UpdateInfo? _updateFromFeed'),
    );

    expect(latestFeedMethod, contains('_configuredGithubRepoPart'));
    expect(resolverMethod, contains('_configuredGithubRepoPart'));
    expect(trustedAssetMethod, contains('_configuredGithubRepoPart'));
    expect(validatorMethod, contains('Configured GitHub update'));
    expect(validatorMethod, contains("label == 'owner'"));
    expect(validatorMethod, contains("normalized.contains('..')"));
    expect(resolverMethod, contains(r"'/repos/$owner/$repo/releases'"));
  });

  test('dev-channel verification and install pass explicit dev key flag', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final verifyMethod = source.substring(
      source.indexOf('Future<void> verifyDownloadedPackage'),
      source.indexOf('Future<void> installDownloadedPackage'),
    );
    final installMethod = source.substring(
      source.indexOf('Future<void> installDownloadedPackage'),
      source.indexOf('Future<void> rollbackPreviousVersion'),
    );

    expect(source, contains('List<String> _updaterArgsFor'));
    expect(source, contains("update.channel == 'dev'"));
    expect(source, contains("'--allow-development-key'"));
    expect(verifyMethod, contains('_updaterArgsFor(update'));
    expect(installMethod, contains('_updaterArgsFor(update'));
  });

  test('Windows verification uses elevated updater path', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final verifyMethod = source.substring(
      source.indexOf('Future<void> verifyDownloadedPackage'),
      source.indexOf('Future<void> installDownloadedPackage'),
    );

    expect(verifyMethod, contains('_runUpdater'));
    expect(verifyMethod, contains('elevated: Platform.isWindows'));
    expect(verifyMethod, isNot(contains('Process.run(updater)')));
    expect(source, contains('-Verb RunAs -Wait -PassThru'));
    expect(source, contains(r'exit \$process.ExitCode'));
    expect(source, isNot(contains(r'\\$p')));
  });

  test('source marker: update metadata arrays and strings are bounded', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final resolverMethod = source.substring(
      source.indexOf('Future<Uri?> _resolveGithubReleaseFeedAssetUri'),
      source.indexOf('UpdateInfo? _updateFromFeed'),
    );
    final updateFromFeedMethod = source.substring(
      source.indexOf('UpdateInfo? _updateFromFeed'),
      source.indexOf('Uri _resolvePackageUri'),
    );
    final requiredStringMethod = source.substring(
      source.indexOf('String _requiredString'),
      source.indexOf('String? _optionalString'),
    );
    final optionalStringMethod = source.substring(
      source.indexOf('String? _optionalString'),
      source.indexOf('bool? _githubOptionalBool'),
    );
    final optionalBoundedStringMethod = source.substring(
      source.indexOf('String? _optionalBoundedString'),
      source.indexOf('DateTime? _optionalDateTime'),
    );
    final githubStringMethod = source.substring(
      source.indexOf('String _githubRequiredString'),
      source.indexOf('String? _optionalBoundedString'),
    );
    final optionalDateTimeMethod = source.substring(
      source.indexOf('DateTime? _optionalDateTime'),
      source.indexOf('String? _updateServiceExecutable'),
    );

    expect(source, contains('const int maxUpdateFeedPackages = 64'));
    expect(source, contains('const int maxGithubReleases = 20'));
    expect(source, contains('const int maxGithubReleaseAssets = 64'));
    expect(source, contains('const int maxUpdateMetadataStringChars = 4096'));
    expect(resolverMethod, contains('decoded.length > maxGithubReleases'));
    expect(resolverMethod, contains('assets.length > maxGithubReleaseAssets'));
    expect(
      updateFromFeedMethod,
      contains('packages.length > maxUpdateFeedPackages'),
    );
    expect(requiredStringMethod, contains('maxUpdateMetadataStringChars'));
    expect(requiredStringMethod, contains('_containsControlOrNul(value)'));
    expect(
      requiredStringMethod,
      contains('must not contain control characters'),
    );
    expect(optionalStringMethod, contains('maxUpdateMetadataStringChars'));
    expect(optionalStringMethod, contains('_containsControlOrNul(value)'));
    expect(
      optionalStringMethod,
      contains('must not contain control characters'),
    );
    expect(githubStringMethod, contains('maxUpdateMetadataStringChars'));
    expect(githubStringMethod, contains('_containsControlOrNul(value)'));
    expect(githubStringMethod, contains('must not contain control characters'));
    expect(optionalDateTimeMethod, contains('maxUpdateMetadataStringChars'));
    expect(optionalDateTimeMethod, contains('_containsControlOrNul(value)'));
    expect(
      optionalDateTimeMethod,
      contains('must not contain control characters'),
    );
    expect(optionalDateTimeMethod, contains('DateTime.tryParse(value.trim())'));
    expect(source, contains('bool _containsUnsafeFreeTextControlOrNul'));
    expect(
      optionalBoundedStringMethod,
      contains('_containsUnsafeFreeTextControlOrNul(value)'),
    );
    expect(
      optionalBoundedStringMethod,
      contains('must not contain unsupported control characters'),
    );
    expect(optionalBoundedStringMethod, contains('maxLength'));
  });

  test('source marker: update Content-Length headers are bounded', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final packageHeaderMethod = source.substring(
      source.indexOf('void _rejectOversizedPackageHeader'),
      source.indexOf('void _rejectOversizedJson'),
    );
    final jsonHeaderMethod = source.substring(
      source.indexOf('void _rejectOversizedJsonHeader'),
      source.indexOf('Future<void> verifyDownloadedPackage'),
    );
    final parserMethod = source.substring(
      source.indexOf('int? _parseContentLengthHeader'),
      source.indexOf('Future<void> verifyDownloadedPackage'),
    );

    expect(
      source,
      contains('const int maxUpdateContentLengthHeaderChars = 32'),
    );
    expect(packageHeaderMethod, contains('_parseContentLengthHeader'));
    expect(jsonHeaderMethod, contains('_parseContentLengthHeader'));
    expect(parserMethod, contains('maxUpdateContentLengthHeaderChars'));
    expect(
      parserMethod,
      contains('value.length > maxUpdateContentLengthHeaderChars'),
    );
    expect(parserMethod, contains('_containsControlOrNul(value)'));
    expect(parserMethod, contains('final normalized = value.trim()'));
    expect(
      parserMethod.indexOf('value.length > maxUpdateContentLengthHeaderChars'),
      lessThan(parserMethod.indexOf('final normalized = value.trim()')),
    );
    expect(
      parserMethod.indexOf('_containsControlOrNul(value)'),
      lessThan(parserMethod.indexOf('final normalized = value.trim()')),
    );
    expect(parserMethod, contains(r"RegExp(r'^\d{1,32}$')"));
    expect(parserMethod, contains('int.tryParse(normalized)'));
    expect(parserMethod, isNot(contains('value.trim().isEmpty')));
  });

  test('updater executable is validated before launch', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final requireMethod = source.substring(
      source.indexOf('String _requireInstalledUpdateServiceExecutable'),
      source.indexOf('Future<void> _runUpdater'),
    );
    final finderMethod = source.substring(
      source.indexOf('String? _updateServiceExecutable'),
      source.indexOf('String _installDir'),
    );
    final regularFileMethod = source.substring(
      source.indexOf('void _requireRegularFile'),
      source.indexOf('void _rejectLinkPath'),
    );

    expect(
      requireMethod,
      contains(
        "_requireRegularFile(updater, 'Avorax Update Service executable')",
      ),
    );
    expect(requireMethod, isNot(contains('existsSync()')));
    expect(requireMethod, contains('_updateServiceExecutable('));
    expect(requireMethod, contains('includeDevelopmentCandidates: false'));
    expect(
      requireMethod,
      contains('_firstDevelopmentUpdateServiceExecutable()'),
    );
    expect(finderMethod, contains('_regularUpdateFileProbe(candidate)'));
    expect(finderMethod, contains('_updateServiceExecutableParentPath()'));
    expect(finderMethod, contains('Platform.resolvedExecutable'));
    expect(finderMethod, contains('_isAbsoluteLocalPath(parent)'));
    expect(
      finderMethod,
      contains(
        'Avorax Update Service executable directory must be an absolute local path.',
      ),
    );
    expect(regularFileMethod, contains('_regularUpdateFileProbe(path)'));
    expect(regularFileMethod, contains('Probe failed:'));
    expect(finderMethod, contains('_developmentUpdateServiceCandidates(name)'));
    expect(finderMethod, contains("'target'"));
    expect(finderMethod, contains("'release'"));
    expect(finderMethod, contains('_candidateDevelopmentRepoRoots()'));
    expect(finderMethod, contains('_isUpdateServiceDevelopmentRepoRoot('));
    expect(finderMethod, contains('apps'));
    expect(finderMethod, contains('zentor_client'));
    expect(finderMethod, contains('pubspec.yaml'));
    expect(finderMethod, contains('avorax_update_service'));
    expect(finderMethod, contains('Cargo.toml'));
    expect(
      finderMethod,
      contains('FileSystemEntity.typeSync(path, followLinks: false)'),
    );
    expect(finderMethod, contains('FileSystemEntityType.notFound'));
    expect(finderMethod, contains('exists but is not a regular file'));
    expect(
      finderMethod,
      contains('if (probe.diagnostic != null) return candidate'),
    );
    expect(finderMethod, contains('on FileSystemException catch (error)'));
    expect(finderMethod, contains('on ArgumentError catch (error)'));
    expect(finderMethod, contains(r'Unable to inspect $path'));
    expect(
      finderMethod,
      isNot(contains('File(Platform.resolvedExecutable).parent.path')),
    );
    expect(finderMethod, isNot(contains('File(candidate).existsSync()')));
    expect(
      finderMethod,
      isNot(
        contains(r'${Directory.current.path}${Platform.pathSeparator}$name'),
      ),
    );
    expect(source, contains('Refusing to use symbolic link'));
  });

  test('rollback refuses development checkout update service', () async {
    if (!Platform.isWindows) return;
    final devUpdater = File(
      '../../target/release/avorax_update_service.exe',
    ).absolute;
    if (!devUpdater.existsSync()) return;

    final service = ZentorUpdateService();

    await expectLater(
      service.rollbackPreviousVersion(),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          contains(
            'Refusing to use a development checkout Avorax Update Service',
          ),
        ),
      ),
    );
  });

  test('source marker: in-app updater uses installed-only executable', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final verifyMethod = source.substring(
      source.indexOf('Future<void> verifyDownloadedPackage'),
      source.indexOf('Future<void> installDownloadedPackage'),
    );
    final installMethod = source.substring(
      source.indexOf('Future<void> installDownloadedPackage'),
      source.indexOf('Future<void> rollbackPreviousVersion'),
    );
    final rollbackMethod = source.substring(
      source.indexOf('Future<void> rollbackPreviousVersion'),
      source.indexOf('Future<void> _runUpdater'),
    );
    final requireInstalledMethod = source.substring(
      source.indexOf('String _requireInstalledUpdateServiceExecutable'),
      source.indexOf('Future<void> _runUpdater'),
    );

    expect(
      verifyMethod,
      contains('_requireInstalledUpdateServiceExecutable()'),
    );
    expect(
      installMethod,
      contains('_requireInstalledUpdateServiceExecutable()'),
    );
    expect(
      rollbackMethod,
      contains('_requireInstalledUpdateServiceExecutable()'),
    );
    expect(requireInstalledMethod, contains('_updateServiceExecutable('));
    expect(
      requireInstalledMethod,
      contains('includeDevelopmentCandidates: false'),
    );
    expect(
      requireInstalledMethod,
      contains('_firstDevelopmentUpdateServiceExecutable()'),
    );
    expect(
      requireInstalledMethod,
      contains('_developmentUpdateServiceExecutionBlocker(path)'),
    );
    expect(
      requireInstalledMethod,
      contains('Refusing to use a development checkout Avorax Update Service'),
    );
  });

  test('source marker: update install directory is executable-derived', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final installDirMethod = source.substring(
      source.indexOf('String _installDir'),
      source.indexOf('static int _compareVersions'),
    );

    expect(installDirMethod, contains('Platform.resolvedExecutable'));
    expect(installDirMethod, contains('_isAbsoluteLocalPath(parent)'));
    expect(
      installDirMethod,
      contains('Update install directory must be an absolute local path.'),
    );
    expect(installDirMethod, isNot(contains(r'C:\Program Files\Avorax')));
  });

  test(
    'updater process diagnostics are bounded and both streams are drained',
    () {
      final source = File(
        'lib/core/updates/update_service.dart',
      ).readAsStringSync();
      final runUpdaterMethod = source.substring(
        source.indexOf('Future<void> _runUpdater'),
        source.indexOf('Future<String> _collectBoundedUtf8'),
      );
      final collectorMethod = source.substring(
        source.indexOf('Future<String> _collectBoundedUtf8'),
        source.indexOf('String _updaterDiagnosticWithTruncationSuffix'),
      );
      final truncationMethod = source.substring(
        source.indexOf('String _updaterDiagnosticWithTruncationSuffix'),
        source.indexOf('String _formatUpdaterDiagnostics'),
      );
      final formatterMethod = source.substring(
        source.indexOf('String _formatUpdaterDiagnostics'),
        source.indexOf('Future<String> _installedVersion'),
      );

      expect(source, contains('maxUpdaterDiagnosticChars'));
      expect(runUpdaterMethod, contains('Process.start(updater, args)'));
      expect(runUpdaterMethod, contains('_collectBoundedUtf8(process.stdout)'));
      expect(runUpdaterMethod, contains('_collectBoundedUtf8(process.stderr)'));
      expect(
        runUpdaterMethod,
        contains('process.exitCode.timeout(updaterProcessTimeout)'),
      );
      expect(runUpdaterMethod, contains('process.kill()'));
      expect(source, contains('updaterProcessReapTimeout'));
      expect(source, contains('String _updaterTerminationStatus(bool killed)'));
      expect(source, contains('Future<String> _updaterReapStatus'));
      expect(runUpdaterMethod, contains('Avorax Update Service timed out.'));
      expect(runUpdaterMethod, contains('Termination requested.'));
      expect(runUpdaterMethod, contains('Termination request failed.'));
      expect(
        runUpdaterMethod,
        contains('final reapStatus = await _updaterReapStatus(process)'),
      );
      expect(
        source,
        contains('Timed-out process did not exit after termination request.'),
      );
      expect(
        source,
        contains(r'Timed-out process exited with code $exitCode.'),
      );
      expect(runUpdaterMethod, isNot(contains('Process.run(updater, args)')));
      expect(collectorMethod, contains('maxUpdaterDiagnosticChars'));
      expect(collectorMethod, contains('Utf8Decoder(allowMalformed: true)'));
      expect(
        collectorMethod,
        contains('_updaterDiagnosticWithTruncationSuffix(buffer.toString())'),
      );
      expect(truncationMethod, contains('_updaterDiagnosticTruncationSuffix'));
      expect(
        truncationMethod,
        contains(
          'maxUpdaterDiagnosticChars - _updaterDiagnosticTruncationSuffix.length',
        ),
      );
      expect(formatterMethod, contains('_formatUpdaterDiagnostics'));
      expect(formatterMethod, contains(r"RegExp(r'[\x00-\x1F\x7F]+')"));
      expect(formatterMethod, contains('stderrText.isNotEmpty'));
      expect(formatterMethod, contains('stdoutText.isNotEmpty'));
      expect(
        formatterMethod,
        contains('_boundedUpdaterDiagnosticText(parts.join())'),
      );
      expect(formatterMethod, isNot(contains('return parts.join();')));
    },
  );

  test('elevated updater launch uses encoded PowerShell command', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final runUpdaterMethod = source.substring(
      source.indexOf('Future<void> _runUpdater'),
      source.indexOf('Future<String> _collectBoundedUtf8'),
    );
    final encodedHelpers = source.substring(
      source.indexOf('String _elevatedUpdaterScript'),
      source.indexOf('String _installDir'),
    );

    expect(runUpdaterMethod, contains("'-EncodedCommand'"));
    expect(
      runUpdaterMethod,
      contains(
        '_powershellEncodedCommand(_elevatedUpdaterScript(updater, args))',
      ),
    );
    expect(runUpdaterMethod, contains('_windowsPowerShellExecutable()'));
    expect(runUpdaterMethod, isNot(contains("'-Command'")));
    expect(runUpdaterMethod, isNot(contains("Process.start('powershell.exe'")));
    expect(runUpdaterMethod, isNot(contains('Start-Process -FilePath')));
    expect(encodedHelpers, contains('String _elevatedUpdaterScript'));
    expect(encodedHelpers, contains('String _powershellSingleQuoted'));
    expect(encodedHelpers, contains('String _powershellEncodedCommand'));
    expect(encodedHelpers, contains('String _windowsPowerShellExecutable'));
    expect(
      encodedHelpers,
      contains("_checkedWindowsSystemRootValue('SystemRoot')"),
    );
    expect(
      encodedHelpers,
      contains("_checkedWindowsSystemRootValue('WINDIR')"),
    );
    expect(encodedHelpers, contains('_nonEmptyEnvironmentValue(name)'));
    expect(
      encodedHelpers,
      contains('SystemRoot or WINDIR is required to locate'),
    );
    expect(
      encodedHelpers,
      contains('PowerShell update launcher root must be on a local drive'),
    );
    expect(encodedHelpers, contains('WindowsPowerShell'));
    expect(encodedHelpers, contains('powershell.exe'));
    expect(encodedHelpers, isNot(contains(r'C:\Windows')));
    expect(encodedHelpers, contains('_isWindowsRemoteOrDevicePath(candidate)'));
    expect(
      encodedHelpers,
      contains('PowerShell update launcher command must be on a local drive'),
    );
    expect(
      encodedHelpers,
      contains(
        "_requireRegularFile(candidate, 'PowerShell update launcher executable')",
      ),
    );
    expect(encodedHelpers, contains('value.replaceAll("\'", "\'\'")'));
    expect(
      encodedHelpers,
      contains('for (final codeUnit in script.codeUnits)'),
    );
    expect(encodedHelpers, contains('base64Encode(bytes)'));
  });

  test('verify rejects cached update package hash drift before updater', () async {
    final directory = Directory(
      '${temporaryRoot.path}${Platform.pathSeparator}AvoraxUpdates',
    );
    await directory.create(recursive: true);
    try {
      final package = File(
        '${directory.path}${Platform.pathSeparator}Avorax-AntiVirus-0.1.15.aup',
      );
      await package.writeAsString('changed package', flush: true);
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(updateChannel: 'dev'),
        client: MockClient((request) async => http.Response('', 500)),
      );
      final update = UpdateInfo(
        currentVersion: '0.1.14',
        latestVersion: '0.1.15',
        feedUrl: Uri.parse('https://updates.example.test/update-feed.json'),
        packageUrl: Uri.parse(
          'https://updates.example.test/Avorax-AntiVirus-0.1.15.aup',
        ),
        packageSha256:
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        channel: 'dev',
        rollbackSupported: true,
        packageName: 'Avorax-AntiVirus-0.1.15.aup',
        localPackagePath: package.path,
      );

      await expectLater(
        service.verifyDownloadedPackage(update),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            contains('SHA-256 changed before verify'),
          ),
        ),
      );
    } finally {
      if (await directory.exists()) {
        await directory.delete(recursive: true);
      }
    }
  });

  test('verify rejects oversized cached update package before hashing', () async {
    final directory = Directory(
      '${temporaryRoot.path}${Platform.pathSeparator}AvoraxUpdates',
    );
    await directory.create(recursive: true);
    try {
      final package = File(
        '${directory.path}${Platform.pathSeparator}Avorax-AntiVirus-0.1.15.aup',
      );
      await package.writeAsString(
        'benign package fixture larger than test limit',
        flush: true,
      );
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(updateChannel: 'dev'),
        client: MockClient((request) async => http.Response('', 500)),
        maxPackageBytes: 16,
      );
      final update = UpdateInfo(
        currentVersion: '0.1.14',
        latestVersion: '0.1.15',
        feedUrl: Uri.parse('https://updates.example.test/update-feed.json'),
        packageUrl: Uri.parse(
          'https://updates.example.test/Avorax-AntiVirus-0.1.15.aup',
        ),
        packageSha256:
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        channel: 'dev',
        rollbackSupported: true,
        packageName: 'Avorax-AntiVirus-0.1.15.aup',
        localPackagePath: package.path,
      );

      await expectLater(
        service.verifyDownloadedPackage(update),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            allOf(
              contains('update package hash input exceeds'),
              contains('16 bytes in-app update package limit'),
            ),
          ),
        ),
      );
    } finally {
      if (await directory.exists()) {
        await directory.delete(recursive: true);
      }
    }
  });

  test('verify rejects malformed update metadata before updater', () async {
    final directory = Directory(
      '${temporaryRoot.path}${Platform.pathSeparator}AvoraxUpdates',
    );
    await directory.create(recursive: true);
    try {
      final package = File(
        '${directory.path}${Platform.pathSeparator}Avorax-AntiVirus-0.1.15.aup',
      );
      await package.writeAsString('benign package fixture', flush: true);
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(updateChannel: 'dev'),
        client: MockClient((request) async => http.Response('', 500)),
      );
      final update = UpdateInfo(
        currentVersion: 'not-a-version',
        latestVersion: '0.1.15',
        feedUrl: Uri.parse('https://updates.example.test/update-feed.json'),
        packageUrl: Uri.parse(
          'https://updates.example.test/Avorax-AntiVirus-0.1.15.aup',
        ),
        packageSha256:
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        channel: 'dev',
        rollbackSupported: true,
        packageName: 'Avorax-AntiVirus-0.1.15.aup',
        localPackagePath: package.path,
      );

      await expectLater(
        service.verifyDownloadedPackage(update),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            contains('current version is not a supported version string'),
          ),
        ),
      );
    } finally {
      if (await directory.exists()) {
        await directory.delete(recursive: true);
      }
    }
  });

  test('verify rejects non-file package paths with probe diagnostics', () async {
    final directory = Directory(
      '${temporaryRoot.path}${Platform.pathSeparator}AvoraxUpdates',
    );
    await directory.create(recursive: true);
    try {
      final packageDirectory = Directory(
        '${directory.path}${Platform.pathSeparator}Avorax-AntiVirus-0.1.15.aup',
      );
      await packageDirectory.create();
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(updateChannel: 'dev'),
        client: MockClient((request) async => http.Response('', 500)),
      );
      final update = UpdateInfo(
        currentVersion: '0.1.14',
        latestVersion: '0.1.15',
        feedUrl: Uri.parse('https://updates.example.test/update-feed.json'),
        packageUrl: Uri.parse(
          'https://updates.example.test/Avorax-AntiVirus-0.1.15.aup',
        ),
        packageSha256:
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        channel: 'dev',
        rollbackSupported: true,
        packageName: 'Avorax-AntiVirus-0.1.15.aup',
        localPackagePath: packageDirectory.path,
      );

      await expectLater(
        service.verifyDownloadedPackage(update),
        throwsA(
          isA<StateError>().having(
            (error) {
              expect(
                error.message,
                contains('downloaded update package is not a regular file.'),
              );
              expect(error.message, contains('Probe failed:'));
              expect(
                error.message,
                contains('exists but is not a regular file'),
              );
              expect(error.message, isNot(contains('\x00')));
              expect(error.message, isNot(contains('\n\t')));
              return error.message;
            },
            'message',
            isNotEmpty,
          ),
        ),
      );
    } finally {
      if (await directory.exists()) {
        await directory.delete(recursive: true);
      }
    }
  });

  test(
    'download rejects malformed update metadata before package fetch',
    () async {
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(updateChannel: 'dev'),
        client: MockClient((request) async => http.Response('', 200)),
      );
      final update = UpdateInfo(
        currentVersion: '0.1.14',
        latestVersion: 'not-a-version',
        feedUrl: Uri.parse('https://updates.example.test/update-feed.json'),
        packageUrl: Uri.parse(
          'https://updates.example.test/Avorax-AntiVirus-0.1.15.aup',
        ),
        packageSha256: 'a' * 64,
        channel: 'dev',
        rollbackSupported: true,
        packageName: 'Avorax-AntiVirus-0.1.15.aup',
      );

      expect(
        () => service.downloadUpdatePackage(update),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            contains('latest version is not a supported version string'),
          ),
        ),
      );
    },
  );

  test(
    'download rejects remote-feed local package URLs before package fetch',
    () {
      final source = File(
        'lib/core/updates/update_service.dart',
      ).readAsStringSync();
      final downloadMethod = source.substring(
        source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
        source.indexOf(
          'Future<http.StreamedResponse> _getPackageWithAllowedRedirects',
        ),
      );

      expect(downloadMethod, contains('_requireUpdateInfoForUse(update)'));
      expect(downloadMethod, contains('_isTrustedPackageUri'));
      expect(
        downloadMethod.indexOf('_requireUpdateInfoForUse(update)'),
        lessThan(downloadMethod.indexOf('_getPackageWithAllowedRedirects')),
      );
    },
  );

  test('download fails visibly when remote package stream stalls', () async {
    final controller = StreamController<List<int>>();
    addTearDown(controller.close);
    final requests = <Uri>[];
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(updateChannel: 'dev'),
      client: _StreamingClient((request) {
        requests.add(request.url);
        return http.StreamedResponse(
          controller.stream,
          200,
          request: request,
          headers: const {},
        );
      }),
      networkReadTimeout: const Duration(milliseconds: 10),
    );
    final update = UpdateInfo(
      currentVersion: '0.1.14',
      latestVersion: '0.1.15',
      feedUrl: Uri.parse('https://updates.example.test/update-feed.json'),
      packageUrl: Uri.parse(
        'https://updates.example.test/Avorax-AntiVirus-0.1.15.aup',
      ),
      packageSha256: 'a' * 64,
      channel: 'dev',
      rollbackSupported: true,
      packageName: 'Avorax-AntiVirus-0.1.15.aup',
    );

    await expectLater(
      service.downloadUpdatePackage(update),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          contains('downloaded update package download timed out'),
        ),
      ),
    );
    expect(requests, [
      Uri.parse('https://updates.example.test/Avorax-AntiVirus-0.1.15.aup'),
    ]);
  });

  test('verify and install revalidate downloaded update packages', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final verifyMethod = source.substring(
      source.indexOf('Future<void> verifyDownloadedPackage'),
      source.indexOf('Future<void> installDownloadedPackage'),
    );
    final installMethod = source.substring(
      source.indexOf('Future<void> installDownloadedPackage'),
      source.indexOf('List<String> _updaterArgsFor'),
    );
    final hashMethod = source.substring(
      source.indexOf('Future<String> _sha256File'),
      source.indexOf('Future<void> _activateDownloadedPackage'),
    );

    expect(source, contains('_requireDownloadedPackageForUse'));
    expect(source, contains('_requireUpdateInfoForUse'));
    expect(
      source,
      contains('Downloaded update channel does not match this build'),
    );
    expect(source, contains('Downloaded update package SHA-256 is invalid'));
    expect(source, contains('downloaded update package'));
    expect(source, contains('SHA-256 changed before'));
    expect(verifyMethod, contains('_requireDownloadedPackageForUse'));
    expect(installMethod, contains('_requireDownloadedPackageForUse'));
    expect(
      hashMethod,
      contains("_requireRegularFile(file.path, 'update package hash input')"),
    );
    expect(
      hashMethod,
      contains(
        "_rejectOversizedPackage(await file.length(), 'update package hash input')",
      ),
    );
    expect(
      hashMethod.lastIndexOf(
        "_requireRegularFile(file.path, 'update package hash input')",
      ),
      greaterThan(hashMethod.indexOf("await file.length()")),
    );
    expect(
      hashMethod.lastIndexOf(
        "_requireRegularFile(file.path, 'update package hash input')",
      ),
      lessThan(hashMethod.indexOf('file.openRead()')),
    );
  });

  test('downloaded update packages must stay in managed cache', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final downloadMethod = source.substring(
      source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
      source.indexOf(
        'Future<http.StreamedResponse> _getPackageWithAllowedRedirects',
      ),
    );
    final requireMethod = source.substring(
      source.indexOf('Future<String> _requireDownloadedPackageForUse'),
      source.indexOf('void _requireUpdateInfoForUse'),
    );

    expect(source, contains('Future<Directory> _updateCacheDirectory()'));
    expect(downloadMethod, contains('await _updateCacheDirectory()'));
    expect(requireMethod, contains('await _updateCacheDirectory()'));
    expect(requireMethod, contains('_ensureSafeDirectory'));
    expect(requireMethod, contains('_isPathInside'));
    expect(
      requireMethod,
      contains('Downloaded update package is outside the update cache'),
    );
  });

  test('downloaded update packages are staged before cache activation', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final downloadMethod = source.substring(
      source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
      source.indexOf(
        'Future<http.StreamedResponse> _getPackageWithAllowedRedirects',
      ),
    );

    expect(source, contains('.part'));
    expect(downloadMethod, contains('_ensureSafeDirectory'));
    expect(downloadMethod, contains('_temporaryPackageFile'));
    expect(downloadMethod, contains('_requireRegularFile'));
    expect(downloadMethod, contains('_sha256File(tempFile)'));
    expect(downloadMethod, contains('_activateDownloadedPackage'));
    expect(source, contains('followLinks: false'));
    expect(source, contains('Refusing to use symbolic link'));
    expect(downloadMethod, contains('await _temporaryPackageFile'));
    expect(source, contains('await tempFile.create(exclusive: true)'));
    expect(downloadMethod, contains('_copyLocalPackageToReservedTempFile'));
    expect(downloadMethod, contains('_writeStreamToReservedPackageFile'));
    expect(downloadMethod, contains('response.stream'));
    expect(source, contains('await output.writeFrom(chunk)'));
    expect(source, contains('_rejectOversizedPackage(totalBytes'));
    expect(source, isNot(contains('source.copy(tempFile.path)')));
    expect(source, isNot(contains('tempFile.writeAsBytes')));
    expect(downloadMethod, isNot(contains('response.bodyBytes.length')));
    expect(source, isNot(contains('_writeBytesToReservedPackageFile')));
    expect(source, contains('Failed to reserve temporary update package path'));
    expect(source, contains('Temporary update package path became unsafe'));
    expect(
      source,
      contains('Cached update package path is not a regular file'),
    );
    expect(source, contains('_temporaryPackageBackupFile(packageFile)'));
    expect(source, contains('await packageFile.rename(backupFile.path)'));
    expect(source, contains('await backupFile.rename(packageFile.path)'));
    expect(
      source,
      contains(
        'Cached update package activation failed and restore also failed',
      ),
    );
    expect(source, contains('await _deleteTemporaryPackageFile(backupFile)'));
    expect(source, isNot(contains('await packageFile.delete()')));
    expect(
      source,
      contains('Unable to allocate a safe temporary update package path'),
    );
  });

  test(
    'source marker: local update package copy rechecks source after streaming',
    () {
      final source = File(
        'lib/core/updates/update_service.dart',
      ).readAsStringSync();
      final localCopyHelper = source.substring(
        source.indexOf('Future<void> _copyLocalPackageToReservedTempFile'),
        source.indexOf('Future<void> _writeStreamToReservedPackageFile'),
      );

      expect(
        localCopyHelper,
        contains(
          "_requireRegularFile(source.path, 'local update package source')",
        ),
      );
      expect(
        localCopyHelper,
        contains('await for (final chunk in source.openRead())'),
      );
      expect(localCopyHelper, contains('_rejectOversizedPackage(totalBytes'));
      expect(
        localCopyHelper.lastIndexOf(
          "_requireRegularFile(source.path, 'local update package source')",
        ),
        greaterThan(localCopyHelper.indexOf('await output.close()')),
      );
      expect(
        localCopyHelper.lastIndexOf(
          "_requireRegularFile(source.path, 'local update package source')",
        ),
        lessThan(
          localCopyHelper.lastIndexOf(
            'temporary update package local-copy output',
          ),
        ),
      );
    },
  );

  test('download temp cleanup failures are reported', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final downloadMethod = source.substring(
      source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
      source.indexOf(
        'Future<http.StreamedResponse> _getPackageWithAllowedRedirects',
      ),
    );

    expect(downloadMethod, contains('temporary package cleanup also failed'));
    expect(
      downloadMethod,
      contains(r"Original error: ${_boundedUpdateCheckError('$error')}"),
    );
    expect(
      downloadMethod,
      contains(r"Cleanup error: ${_boundedUpdateCheckError('$cleanupError')}"),
    );
    expect(downloadMethod, isNot(contains(r'Original error: $error')));
    expect(downloadMethod, isNot(contains(r'Cleanup error: $cleanupError')));
    expect(downloadMethod, contains('Error.throwWithStackTrace'));
    expect(downloadMethod, contains('_deleteTemporaryPackageFile(tempFile)'));
    expect(downloadMethod, isNot(contains('catch (_)')));
    expect(downloadMethod, isNot(contains('tempFile.exists()')));
    expect(downloadMethod, isNot(contains('Keep the original update error')));
  });

  test(
    'download temp cleanup failures preserve bounded original diagnostics',
    () async {
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(updateChannel: 'dev'),
        client: MockClient((request) async {
          await _replaceReservedPackageTempWithDirectory(temporaryRoot);
          throw StateError('download failed\x00\n\twith control text');
        }),
      );
      final update = UpdateInfo(
        currentVersion: '0.1.14',
        latestVersion: '0.1.15',
        feedUrl: Uri.parse('https://updates.example.test/update-feed.json'),
        packageUrl: Uri.parse(
          'https://updates.example.test/Avorax-AntiVirus-0.1.15.aup',
        ),
        packageSha256: 'a' * 64,
        channel: 'dev',
        rollbackSupported: true,
        packageName: 'Avorax-AntiVirus-0.1.15.aup',
      );

      await expectLater(
        service.downloadUpdatePackage(update),
        throwsA(
          isA<StateError>().having(
            (error) {
              expect(
                error.message,
                contains(
                  'Update package download failed and temporary package cleanup also failed.',
                ),
              );
              expect(
                error.message,
                contains(
                  'Original error: Bad state: download failed with control text',
                ),
              );
              expect(
                error.message,
                contains(
                  'Cleanup error: Bad state: Temporary update package cleanup target was unsafe.',
                ),
              );
              expect(error.message, isNot(contains('\x00')));
              expect(error.message, isNot(contains('\n\t')));
              return error.message;
            },
            'message',
            isNotEmpty,
          ),
        ),
      );
    },
  );

  test(
    'rejects control text in update feed Content-Length at runtime',
    () async {
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(
          updateFeedUrl: 'https://updates.example.test/update-feed.json',
          updateChannel: 'dev',
        ),
        client: MockClient((request) async {
          return http.Response(
            jsonEncode(_feed('0.1.15')),
            200,
            headers: {'content-length': '1\x00'},
          );
        }),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(result.status, UpdateStatus.failed);
      expect(result.error, contains('Update feed Content-Length is invalid'));
      expect(result.error, isNot(contains('\x00')));
    },
  );

  test(
    'rejects control text in update package Content-Length at runtime',
    () async {
      final service = ZentorUpdateService(
        buildConfig: const BuildConfig(updateChannel: 'dev'),
        client: MockClient((request) async {
          return http.Response(
            'not-a-package',
            200,
            headers: {'content-length': '1\x00'},
          );
        }),
      );
      final update = UpdateInfo(
        currentVersion: '0.1.14',
        latestVersion: '0.1.15',
        feedUrl: Uri.parse('https://updates.example.test/update-feed.json'),
        packageUrl: Uri.parse(
          'https://updates.example.test/Avorax-AntiVirus-0.1.15.aup',
        ),
        packageSha256: 'a' * 64,
        channel: 'dev',
        rollbackSupported: true,
        packageName: 'Avorax-AntiVirus-0.1.15.aup',
      );

      await expectLater(
        service.downloadUpdatePackage(update),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            allOf(
              contains('Update package Content-Length is invalid'),
              isNot(contains('\x00')),
            ),
          ),
        ),
      );
    },
  );

  test('download temp cleanup uses non-following path checks', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final cleanupHelper = source.substring(
      source.indexOf('Future<void> _deleteTemporaryPackageFile'),
      source.indexOf('Future<void> _ensureSafeDirectory'),
    );

    expect(cleanupHelper, contains('FileSystemEntity.typeSync'));
    expect(cleanupHelper, contains('followLinks: false'));
    expect(cleanupHelper, contains('FileSystemEntityType.notFound'));
    expect(
      cleanupHelper,
      contains('Temporary update package cleanup target was unsafe'),
    );
    expect(cleanupHelper, contains('await tempFile.delete()'));
  });

  test('in-app update package downloads have explicit size limits', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final downloadMethod = source.substring(
      source.indexOf('Future<UpdateInfo> downloadUpdatePackage'),
      source.indexOf(
        'Future<http.StreamedResponse> _getPackageWithAllowedRedirects',
      ),
    );

    expect(source, contains('maxInAppUpdatePackageBytes'));
    expect(downloadMethod, contains('await source.length()'));
    expect(downloadMethod, contains("_rejectOversizedPackageHeader"));
    expect(downloadMethod, contains("response.headers['content-length']"));
    expect(downloadMethod, contains('_writeStreamToReservedPackageFile'));
    expect(downloadMethod, contains('response.stream'));
    expect(downloadMethod, isNot(contains('response.bodyBytes')));
    expect(
      source,
      contains(
        'Future<http.StreamedResponse> _sendWithAllowedGithubReleaseRedirects',
      ),
    );
    expect(source, contains('return streamed;'));
    expect(source, contains('in-app update package limit'));
    expect(source, contains('Content-Length'));
  });

  test('update feed metadata parsing has explicit size limits', () {
    final source = File(
      'lib/core/updates/update_service.dart',
    ).readAsStringSync();
    final loadFeedMethod = source.substring(
      source.indexOf('Future<Map<String, Object?>> _loadFeed'),
      source.indexOf('bool _isGithubLatestDownloadFeed'),
    );
    final githubResolverMethod = source.substring(
      source.indexOf('Future<Uri?> _resolveGithubReleaseFeedAssetUri'),
      source.indexOf('UpdateInfo? _updateFromFeed'),
    );

    expect(source, contains('maxUpdateFeedBytes'));
    expect(source, contains('maxGithubReleasesResponseBytes'));
    expect(source, contains('_rejectOversizedJson'));
    expect(source, contains('_rejectOversizedJsonHeader'));
    expect(source, contains('_responseFromBoundedStreamedResponse'));
    expect(
      source,
      contains('await for (final chunk in streamed.stream.timeout'),
    );
    expect(source, contains('_networkReadTimeout'));
    expect(source, contains('updateNetworkRequestTimeout'));
    expect(source, contains('updateNetworkReadTimeout'));
    expect(source, contains('_networkRequestTimeout'));
    expect(source, contains('.timeout(_networkRequestTimeout)'));
    expect(source, contains('_requirePositiveTimeout'));
    expect(
      source,
      contains('_rejectOversizedJson(totalBytes, maxBytes, label)'),
    );
    expect(source, contains('http.Response.bytes'));
    expect(source, isNot(contains('http.Response.fromStream')));
    expect(loadFeedMethod, contains('_readBoundedUtf8File'));
    expect(loadFeedMethod, contains('file.openRead()'));
    expect(loadFeedMethod, contains('utf8.decode(bytes)'));
    expect(loadFeedMethod, isNot(contains('readAsString()')));
    expect(loadFeedMethod, isNot(contains('await file.length()')));
    expect(loadFeedMethod, contains("response.headers['content-length']"));
    expect(loadFeedMethod, contains('response.bodyBytes.length'));
    expect(
      githubResolverMethod,
      contains("response.headers['content-length']"),
    );
    expect(githubResolverMethod, contains('response.bodyBytes.length'));
    expect(source, contains('update metadata limit'));
  });
}

Map<String, Object?> _feed(
  String version, {
  String? packageName,
  String? packageUrl,
  String? packageSha256,
}) {
  final name = packageName ?? 'Avorax-AntiVirus-$version.aup';
  return {
    'product': 'Avorax Anti-Virus',
    'channel': 'dev',
    'latest_version': version,
    'minimum_supported_version': '0.1.0',
    'packages': [
      {
        'version': version,
        'package_url': packageUrl ?? name,
        'package_sha256': packageSha256 ?? 'a' * 64,
        'release_notes': 'Test update',
        'published_at': '2026-05-31T12:00:00Z',
        'required': false,
        'critical': false,
        'rollback_supported': true,
      },
    ],
  };
}

class _FakePathProviderPlatform extends PathProviderPlatform {
  _FakePathProviderPlatform(this.temporaryPath);

  final String temporaryPath;

  @override
  Future<String?> getTemporaryPath() async => temporaryPath;
}

class _StreamingClient extends http.BaseClient {
  _StreamingClient(this._handler);

  final FutureOr<http.StreamedResponse> Function(http.BaseRequest request)
  _handler;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    return _handler(request);
  }
}

class _HangingClient extends http.BaseClient {
  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    return Completer<http.StreamedResponse>().future;
  }
}

Future<void> _replaceReservedPackageTempWithDirectory(
  Directory temporaryRoot,
) async {
  final tempFiles = temporaryRoot
      .listSync(recursive: true, followLinks: false)
      .whereType<File>()
      .where((file) => file.path.endsWith('.part'))
      .toList();
  expect(tempFiles, hasLength(1));
  final tempFile = tempFiles.single;
  await tempFile.delete();
  await Directory(tempFile.path).create();
}
