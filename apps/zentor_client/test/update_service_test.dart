import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:zentor_client/core/config/build_config.dart';
import 'package:zentor_client/core/updates/update_service.dart';

void main() {
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
    expect(result.error, contains('No .aup package'));
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
}

Map<String, Object?> _feed(String version, {String? packageName}) {
  final name = packageName ?? 'Avorax-AntiVirus-$version.aup';
  return {
    'product': 'Avorax Anti-Virus',
    'channel': 'dev',
    'latest_version': version,
    'minimum_supported_version': '0.1.0',
    'packages': [
      {
        'version': version,
        'package_url': name,
        'package_sha256': 'a' * 64,
        'release_notes': 'Test update',
        'published_at': '2026-05-31T12:00:00Z',
        'required': false,
        'critical': false,
        'rollback_supported': true,
      },
    ],
  };
}
