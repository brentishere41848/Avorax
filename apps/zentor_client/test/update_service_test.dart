import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:zentor_client/core/config/build_config.dart';
import 'package:zentor_client/core/updates/update_service.dart';

void main() {
  test('detects newer GitHub release and selects installer asset', () async {
    final service = ZentorUpdateService(
      buildConfig: const BuildConfig(
        updatesRepoOwner: 'owner',
        updatesRepoName: 'repo',
      ),
      client: MockClient((request) async {
        expect(request.url.path, '/repos/owner/repo/releases');
        return http.Response(
          jsonEncode([
            _release('v0.1.15', assets: ['Avorax-0.1.15-x64-setup.exe']),
            _release('v0.1.14', assets: ['Avorax-0.1.14-x64-setup.exe']),
          ]),
          200,
        );
      }),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.updateAvailable);
    expect(result.update?.latestVersion, '0.1.15');
    expect(result.update?.assetName, 'Avorax-0.1.15-x64-setup.exe');
  });

  test(
    'returns up to date when installed version matches latest release',
    () async {
      final service = ZentorUpdateService(
        client: MockClient((request) async {
          return http.Response(jsonEncode([_release('v0.1.14')]), 200);
        }),
      );

      final result = await service.checkForUpdate(currentVersion: '0.1.14');

      expect(result.status, UpdateStatus.upToDate);
      expect(result.update, isNull);
    },
  );

  test('does not fake success when GitHub check fails', () async {
    final service = ZentorUpdateService(
      client: MockClient((request) async => http.Response('rate limited', 403)),
    );

    final result = await service.checkForUpdate(currentVersion: '0.1.14');

    expect(result.status, UpdateStatus.failed);
    expect(result.error, contains('HTTP 403'));
  });
}

Map<String, Object?> _release(String tag, {List<String> assets = const []}) {
  return {
    'tag_name': tag,
    'html_url': 'https://github.com/owner/repo/releases/tag/$tag',
    'draft': false,
    'published_at': '2026-05-27T12:00:00Z',
    'assets': [
      for (final asset in assets)
        {
          'name': asset,
          'browser_download_url':
              'https://github.com/owner/repo/releases/download/$tag/$asset',
        },
    ],
  };
}
