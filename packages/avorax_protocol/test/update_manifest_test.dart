import 'dart:io';

import 'package:avorax_protocol/avorax_protocol.dart';
import 'package:test/test.dart';

void main() {
  group('AvoraxUpdateManifest', () {
    test('parses a signed update manifest schema used by .aup packages', () {
      final manifest = AvoraxUpdateManifest.fromJson({
        'product': 'Avorax',
        'package_format_version': 1,
        'version': '0.2.32',
        'previous_min_version': '0.2.31',
        'channel': 'stable',
        'release_date': '2026-06-25T00:00:00Z',
        'package_id': 'avorax-0.2.32-win-x64',
        'components': {
          'app': true,
          'core_service': true,
          'guard_service': true,
          'update_service': false,
          'native_engine_assets': true,
          'signatures': true,
          'rules': true,
          'ml_model': true,
          'trust_packs': true,
          'docs': true,
          'driver_tools': false,
        },
        'requires_restart': true,
        'requires_reboot': false,
        'requires_admin': true,
        'driver_update_included': false,
        'migration_steps': [],
        'rollback_supported': true,
        'payload_hashes': {
          'app/Avorax.exe': 'a' * 64,
          'engine/signatures.json': 'b' * 64,
        },
        'package_sha256': 'c' * 64,
        'signature_algorithm': 'ed25519',
        'public_key_id': 'avorax-prod-2026',
        'release_notes_url': null,
      });

      expect(manifest.product, 'Avorax');
      expect(manifest.packageFormatVersion, 1);
      expect(manifest.version, '0.2.32');
      expect(manifest.previousMinVersion, '0.2.31');
      expect(manifest.channel, 'stable');
      expect(manifest.packageId, 'avorax-0.2.32-win-x64');
      expect(manifest.requiresRestart, isTrue);
      expect(manifest.requiresReboot, isFalse);
      expect(manifest.requiresAdmin, isTrue);
      expect(manifest.driverUpdateIncluded, isFalse);
      expect(manifest.rollbackSupported, isTrue);
      expect(manifest.payloadHashes, {
        'app/Avorax.exe': 'a' * 64,
        'engine/signatures.json': 'b' * 64,
      });
      expect(manifest.packageSha256, 'c' * 64);
      expect(manifest.signatureAlgorithm, 'ed25519');
      expect(manifest.publicKeyId, 'avorax-prod-2026');
    });

    test('uses conservative defaults for missing optional fields', () {
      final manifest = AvoraxUpdateManifest.fromJson({});

      expect(manifest.product, isEmpty);
      expect(manifest.packageFormatVersion, 0);
      expect(manifest.requiresRestart, isTrue);
      expect(manifest.requiresReboot, isFalse);
      expect(manifest.requiresAdmin, isTrue);
      expect(manifest.driverUpdateIncluded, isFalse);
      expect(manifest.rollbackSupported, isFalse);
      expect(manifest.payloadHashes, isEmpty);
    });

    test('rejects malformed supplied fields instead of silent defaults', () {
      expect(
        () => AvoraxUpdateManifest.fromJson({'product': 42}),
        throwsFormatException,
      );
      expect(
        () => AvoraxUpdateManifest.fromJson({'package_format_version': '1'}),
        throwsFormatException,
      );
      expect(
        () => AvoraxUpdateManifest.fromJson({'requires_restart': 'true'}),
        throwsFormatException,
      );
      expect(
        () => AvoraxUpdateManifest.fromJson({'payload_hashes': []}),
        throwsFormatException,
      );
      expect(
        () => AvoraxUpdateManifest.fromJson({
          'payload_hashes': {42: 'a' * 64},
        }),
        throwsFormatException,
      );
      expect(
        () => AvoraxUpdateManifest.fromJson({
          'payload_hashes': {'app/Avorax.exe': 42},
        }),
        throwsFormatException,
      );
    });

    test(
      'rejects unknown supplied fields instead of silently ignoring them',
      () {
        expect(
          () => AvoraxUpdateManifest.fromJson({
            'product': 'Avorax',
            'install_script': 'run.ps1',
          }),
          throwsFormatException,
        );
      },
    );

    test('source marker: malformed supplied manifest fields fail visibly', () {
      final source = File('lib/update_manifest.dart').readAsStringSync();

      expect(source, contains('static const Set<String> _knownFields'));
      expect(source, contains('_rejectUnknownFields(json);'));
      expect(source, contains('update manifest contains unknown field'));
      expect(source, contains("'release_date'"));
      expect(source, contains("'components'"));
      expect(source, contains("'migration_steps'"));
      expect(source, contains("'release_notes_url'"));
      expect(source, contains('static String _stringField'));
      expect(source, contains('static int _intField'));
      expect(source, contains('static bool _boolField'));
      expect(source, contains('static Map<String, String> _payloadHashes'));
      expect(source, contains(r'update manifest field $fieldName must be'));
      expect(source, contains('payload_hashes contains a malformed key'));
      expect(source, contains('payload_hashes contains a malformed value'));
      expect(source, isNot(contains("json['product'] as String? ?? ''")));
      expect(
        source,
        isNot(contains("json['package_format_version'] as int? ?? 0")),
      );
      expect(source, isNot(contains("json['payload_hashes'] as Map? ?? {}")));
      expect(source, isNot(contains('value.toString()')));
      expect(source, isNot(contains('install_script')));
    });

    test('serializes with exact wire keys for verifier/app compatibility', () {
      final manifest = AvoraxUpdateManifest(
        product: 'Avorax',
        packageFormatVersion: 1,
        version: '0.2.32',
        previousMinVersion: '0.2.31',
        channel: 'stable',
        packageId: 'avorax-0.2.32-win-x64',
        requiresRestart: true,
        requiresReboot: false,
        requiresAdmin: true,
        driverUpdateIncluded: false,
        rollbackSupported: true,
        payloadHashes: {'app/Avorax.exe': 'a' * 64},
        packageSha256: 'c' * 64,
        signatureAlgorithm: 'ed25519',
        publicKeyId: 'avorax-prod-2026',
      );

      expect(manifest.toJson(), {
        'product': 'Avorax',
        'package_format_version': 1,
        'version': '0.2.32',
        'previous_min_version': '0.2.31',
        'channel': 'stable',
        'package_id': 'avorax-0.2.32-win-x64',
        'requires_restart': true,
        'requires_reboot': false,
        'requires_admin': true,
        'driver_update_included': false,
        'rollback_supported': true,
        'payload_hashes': {'app/Avorax.exe': 'a' * 64},
        'package_sha256': 'c' * 64,
        'signature_algorithm': 'ed25519',
        'public_key_id': 'avorax-prod-2026',
      });
    });
  });
}
