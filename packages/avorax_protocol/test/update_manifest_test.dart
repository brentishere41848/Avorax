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
        'package_id': 'avorax-0.2.32-win-x64',
        'requires_restart': true,
        'requires_reboot': false,
        'requires_admin': true,
        'driver_update_included': false,
        'rollback_supported': true,
        'payload_hashes': {
          'app/Avorax.exe': 'a' * 64,
          'engine/signatures.json': 'b' * 64,
        },
        'package_sha256': 'c' * 64,
        'signature_algorithm': 'ed25519',
        'public_key_id': 'avorax-prod-2026',
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
