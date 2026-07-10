class AvoraxUpdateManifest {
  const AvoraxUpdateManifest({
    required this.product,
    required this.packageFormatVersion,
    required this.version,
    required this.previousMinVersion,
    required this.channel,
    required this.packageId,
    required this.requiresRestart,
    required this.requiresReboot,
    required this.requiresAdmin,
    required this.driverUpdateIncluded,
    required this.rollbackSupported,
    required this.payloadHashes,
    required this.packageSha256,
    required this.signatureAlgorithm,
    required this.publicKeyId,
  });

  factory AvoraxUpdateManifest.fromJson(Map<String, Object?> json) {
    _rejectUnknownFields(json);
    return AvoraxUpdateManifest(
      product: _stringField(json, 'product'),
      packageFormatVersion: _intField(json, 'package_format_version'),
      version: _stringField(json, 'version'),
      previousMinVersion: _stringField(json, 'previous_min_version'),
      channel: _stringField(json, 'channel'),
      packageId: _stringField(json, 'package_id'),
      requiresRestart: _boolField(json, 'requires_restart', fallback: true),
      requiresReboot: _boolField(json, 'requires_reboot'),
      requiresAdmin: _boolField(json, 'requires_admin', fallback: true),
      driverUpdateIncluded: _boolField(json, 'driver_update_included'),
      rollbackSupported: _boolField(json, 'rollback_supported'),
      payloadHashes: _payloadHashes(json['payload_hashes']),
      packageSha256: _stringField(json, 'package_sha256'),
      signatureAlgorithm: _stringField(json, 'signature_algorithm'),
      publicKeyId: _stringField(json, 'public_key_id'),
    );
  }

  final String product;
  final int packageFormatVersion;
  final String version;
  final String previousMinVersion;
  final String channel;
  final String packageId;
  final bool requiresRestart;
  final bool requiresReboot;
  final bool requiresAdmin;
  final bool driverUpdateIncluded;
  final bool rollbackSupported;
  final Map<String, String> payloadHashes;
  final String packageSha256;
  final String signatureAlgorithm;
  final String publicKeyId;

  static const Set<String> _knownFields = {
    'product',
    'package_format_version',
    'version',
    'previous_min_version',
    'channel',
    'release_date',
    'package_id',
    'components',
    'requires_restart',
    'requires_reboot',
    'requires_admin',
    'driver_update_included',
    'migration_steps',
    'rollback_supported',
    'payload_hashes',
    'package_sha256',
    'signature_algorithm',
    'public_key_id',
    'release_notes_url',
  };

  Map<String, Object?> toJson() {
    return {
      'product': product,
      'package_format_version': packageFormatVersion,
      'version': version,
      'previous_min_version': previousMinVersion,
      'channel': channel,
      'package_id': packageId,
      'requires_restart': requiresRestart,
      'requires_reboot': requiresReboot,
      'requires_admin': requiresAdmin,
      'driver_update_included': driverUpdateIncluded,
      'rollback_supported': rollbackSupported,
      'payload_hashes': Map<String, String>.from(payloadHashes),
      'package_sha256': packageSha256,
      'signature_algorithm': signatureAlgorithm,
      'public_key_id': publicKeyId,
    };
  }

  static String _stringField(
    Map<String, Object?> json,
    String fieldName, {
    String fallback = '',
  }) {
    final value = json[fieldName];
    if (value == null) return fallback;
    if (value is String) return value;
    throw FormatException('update manifest field $fieldName must be a string');
  }

  static int _intField(
    Map<String, Object?> json,
    String fieldName, {
    int fallback = 0,
  }) {
    final value = json[fieldName];
    if (value == null) return fallback;
    if (value is int) return value;
    throw FormatException(
      'update manifest field $fieldName must be an integer',
    );
  }

  static bool _boolField(
    Map<String, Object?> json,
    String fieldName, {
    bool fallback = false,
  }) {
    final value = json[fieldName];
    if (value == null) return fallback;
    if (value is bool) return value;
    throw FormatException('update manifest field $fieldName must be a boolean');
  }

  static Map<String, String> _payloadHashes(Object? value) {
    if (value == null) return const {};
    if (value is! Map) {
      throw const FormatException(
        'update manifest field payload_hashes must be an object',
      );
    }
    final hashes = <String, String>{};
    for (final entry in value.entries) {
      if (entry.key is! String || (entry.key as String).trim().isEmpty) {
        throw const FormatException(
          'update manifest payload_hashes contains a malformed key',
        );
      }
      if (entry.value is! String || (entry.value as String).trim().isEmpty) {
        throw const FormatException(
          'update manifest payload_hashes contains a malformed value',
        );
      }
      hashes[entry.key as String] = entry.value as String;
    }
    return hashes;
  }

  static void _rejectUnknownFields(Map<String, Object?> json) {
    for (final key in json.keys) {
      if (!_knownFields.contains(key)) {
        throw FormatException('update manifest contains unknown field $key');
      }
    }
  }
}
