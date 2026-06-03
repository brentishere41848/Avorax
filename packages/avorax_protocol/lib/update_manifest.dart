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
    return AvoraxUpdateManifest(
      product: json['product'] as String? ?? '',
      packageFormatVersion: json['package_format_version'] as int? ?? 0,
      version: json['version'] as String? ?? '',
      previousMinVersion: json['previous_min_version'] as String? ?? '',
      channel: json['channel'] as String? ?? '',
      packageId: json['package_id'] as String? ?? '',
      requiresRestart: json['requires_restart'] as bool? ?? true,
      requiresReboot: json['requires_reboot'] as bool? ?? false,
      requiresAdmin: json['requires_admin'] as bool? ?? true,
      driverUpdateIncluded: json['driver_update_included'] as bool? ?? false,
      rollbackSupported: json['rollback_supported'] as bool? ?? false,
      payloadHashes: (json['payload_hashes'] as Map? ?? {}).map(
        (key, value) => MapEntry(key.toString(), value.toString()),
      ),
      packageSha256: json['package_sha256'] as String? ?? '',
      signatureAlgorithm: json['signature_algorithm'] as String? ?? '',
      publicKeyId: json['public_key_id'] as String? ?? '',
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
}
