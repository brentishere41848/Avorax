// ignore_for_file: prefer_initializing_formals

import 'dart:convert';

import 'package:zentor_protocol/zentor_protocol.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'build_config.dart';

class ConfigRepository {
  ConfigRepository(
    this._preferences, {
    this.buildConfig = const BuildConfig(),
    Future<bool> Function(String key, String value)? debugSetString,
    Future<bool> Function(String key)? debugRemove,
  }) : _debugSetString = debugSetString,
       _debugRemove = debugRemove;

  static const _configKey = 'zentor.config.v1';
  static const _maxPersistedConfigJsonChars = 256 * 1024;
  static const _maxConfigRecoveryDiagnosticChars = 4096;

  final SharedPreferences _preferences;
  final BuildConfig buildConfig;
  final Future<bool> Function(String key, String value)? _debugSetString;
  final Future<bool> Function(String key)? _debugRemove;
  String? lastLoadRecoveryReason;

  ZentorConfig load() {
    lastLoadRecoveryReason = null;
    final raw = _preferences.getString(_configKey);
    if (raw == null || raw.isEmpty) {
      return _buildConfigDefaults();
    }
    if (raw.length > _maxPersistedConfigJsonChars) {
      lastLoadRecoveryReason =
          'Persisted config exceeded the size limit; build defaults were restored.';
      return _buildConfigDefaults();
    }
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map<String, Object?>) {
        lastLoadRecoveryReason =
            'Persisted config was not a JSON object; build defaults were restored.';
        return _buildConfigDefaults();
      }
      final stored = ZentorConfig.fromJson(decoded);
      if (stored.developerOverrideEnabled) {
        return stored;
      }
      return stored.copyWith(
        apiBaseUrl: buildConfig.apiBaseUrl,
        projectId: buildConfig.projectId,
        publicClientKey: buildConfig.publicClientKey,
      );
    } on Object catch (error) {
      lastLoadRecoveryReason =
          'Persisted config was invalid and build defaults were restored: ${_boundedConfigRecoveryDiagnostic(error)}';
      return _buildConfigDefaults();
    }
  }

  Future<void> save(ZentorConfig config) async {
    _validateConfigBeforeSave(config);
    final stored = await _setString(_configKey, jsonEncode(config.toJson()));
    if (!stored) {
      throw StateError(
        'Configuration save failed: SharedPreferences did not accept the persisted policy.',
      );
    }
  }

  Future<void> reset() async {
    final removed = await _remove(_configKey);
    if (!removed) {
      throw StateError(
        'Configuration reset failed: SharedPreferences did not remove the persisted policy.',
      );
    }
  }

  Future<bool> _setString(String key, String value) {
    return (_debugSetString ?? _preferences.setString)(key, value);
  }

  Future<bool> _remove(String key) {
    return (_debugRemove ?? _preferences.remove)(key);
  }

  void _validateConfigBeforeSave(ZentorConfig config) {
    if (!config.developerOverrideEnabled) return;
    final errors = config.validateCloudConfiguration();
    if (errors.isNotEmpty) {
      throw FormatException(
        'Developer cloud override is invalid: ${errors.join(' ')}',
      );
    }
  }

  ZentorConfig _buildConfigDefaults() => ZentorConfig(
    apiBaseUrl: buildConfig.apiBaseUrl,
    projectId: buildConfig.projectId,
    publicClientKey: buildConfig.publicClientKey,
  );

  String _boundedConfigRecoveryDiagnostic(Object error) {
    final text = '$error'.replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ').trim();
    if (text.isEmpty) return 'unknown error';
    if (text.length <= _maxConfigRecoveryDiagnosticChars) return text;
    return '${text.substring(0, _maxConfigRecoveryDiagnosticChars - 3)}...';
  }
}
