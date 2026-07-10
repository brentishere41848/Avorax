// ignore_for_file: prefer_initializing_formals

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';
import 'package:zentor_protocol/zentor_protocol.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';

class LocalEventRepository {
  LocalEventRepository(
    this._preferences, {
    FutureOr<void> Function(File temp, File exportFile)?
    debugBeforeExportActivation,
    Future<bool> Function(String key, String value)? debugSetString,
    Future<bool> Function(String key)? debugRemove,
  }) : _debugBeforeExportActivation = debugBeforeExportActivation,
       _debugSetString = debugSetString,
       _debugRemove = debugRemove;

  static const _eventsKeyPrefix = 'zentor.local_events.v1';
  static const _allowedCategories = {
    'app',
    'protection',
    'scan',
    'update',
    'quarantine',
    'settings',
  };
  static const _allowedSeverities = {'info', 'warning', 'error'};
  static const _maxIdLength = 128;
  static const _maxTypeLength = 96;
  static const _maxMessageLength = 320;
  static const _maxDetailsLength = 4096;
  static const _maxTimestampLength = 64;
  static const _maxPersistedEventJsonChars = 1024 * 1024;
  static const _maxPersistedEventRows = 1000;
  static const _maxLocalEventExportJsonChars = 2 * 1024 * 1024;
  static const _maxStoredEvents = 200;
  static const _maxEventsHostKeySegmentLength = 128;
  static const _maxShareableExportRedactionDepth = 8;
  static const _shareableExportRedacted = '[redacted]';
  static const _uuid = Uuid();
  static final _eventControlTextPattern = RegExp(
    r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]',
  );
  static final _eventLineBreakTextPattern = RegExp(r'[\t\r\n]');
  static final _eventsHostKeyUnsafePattern = RegExp(r'[^a-z0-9._-]+');
  static final _shareableExportAuthorizationPattern = RegExp(
    r'\b(Authorization\s*[:=]\s*)(?:(?:Bearer|Basic|Digest|Negotiate|NTLM)\s+)?[A-Za-z0-9._~+/=-]{8,}',
    caseSensitive: false,
  );
  static final _shareableExportBearerPattern = RegExp(
    r'\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}',
    caseSensitive: false,
  );
  static final _shareableExportCookieHeaderPattern = RegExp(
    r'\b((?:Set-Cookie|Cookie)\s*[:=]\s*)[^;\s,]+(?:;\s*[^;\s,]+)*',
    caseSensitive: false,
  );
  static final _shareableExportUrlUserInfoPattern = RegExp(
    r'\b([a-z][a-z0-9+.-]*://)[^\s/@:]+:[^\s/@]+@',
    caseSensitive: false,
  );
  static final _shareableExportAssignmentSecretPattern = RegExp(
    r'''\b(password|passphrase|secret|access[_-]?token|refresh[_-]?token|session[_-]?id|session|token|api[_-]?key|client[_-]?key|public[_-]?client[_-]?key|publicClientKey|credential|cookie|set[_-]?cookie)\b(\s*[:=]\s*)["']?[^"'\s,;]+''',
    caseSensitive: false,
  );
  static final _shareableExportOpenAiKeyPattern = RegExp(
    r'\bsk-(?:proj-)?[A-Za-z0-9_-]{8,}\b',
  );
  static final _shareableExportGithubTokenPattern = RegExp(
    r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{12,}\b|github_pat_[A-Za-z0-9_]{12,}',
  );
  static final _shareableExportJwtPattern = RegExp(
    r'\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b',
  );

  String get _eventsKey =>
      '$_eventsKeyPrefix.${_eventsHostKeySegment(Platform.localHostname)}';

  final SharedPreferences _preferences;
  final FutureOr<void> Function(File temp, File exportFile)?
  _debugBeforeExportActivation;
  final Future<bool> Function(String key, String value)? _debugSetString;
  final Future<bool> Function(String key)? _debugRemove;
  final List<LocalEvent> _maintenanceEvents = [];

  List<LocalEvent> load() {
    final currentRaw = _preferences.getString(_eventsKey);
    if (currentRaw != null && currentRaw.isNotEmpty) {
      final recoveryReasons = <String>[];
      final events = _decodeEvents(
        currentRaw,
        recoveryReasons: recoveryReasons,
      );
      if (events != null) return _withMaintenanceEvents(events);
      _scheduleStorageRemoval(
        _eventsKey,
        'Current host local event history cleanup',
      );
      _recordRecoveryEvent(
        _decodeFailureDetails('Current host', recoveryReasons),
      );
      return _withMaintenanceEvents(const []);
    }

    if (_eventsKey != _eventsKeyPrefix) {
      final legacyRaw = _preferences.getString(_eventsKeyPrefix);
      if (legacyRaw != null && legacyRaw.isNotEmpty) {
        final recoveryReasons = <String>[];
        final events = _decodeEvents(
          legacyRaw,
          recoveryReasons: recoveryReasons,
        );
        if (events != null) {
          _scheduleLegacyMigration(events);
          return _withMaintenanceEvents(events);
        }
        _scheduleStorageRemoval(
          _eventsKeyPrefix,
          'Legacy local event history cleanup',
        );
        _recordRecoveryEvent(_decodeFailureDetails('Legacy', recoveryReasons));
        return _withMaintenanceEvents(const []);
      }
    }

    return _withMaintenanceEvents(const []);
  }

  List<LocalEvent> _withMaintenanceEvents(List<LocalEvent> events) {
    if (_maintenanceEvents.isEmpty) return events;
    return [..._maintenanceEvents, ...events].take(_maxStoredEvents).toList();
  }

  void _scheduleLegacyMigration(List<LocalEvent> events) {
    final encoded = jsonEncode(events.map((event) => event.toJson()).toList());
    _scheduleMaintenance(() async {
      final migrated = await _preferences.setString(_eventsKey, encoded);
      if (!migrated) {
        _recordMaintenanceFailure(
          'Legacy local event history migration failed: SharedPreferences did not accept the current-host event history.',
        );
        return;
      }
      final removed = await _preferences.remove(_eventsKeyPrefix);
      if (!removed) {
        _recordMaintenanceFailure(
          'Legacy local event history cleanup failed: SharedPreferences did not remove the legacy event history.',
        );
      }
    });
  }

  void _scheduleStorageRemoval(String key, String operation) {
    _scheduleMaintenance(() async {
      final removed = await _preferences.remove(key);
      if (!removed) {
        _recordMaintenanceFailure(
          '$operation failed: SharedPreferences did not remove the invalid event history.',
        );
      }
    });
  }

  void _scheduleMaintenance(Future<void> Function() operation) {
    unawaited(
      operation().catchError((Object error) {
        _recordMaintenanceFailure(
          'Local event history maintenance failed: ${_boundedDiagnosticText(error)}',
        );
      }),
    );
  }

  void _recordMaintenanceFailure(String details) {
    _recordRecoveryEvent(details);
  }

  void _recordRecoveryEvent(String details) {
    _maintenanceEvents.insert(0, _localEventHistoryRecoveryEvent(details));
    if (_maintenanceEvents.length > _maxStoredEvents) {
      _maintenanceEvents.removeRange(
        _maxStoredEvents,
        _maintenanceEvents.length,
      );
    }
  }

  LocalEvent _localEventHistoryRecoveryEvent(String details) {
    return LocalEvent(
      id: _uuid.v4(),
      type: 'local_event_history_recovered',
      message: 'Local event history was reset',
      createdAt: DateTime.now().toUtc(),
      details: details,
      category: 'app',
      severity: 'warning',
    );
  }

  String _decodeFailureDetails(String scope, List<String> recoveryReasons) {
    final reason = recoveryReasons.isEmpty
        ? 'persisted data was malformed or oversized.'
        : recoveryReasons.take(3).join('; ');
    return _truncate(
      '$scope local event history was reset: $reason',
      _maxDetailsLength,
    );
  }

  List<LocalEvent>? _decodeEvents(String raw, {List<String>? recoveryReasons}) {
    if (raw.length > _maxPersistedEventJsonChars) {
      recoveryReasons?.add('persisted JSON exceeded the size limit.');
      return null;
    }
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! List) {
        recoveryReasons?.add('persisted JSON root was not a list.');
        return null;
      }
      if (decoded.length > _maxPersistedEventRows) {
        recoveryReasons?.add(
          'persisted JSON contained too many event records.',
        );
        return null;
      }
      var malformedRecords = 0;
      final malformedRecordReasons = <String>[];
      final events = <LocalEvent>[];
      for (var index = 0; index < decoded.length; index++) {
        final event = _eventFromPersisted(
          decoded[index],
          index: index,
          malformedReasons: malformedRecordReasons,
        );
        if (event == null) {
          malformedRecords++;
          continue;
        }
        events.add(event);
      }
      events.sort((a, b) => b.createdAt.compareTo(a.createdAt));
      if (malformedRecords == 0) return events.take(_maxStoredEvents).toList();
      final plural = malformedRecords == 1 ? 'record' : 'records';
      final reasonDetails = malformedRecordReasons.isEmpty
          ? ''
          : ': ${malformedRecordReasons.take(3).join('; ')}';
      final message =
          'Ignored $malformedRecords malformed local event history $plural during recovery$reasonDetails.';
      return [
        _localEventHistoryRecoveryEvent(_truncate(message, _maxDetailsLength)),
        ...events,
      ].take(_maxStoredEvents).toList();
    } on Object catch (error) {
      // Local event history is audit evidence, but corrupt persisted UI
      // history must not block startup, scans, or quarantine actions.
      recoveryReasons?.add(
        'persisted JSON could not be decoded: ${_boundedDiagnosticText(error)}',
      );
      return null;
    }
  }

  Future<LocalEvent> add(
    String type,
    String message, {
    String? details,
    String category = 'app',
    String severity = 'info',
  }) async {
    final normalizedType = _boundedRequiredText(
      type,
      fieldName: 'type',
      maxLength: _maxTypeLength,
    );
    final normalizedMessage = _boundedRequiredText(
      message,
      fieldName: 'message',
      maxLength: _maxMessageLength,
    );
    final event = LocalEvent(
      id: _uuid.v4(),
      type: normalizedType,
      message: normalizedMessage,
      createdAt: DateTime.now().toUtc(),
      details: _boundedOptionalText(
        details,
        fieldName: 'details',
        maxLength: _maxDetailsLength,
      ),
      category: _requiredAllowedValue(
        category,
        fieldName: 'category',
        allowed: _allowedCategories,
      ),
      severity: _requiredAllowedValue(
        severity,
        fieldName: 'severity',
        allowed: _allowedSeverities,
      ),
    );
    final events = [event, ...load()].take(_maxStoredEvents).toList();
    final stored = await _setString(
      _eventsKey,
      jsonEncode(events.map((event) => event.toJson()).toList()),
    );
    if (!stored) {
      throw StateError(
        'Local event history write failed: SharedPreferences did not accept the event history.',
      );
    }
    _maintenanceEvents.clear();
    return event;
  }

  Future<void> clear() async {
    final removed = await _remove(_eventsKey);
    if (!removed) {
      throw StateError(
        'Local event history clear failed: SharedPreferences did not remove the event history.',
      );
    }
  }

  Future<bool> _setString(String key, String value) {
    return (_debugSetString ?? _preferences.setString)(key, value);
  }

  Future<bool> _remove(String key) {
    return (_debugRemove ?? _preferences.remove)(key);
  }

  Future<File> export() async {
    final directory = await getApplicationDocumentsDirectory();
    final file = File(
      '${directory.path}${Platform.pathSeparator}zentor-local-events.json',
    );
    _rejectUnsafeExportTarget(file.path);
    final body = const JsonEncoder.withIndent('  ').convert(
      load()
          .map((event) => _redactShareableExportValue(event.toJson()))
          .toList(),
    );
    await _writeJsonExportAtomically(file, body);
    return file;
  }

  Future<File> exportSupportBundle({
    required Map<String, Object?> diagnostics,
  }) async {
    final directory = await getApplicationDocumentsDirectory();
    final file = File(
      '${directory.path}${Platform.pathSeparator}avorax-support-bundle.json',
    );
    _rejectUnsafeExportTarget(file.path);
    final body = const JsonEncoder.withIndent('  ').convert({
      'schema_version': 1,
      'generated_at_utc': DateTime.now().toUtc().toIso8601String(),
      'privacy': const {
        'contains_file_contents': false,
        'contains_quarantine_payloads': false,
        'contains_live_malware': false,
        'contains_credentials': false,
        'credential_redaction_applied': true,
        'redacted_value_marker': _shareableExportRedacted,
        'includes_local_file_paths_from_events': true,
        'manual_review_required_before_sharing': true,
      },
      'diagnostics': _redactShareableExportValue(diagnostics),
      'events': load()
          .map((event) => _redactShareableExportValue(event.toJson()))
          .toList(),
    });
    await _writeJsonExportAtomically(file, body);
    return file;
  }

  Object? _redactShareableExportValue(
    Object? value, {
    String? key,
    int depth = 0,
  }) {
    if (_isSensitiveShareableExportKey(key)) {
      return value == null ? null : _shareableExportRedacted;
    }
    if (depth >= _maxShareableExportRedactionDepth) {
      return _shareableExportRedacted;
    }
    if (value is Map) {
      return <String, Object?>{
        for (final entry in value.entries)
          entry.key.toString(): _redactShareableExportValue(
            entry.value,
            key: entry.key.toString(),
            depth: depth + 1,
          ),
      };
    }
    if (value is List) {
      return value
          .map((item) => _redactShareableExportValue(item, depth: depth + 1))
          .toList();
    }
    if (value is String) return _redactShareableExportText(value);
    if (value == null || value is num || value is bool) return value;
    return _redactShareableExportText(value.toString());
  }

  bool _isSensitiveShareableExportKey(String? key) {
    if (key == null) return false;
    final normalized = key.toLowerCase().replaceAll(RegExp(r'[^a-z0-9]+'), '');
    return normalized.contains('authorization') ||
        normalized.contains('password') ||
        normalized.contains('passphrase') ||
        normalized.contains('secret') ||
        normalized.contains('cookie') ||
        normalized.contains('session') ||
        normalized.contains('token') ||
        normalized.contains('apikey') ||
        normalized.contains('clientkey') ||
        normalized.contains('publicclientkey') ||
        normalized.contains('credential');
  }

  String _redactShareableExportText(String value) {
    var redacted = value.replaceAllMapped(
      _shareableExportAuthorizationPattern,
      (match) => '${match.group(1)}$_shareableExportRedacted',
    );
    redacted = redacted.replaceAllMapped(
      _shareableExportBearerPattern,
      (match) => '${match.group(1)} $_shareableExportRedacted',
    );
    redacted = redacted.replaceAllMapped(
      _shareableExportCookieHeaderPattern,
      (match) => '${match.group(1)}$_shareableExportRedacted',
    );
    redacted = redacted.replaceAllMapped(
      _shareableExportUrlUserInfoPattern,
      (match) => '${match.group(1)}$_shareableExportRedacted@',
    );
    redacted = redacted.replaceAllMapped(
      _shareableExportAssignmentSecretPattern,
      (match) {
        return '${match.group(1)}${match.group(2)}$_shareableExportRedacted';
      },
    );
    redacted = redacted.replaceAll(
      _shareableExportOpenAiKeyPattern,
      _shareableExportRedacted,
    );
    redacted = redacted.replaceAll(
      _shareableExportGithubTokenPattern,
      _shareableExportRedacted,
    );
    redacted = redacted.replaceAll(
      _shareableExportJwtPattern,
      _shareableExportRedacted,
    );
    return redacted;
  }

  Future<void> _writeJsonExportAtomically(File file, String body) async {
    _rejectOversizedExportBody(body);
    final temp = await _temporaryExportFile(file);
    try {
      await _writeLocalEventExportTempFile(temp, body);
      await _debugBeforeExportActivation?.call(temp, file);
      _rejectUnsafeExportTarget(file.path);
      await temp.rename(file.path);
    } on Object catch (error, stackTrace) {
      try {
        await _deleteTemporaryExportFile(temp);
      } on Object catch (cleanupError) {
        Error.throwWithStackTrace(
          StateError(
            'Local event export failed and temporary export cleanup also failed. '
            'Original error: ${_boundedDiagnosticText(error)}. '
            'Cleanup error: ${_boundedDiagnosticText(cleanupError)}',
          ),
          stackTrace,
        );
      }
      Error.throwWithStackTrace(error, stackTrace);
    }
  }

  Future<File> _temporaryExportFile(File file) async {
    for (var attempt = 0; attempt < 16; attempt += 1) {
      final path =
          '${file.path}.${DateTime.now().microsecondsSinceEpoch}.$attempt.tmp';
      final type = FileSystemEntity.typeSync(path, followLinks: false);
      if (type == FileSystemEntityType.file) {
        continue;
      }
      if (type != FileSystemEntityType.notFound) {
        throw StateError('Temporary local event export path was unsafe.');
      }
      final temp = File(path);
      try {
        await temp.create(exclusive: true);
        return temp;
      } on FileSystemException catch (error) {
        final racedType = FileSystemEntity.typeSync(path, followLinks: false);
        if (racedType == FileSystemEntityType.file) {
          continue;
        }
        if (racedType != FileSystemEntityType.notFound) {
          throw StateError('Temporary local event export path became unsafe.');
        }
        throw FileSystemException(
          'Failed to reserve temporary local event export path: '
          '${_boundedDiagnosticText(error)}',
          path,
        );
      }
    }
    throw StateError('Unable to allocate a temporary local event export path.');
  }

  Future<void> _writeLocalEventExportTempFile(File temp, String body) async {
    _rejectOversizedExportBody(body);
    final type = FileSystemEntity.typeSync(temp.path, followLinks: false);
    if (type != FileSystemEntityType.file) {
      throw StateError('Temporary local event export output was unsafe.');
    }
    final output = await temp.open(mode: FileMode.write);
    try {
      await output.truncate(0);
      await output.writeString(body);
      await output.flush();
    } finally {
      await output.close();
    }
    final writtenType = FileSystemEntity.typeSync(
      temp.path,
      followLinks: false,
    );
    if (writtenType != FileSystemEntityType.file) {
      throw StateError('Temporary local event export output became unsafe.');
    }
  }

  void _rejectOversizedExportBody(String body) {
    if (body.length > _maxLocalEventExportJsonChars) {
      throw StateError('Local event export body exceeded the size limit.');
    }
  }

  String _eventsHostKeySegment(String hostName) {
    final normalized = hostName
        .toLowerCase()
        .replaceAll(_eventsHostKeyUnsafePattern, '-')
        .replaceAll(RegExp(r'-+'), '-')
        .replaceAll(RegExp(r'^[._-]+|[._-]+$'), '');
    if (normalized.isEmpty) return 'unknown-host';
    if (normalized.length <= _maxEventsHostKeySegmentLength) {
      return normalized;
    }
    return normalized.substring(0, _maxEventsHostKeySegmentLength);
  }

  Future<void> _deleteTemporaryExportFile(File temp) async {
    final type = FileSystemEntity.typeSync(temp.path, followLinks: false);
    if (type == FileSystemEntityType.notFound) return;
    if (type != FileSystemEntityType.file) {
      throw StateError(
        'Temporary local event export cleanup target was unsafe.',
      );
    }
    await temp.delete();
  }

  void _rejectUnsafeExportTarget(String path) {
    final type = FileSystemEntity.typeSync(path, followLinks: false);
    if (type == FileSystemEntityType.notFound ||
        type == FileSystemEntityType.file) {
      return;
    }
    throw FileSystemException(
      'Refusing to write local event export through unsafe target',
      path,
    );
  }

  LocalEvent? _eventFromPersisted(
    Object? item, {
    required int index,
    List<String>? malformedReasons,
  }) {
    if (item is! Map) {
      malformedReasons?.add('record $index was not a JSON object');
      return null;
    }
    try {
      final event = _eventFromJson(Map<String, Object?>.from(item));
      if (event == null) {
        malformedReasons?.add(
          'record $index was missing required id, type, message, '
          'or timestamp fields',
        );
      }
      return event;
    } on Object catch (error) {
      malformedReasons?.add(
        'record $index could not be decoded: ${_boundedDiagnosticText(error)}',
      );
      return null;
    }
  }

  LocalEvent? _eventFromJson(Map<String, Object?> json) {
    final id = _boundedPersistedRequiredText(
      json['id'],
      fieldName: 'id',
      maxLength: _maxIdLength,
    );
    final type = _boundedPersistedRequiredText(
      json['type'],
      fieldName: 'type',
      maxLength: _maxTypeLength,
    );
    final message = _boundedPersistedRequiredText(
      json['message'],
      fieldName: 'message',
      maxLength: _maxMessageLength,
    );
    final createdAt = _dateTime(json['createdAt'], fieldName: 'createdAt');
    final category = _allowedValue(
      json['category'],
      fieldName: 'category',
      allowed: _allowedCategories,
      fallback: 'app',
    );
    final severity = _allowedValue(
      json['severity'],
      fieldName: 'severity',
      allowed: _allowedSeverities,
      fallback: 'info',
    );
    if (id == null || type == null || message == null || createdAt == null) {
      return null;
    }
    return LocalEvent(
      id: id,
      type: type,
      message: message,
      createdAt: createdAt,
      details: _boundedPersistedOptionalText(
        json['details'] is String ? json['details'] as String : null,
        fieldName: 'details',
        maxLength: _maxDetailsLength,
      ),
      category: category,
      severity: severity,
    );
  }

  String _boundedRequiredText(
    String value, {
    required String fieldName,
    required int maxLength,
  }) {
    _rejectControlText(value, fieldName: fieldName);
    final trimmed = value.trim();
    if (trimmed.isEmpty) {
      throw ArgumentError.value(value, fieldName, 'must not be empty');
    }
    return _truncate(trimmed, maxLength);
  }

  String? _boundedOptionalText(
    String? value, {
    required String fieldName,
    required int maxLength,
  }) {
    if (value == null) return null;
    _rejectControlText(value, fieldName: fieldName, allowMultiline: true);
    final trimmed = value.trim();
    if (trimmed.isEmpty) return null;
    return _truncate(trimmed, maxLength);
  }

  String? _boundedPersistedRequiredText(
    Object? value, {
    required String fieldName,
    required int maxLength,
  }) {
    if (value is! String) return null;
    final trimmed = _trimPersistedText(
      value,
      fieldName: fieldName,
      maxLength: maxLength,
    );
    if (trimmed.isEmpty) return null;
    return trimmed;
  }

  String? _boundedPersistedOptionalText(
    String? value, {
    required String fieldName,
    required int maxLength,
  }) {
    if (value == null) return null;
    final trimmed = _trimPersistedText(
      value,
      fieldName: fieldName,
      maxLength: maxLength,
      allowMultiline: true,
    );
    if (trimmed.isEmpty) return null;
    return trimmed;
  }

  String _trimPersistedText(
    String value, {
    required String fieldName,
    required int maxLength,
    bool allowMultiline = false,
  }) {
    _rejectControlText(
      value,
      fieldName: fieldName,
      allowMultiline: allowMultiline,
    );
    final trimmed = value.trim();
    if (trimmed.length > maxLength) {
      throw ArgumentError.value(
        value,
        fieldName,
        'must be at most $maxLength characters',
      );
    }
    return trimmed;
  }

  String _boundedDiagnosticText(Object error) {
    final text = error
        .toString()
        .replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ')
        .trim();
    if (text.isEmpty) return 'unknown error';
    return _truncate(text, _maxDetailsLength);
  }

  String _truncate(String value, int maxLength) {
    if (value.length <= maxLength) return value;
    return value.substring(0, maxLength);
  }

  DateTime? _dateTime(Object? value, {required String fieldName}) {
    if (value is! String) return null;
    _rejectControlText(value, fieldName: fieldName);
    final trimmed = value.trim();
    if (trimmed.isEmpty || trimmed.length > _maxTimestampLength) return null;
    return DateTime.tryParse(trimmed);
  }

  String _requiredAllowedValue(
    String value, {
    required String fieldName,
    required Set<String> allowed,
  }) {
    _rejectControlText(value, fieldName: fieldName);
    final trimmed = value.trim();
    if (allowed.contains(trimmed)) return trimmed;
    throw ArgumentError.value(
      value,
      fieldName,
      'must be one of ${allowed.join(', ')}',
    );
  }

  String _allowedValue(
    Object? value, {
    required String fieldName,
    required Set<String> allowed,
    required String fallback,
  }) {
    if (value is String) {
      _rejectControlText(value, fieldName: fieldName);
      final trimmed = value.trim();
      if (allowed.contains(trimmed)) return trimmed;
    }
    return fallback;
  }

  void _rejectControlText(
    String value, {
    required String fieldName,
    bool allowMultiline = false,
  }) {
    if (_eventControlTextPattern.hasMatch(value) ||
        (!allowMultiline && _eventLineBreakTextPattern.hasMatch(value))) {
      throw ArgumentError.value(
        value,
        fieldName,
        'must not contain control characters',
      );
    }
  }
}
