import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:path_provider_platform_interface/path_provider_platform_interface.dart';
import 'package:zentor_client/app/app_state.dart';
import 'package:zentor_client/core/apps/app_detector.dart';
import 'package:zentor_client/core/config/config_repository.dart';
import 'package:zentor_client/core/local_core/local_core_client.dart';
import 'package:zentor_client/core/logging/local_event_repository.dart';
import 'package:zentor_client/core/network/zentor_api_client.dart';
import 'package:zentor_client/core/scanning/scan_target_service.dart';
import 'package:zentor_client/core/security/hash_service.dart';
import 'package:zentor_client/core/updates/update_service.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

String get _currentEventKey =>
    'zentor.local_events.v1.${_hostKeySegment(Platform.localHostname)}';

String _hostKeySegment(String hostName) {
  final normalized = hostName
      .toLowerCase()
      .replaceAll(RegExp(r'[^a-z0-9._-]+'), '-')
      .replaceAll(RegExp(r'-+'), '-')
      .replaceAll(RegExp(r'^[._-]+|[._-]+$'), '');
  if (normalized.isEmpty) return 'unknown-host';
  if (normalized.length <= 128) return normalized;
  return normalized.substring(0, 128);
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('local event creation persists a real app event', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final event = await repository.add('app_started', 'App started');

    expect(event.type, 'app_started');
    expect(repository.load(), hasLength(1));
    expect(repository.load().single.message, 'App started');
  });

  test('local event writes check SharedPreferences acknowledgement', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();
    final addMethod = source.substring(
      source.indexOf('Future<LocalEvent> add('),
      source.indexOf('Future<void> clear()'),
    );

    expect(addMethod, contains('final stored = await _setString'));
    expect(addMethod, contains('if (!stored)'));
    expect(
      addMethod,
      contains(
        'Local event history write failed: SharedPreferences did not accept the event history.',
      ),
    );
    expect(addMethod, isNot(contains('\n    await _preferences.setString(')));
  });

  test('local event write rejection fails visibly at runtime', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(
      preferences,
      debugSetString: (_, _) async => false,
    );

    await expectLater(
      repository.add('app_started', 'App started'),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          contains('Local event history write failed'),
        ),
      ),
    );
    expect(repository.load(), isEmpty);
  });

  test('local event clear checks SharedPreferences acknowledgement', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();
    final clearMethod = source.substring(
      source.indexOf('Future<void> clear()'),
      source.indexOf('Future<File> export()'),
    );

    expect(clearMethod, contains('final removed = await _remove'));
    expect(clearMethod, contains('if (!removed)'));
    expect(
      clearMethod,
      contains(
        'Local event history clear failed: SharedPreferences did not remove the event history.',
      ),
    );
    expect(clearMethod, isNot(contains('\n    await _preferences.remove(')));
  });

  test('local event clear rejection fails visibly at runtime', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);
    await repository.add('app_started', 'App started');
    final rejectingRepository = LocalEventRepository(
      preferences,
      debugRemove: (_) async => false,
    );

    await expectLater(
      rejectingRepository.clear(),
      throwsA(
        isA<StateError>().having(
          (error) => error.message,
          'message',
          contains('Local event history clear failed'),
        ),
      ),
    );
    expect(repository.load(), hasLength(1));
  });

  test('host-scoped local event key segment is safe and bounded', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();
    final keyGetter = source.substring(
      source.indexOf('String get _eventsKey'),
      source.indexOf('final SharedPreferences _preferences'),
    );
    final hostHelper = source.substring(
      source.indexOf('String _eventsHostKeySegment'),
      source.indexOf('Future<void> _deleteTemporaryExportFile'),
    );

    expect(
      keyGetter,
      contains('_eventsHostKeySegment(Platform.localHostname)'),
    );
    expect(
      source,
      contains('static const _maxEventsHostKeySegmentLength = 128'),
    );
    expect(
      source,
      contains("_eventsHostKeyUnsafePattern = RegExp(r'[^a-z0-9._-]+')"),
    );
    expect(
      hostHelper,
      contains('replaceAll(_eventsHostKeyUnsafePattern, \'-\')'),
    );
    expect(
      hostHelper,
      contains("if (normalized.isEmpty) return 'unknown-host';"),
    );
    expect(
      hostHelper,
      contains('normalized.substring(0, _maxEventsHostKeySegmentLength)'),
    );
    expect(source, isNot(contains('Platform.localHostname.toLowerCase()')));
  });

  test('corrupt local event history is recovered without crashing', () async {
    SharedPreferences.setMockInitialValues({
      'zentor.local_events.v1': '{this is not valid json',
    });
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final recovered = repository.load();

    expect(recovered.single.type, 'local_event_history_recovered');
    expect(recovered.single.severity, 'warning');
    expect(recovered.single.details, contains('could not be decoded'));

    final event = await repository.add('scan_started', 'Scan started');
    expect(event.type, 'scan_started');
    expect(repository.load(), hasLength(2));
    expect(
      repository.load().map((event) => event.type),
      contains('local_event_history_recovered'),
    );
  });

  test(
    'oversized local event history is dropped before JSON parsing',
    () async {
      SharedPreferences.setMockInitialValues({
        _currentEventKey: 'x' * (1024 * 1024 + 1),
      });
      final preferences = await SharedPreferences.getInstance();
      final repository = LocalEventRepository(preferences);

      final events = repository.load();
      expect(events.single.type, 'local_event_history_recovered');
      expect(
        events.single.details,
        contains('Current host local event history'),
      );
      await Future<void>.delayed(Duration.zero);
      expect(preferences.getString(_currentEventKey), isNull);
    },
  );

  test('local event decode failures keep bounded recovery details', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();
    final decodeMethod = source.substring(
      source.indexOf('List<LocalEvent>? _decodeEvents'),
      source.indexOf('Future<LocalEvent> add('),
    );

    expect(source, contains('String _decodeFailureDetails'));
    expect(decodeMethod, contains('List<String>? recoveryReasons'));
    expect(decodeMethod, contains('persisted JSON exceeded the size limit'));
    expect(decodeMethod, contains('persisted JSON root was not a list'));
    expect(decodeMethod, contains('persisted JSON could not be decoded'));
    expect(decodeMethod, contains('_boundedDiagnosticText(error)'));
    expect(
      decodeMethod,
      isNot(contains('} on Object {\n      // Local event history')),
    );
  });

  test('legacy local event history is loaded and migrated', () async {
    final now = DateTime.now().toUtc().toIso8601String();
    SharedPreferences.setMockInitialValues({
      'zentor.local_events.v1': jsonEncode([
        {
          'id': 'legacy',
          'type': 'app_started',
          'message': 'App started',
          'createdAt': now,
        },
      ]),
    });
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final events = repository.load();

    expect(events.single.id, 'legacy');
    await Future<void>.delayed(Duration.zero);
    expect(preferences.getString(_currentEventKey), isNotNull);
    expect(preferences.getString('zentor.local_events.v1'), isNull);
  });

  test('current host event history wins over legacy history', () async {
    final now = DateTime.now().toUtc().toIso8601String();
    SharedPreferences.setMockInitialValues({
      _currentEventKey: jsonEncode([
        {
          'id': 'current',
          'type': 'app_started',
          'message': 'Current app started',
          'createdAt': now,
        },
      ]),
      'zentor.local_events.v1': jsonEncode([
        {
          'id': 'legacy',
          'type': 'app_started',
          'message': 'Legacy app started',
          'createdAt': now,
        },
      ]),
    });
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final events = repository.load();

    expect(events.single.id, 'current');
    expect(preferences.getString('zentor.local_events.v1'), isNotNull);
  });

  test(
    'wrong-shaped legacy event history is not migrated as empty current',
    () async {
      SharedPreferences.setMockInitialValues({
        'zentor.local_events.v1': jsonEncode({'events': []}),
      });
      final preferences = await SharedPreferences.getInstance();
      final repository = LocalEventRepository(preferences);

      final events = repository.load();

      expect(events.single.type, 'local_event_history_recovered');
      expect(events.single.details, contains('Legacy local event history'));
      await Future<void>.delayed(Duration.zero);
      expect(preferences.getString(_currentEventKey), isNull);
      expect(preferences.getString('zentor.local_events.v1'), isNull);
    },
  );

  test(
    'protection and ransomware events persist category and severity',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final repository = LocalEventRepository(preferences);

      final event = await repository.add(
        'ransomware_guard_settings_changed',
        'Ransomware guard settings changed',
        details: '2 protected roots',
        category: 'protection',
        severity: 'warning',
      );

      expect(event.category, 'protection');
      expect(event.severity, 'warning');
      final restored = repository.load().single;
      expect(restored.category, 'protection');
      expect(restored.severity, 'warning');
    },
  );

  test(
    'malformed persisted events are not loaded as forged audit rows',
    () async {
      final now = DateTime.now().toUtc().toIso8601String();
      SharedPreferences.setMockInitialValues({
        'zentor.local_events.v1': jsonEncode([
          {
            'id': 'valid',
            'type': 'scan_started',
            'message': 'Scan started',
            'createdAt': now,
            'category': 'scan',
            'severity': 'warning',
          },
          {
            'id': '',
            'type': 'unknown',
            'message': 'Forged blank id',
            'createdAt': now,
          },
          {'id': 'missing-message', 'type': 'scan_started', 'createdAt': now},
          {
            'id': 'bad-date',
            'type': 'scan_started',
            'message': 'Bad date',
            'createdAt': 'not-a-date',
          },
          {
            'id': 'oversized-date',
            'type': 'scan_started',
            'message': 'Oversized date',
            'createdAt': 't' * 65,
          },
          {
            'id': 'bad-details',
            'type': 'scan_started',
            'message': 'Bad details',
            'createdAt': now,
            'details': ['not', 'a', 'string'],
          },
        ]),
      });
      final preferences = await SharedPreferences.getInstance();
      final repository = LocalEventRepository(preferences);

      final events = repository.load();

      expect(events, hasLength(3));
      expect(
        events.map((event) => event.id),
        containsAll(['valid', 'bad-details']),
      );
      expect(events.map((event) => event.id), isNot(contains('bad-date')));
      expect(
        events.map((event) => event.id),
        isNot(contains('oversized-date')),
      );
      expect(
        events.singleWhere((event) => event.id == 'valid').category,
        'scan',
      );
      expect(
        events.singleWhere((event) => event.id == 'valid').severity,
        'warning',
      );
      final recovery = events.singleWhere(
        (event) => event.type == 'local_event_history_recovered',
      );
      expect(recovery.severity, 'warning');
      expect(
        recovery.details,
        contains('Ignored 4 malformed local event history records'),
      );
      expect(recovery.details, contains('record 1 was missing required'));
      expect(recovery.details, contains('record 2 was missing required'));
      expect(recovery.details, contains('record 3 was missing required'));
    },
  );

  test('persisted event history is capped to newest retained rows', () async {
    final base = DateTime.utc(2026);
    SharedPreferences.setMockInitialValues({
      'zentor.local_events.v1': jsonEncode([
        for (var index = 0; index < 240; index++)
          {
            'id': 'event-$index',
            'type': 'scan_started',
            'message': 'Scan started',
            'createdAt': base.add(Duration(minutes: index)).toIso8601String(),
          },
      ]),
    });
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final events = repository.load();

    expect(events, hasLength(200));
    expect(events.first.id, 'event-239');
    expect(events.last.id, 'event-40');
    expect(events.any((event) => event.id == 'event-39'), isFalse);
  });

  test(
    'oversized local event record count is dropped before row parsing',
    () async {
      final base = DateTime.utc(2026);
      SharedPreferences.setMockInitialValues({
        'zentor.local_events.v1': jsonEncode([
          for (var index = 0; index < 1001; index++)
            {
              'id': 'event-$index',
              'type': 'scan_started',
              'message': 'Scan started',
              'createdAt': base.add(Duration(minutes: index)).toIso8601String(),
            },
        ]),
      });
      final preferences = await SharedPreferences.getInstance();
      final repository = LocalEventRepository(preferences);

      final events = repository.load();

      expect(events, hasLength(1));
      expect(events.single.type, 'local_event_history_recovered');
      expect(events.single.details, contains('too many event records'));
    },
  );

  test('source marker: persisted event timestamps are bounded', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();
    final dateTimeMethod = source.substring(
      source.indexOf('DateTime? _dateTime'),
      source.indexOf('String _allowedValue'),
    );

    expect(source, contains('static const _maxTimestampLength = 64'));
    expect(dateTimeMethod, contains('trimmed.length > _maxTimestampLength'));
    expect(dateTimeMethod, contains('DateTime.tryParse(trimmed)'));
  });

  test(
    'source marker: persisted event JSON is size bounded before parsing',
    () {
      final source = File(
        'lib/core/logging/local_event_repository.dart',
      ).readAsStringSync();
      final decodeMethod = source.substring(
        source.indexOf('List<LocalEvent>? _decodeEvents'),
        source.indexOf('Future<LocalEvent> add'),
      );

      expect(
        source,
        contains('static const _maxPersistedEventJsonChars = 1024 * 1024'),
      );
      expect(
        decodeMethod,
        contains('raw.length > _maxPersistedEventJsonChars'),
      );
      expect(
        decodeMethod.indexOf('raw.length > _maxPersistedEventJsonChars'),
        lessThan(decodeMethod.indexOf('jsonDecode(raw)')),
      );
    },
  );

  test('source marker: persisted event row count is retention bounded', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();
    final decodeMethod = source.substring(
      source.indexOf('List<LocalEvent>? _decodeEvents'),
      source.indexOf('Future<LocalEvent> add'),
    );
    final addMethod = source.substring(
      source.indexOf('Future<LocalEvent> add'),
      source.indexOf('Future<void> clear'),
    );

    expect(source, contains('static const _maxStoredEvents = 200'));
    expect(decodeMethod, contains('events.take(_maxStoredEvents).toList()'));
    expect(addMethod, contains('take(_maxStoredEvents).toList()'));
  });

  test('malformed optional event fields do not clear valid history', () async {
    final now = DateTime.now().toUtc().toIso8601String();
    SharedPreferences.setMockInitialValues({
      'zentor.local_events.v1': jsonEncode([
        {
          'id': 'valid',
          'type': 'app_started',
          'message': 'App started',
          'createdAt': now,
          'details': 'valid details',
        },
        {
          'id': 'invalid-details',
          'type': 'scan_started',
          'message': 'Scan started',
          'createdAt': now,
          'details': {'unexpected': 'object'},
        },
      ]),
    });
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final events = repository.load();

    expect(events, hasLength(2));
    expect(
      events.singleWhere((event) => event.id == 'valid').details,
      'valid details',
    );
    expect(
      events.singleWhere((event) => event.id == 'invalid-details').details,
      isNull,
    );
  });

  test('stored event category and severity are constrained', () async {
    SharedPreferences.setMockInitialValues({
      'zentor.local_events.v1': jsonEncode([
        {
          'id': 'event',
          'type': ' app_started ',
          'message': ' App started ',
          'createdAt': DateTime.now().toUtc().toIso8601String(),
          'category': 'forged',
          'severity': 'critical',
        },
      ]),
    });
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final restored = repository.load().single;

    expect(restored.type, 'app_started');
    expect(restored.message, 'App started');
    expect(restored.category, 'app');
    expect(restored.severity, 'info');
  });

  test('stored event text with control characters is rejected', () async {
    final createdAt = DateTime.now().toUtc().toIso8601String();
    SharedPreferences.setMockInitialValues({
      'zentor.local_events.v1': jsonEncode([
        {
          'id': 'valid',
          'type': 'scan_completed',
          'message': 'Scan completed',
          'createdAt': createdAt,
          'details': 'valid details',
          'category': 'scan',
          'severity': 'info',
        },
        {
          'id': 'invalid-message',
          'type': 'scan_completed',
          'message': 'Complete\u0000d',
          'createdAt': createdAt,
          'category': 'scan',
          'severity': 'info',
        },
        {
          'id': 'invalid-details',
          'type': 'scan_completed',
          'message': 'Scan completed',
          'createdAt': createdAt,
          'details': 'line\u000Bbreak',
          'category': 'scan',
          'severity': 'info',
        },
        {
          'id': 'invalid-category',
          'type': 'scan_completed',
          'message': 'Scan completed',
          'createdAt': createdAt,
          'category': ' settings\n',
          'severity': 'info',
        },
        {
          'id': 'invalid-timestamp',
          'type': 'scan_completed',
          'message': 'Scan completed',
          'createdAt': '$createdAt\n',
          'category': 'scan',
          'severity': 'info',
        },
      ]),
    });
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final restored = repository.load();

    expect(
      restored.any((event) => event.type == 'local_event_history_recovered'),
      isTrue,
    );
    expect(
      restored.singleWhere((event) => event.id == 'valid').message,
      'Scan completed',
    );
    expect(restored.any((event) => event.id == 'invalid-message'), isFalse);
    expect(restored.any((event) => event.id == 'invalid-details'), isFalse);
    expect(restored.any((event) => event.id == 'invalid-category'), isFalse);
    expect(restored.any((event) => event.id == 'invalid-timestamp'), isFalse);
  });

  test('stored event text over length limits is rejected', () async {
    final createdAt = DateTime.now().toUtc().toIso8601String();
    SharedPreferences.setMockInitialValues({
      'zentor.local_events.v1': jsonEncode([
        {
          'id': 'valid',
          'type': 'scan_completed',
          'message': 'Scan completed',
          'createdAt': createdAt,
          'details': 'valid details',
          'category': 'scan',
          'severity': 'info',
        },
        {
          'id': 'i' * 129,
          'type': 'scan_completed',
          'message': 'Scan completed',
          'createdAt': createdAt,
          'category': 'scan',
          'severity': 'info',
        },
        {
          'id': 'oversized-type',
          'type': 't' * 97,
          'message': 'Scan completed',
          'createdAt': createdAt,
          'category': 'scan',
          'severity': 'info',
        },
        {
          'id': 'oversized-message',
          'type': 'scan_completed',
          'message': 'm' * 321,
          'createdAt': createdAt,
          'category': 'scan',
          'severity': 'info',
        },
        {
          'id': 'oversized-details',
          'type': 'scan_completed',
          'message': 'Scan completed',
          'createdAt': createdAt,
          'details': 'd' * 4097,
          'category': 'scan',
          'severity': 'info',
        },
      ]),
    });
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final restored = repository.load();

    expect(
      restored.any((event) => event.type == 'local_event_history_recovered'),
      isTrue,
    );
    expect(
      restored.singleWhere((event) => event.id == 'valid').details,
      'valid details',
    );
    expect(restored.any((event) => event.id == 'oversized-type'), isFalse);
    expect(restored.any((event) => event.id == 'oversized-message'), isFalse);
    expect(restored.any((event) => event.id == 'oversized-details'), isFalse);
  });

  test('new event category and severity are rejected before storage', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    await expectLater(
      repository.add(
        ' app_started ',
        ' App started ',
        details: '   details   ',
        category: 'forged',
      ),
      throwsArgumentError,
    );
    await expectLater(
      repository.add(
        ' app_started ',
        ' App started ',
        details: '   details   ',
        severity: 'critical',
      ),
      throwsArgumentError,
    );
    expect(repository.load(), isEmpty);
  });

  test('new event text rejects control characters before storage', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    await expectLater(
      repository.add('app\nstarted', 'App started'),
      throwsArgumentError,
    );
    await expectLater(
      repository.add('app_started', 'App\u0000started'),
      throwsArgumentError,
    );
    await expectLater(
      repository.add('app_started', 'App started', details: 'line\u000Bbreak'),
      throwsArgumentError,
    );
    await expectLater(
      repository.add('app_started', 'App started', category: 'settings\n'),
      throwsArgumentError,
    );
    await expectLater(
      repository.add('app_started', 'App started', severity: 'warning\n'),
      throwsArgumentError,
    );
    expect(repository.load(), isEmpty);
  });

  test('settings event category is preserved', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final event = await repository.add(
      'configuration_reset',
      'Configuration reset',
      category: 'settings',
      severity: 'warning',
    );

    expect(event.category, 'settings');
    expect(event.severity, 'warning');
    final restored = repository.load().single;
    expect(restored.category, 'settings');
    expect(restored.severity, 'warning');
  });

  test('new event text is bounded and blank required fields fail', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final repository = LocalEventRepository(preferences);

    final event = await repository.add(
      'scan_started',
      'm' * 400,
      details: 'd' * 5000,
    );

    expect(event.message.length, 320);
    expect(event.details, isNotNull);
    expect(event.details!.length, 4096);
    await expectLater(repository.add('', 'message'), throwsArgumentError);
    await expectLater(repository.add('type', '   '), throwsArgumentError);
  });

  test('local event export uses staged safe target writes', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();

    expect(source, contains('_rejectUnsafeExportTarget(file.path)'));
    expect(source, contains('_temporaryExportFile(file)'));
    expect(source, contains('followLinks: false'));
    expect(source, contains('await _temporaryExportFile(file)'));
    expect(source, contains('await temp.create(exclusive: true)'));
    expect(source, contains('_writeLocalEventExportTempFile(temp, body)'));
    expect(source, contains('await output.writeString(body)'));
    expect(source, contains('await output.flush()'));
    expect(source, contains('Temporary local event export output was unsafe'));
    expect(
      source,
      contains('Temporary local event export output became unsafe'),
    );
    expect(source, isNot(contains('temp.writeAsString')));
    expect(
      source,
      contains('Failed to reserve temporary local event export path'),
    );
    expect(source, contains('Temporary local event export path became unsafe'));
    expect(source, contains('DateTime.now().microsecondsSinceEpoch'));
    expect(
      source,
      contains('Unable to allocate a temporary local event export path'),
    );
    expect(source, contains('Temporary local event export path was unsafe'));
    expect(source, contains('await temp.rename(file.path)'));
    expect(source, isNot(contains("File('\${file.path}.tmp')")));
  });

  test('local event export body is size bounded before writes', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();
    final exportMethod = source.substring(
      source.indexOf('Future<File> export()'),
      source.indexOf('Future<File> _temporaryExportFile'),
    );
    final writerMethod = source.substring(
      source.indexOf('Future<void> _writeLocalEventExportTempFile'),
      source.indexOf('Future<void> _deleteTemporaryExportFile'),
    );

    expect(
      source,
      contains('static const _maxLocalEventExportJsonChars = 2 * 1024 * 1024'),
    );
    expect(source, contains('void _rejectOversizedExportBody(String body)'));
    expect(source, contains('body.length > _maxLocalEventExportJsonChars'));
    expect(
      source,
      contains('Local event export body exceeded the size limit.'),
    );
    expect(exportMethod, contains('_rejectOversizedExportBody(body)'));
    expect(
      exportMethod.indexOf('_rejectOversizedExportBody(body)'),
      lessThan(exportMethod.indexOf('await _temporaryExportFile(file)')),
    );
    expect(writerMethod, contains('_rejectOversizedExportBody(body)'));
    expect(
      writerMethod.indexOf('_rejectOversizedExportBody(body)'),
      lessThan(writerMethod.indexOf('await temp.open(mode: FileMode.write)')),
    );
  });

  test('local event export cleanup failures are reported', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();
    final exportMethod = source.substring(
      source.indexOf('Future<File> export()'),
      source.indexOf('void _rejectUnsafeExportTarget'),
    );

    expect(exportMethod, contains('temporary export cleanup also failed'));
    expect(
      exportMethod,
      contains('Original error: \${_boundedDiagnosticText(error)}'),
    );
    expect(
      exportMethod,
      contains('Cleanup error: \${_boundedDiagnosticText(cleanupError)}'),
    );
    expect(exportMethod, contains('Error.throwWithStackTrace'));
    expect(exportMethod, contains('_deleteTemporaryExportFile(temp)'));
    expect(exportMethod, isNot(contains('catch (_)')));
    expect(exportMethod, isNot(contains('temp.existsSync()')));
    expect(exportMethod, isNot(contains('Best-effort cleanup')));
    expect(source, contains('String _boundedDiagnosticText(Object error)'));
    expect(source, contains('return _truncate(text, _maxDetailsLength)'));
  });

  test('local event export cleanup uses non-following path checks', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();
    final cleanupHelper = source.substring(
      source.indexOf('Future<void> _deleteTemporaryExportFile'),
      source.indexOf('void _rejectUnsafeExportTarget'),
    );

    expect(cleanupHelper, contains('FileSystemEntity.typeSync'));
    expect(cleanupHelper, contains('followLinks: false'));
    expect(cleanupHelper, contains('FileSystemEntityType.notFound'));
    expect(
      cleanupHelper,
      contains('Temporary local event export cleanup target was unsafe'),
    );
    expect(cleanupHelper, contains('await temp.delete()'));
  });

  test(
    'local event export cleanup failures include original and cleanup details',
    () async {
      final temporaryRoot = await Directory.systemTemp.createTemp(
        'avorax-local-event-export-test-',
      );
      try {
        PathProviderPlatform.instance = _FakeLocalEventPathProvider(
          temporaryRoot.path,
        );
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final repository = LocalEventRepository(
          preferences,
          debugBeforeExportActivation: (temp, exportFile) async {
            await temp.delete();
            await Directory(temp.path).create();
            await Directory(exportFile.path).create();
          },
        );

        await repository.add('app_started', 'App started');

        await expectLater(
          repository.export(),
          throwsA(
            isA<StateError>().having(
              (error) => error.message,
              'message',
              allOf(
                contains(
                  'Local event export failed and temporary export cleanup also failed',
                ),
                contains(
                  'Refusing to write local event export through unsafe target',
                ),
                contains(
                  'Temporary local event export cleanup target was unsafe',
                ),
              ),
            ),
          ),
        );
      } finally {
        if (await temporaryRoot.exists()) {
          await temporaryRoot.delete(recursive: true);
        }
      }
    },
  );

  test(
    'local event export redacts credentials without changing history',
    () async {
      final temporaryRoot = await Directory.systemTemp.createTemp(
        'avorax-local-event-export-redaction-test-',
      );
      try {
        PathProviderPlatform.instance = _FakeLocalEventPathProvider(
          temporaryRoot.path,
        );
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final repository = LocalEventRepository(preferences);

        await repository.add(
          'cloud_failure',
          'Cloud request failed',
          details:
              'path=C:\\Users\\Brent\\Downloads\\sample.exe '
              'Authorization: Bearer SECRETBEARER123456 '
              'Authorization: Basic BASICSECRET123456 '
              'session_id=SESSIONSECRET123456 '
              'endpoint=https://user:URLPASSSECRET123456@api.example.test/v1 '
              'password=hunter2 token=LOGEXPORTTOKEN123456 '
              'sk-proj-LOGEXPORTSECRET123456 '
              'Cookie: sessionid=COOKIESECRET123456;',
          category: 'settings',
          severity: 'warning',
        );

        final storedEvent = repository.load().single;
        expect(storedEvent.details, contains('SECRETBEARER123456'));
        expect(storedEvent.details, contains('BASICSECRET123456'));
        expect(storedEvent.details, contains('COOKIESECRET123456'));
        expect(storedEvent.details, contains('SESSIONSECRET123456'));
        expect(storedEvent.details, contains('URLPASSSECRET123456'));
        expect(storedEvent.details, contains('hunter2'));
        expect(storedEvent.details, contains('LOGEXPORTTOKEN123456'));
        expect(storedEvent.details, contains('LOGEXPORTSECRET123456'));

        final file = await repository.export();
        expect(file.path, endsWith('zentor-local-events.json'));
        final raw = await file.readAsString();
        for (final secret in const [
          'SECRETBEARER123456',
          'BASICSECRET123456',
          'COOKIESECRET123456',
          'SESSIONSECRET123456',
          'URLPASSSECRET123456',
          'hunter2',
          'LOGEXPORTTOKEN123456',
          'LOGEXPORTSECRET123456',
        ]) {
          expect(raw, isNot(contains(secret)));
        }

        final decoded = jsonDecode(raw) as List<Object?>;
        final exportedEvent = decoded.single as Map<String, Object?>;
        final details = exportedEvent['details'] as String;
        expect(details, contains(r'path=C:\Users\Brent\Downloads\sample.exe'));
        expect(details, contains('Authorization: [redacted]'));
        expect(details, contains('Cookie: [redacted]'));
        expect(details, contains('session_id=[redacted]'));
        expect(details, contains('https://[redacted]@api.example.test/v1'));
        expect(details, contains('password=[redacted]'));
        expect(details, contains('token=[redacted]'));
        expect(details, contains('[redacted]'));
      } finally {
        if (await temporaryRoot.exists()) {
          await temporaryRoot.delete(recursive: true);
        }
      }
    },
  );

  test(
    'support bundle export writes bounded diagnostic JSON without payloads',
    () async {
      final temporaryRoot = await Directory.systemTemp.createTemp(
        'avorax-support-bundle-test-',
      );
      try {
        PathProviderPlatform.instance = _FakeLocalEventPathProvider(
          temporaryRoot.path,
        );
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final repository = LocalEventRepository(preferences);

        await repository.add(
          'scan_completed',
          'Scan completed',
          details: r'path=C:\Users\Brent\Downloads\sample.exe',
          category: 'scan',
        );

        final file = await repository.exportSupportBundle(
          diagnostics: {
            'status': 'test-ok',
            'counts': {'events': 1},
          },
        );

        expect(file.path, endsWith('avorax-support-bundle.json'));
        final decoded =
            jsonDecode(await file.readAsString()) as Map<String, Object?>;
        expect(decoded['schema_version'], 1);
        final privacy = decoded['privacy'] as Map<String, Object?>;
        expect(privacy['contains_file_contents'], isFalse);
        expect(privacy['contains_quarantine_payloads'], isFalse);
        expect(privacy['contains_live_malware'], isFalse);
        expect(privacy['contains_credentials'], isFalse);
        expect(privacy['credential_redaction_applied'], isTrue);
        expect(privacy['redacted_value_marker'], '[redacted]');
        expect(privacy['includes_local_file_paths_from_events'], isTrue);
        expect(privacy['manual_review_required_before_sharing'], isTrue);
        expect(decoded['diagnostics'], isA<Map<String, Object?>>());
        final events = decoded['events'] as List<Object?>;
        expect(events, hasLength(1));
        final event = events.single as Map<String, Object?>;
        expect(event['type'], 'scan_completed');
        expect(event['details'], r'path=C:\Users\Brent\Downloads\sample.exe');
        final raw = await file.readAsString();
        expect(raw, isNot(contains('FILE_CONTENT_SENTINEL')));
      } finally {
        if (await temporaryRoot.exists()) {
          await temporaryRoot.delete(recursive: true);
        }
      }
    },
  );

  test(
    'support bundle export redacts credentials from diagnostics and events',
    () async {
      final temporaryRoot = await Directory.systemTemp.createTemp(
        'avorax-support-bundle-redaction-test-',
      );
      try {
        PathProviderPlatform.instance = _FakeLocalEventPathProvider(
          temporaryRoot.path,
        );
        SharedPreferences.setMockInitialValues({});
        final preferences = await SharedPreferences.getInstance();
        final repository = LocalEventRepository(preferences);

        await repository.add(
          'cloud_failure',
          'Cloud request failed',
          details:
              'path=C:\\Users\\Brent\\Downloads\\sample.exe '
              'Authorization: Bearer SECRETBEARER123456 '
              'Authorization: Basic BASICBUNDLESECRET123456 '
              'session_id=BUNDLESESSIONSECRET123456 '
              'password=hunter2 '
              'token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdXBwb3J0In0.signature123456 '
              'apiKey=APIKEYSECRET123456 '
              'sk-proj-SUPPORTBUNDLESECRET123456 '
              'ghp_SUPPORTBUNDLESECRET123456 '
              'Cookie: sessionid=BUNDLECOOKIESECRET123456;',
          category: 'settings',
          severity: 'warning',
        );

        final file = await repository.exportSupportBundle(
          diagnostics: {
            'publicClientKey': 'PUBLICCLIENTSECRET123456',
            'nested': {
              'authorization': 'Bearer NESTEDAUTHSECRET123456',
              'cookie': 'sessionid=NESTEDCOOKIESECRET123456',
              'safe_path': r'C:\Users\Brent\Downloads\sample.exe',
              'callback':
                  'https://user:BUNDLEURLPASSSECRET123456@api.example.test/status?token=URLTOKEN123456',
            },
          },
        );

        final raw = await file.readAsString();
        for (final secret in const [
          'SECRETBEARER123456',
          'BASICBUNDLESECRET123456',
          'BUNDLECOOKIESECRET123456',
          'BUNDLESESSIONSECRET123456',
          'hunter2',
          'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzdXBwb3J0In0.signature123456',
          'APIKEYSECRET123456',
          'SUPPORTBUNDLESECRET123456',
          'PUBLICCLIENTSECRET123456',
          'NESTEDAUTHSECRET123456',
          'NESTEDCOOKIESECRET123456',
          'BUNDLEURLPASSSECRET123456',
          'URLTOKEN123456',
        ]) {
          expect(raw, isNot(contains(secret)));
        }
        expect(raw, contains('[redacted]'));

        final decoded = jsonDecode(raw) as Map<String, Object?>;
        final diagnostics = decoded['diagnostics'] as Map<String, Object?>;
        expect(diagnostics['publicClientKey'], '[redacted]');
        final nested = diagnostics['nested'] as Map<String, Object?>;
        expect(nested['authorization'], '[redacted]');
        expect(nested['cookie'], '[redacted]');
        expect(nested['safe_path'], r'C:\Users\Brent\Downloads\sample.exe');
        expect(
          nested['callback'],
          'https://[redacted]@api.example.test/status?token=[redacted]',
        );
        final events = decoded['events'] as List<Object?>;
        final event = events.single as Map<String, Object?>;
        final details = event['details'] as String;
        expect(details, contains('Authorization: [redacted]'));
        expect(details, contains('Cookie: [redacted]'));
        expect(details, contains('session_id=[redacted]'));
        expect(details, contains('password=[redacted]'));
        expect(details, contains('apiKey=[redacted]'));
      } finally {
        if (await temporaryRoot.exists()) {
          await temporaryRoot.delete(recursive: true);
        }
      }
    },
  );

  test('local event history recovery is visible', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();

    expect(source, contains('_localEventHistoryRecoveryEvent'));
    expect(source, contains('local_event_history_recovered'));
    expect(source, contains('Local event history was reset'));
    expect(source, contains('severity: \'warning\''));
  });

  test('partial malformed local event history recovery is visible', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();

    expect(source, contains('malformedRecords++'));
    expect(source, contains('final malformedRecordReasons = <String>[]'));
    expect(source, contains('malformedReasons: malformedRecordReasons'));
    expect(
      source,
      contains('Ignored \$malformedRecords malformed local event history'),
    );
    expect(source, contains('malformedRecordReasons.take(3).join'));
    expect(source, contains('record \$index was not a JSON object'));
    expect(source, contains('record \$index was missing required id'));
    expect(source, contains('record \$index could not be decoded'));
    expect(source, contains('_boundedDiagnosticText(error)'));
    expect(source, contains('...events'));
  });

  test('local event history maintenance failures are visible', () {
    final source = File(
      'lib/core/logging/local_event_repository.dart',
    ).readAsStringSync();
    final loadMethod = source.substring(
      source.indexOf('List<LocalEvent> load()'),
      source.indexOf('LocalEvent _localEventHistoryRecoveryEvent'),
    );

    expect(loadMethod, contains('_scheduleStorageRemoval'));
    expect(loadMethod, contains('_scheduleLegacyMigration'));
    expect(loadMethod, isNot(contains('unawaited(_preferences')));
    expect(source, contains('void _scheduleMaintenance'));
    expect(source, contains('operation().catchError((Object error)'));
    expect(source, contains('_recordMaintenanceFailure'));
    expect(source, contains('_maintenanceEvents.insert'));
    expect(source, contains('_maintenanceEvents.clear()'));
    expect(source, contains('Local event history maintenance failed'));
    expect(
      source,
      contains(
        'Local event history maintenance failed: \${_boundedDiagnosticText(error)}',
      ),
    );
    expect(source, contains('Local event history is audit evidence'));
    expect(source, isNot(contains('not security-critical')));
    expect(
      source,
      isNot(contains(r'Local event history maintenance failed: $error')),
    );
  });

  test('log export failures are surfaced instead of thrown from controls', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final logsScreen = File(
      'lib/features/logs/logs_screen.dart',
    ).readAsStringSync();
    final settingsScreen = File(
      'lib/features/settings/settings_screen.dart',
    ).readAsStringSync();

    expect(appState, contains('logs_export_failed'));
    expect(
      appState,
      contains('Future<String?> exportLogs({bool confirmed = false})'),
    );
    expect(appState, contains('logs_export_confirmation_required'));
    expect(appState, contains('Log export requires explicit confirmation'));
    expect(appState, contains('String _boundedExportPath(String path)'));
    expect(
      appState,
      contains(
        "_boundedUiDiagnostic(path, fallback: 'export path unavailable')",
      ),
    );
    expect(
      appState,
      contains('final exportedPath = _boundedExportPath(file.path)'),
    );
    expect(appState, contains('details: exportedPath'));
    expect(appState, contains('return exportedPath;'));
    expect(appState, isNot(contains('details: file.path')));
    expect(appState, isNot(contains('return file.path;')));
    expect(appState, contains(r'Unable to export logs: $details'));
    expect(appState, isNot(contains(r'Unable to export logs: $error')));
    expect(appState, contains('return null;'));
    expect(logsScreen, contains('Future<bool> _confirmExportLogs'));
    expect(logsScreen, contains('Export logs?'));
    expect(logsScreen, contains('file paths, protection actions'));
    expect(logsScreen, contains('controller.exportLogs('));
    expect(logsScreen, contains('confirmed: true'));
    expect(logsScreen, contains('path != null'));
    expect(settingsScreen, contains('_confirmExportLogs(controller)'));
    expect(
      settingsScreen,
      contains('controller.exportLogs(confirmed: confirmed)'),
    );
    expect(settingsScreen, contains('path == null'));
    expect(settingsScreen, contains('See the error banner'));
    expect(settingsScreen, contains('_maxSettingsDiagnosticChars'));
    expect(
      settingsScreen,
      contains('String _boundedSettingsDiagnostic(Object error)'),
    );
    expect(settingsScreen, contains(r"RegExp(r'[\x00-\x1F\x7F]+')"));
    expect(
      settingsScreen,
      contains('substring(0, _maxSettingsDiagnosticChars - 3)'),
    );
    expect(
      settingsScreen,
      contains('final details = _boundedSettingsDiagnostic(error)'),
    );
    expect(settingsScreen, contains(r'Unable to export logs: $details'));
    expect(settingsScreen, isNot(contains(r'Unable to export logs: $error')));
  });

  test(
    'controller log export failures are normalized before display',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final eventRepository = _FailingExportEventRepository(preferences);
      final controller = ZentorController(
        configRepository: ConfigRepository(preferences),
        eventRepository: eventRepository,
        apiClient: ZentorApiClient(),
        hashService: HashService(),
        appDetector: const _FakeAppDetector(),
        localCoreClient: const LocalCoreClient(),
        scanTargetService: const ScanTargetService(),
        updateService: ZentorUpdateService(),
      );
      addTearDown(controller.dispose);

      final path = await controller.exportLogs(confirmed: true);

      expect(path, isNull);
      expect(
        controller.state.errorMessage,
        contains(
          'Unable to export logs: Bad state: export failed with control text',
        ),
      );
      expect(controller.state.errorMessage, isNot(contains('\x00')));
      expect(controller.state.errorMessage, isNot(contains('\n\t')));
      final failedEvent = controller.state.events.singleWhere(
        (event) => event.type == 'logs_export_failed',
      );
      expect(failedEvent.details, contains('export failed with control text'));
      expect(failedEvent.details, isNot(contains('\x00')));
      expect(failedEvent.details, isNot(contains('\n\t')));
    },
  );

  test(
    'controller log export blocks duplicate exports while pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingExport = Completer<File>();
      final eventRepository = _PendingExportEventRepository(
        preferences,
        pendingExport: pendingExport,
      );
      final controller = ZentorController(
        configRepository: ConfigRepository(preferences),
        eventRepository: eventRepository,
        apiClient: ZentorApiClient(),
        hashService: HashService(),
        appDetector: const _FakeAppDetector(),
        localCoreClient: const LocalCoreClient(),
        scanTargetService: const ScanTargetService(),
        updateService: ZentorUpdateService(),
      );
      addTearDown(controller.dispose);

      final firstExport = controller.exportLogs(confirmed: true);
      await Future<void>.delayed(Duration.zero);
      expect(controller.state.logExportInFlight, isTrue);

      final duplicate = await controller.exportLogs(confirmed: true);

      expect(duplicate, isNull);
      expect(eventRepository.exportCalls, 1);
      expect(controller.state.logExportInFlight, isTrue);
      expect(
        controller.state.errorMessage,
        contains('Log export is already in progress'),
      );
      final busyEvent = controller.state.events.singleWhere(
        (event) => event.type == 'logs_export_busy',
      );
      expect(busyEvent.category, 'settings');
      expect(busyEvent.severity, 'warning');

      pendingExport.complete(File(r'C:\Users\Brent\Documents\avorax-log.json'));
      final exportedPath = await firstExport;

      expect(exportedPath, contains('avorax-log.json'));
      expect(controller.state.logExportInFlight, isFalse);
      expect(eventRepository.exportCalls, 1);
      expect(
        controller.state.events.map((event) => event.type),
        contains('logs_exported'),
      );
    },
  );

  test(
    'controller support bundle export blocks duplicate exports while pending',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final pendingExport = Completer<File>();
      final eventRepository = _PendingSupportBundleEventRepository(
        preferences,
        pendingExport: pendingExport,
      );
      final controller = ZentorController(
        configRepository: ConfigRepository(preferences),
        eventRepository: eventRepository,
        apiClient: ZentorApiClient(),
        hashService: HashService(),
        appDetector: const _FakeAppDetector(),
        localCoreClient: const LocalCoreClient(),
        scanTargetService: const ScanTargetService(),
        updateService: ZentorUpdateService(),
      );
      addTearDown(controller.dispose);

      final firstExport = controller.exportSupportBundle(confirmed: true);
      await Future<void>.delayed(Duration.zero);
      expect(controller.state.supportBundleExportInFlight, isTrue);

      final duplicate = await controller.exportSupportBundle(confirmed: true);

      expect(duplicate, isNull);
      expect(eventRepository.exportCalls, 1);
      expect(controller.state.supportBundleExportInFlight, isTrue);
      expect(
        controller.state.errorMessage,
        contains('Support bundle export is already in progress'),
      );
      final busyEvent = controller.state.events.singleWhere(
        (event) => event.type == 'support_bundle_export_busy',
      );
      expect(busyEvent.category, 'settings');
      expect(busyEvent.severity, 'warning');

      pendingExport.complete(
        File(r'C:\Users\Brent\Documents\avorax-support-bundle.json'),
      );
      final exportedPath = await firstExport;

      expect(exportedPath, contains('avorax-support-bundle.json'));
      expect(controller.state.supportBundleExportInFlight, isFalse);
      expect(eventRepository.exportCalls, 1);
      expect(
        controller.state.events.map((event) => event.type),
        contains('support_bundle_exported'),
      );
    },
  );

  test('app detection records process snapshot evaluation evidence', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCoreClient = _ProcessSnapshotLocalCoreClient(
      const ProcessSnapshotReport(
        ok: true,
        status: 'notActive',
        capability: 'userModeSnapshot',
        statusReason: 'snapshot-only test fixture',
        observedProcesses: 1,
        findings: [
          ProcessFinding(
            pid: 442,
            imagePath: r'C:\Users\Brent\AppData\Local\Temp\runner.exe',
            score: 60,
            verdict: 'suspicious',
            reasons: ['unsigned user-writable process image'],
          ),
        ],
      ),
    );
    final controller = ZentorController(
      configRepository: ConfigRepository(preferences),
      eventRepository: LocalEventRepository(preferences),
      apiClient: ZentorApiClient(),
      hashService: HashService(),
      appDetector: const _FakeAppDetector(
        supportsAutomatic: true,
        detectedApps: [
          DetectedApp(
            appId: 'fixture',
            displayName: 'Fixture App',
            path: r'C:\Program Files\Fixture\fixture.exe',
            source: 'test',
          ),
        ],
        observations: [
          ProcessObservation(
            pid: 442,
            imagePath: r'C:\Users\Brent\AppData\Local\Temp\runner.exe',
          ),
        ],
      ),
      localCoreClient: localCoreClient,
      scanTargetService: const ScanTargetService(),
      updateService: ZentorUpdateService(),
    );
    addTearDown(controller.dispose);

    await controller.unawaitedDetectApps();

    expect(localCoreClient.snapshotCalls, 1);
    expect(
      controller.state.events.map((event) => event.type),
      contains('process_snapshot_suspicious'),
    );
    final snapshotEvent = controller.state.events.singleWhere(
      (event) => event.type == 'process_snapshot_suspicious',
    );
    expect(snapshotEvent.category, 'protection');
    expect(snapshotEvent.severity, 'warning');
    expect(snapshotEvent.details, contains('observed=1'));
    expect(snapshotEvent.details, contains('capability=userModeSnapshot'));
    expect(controller.state.detectedApps, hasLength(1));
  });

  test('local event write failures are contained by the controller', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();

    expect(appState, contains(r'Unable to record local event: $details'));
    expect(appState, isNot(contains(r'Unable to record local event: $error')));
    expect(appState, contains('} on Object catch (error) {'));
  });
}

class _FailingExportEventRepository extends LocalEventRepository {
  _FailingExportEventRepository(super.preferences);

  @override
  Future<File> export() async {
    throw StateError('export failed\x00\n\twith control text');
  }
}

class _PendingExportEventRepository extends LocalEventRepository {
  _PendingExportEventRepository(
    super.preferences, {
    required this.pendingExport,
  });

  final Completer<File> pendingExport;
  int exportCalls = 0;

  @override
  Future<File> export() {
    exportCalls += 1;
    return pendingExport.future;
  }
}

class _PendingSupportBundleEventRepository extends LocalEventRepository {
  _PendingSupportBundleEventRepository(
    super.preferences, {
    required this.pendingExport,
  });

  final Completer<File> pendingExport;
  int exportCalls = 0;

  @override
  Future<File> exportSupportBundle({
    required Map<String, Object?> diagnostics,
  }) {
    exportCalls += 1;
    expect(diagnostics['privacy'], isA<Map<String, Object?>>());
    return pendingExport.future;
  }
}

class _FakeLocalEventPathProvider extends PathProviderPlatform {
  _FakeLocalEventPathProvider(this.documentsPath);

  final String documentsPath;

  @override
  Future<String?> getApplicationDocumentsPath() async => documentsPath;
}

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector({
    this.supportsAutomatic = false,
    this.detectedApps = const [],
    this.observations = const [],
  });

  final bool supportsAutomatic;
  final List<DetectedApp> detectedApps;
  final List<ProcessObservation> observations;

  @override
  bool get supportsAutomaticDetection => supportsAutomatic;

  @override
  Future<List<DetectedApp>> detect() async => detectedApps;

  @override
  Future<List<ProcessObservation>> processSnapshotObservations() async =>
      observations;
}

class _ProcessSnapshotLocalCoreClient extends LocalCoreClient {
  _ProcessSnapshotLocalCoreClient(this.report);

  final ProcessSnapshotReport report;
  int snapshotCalls = 0;

  @override
  Future<ProcessSnapshotReport> evaluateProcessSnapshot(
    List<ProcessObservation> observations, {
    ProcessMonitorPolicy policy = const ProcessMonitorPolicy(),
  }) async {
    snapshotCalls += 1;
    return report;
  }
}
