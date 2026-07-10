import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:zentor_client/app/app_state.dart';
import 'package:zentor_client/core/apps/app_detector.dart';
import 'package:zentor_client/core/config/config_repository.dart';
import 'package:zentor_client/core/config/build_config.dart';
import 'package:zentor_client/core/local_core/local_core_client.dart';
import 'package:zentor_client/core/scanning/scan_target_service.dart';
import 'package:zentor_client/core/updates/update_service.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

void main() {
  test('build config has production defaults', () {
    const config = BuildConfig();
    expect(config.apiBaseUrl, 'http://127.0.0.1:8000');
    expect(config.projectId, 'avorax-default');
    expect(config.publicClientKey, 'avorax-public-client');
    expect(config.updatesRepoOwner, 'brentishere41848');
    expect(config.updatesRepoName, 'Avorax');
  });

  test('config validation uses cloud wording instead of form errors', () {
    const empty = ZentorConfig();
    expect(
      empty.validateCloudConfiguration().join(' '),
      contains(
        'Cloud settings are managed by your Avorax build configuration.',
      ),
    );

    const valid = ZentorConfig(
      apiBaseUrl: 'http://127.0.0.1:8000',
      projectId: 'project-1',
      publicClientKey: 'public-key',
    );
    expect(valid.validateCloudConfiguration(), isEmpty);
  });

  test('cloud config fields are typed and bounded', () {
    expect(
      ZentorConfig(
        apiBaseUrl: 'ftp://api.example.test',
        projectId: 'project',
        publicClientKey: 'key',
      ).validateCloudConfiguration(),
      contains('Avorax Cloud endpoint must be an absolute URL.'),
    );
    expect(
      ZentorConfig(
        apiBaseUrl: 'https://api.example.test/${'a' * 2048}',
        projectId: 'project',
        publicClientKey: 'key',
      ).validateCloudConfiguration(),
      contains('Avorax Cloud endpoint is too long.'),
    );
    expect(
      ZentorConfig(
        apiBaseUrl: 'https://api.example.test',
        projectId: 'project\u0000id',
        publicClientKey: 'key',
      ).validateCloudConfiguration(),
      contains(
        'Avorax Cloud project ID contains unsupported control characters.',
      ),
    );
    expect(
      () => ZentorConfig.fromJson({'apiBaseUrl': 42}),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({'projectId': 'p' * 257}),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({'publicClientKey': 'k' * 513}),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({'publicClientKey': 'key\nvalue'}),
      throwsFormatException,
    );
  });

  test(
    'ransomware protection paths and trusted processes survive config json',
    () {
      const config = ZentorConfig(
        ransomwareProtectedRoots: ['C:/Users/Test/Documents'],
        ransomwareTrustedProcesses: ['C:/Program Files/Backup/backup.exe'],
      );

      final restored = ZentorConfig.fromJson(config.toJson());

      expect(restored.ransomwareProtectedRoots, ['C:/Users/Test/Documents']);
      expect(restored.ransomwareTrustedProcesses, [
        'C:/Program Files/Backup/backup.exe',
      ]);
    },
  );
  test('real-time protection preference survives config json', () {
    const config = ZentorConfig(realtimeProtectionEnabled: true);

    final restored = ZentorConfig.fromJson(config.toJson());

    expect(restored.realtimeProtectionEnabled, isTrue);
  });

  test('scheduled quick scan settings survive config json', () {
    const config = ZentorConfig(
      scheduledQuickScanEnabled: true,
      scheduledQuickScanIntervalHours: 12,
    );

    final restored = ZentorConfig.fromJson(config.toJson());

    expect(restored.scheduledQuickScanEnabled, isTrue);
    expect(restored.scheduledQuickScanIntervalHours, 12);
  });

  test('scheduled quick scan bounds are shared by runtime controls', () {
    expect(ZentorConfig.minScheduledQuickScanIntervalHours, 1);
    expect(ZentorConfig.maxScheduledQuickScanIntervalHours, 168);

    final protocolCandidates = [
      File('../../packages/zentor_protocol/lib/zentor_protocol.dart'),
      File('packages/zentor_protocol/lib/zentor_protocol.dart'),
    ];
    final protocol = protocolCandidates
        .firstWhere((file) => file.existsSync())
        .readAsStringSync();
    final appState = File('lib/app/app_state.dart').readAsStringSync();

    expect(protocol, contains('min: minScheduledQuickScanIntervalHours'));
    expect(protocol, contains('max: maxScheduledQuickScanIntervalHours'));
    expect(
      appState,
      contains('ZentorConfig.minScheduledQuickScanIntervalHours'),
    );
    expect(
      appState,
      contains('ZentorConfig.maxScheduledQuickScanIntervalHours'),
    );
    expect(appState, contains('scheduled_quick_scan_settings_failed'));
  });

  test('malformed safety-sensitive config fields are rejected', () {
    expect(
      () => ZentorConfig.fromJson({'realtimeProtectionEnabled': 'true'}),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({
        'ransomwareProtectedRoots': ['C:/Users/Test/Documents', 42],
      }),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({'scheduledQuickScanEnabled': 'true'}),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({'scheduledQuickScanIntervalHours': 0}),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({
        'protectedAppConfig': ['not', 'an', 'object'],
      }),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({'protectionMode': 'turbo'}),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({'protectionMode': 42}),
      throwsFormatException,
    );
  });

  test('config path lists trim entries and reject empty entries', () {
    final restored = ZentorConfig.fromJson({
      'scanPaths': [' C:/Users/Test/Downloads '],
      'ransomwareTrustedProcesses': [' C:/Program Files/App/app.exe '],
    });

    expect(restored.scanPaths, ['C:/Users/Test/Downloads']);
    expect(restored.ransomwareTrustedProcesses, [
      'C:/Program Files/App/app.exe',
    ]);
    expect(
      () => ZentorConfig.fromJson({
        'scanPaths': [' C:/Users/Test/Downloads ', ''],
      }),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({
        'ransomwareTrustedProcesses': [' C:/Program Files/App/app.exe ', '   '],
      }),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({
        'scanPaths': ['C:/Users/Test/Down\u0000loads'],
      }),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({
        'ransomwareProtectedRoots': ['C:/Users/Test/Documents\n'],
      }),
      throwsFormatException,
    );
  });

  test('config path lists are bounded', () {
    expect(
      () => ZentorConfig.fromJson({
        'scanPaths': List<String>.filled(
          ZentorConfig.maxConfigStringListEntries + 1,
          'C:/Users/Test/Downloads',
        ),
      }),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({
        'ransomwareProtectedRoots': [
          'C:/${'a' * ZentorConfig.maxConfigStringListEntryLength}x',
        ],
      }),
      throwsFormatException,
    );
  });

  test('runtime ransomware path settings use shared config bounds', () {
    final appState = File('lib/app/app_state.dart').readAsStringSync();
    final normalizer = appState.substring(
      appState.indexOf('List<String> _normalizeUserPaths'),
      appState.indexOf('Future<void> runProtectionSelfTest'),
    );

    expect(normalizer, contains('ZentorConfig.maxConfigStringListEntryLength'));
    expect(normalizer, contains('ZentorConfig.maxConfigStringListEntries'));
    expect(normalizer, contains('throw FormatException'));
    expect(
      normalizer,
      contains('value.length > ZentorConfig.maxConfigStringListEntryLength'),
    );
    expect(
      appState,
      contains(
        "_runtimePathListControlPattern = RegExp(r'[\\x00-\\x1F\\x7F]')",
      ),
    );
    expect(
      normalizer,
      contains('_runtimePathListControlPattern.hasMatch(raw)'),
    );
    expect(
      normalizer,
      contains('Path entries must not contain control characters.'),
    );
    expect(
      normalizer,
      contains('normalized.length > ZentorConfig.maxConfigStringListEntries'),
    );
  });

  test('runtime ransomware path settings reject control characters', () async {
    SharedPreferences.setMockInitialValues({});
    final preferences = await SharedPreferences.getInstance();
    final localCoreClient = _FakeLocalCoreClient();
    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        appDetectorProvider.overrideWithValue(const _FakeAppDetector()),
        localCoreClientProvider.overrideWithValue(localCoreClient),
        scanTargetServiceProvider.overrideWithValue(
          const _FakeScanTargetService(),
        ),
        updateServiceProvider.overrideWithValue(_FakeUpdateService()),
      ],
    );
    addTearDown(container.dispose);

    final controller = container.read(zentorControllerProvider.notifier);
    await _waitForControllerStartup(container);

    final changed = await controller.updateRansomwareGuardSettings(
      protectedRoots: ['C:/Users/Test/Documents\u0000bad'],
      trustedProcesses: const ['C:/Program Files/App/app.exe'],
      confirmed: true,
    );

    final state = container.read(zentorControllerProvider);
    expect(changed, isFalse);
    expect(localCoreClient.ransomwareGuardCalls, 0);
    expect(state.config.ransomwareProtectedRoots, isEmpty);
    expect(
      state.errorMessage,
      contains('Path entries must not contain control characters.'),
    );
    final failureEvent = state.events.firstWhere(
      (event) => event.type == 'ransomware_guard_settings_failed',
    );
    expect(failureEvent.details, contains('Path entries must not contain'));
    expect(preferences.getString('zentor.config.v1'), isNull);
  });

  test('protected app config fields are trimmed and validated', () {
    final restored = ProtectedAppConfig.fromJson({
      'appName': ' Sample App ',
      'appPath': ' C:/Program Files/Sample/sample.exe ',
      'expectedBuildHash': 'A' * 64,
      'lastCalculatedHash': 'b' * 64,
      'protectionProfile': ' standard ',
    });

    expect(restored.appName, 'Sample App');
    expect(restored.appPath, 'C:/Program Files/Sample/sample.exe');
    expect(restored.expectedBuildHash, 'a' * 64);
    expect(restored.lastCalculatedHash, 'b' * 64);
    expect(restored.protectionProfile, 'standard');
    expect(ProtectedAppConfig.fromJson({}).protectionProfile, 'standard');
  });

  test('malformed protected app config fields are rejected', () {
    expect(
      () => ProtectedAppConfig.fromJson({'appName': 42}),
      throwsFormatException,
    );
    expect(
      () => ProtectedAppConfig.fromJson({
        'appPath': 'C:/${'a' * ProtectedAppConfig.maxProtectedAppPathLength}x',
      }),
      throwsFormatException,
    );
    expect(
      () => ProtectedAppConfig.fromJson({'expectedBuildHash': 'not-a-sha256'}),
      throwsFormatException,
    );
    expect(
      () => ProtectedAppConfig.fromJson({'lastCalculatedHash': 'f' * 65}),
      throwsFormatException,
    );
    expect(
      () => ProtectedAppConfig.fromJson({'protectionProfile': '   '}),
      throwsFormatException,
    );
    expect(
      () => ProtectedAppConfig.fromJson({'appName': 'Sample\u0000App'}),
      throwsFormatException,
    );
    expect(
      () => ProtectedAppConfig.fromJson({
        'appPath': 'C:/Program Files/Sample/sample.exe\n',
      }),
      throwsFormatException,
    );
    expect(
      () => ProtectedAppConfig.fromJson({'protectionProfile': 'standard\t'}),
      throwsFormatException,
    );
  });

  test('protected app config normalization covers runtime selection paths', () {
    final restored = ProtectedAppConfig(
      appName: ' Runtime App ',
      appPath: ' C:/Program Files/Runtime/runtime.exe ',
      expectedBuildHash: '',
      lastCalculatedHash: 'C' * 64,
    ).normalized();

    expect(restored.appName, 'Runtime App');
    expect(restored.appPath, 'C:/Program Files/Runtime/runtime.exe');
    expect(restored.lastCalculatedHash, 'c' * 64);

    final appState = File('lib/app/app_state.dart').readAsStringSync();
    expect(appState, contains('.normalized()'));
    expect(
      appState,
      contains('scanPaths: {...state.config.scanPaths, app.appPath}'),
    );
  });

  test(
    'config repository reports recovered corrupt persisted policy',
    () async {
      SharedPreferences.setMockInitialValues({
        'zentor.config.v1': '{"realtimeProtectionEnabled":"true"}',
      });
      final preferences = await SharedPreferences.getInstance();
      final repository = ConfigRepository(preferences);

      final config = repository.load();

      expect(config.realtimeProtectionEnabled, isFalse);
      expect(repository.lastLoadRecoveryReason, contains('Persisted config'));
    },
  );

  test(
    'config repository bounds persisted policy JSON before parsing',
    () async {
      SharedPreferences.setMockInitialValues({
        'zentor.config.v1': 'x' * (256 * 1024 + 1),
      });
      final preferences = await SharedPreferences.getInstance();
      final repository = ConfigRepository(preferences);

      final config = repository.load();

      expect(config.apiBaseUrl, const BuildConfig().apiBaseUrl);
      expect(repository.lastLoadRecoveryReason, contains('size limit'));
    },
  );

  test(
    'config repository rejects invalid enabled developer cloud override before persistence',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final repository = ConfigRepository(preferences);
      const storedConfig = ZentorConfig(
        developerOverrideEnabled: true,
        apiBaseUrl: 'https://api.example.test',
        projectId: 'project-1',
        publicClientKey: 'public-key',
      );
      await repository.save(storedConfig);
      final rawBefore = preferences.getString('zentor.config.v1');

      await expectLater(
        repository.save(
          const ZentorConfig(
            developerOverrideEnabled: true,
            apiBaseUrl: 'ftp://api.example.test',
            projectId: 'project-1',
            publicClientKey: 'public-key',
          ),
        ),
        throwsA(
          isA<FormatException>().having(
            (error) => error.message,
            'message',
            contains('Developer cloud override is invalid'),
          ),
        ),
      );

      final rawAfter = preferences.getString('zentor.config.v1');
      expect(rawAfter, rawBefore);
      expect(jsonDecode(rawAfter!)['apiBaseUrl'], 'https://api.example.test');
      expect(repository.load().apiBaseUrl, 'https://api.example.test');
    },
  );

  test('source marker: config JSON is size bounded before parsing', () {
    final source = File(
      'lib/core/config/config_repository.dart',
    ).readAsStringSync();
    final loadMethod = source.substring(
      source.indexOf('ZentorConfig load()'),
      source.indexOf('Future<void> save'),
    );

    expect(
      source,
      contains('static const _maxPersistedConfigJsonChars = 256 * 1024'),
    );
    expect(source, contains('_maxConfigRecoveryDiagnosticChars'));
    expect(
      source,
      contains('String _boundedConfigRecoveryDiagnostic(Object error)'),
    );
    expect(source, contains(r"RegExp(r'[\x00-\x1F\x7F]+')"));
    expect(
      source,
      contains('substring(0, _maxConfigRecoveryDiagnosticChars - 3)'),
    );
    expect(loadMethod, contains('raw.length > _maxPersistedConfigJsonChars'));
    expect(loadMethod, contains('_boundedConfigRecoveryDiagnostic(error)'));
    expect(
      loadMethod,
      isNot(contains('build defaults were restored: \$error')),
    );
    expect(
      loadMethod.indexOf('raw.length > _maxPersistedConfigJsonChars'),
      lessThan(loadMethod.indexOf('jsonDecode(raw)')),
    );
  });

  test('source marker: config repository checks persistence acknowledgements', () {
    final source = File(
      'lib/core/config/config_repository.dart',
    ).readAsStringSync();
    final saveMethod = source.substring(
      source.indexOf('Future<void> save'),
      source.indexOf('Future<void> reset'),
    );
    final resetMethod = source.substring(
      source.indexOf('Future<void> reset'),
      source.indexOf('ZentorConfig _buildConfigDefaults'),
    );

    expect(saveMethod, contains('final stored = await _setString'));
    expect(saveMethod, contains('if (!stored)'));
    expect(
      saveMethod,
      contains(
        'Configuration save failed: SharedPreferences did not accept the persisted policy.',
      ),
    );
    expect(resetMethod, contains('final removed = await _remove'));
    expect(resetMethod, contains('if (!removed)'));
    expect(
      resetMethod,
      contains(
        'Configuration reset failed: SharedPreferences did not remove the persisted policy.',
      ),
    );
    expect(saveMethod, isNot(contains('\n    await _preferences.setString(')));
    expect(resetMethod, isNot(contains('\n    await _preferences.remove(')));
  });

  test(
    'config save acknowledgement rejection fails visibly at runtime',
    () async {
      SharedPreferences.setMockInitialValues({});
      final preferences = await SharedPreferences.getInstance();
      final repository = ConfigRepository(
        preferences,
        debugSetString: (_, _) async => false,
      );

      await expectLater(
        repository.save(const ZentorConfig()),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            contains('Configuration save failed'),
          ),
        ),
      );
      expect(preferences.getString('zentor.config.v1'), isNull);
    },
  );

  test(
    'config reset acknowledgement rejection fails visibly at runtime',
    () async {
      SharedPreferences.setMockInitialValues({
        'zentor.config.v1': jsonEncode(const ZentorConfig().toJson()),
      });
      final preferences = await SharedPreferences.getInstance();
      final repository = ConfigRepository(
        preferences,
        debugRemove: (_) async => false,
      );

      await expectLater(
        repository.reset(),
        throwsA(
          isA<StateError>().having(
            (error) => error.message,
            'message',
            contains('Configuration reset failed'),
          ),
        ),
      );
      expect(preferences.getString('zentor.config.v1'), isNotNull);
    },
  );

  test('startup surfaces config recovery warning markers', () {
    final appStateSource = File('lib/app/app_state.dart').readAsStringSync();

    expect(appStateSource, contains('lastLoadRecoveryReason'));
    expect(appStateSource, contains('configuration_recovered'));
    expect(
      appStateSource,
      contains('Configuration recovered from invalid persisted data'),
    );
    expect(appStateSource, contains('errorMessage: configRecoveryReason'));
  });

  test('startup surfaces config recovery warning at runtime', () async {
    SharedPreferences.setMockInitialValues({
      'zentor.config.v1': '{"scheduledQuickScanIntervalHours":0}',
    });
    final preferences = await SharedPreferences.getInstance();
    final container = ProviderContainer(
      overrides: [
        sharedPreferencesProvider.overrideWithValue(preferences),
        appDetectorProvider.overrideWithValue(const _FakeAppDetector()),
        localCoreClientProvider.overrideWithValue(_FakeLocalCoreClient()),
        scanTargetServiceProvider.overrideWithValue(
          const _FakeScanTargetService(),
        ),
        updateServiceProvider.overrideWithValue(_FakeUpdateService()),
      ],
    );
    addTearDown(container.dispose);

    container.read(zentorControllerProvider);
    await _waitForControllerStartup(container);

    final state = container.read(zentorControllerProvider);
    expect(
      state.errorMessage,
      contains('Persisted config was invalid and build defaults were restored'),
    );
    final recoveryEvent = state.events.firstWhere(
      (event) => event.type == 'configuration_recovered',
    );
    expect(recoveryEvent.category, 'app');
    expect(recoveryEvent.severity, 'warning');
    expect(
      recoveryEvent.details,
      contains('Persisted config was invalid and build defaults were restored'),
    );
  });

  test('local event fields are typed and bounded', () {
    final event = LocalEvent.fromJson({
      'id': ' event-1 ',
      'type': ' scan ',
      'message': ' Completed ',
      'createdAt': '2026-06-23T12:00:00Z',
      'details': ' ok ',
      'category': ' scan ',
      'severity': ' warning ',
    });

    expect(event.id, 'event-1');
    expect(event.type, 'scan');
    expect(event.message, 'Completed');
    expect(event.details, 'ok');
    expect(event.category, 'scan');
    expect(event.severity, 'warning');
    final settingsEvent = LocalEvent.fromJson({
      'id': 'event-settings',
      'type': 'settings',
      'message': 'Settings changed',
      'createdAt': '2026-06-23T12:00:00Z',
      'category': ' settings ',
      'severity': ' info ',
    });
    expect(settingsEvent.category, 'settings');
    expect(settingsEvent.severity, 'info');
    expect(() => LocalEvent.fromJson({'message': 42}), throwsFormatException);
    expect(
      () => LocalEvent.fromJson({
        'type': 'scan',
        'message': 'Completed',
        'createdAt': '2026-06-23T12:00:00Z',
      }),
      throwsFormatException,
    );
    expect(
      () => LocalEvent.fromJson({
        'id': 'event-1',
        'type': '',
        'message': 'Completed',
        'createdAt': '2026-06-23T12:00:00Z',
      }),
      throwsFormatException,
    );
    expect(
      () => LocalEvent.fromJson({'details': 'd' * 4097}),
      throwsFormatException,
    );
    expect(
      () => LocalEvent.fromJson({'createdAt': 't' * 65}),
      throwsFormatException,
    );
    expect(
      () => LocalEvent.fromJson({
        'id': 'event-1',
        'type': 'scan',
        'message': 'Completed',
        'createdAt': 'not-a-date',
      }),
      throwsFormatException,
    );
    expect(
      () => LocalEvent.fromJson({
        'id': 'event-1',
        'type': 'scan',
        'message': 'Complete\u0000d',
        'createdAt': '2026-06-23T12:00:00Z',
      }),
      throwsFormatException,
    );
    expect(
      () => LocalEvent.fromJson({
        'id': 'event-1',
        'type': 'scan',
        'message': 'Completed',
        'createdAt': '2026-06-23T12:00:00Z',
        'details': 'line\nbreak',
      }),
      throwsFormatException,
    );
    expect(
      () => LocalEvent.fromJson({
        'id': 'event-1',
        'type': 'scan',
        'message': 'Completed',
        'createdAt': '2026-06-23T12:00:00Z',
        'category': ' settings\n',
      }),
      throwsFormatException,
    );
    expect(
      () => LocalEvent.fromJson({
        'id': 'event-1',
        'type': 'scan',
        'message': 'Completed',
        'createdAt': '2026-06-23T12:00:00Z\n',
      }),
      throwsFormatException,
    );
    expect(
      () => LocalEvent.fromJson({
        'id': 'event-1',
        'type': 'scan',
        'message': 'Completed',
        'createdAt': '2026-06-23T12:00:00Z',
        'category': 'forged',
        'severity': 'critical',
      }),
      throwsFormatException,
    );
  });
}

Future<void> _waitForControllerStartup(ProviderContainer container) async {
  for (var attempt = 0; attempt < 50; attempt += 1) {
    await Future<void>.delayed(Duration.zero);
    final state = container.read(zentorControllerProvider);
    if (attempt >= 5 &&
        !state.updateOperationInFlight &&
        !state.malwareEngineHealthCheckInFlight &&
        !state.appDetectionInFlight &&
        !state.quarantineRefreshInFlight) {
      return;
    }
  }
}

class _FakeAppDetector extends AppDetector {
  const _FakeAppDetector();

  @override
  bool get supportsAutomaticDetection => false;

  @override
  Future<List<DetectedApp>> detect() async => const [];
}

class _FakeLocalCoreClient extends LocalCoreClient {
  _FakeLocalCoreClient();

  int ransomwareGuardCalls = 0;

  @override
  Future<MalwareEngineStatus> health() async => MalwareEngineStatus.available;

  @override
  Future<LocalCoreHealth> healthSummary() async => const LocalCoreHealth(
    malwareEngineStatus: MalwareEngineStatus.available,
    nativeEngineStatus: 'ready',
    coreServiceStatus: 'running',
    guardStatus: 'running',
  );

  @override
  Future<List<QuarantineRecord>> listQuarantine() async => const [];

  @override
  Future<LocalCoreActionResult> configureRansomwareGuard({
    required List<String> protectedRoots,
    required List<String> trustedProcesses,
  }) async {
    ransomwareGuardCalls += 1;
    return const LocalCoreActionResult.ok();
  }
}

class _FakeScanTargetService extends ScanTargetService {
  const _FakeScanTargetService();
}

class _FakeUpdateService extends ZentorUpdateService {
  @override
  Future<UpdateCheckResult> checkForUpdate({String? currentVersion}) async =>
      UpdateCheckResult.upToDate(currentVersion ?? '0.1.15');
}
