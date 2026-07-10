import 'package:zentor_protocol/zentor_protocol.dart';
import 'package:test/test.dart';

void main() {
  test('ProtectionStatus maps to user-facing labels', () {
    expect(ProtectionStatus.idle.label, 'Protection Idle');
    expect(ProtectionStatus.protected.label, 'Verified Protection Active');
    expect(ProtectionStatus.localOnly.label, 'Local Protection Active');
  });

  test('ZentorConfig validates cloud settings', () {
    final config = ZentorConfig(apiBaseUrl: 'not-a-url');
    expect(config.validateCloudConfiguration(), hasLength(2));

    final valid = ZentorConfig(
      apiBaseUrl: 'https://api.zentor.example',
      projectId: 'project',
      publicClientKey: 'key',
    );
    expect(valid.validateCloudConfiguration(), isEmpty);
  });

  test('ZentorConfig bounds cloud settings', () {
    expect(
      ZentorConfig(
        apiBaseUrl: 'https://api.zentor.example/${'a' * 2048}',
        projectId: 'project',
        publicClientKey: 'key',
      ).validateCloudConfiguration(),
      contains('Avorax Cloud endpoint is too long.'),
    );
    expect(
      ZentorConfig(
        apiBaseUrl: 'https://api.zentor.example',
        projectId: 'project\nid',
        publicClientKey: 'key',
      ).validateCloudConfiguration(),
      contains(
        'Avorax Cloud project ID contains unsupported control characters.',
      ),
    );
    expect(
      ZentorConfig(
        apiBaseUrl: 'https://api.zentor.example',
        projectId: 'project',
        publicClientKey: 'key\u0000value',
      ).validateCloudConfiguration(),
      contains(
        'Avorax Cloud public client key contains unsupported control characters.',
      ),
    );
    expect(
      () => ZentorConfig.fromJson({'apiBaseUrl': 42}),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({'apiBaseUrl': 'https://api.test/\u0000'}),
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
  });

  test('ZentorConfig rejects control text in config string lists', () {
    expect(
      () => ZentorConfig.fromJson({
        'scanPaths': ['C:/Users/Test/Down\u0000loads'],
      }),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({
        'ransomwareTrustedProcesses': ['C:/Program Files/App/app.exe\n'],
      }),
      throwsFormatException,
    );
  });

  test('ZentorConfig rejects blank config string-list entries', () {
    expect(
      () => ZentorConfig.fromJson({
        'scanPaths': ['C:/Users/Test/Downloads', '   '],
      }),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({
        'ransomwareProtectedRoots': ['C:/Users/Test/Documents', ''],
      }),
      throwsFormatException,
    );
    expect(
      () => ZentorConfig.fromJson({
        'ransomwareTrustedProcesses': ['C:/Program Files/App/app.exe', '\t'],
      }),
      throwsFormatException,
    );
  });

  test('ProtectedAppConfig rejects control text in identity fields', () {
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

  test('ProtectedAppConfig rejects blank protection profile when present', () {
    expect(ProtectedAppConfig.fromJson({}).protectionProfile, 'standard');
    expect(
      () => ProtectedAppConfig.fromJson({'protectionProfile': '   '}),
      throwsFormatException,
    );
  });

  test('ZentorConfig defaults to Balanced protection', () {
    const config = ZentorConfig();
    expect(config.protectionMode, ProtectionMode.balanced);
    expect(config.protectionMode.label, 'Balanced Protection');

    final lockdown = config.copyWith(protectionMode: ProtectionMode.lockdown);
    expect(lockdown.toJson()['protectionMode'], 'lockdown');
    expect(
      ZentorConfig.fromJson(lockdown.toJson()).protectionMode,
      ProtectionMode.lockdown,
    );
  });

  test(
    'medium heuristic verdict labels request review instead of detected',
    () {
      expect(RiskVerdict.unknown.label, 'Review suggested');
      expect(RiskVerdict.suspicious.label, 'Review suggested');
      expect(RiskVerdict.probableMalware.label, 'Probable malware');
      expect(RiskVerdict.confirmedMalware.label, 'Confirmed threat');
    },
  );

  test('ScanActionMode labels do not imply review-only auto-quarantine', () {
    expect(ScanActionMode.detectOnly.label, 'Detect only');
    expect(
      ScanActionMode.autoQuarantineConfirmedOnly.label,
      'Auto-quarantine confirmed threats',
    );
    expect(
      ScanActionMode.autoQuarantineAllDetections.label,
      'Legacy confirmed-only quarantine',
    );
  });

  test('ThreatCategory labels cover small-threat review categories', () {
    expect(ThreatCategory.infostealer.label, 'Potential infostealer');
    expect(ThreatCategory.miner.label, 'Potential miner');
    expect(ThreatCategory.persistenceIndicator.label, 'Persistence indicator');
    expect(
      ThreatCategory.credentialTheftIndicator.label,
      'Credential theft indicator',
    );
    expect(ThreatCategory.suspiciousDownloader.label, 'Suspicious downloader');
    expect(ThreatCategory.suspiciousScript.label, 'Suspicious script');
    expect(
      ThreatCategory.securityTamperIndicator.label,
      'Security tamper indicator',
    );
  });

  test('ThreatResult keeps optional quarantine evidence when copied', () {
    final result = ThreatResult(
      id: 'threat-1',
      path: 'C:/Users/Brent/Downloads/eicar.com',
      fileName: 'eicar.com',
      sha256: 'a' * 64,
      sizeBytes: 68,
      detectionType: DetectionType.signature,
      threatCategory: ThreatCategory.unknown,
      threatName: 'EICAR safe anti-malware test file',
      confidence: ThreatConfidence.confirmed,
      engine: 'Avorax Native Engine',
      detectedAt: DateTime.utc(2026),
      recommendedAction: RecommendedAction.quarantine,
      status: ThreatResultStatus.quarantined,
      riskScore: const RiskScore(
        score: 100,
        verdict: RiskVerdict.confirmedMalware,
        confidence: ThreatConfidence.confirmed,
        reasons: [],
        recommendedAction: RecommendedAction.quarantine,
        enginesUsed: [DetectionType.signature],
      ),
      quarantineId: 'record-1',
      quarantinePath: 'C:/ProgramData/Avorax/Quarantine/record-1.avoraxq',
      quarantineActionTaken: 'quarantined',
    );

    final copied = result.copyWith(status: ThreatResultStatus.restored);

    expect(copied.quarantineId, 'record-1');
    expect(copied.quarantinePath, endsWith('.avoraxq'));
    expect(copied.quarantineActionTaken, 'quarantined');
  });

  test('LocalEvent fields are typed and bounded', () {
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
    expect(event.createdAt.toUtc().year, 2026);

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

    final missingOptionalFields = LocalEvent.fromJson({
      'id': 'event-1',
      'type': 'scan',
      'message': 'Completed',
      'createdAt': '2026-06-23T12:00:00Z',
    });
    expect(missingOptionalFields.category, 'app');
    expect(missingOptionalFields.severity, 'info');

    expect(
      () => LocalEvent.fromJson({
        'id': 'event-1',
        'type': 'scan',
        'message': 'Completed',
        'createdAt': '2026-06-23T12:00:00Z',
        'category': 'forged',
      }),
      throwsFormatException,
    );
    expect(
      () => LocalEvent.fromJson({
        'id': 'event-1',
        'type': 'scan',
        'message': 'Completed',
        'createdAt': '2026-06-23T12:00:00Z',
        'severity': 'critical',
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

  test('LocalEvent rejects raw control text in every persisted field', () {
    Map<String, Object?> baseEvent() => {
      'id': 'event-1',
      'type': 'scan',
      'message': 'Completed',
      'createdAt': '2026-06-23T12:00:00Z',
      'details': 'details',
      'category': 'scan',
      'severity': 'info',
    };

    const malformedFields = <String, Object?>{
      'id': 'event-\u00001',
      'type': 'scan\ncompleted',
      'message': 'Complete\u0000d',
      'createdAt': '2026-06-23T12:00:00Z\n',
      'details': 'line\nbreak',
      'category': 'scan\t',
      'severity': 'info\u0000',
    };

    for (final MapEntry(:key, :value) in malformedFields.entries) {
      expect(
        () => LocalEvent.fromJson({...baseEvent(), key: value}),
        throwsFormatException,
        reason: 'LocalEvent.$key must reject raw control text',
      );
    }
  });
}
