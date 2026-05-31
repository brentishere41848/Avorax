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

  test('medium heuristic verdict labels request review instead of detected', () {
    expect(RiskVerdict.unknown.label, 'Review suggested');
    expect(RiskVerdict.suspicious.label, 'Review suggested');
    expect(RiskVerdict.probableMalware.label, 'Probable malware');
    expect(RiskVerdict.confirmedMalware.label, 'Confirmed threat');
  });
}
