import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../core/local_core/local_core_client.dart';
import '../../core/updates/update_service.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_status_card.dart';
import '../../shared/widgets/zentor_text_field.dart';
import '../update/update_confirmation.dart';
import '../update/update_mutation_guard.dart';

const int _maxSettingsDiagnosticChars = 4096;

String _boundedSettingsDiagnostic(Object error) {
  final text = '$error'.replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ').trim();
  if (text.isEmpty) return 'unknown error';
  if (text.length <= _maxSettingsDiagnosticChars) return text;
  return '${text.substring(0, _maxSettingsDiagnosticChars - 3)}...';
}

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  late final TextEditingController _endpoint;
  late final TextEditingController _projectId;
  late final TextEditingController _publicKey;
  late final TextEditingController _ransomwareProtectedRoots;
  late final TextEditingController _ransomwareTrustedProcesses;
  bool _developerOptions = false;

  @override
  void initState() {
    super.initState();
    final config = ref.read(zentorControllerProvider).config;
    _endpoint = TextEditingController(text: config.apiBaseUrl);
    _projectId = TextEditingController(text: config.projectId);
    _publicKey = TextEditingController(text: config.publicClientKey);
    _ransomwareProtectedRoots = TextEditingController(
      text: config.ransomwareProtectedRoots.join('\n'),
    );
    _ransomwareTrustedProcesses = TextEditingController(
      text: config.ransomwareTrustedProcesses.join('\n'),
    );
    _developerOptions = config.developerOverrideEnabled;
  }

  @override
  void dispose() {
    _endpoint.dispose();
    _projectId.dispose();
    _publicKey.dispose();
    _ransomwareProtectedRoots.dispose();
    _ransomwareTrustedProcesses.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
    final engineDiagnostic = state.lastEngineError?.trim();
    final updateBusy =
        state.updateOperationInFlight ||
        {
          UpdateStatus.checking,
          UpdateStatus.downloading,
          UpdateStatus.verifying,
          UpdateStatus.installing,
          UpdateStatus.rollingBack,
        }.contains(state.updateStatus);
    final updateMutationBusy = updateMutationOperationInProgress(state);
    final updateMutationBlocked = updateMutationBlockedByActiveWork(state);
    final engineCheckBusy =
        state.malwareEngineHealthCheckInFlight ||
        state.malwareEngineStatus == MalwareEngineStatus.checking;
    final cloudCheckBusy =
        state.cloudHealthCheckInFlight ||
        state.cloudStatus == CloudStatus.checking;
    final protectionOperationBusy = state.protectionOperationInFlight;
    final securitySettingsBusy = state.securitySettingsActionInFlight;
    final protectionSelfTestBusy = state.protectionSelfTestInFlight;
    final configurationResetBusy = state.configurationResetInFlight;
    final manualDispositionBusy =
        state.quarantineActionInFlight ||
        state.allowlistActionInFlight ||
        state.detectionFeedbackInFlight;
    final scanOperationBusy =
        state.scanStartInFlight ||
        state.scanStatus == ScanStatus.running ||
        state.scanTargetSelectionInFlight ||
        state.scanCancelInFlight;
    final securitySettingsControlsBusy =
        securitySettingsBusy ||
        configurationResetBusy ||
        protectionOperationBusy ||
        protectionSelfTestBusy ||
        manualDispositionBusy ||
        scanOperationBusy ||
        updateMutationBusy;
    final configurationResetControlsBusy =
        configurationResetBusy ||
        securitySettingsBusy ||
        protectionOperationBusy ||
        protectionSelfTestBusy ||
        manualDispositionBusy ||
        scanOperationBusy ||
        updateMutationBusy;
    final developerCloudOverrideBusy =
        state.developerCloudOverrideInFlight || updateMutationBusy;
    final logExportBusy = state.logExportInFlight;
    final supportBundleExportBusy = state.supportBundleExportInFlight;
    final scheduledIntervalPreset =
        {6, 12, 24, 168}.contains(state.config.scheduledQuickScanIntervalHours)
        ? state.config.scheduledQuickScanIntervalHours
        : null;
    return Column(
      children: [
        _Section(
          title: 'General',
          children: const [
            _ValueRow('App', 'Avorax'),
            _ValueRow('Mode', 'Desktop antivirus and security client'),
          ],
        ),
        _Section(
          title: 'Cloud',
          children: [
            _ValueRow('Endpoint', state.config.apiBaseUrl),
            _ValueRow('Status', state.cloudStatus.label),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                ZentorButton(
                  label: cloudCheckBusy
                      ? 'Checking Cloud'
                      : 'Test Cloud Connection',
                  icon: Icons.cloud_sync_outlined,
                  secondary: true,
                  onPressed: cloudCheckBusy
                      ? null
                      : controller.testCloudConnection,
                ),
              ],
            ),
          ],
        ),
        _Section(
          title: 'Updates',
          children: [
            _ValueRow('Installed version', state.currentAppVersion),
            _ValueRow('Status', state.updateStatus.label),
            if (state.updateInfo != null) ...[
              _ValueRow('Latest version', state.updateInfo!.latestVersion),
              _ValueRow('Channel', state.updateInfo!.channel),
              _ValueRow(
                'Update package',
                state.updateInfo!.packageName ?? 'No package available',
              ),
              _ValueRow(
                'Rollback',
                _rollbackSupportLabel(state.updateInfo!.rollbackSupported),
              ),
            ],
            if (state.updateError != null)
              _ValueRow('Last check', state.updateError!),
            const Text(
              'Avorax installs normal updates inside the app from signed .aup packages. '
              'The MSI/EXE installer is for first install, repair, recovery, and offline manual install.',
              style: TextStyle(color: ZentorColors.textSecondary, height: 1.4),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                ZentorButton(
                  label: state.updateStatus == UpdateStatus.checking
                      ? 'Checking'
                      : 'Check for updates',
                  icon: Icons.update_outlined,
                  secondary: true,
                  onPressed: updateBusy
                      ? null
                      : controller.unawaitedCheckForUpdates,
                ),
                if (state.updateStatus == UpdateStatus.updateAvailable ||
                    state.updateStatus == UpdateStatus.downloading ||
                    state.updateStatus == UpdateStatus.verifying ||
                    state.updateStatus == UpdateStatus.installing)
                  ZentorButton(
                    label: switch (state.updateStatus) {
                      UpdateStatus.downloading => 'Downloading',
                      UpdateStatus.verifying => 'Verifying',
                      UpdateStatus.installing => 'Installing',
                      _ => 'Download, verify, install',
                    },
                    icon: Icons.system_update_alt_outlined,
                    onPressed: updateBusy || updateMutationBlocked
                        ? null
                        : () async {
                            if (!await confirmInstallUpdate(context)) return;
                            await controller.installUpdateInApp(
                              confirmed: true,
                            );
                          },
                  ),
              ],
            ),
          ],
        ),
        _Section(
          title: 'Protection',
          children: [
            _ValueRow('Antivirus', _settingsProtectionStatusLabel(state)),
            _ValueRow('Profile', state.config.protectionMode.label),
            DropdownButtonFormField<ProtectionMode>(
              key: ValueKey(state.config.protectionMode),
              initialValue: state.config.protectionMode,
              isExpanded: true,
              dropdownColor: ZentorColors.elevatedSurface,
              decoration: const InputDecoration(labelText: 'Protection mode'),
              items: ProtectionMode.values
                  .where((mode) => mode != ProtectionMode.off)
                  .map(
                    (mode) =>
                        DropdownMenuItem(value: mode, child: Text(mode.label)),
                  )
                  .toList(),
              onChanged: securitySettingsControlsBusy
                  ? null
                  : (mode) {
                      if (mode != null) {
                        _confirmProtectionMode(controller, mode);
                      }
                    },
            ),
            const SizedBox(height: 8),
            Text(
              state.config.protectionMode == ProtectionMode.lockdown
                  ? 'Lockdown requests exact-hash approval for unknown apps. True before-launch blocking requires the signed driver path to be running and passing self-test; otherwise Avorax uses visible user-mode fallback.'
                  : state.config.protectionMode.description,
              style: const TextStyle(
                color: ZentorColors.textSecondary,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 10),
            _ValueRow('Core Service', _serviceLabel(state.coreServiceStatus)),
            if (state.coreServiceStatusError?.trim().isNotEmpty ?? false)
              _ValueRow('Core Service detail', state.coreServiceStatusError!),
            _ValueRow(
              'Core Service IPC',
              _serviceBoundaryLabel(state.coreServiceBoundaryHealth),
            ),
            if (state.coreServiceBoundaryHealth.diagnostic?.trim().isNotEmpty ??
                false)
              _ValueRow(
                'Core Service IPC detail',
                state.coreServiceBoundaryHealth.diagnostic!,
              ),
            _ValueRow('Guard mode', _guardLabel(state.guardStatus)),
            if (state.guardStatusError?.trim().isNotEmpty ?? false)
              _ValueRow('Guard detail', state.guardStatusError!),
            _ValueRow('Driver status', _driverLabel(state.driverStatus)),
            if (state.protectionSelfTestResult != null)
              _ValueRow('Last self-test', state.protectionSelfTestResult!),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                ZentorButton(
                  label: protectionSelfTestBusy
                      ? 'Running Protection Self-Test'
                      : 'Run Protection Self-Test',
                  icon: Icons.verified_user_outlined,
                  secondary: true,
                  onPressed:
                      state.loading ||
                          protectionOperationBusy ||
                          protectionSelfTestBusy ||
                          updateMutationBusy
                      ? null
                      : controller.runProtectionSelfTest,
                ),
              ],
            ),
            const SizedBox(height: 10),
            _ValueRow(
              'Realtime monitoring',
              state.config.realtimeProtectionEnabled
                  ? 'Enabled for protected locations'
                  : 'Off',
            ),
            const SizedBox(height: 12),
            ZentorTextField(
              controller: _ransomwareProtectedRoots,
              label: 'Ransomware protected folders',
              enabled: !securitySettingsControlsBusy,
              hint: 'One folder per line, e.g. C:/Users/You/Documents',
              minLines: 2,
              maxLines: 4,
            ),
            const SizedBox(height: 8),
            ZentorTextField(
              controller: _ransomwareTrustedProcesses,
              label: 'Trusted backup/sync processes',
              enabled: !securitySettingsControlsBusy,
              hint:
                  'One executable path per line, e.g. C:/Program Files/Backup/backup.exe',
              minLines: 2,
              maxLines: 4,
            ),
            const SizedBox(height: 8),
            ZentorButton(
              label: securitySettingsBusy
                  ? 'Saving security settings'
                  : 'Save ransomware protection settings',
              icon: Icons.folder_special_outlined,
              secondary: true,
              onPressed: state.loading || securitySettingsControlsBusy
                  ? null
                  : () => _confirmRansomwareGuardSettings(controller),
            ),
          ],
        ),
        _Section(
          title: 'Scan scheduling',
          children: [
            _ValueRow(
              'Scheduled quick scan',
              state.config.scheduledQuickScanEnabled
                  ? 'Every ${state.config.scheduledQuickScanIntervalHours} hour(s)'
                  : 'Off',
            ),
            const Text(
              'Runs detect-only quick scans while the Avorax app is open. It does not install a Windows scheduled task or claim background service execution.',
              style: TextStyle(color: ZentorColors.textSecondary, height: 1.4),
            ),
            Material(
              color: Colors.transparent,
              child: SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('Enable in-app scheduled quick scan'),
                subtitle: const Text(
                  'Best-effort app-lifetime schedule; no automatic quarantine.',
                  style: TextStyle(color: ZentorColors.textSecondary),
                ),
                value: state.config.scheduledQuickScanEnabled,
                onChanged: securitySettingsControlsBusy
                    ? null
                    : (enabled) => _confirmScheduledQuickScanSettings(
                        controller,
                        enabled: enabled,
                        intervalHours:
                            state.config.scheduledQuickScanIntervalHours,
                      ),
              ),
            ),
            const SizedBox(height: 8),
            DropdownButtonFormField<int>(
              key: ValueKey(
                'scheduled-${state.config.scheduledQuickScanEnabled}-$scheduledIntervalPreset',
              ),
              initialValue: scheduledIntervalPreset,
              isExpanded: true,
              dropdownColor: ZentorColors.elevatedSurface,
              decoration: const InputDecoration(labelText: 'Scan interval'),
              items: const [
                DropdownMenuItem(value: 6, child: Text('Every 6 hours')),
                DropdownMenuItem(value: 12, child: Text('Every 12 hours')),
                DropdownMenuItem(value: 24, child: Text('Daily')),
                DropdownMenuItem(value: 168, child: Text('Weekly')),
              ],
              onChanged: securitySettingsControlsBusy
                  ? null
                  : (intervalHours) {
                      if (intervalHours == null) return;
                      _confirmScheduledQuickScanSettings(
                        controller,
                        enabled: state.config.scheduledQuickScanEnabled,
                        intervalHours: intervalHours,
                      );
                    },
            ),
          ],
        ),
        _Section(
          title: 'Avorax Native Engine',
          children: [
            _ValueRow('Engine status', state.malwareEngineStatus.label),
            _ValueRow('Native status', _nativeEngineLabel(state)),
            _ValueRow('IPC', _ipcModeLabel(state.ipcMode)),
            _ValueRow(
              'Network exposed',
              _networkExposureLabel(state.networkExposed),
            ),
            if (engineDiagnostic?.isNotEmpty ?? false)
              _ValueRow('Engine diagnostic', engineDiagnostic!),
            _ValueRow(
              'Native self-test',
              _selfTestLabel(state.nativeSelfTestPassed),
            ),
            if (state.nativeEngineError?.trim().isNotEmpty ?? false)
              _ValueRow('Native engine error', state.nativeEngineError!),
            if (state.nativeSelfTestError?.trim().isNotEmpty ?? false)
              _ValueRow('Native self-test error', state.nativeSelfTestError!),
            _ValueRow('AI self-test', _selfTestLabel(state.aiSelfTestPassed)),
            if (state.aiSelfTestError?.trim().isNotEmpty ?? false)
              _ValueRow('AI self-test error', state.aiSelfTestError!),
            _ValueRow(
              'ProgramData dir',
              _optionalPathLabel(state.programDataDirectory),
            ),
            if (state.programDataDirectoryError?.trim().isNotEmpty ?? false)
              _ValueRow('ProgramData error', state.programDataDirectoryError!),
            _ValueRow('Install root', _optionalPathLabel(state.installPath)),
            _ValueRow(
              'Engine directory',
              _optionalPathLabel(state.engineDirectory),
            ),
            _ValueRow(
              'Engine paths checked',
              _enginePathsCheckedLabel(state.enginePathsChecked),
            ),
            _ValueRow(
              'Signatures dir',
              _optionalPathLabel(state.nativeSignaturesDirectory),
            ),
            _ValueRow(
              'Rules dir',
              _optionalPathLabel(state.nativeRulesDirectory),
            ),
            _ValueRow('ML dir', _optionalPathLabel(state.nativeMlDirectory)),
            _ValueRow(
              'Trust dir',
              _optionalPathLabel(state.nativeTrustDirectory),
            ),
            _ValueRow(
              'Config dir',
              _optionalPathLabel(state.nativeConfigDirectory),
            ),
            _ValueRow(
              'Native signatures',
              _nativePackagedCountLabel(
                count: state.nativeSignatureCount,
                state: state,
                noun: 'signatures',
              ),
            ),
            _ValueRow(
              'Native rules',
              _nativePackagedCountLabel(
                count: state.nativeRuleCount,
                state: state,
                noun: 'rules',
              ),
            ),
            _ValueRow(
              'Compatibility engines',
              state.compatibilityEnginesEnabled ? 'Enabled' : 'Disabled',
            ),
            _ValueRow('Reputation', _reputationLabel(state.reputationStatus)),
            if (state.reputationStatusReason?.trim().isNotEmpty ?? false)
              _ValueRow('Reputation detail', state.reputationStatusReason!),
            ZentorButton(
              label: engineCheckBusy ? 'Checking engine' : 'Check engine',
              icon: Icons.health_and_safety_outlined,
              secondary: true,
              onPressed: engineCheckBusy
                  ? null
                  : controller.unawaitedCheckMalwareEngine,
            ),
          ],
        ),
        _Section(
          title: 'Native ML',
          children: [
            _ValueRow('Local AI status', state.aiStatus.label),
            _ValueRow('Model status', _nativeMlLabel(state.nativeMlStatus)),
            _ValueRow(
              'Model version',
              state.nativeMlModelVersion ?? 'Not loaded',
            ),
            _ValueRow(
              'Feature schema',
              _featureSchemaLabel(state.aiModelInfo.featureSchemaVersion),
            ),
            _ValueRow('Production-ready', _nativeMlProductionReadyLabel(state)),
            const _ValueRow(
              'Last inference test',
              'Native engine self-test runs EICAR matching in memory.',
            ),
            const _ValueRow(
              'Policy',
              'Conservative. AI alone cannot permanently delete files and does not mark confirmed malware.',
            ),
          ],
        ),
        _Section(
          title: 'False positives',
          children: const [
            _ValueRow(
              'Feedback',
              'Detection cards can be marked as false positive, trusted, malicious, or unsure.',
            ),
            _ValueRow(
              'Training',
              'Labels are saved locally for export. Avorax does not retrain itself silently.',
            ),
          ],
        ),
        _Section(
          title: 'Ransomware protection',
          children: const [
            _ValueRow('Mode', 'Block confirmed behavior'),
            _ValueRow(
              'Recovery',
              'Recovery uses Avorax Recovery Vault or OS backups only when a protected copy or snapshot exists.',
            ),
          ],
        ),
        _Section(
          title: 'Privacy',
          children: [
            const _ValueRow(
              'Policy',
              'Visible scans only. No credential theft, hidden surveillance, or silent driver installation.',
            ),
            ZentorButton(
              label: 'View privacy policy',
              icon: Icons.privacy_tip_outlined,
              secondary: true,
              onPressed: () => context.go('/privacy'),
            ),
          ],
        ),
        _Section(
          title: 'Advanced',
          children: [
            Material(
              color: Colors.transparent,
              child: SwitchListTile(
                contentPadding: EdgeInsets.zero,
                title: const Text('Developer options'),
                subtitle: const Text(
                  'Cloud settings are normally managed by the Avorax build configuration.',
                  style: TextStyle(color: ZentorColors.textSecondary),
                ),
                value: _developerOptions,
                onChanged: developerCloudOverrideBusy
                    ? null
                    : (value) async {
                        setState(() => _developerOptions = value);
                        if (!value && state.config.developerOverrideEnabled) {
                          final disabled = await _saveDeveloperOverride(
                            controller,
                            enabled: false,
                          );
                          if (!disabled && mounted) {
                            setState(() => _developerOptions = true);
                          }
                        }
                      },
              ),
            ),
            if (_developerOptions || state.config.developerOverrideEnabled) ...[
              if (_developerOptions) ...[
                ZentorTextField(
                  controller: _endpoint,
                  label: 'API endpoint',
                  enabled: !developerCloudOverrideBusy,
                ),
                const SizedBox(height: 12),
                ZentorTextField(
                  controller: _projectId,
                  label: 'Project ID',
                  enabled: !developerCloudOverrideBusy,
                ),
                const SizedBox(height: 12),
                ZentorTextField(
                  controller: _publicKey,
                  label: 'Public Client Key',
                  enabled: !developerCloudOverrideBusy,
                ),
                const SizedBox(height: 12),
              ],
              ZentorButton(
                label: _developerOptions
                    ? 'Save developer override'
                    : 'Disable developer override',
                icon: _developerOptions
                    ? Icons.save_outlined
                    : Icons.cloud_off_outlined,
                onPressed: developerCloudOverrideBusy
                    ? null
                    : () => _saveDeveloperOverride(
                        controller,
                        enabled: _developerOptions,
                      ),
              ),
            ],
          ],
        ),
        _Section(
          title: 'Diagnostics',
          children: [
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                ZentorButton(
                  label: logExportBusy ? 'Exporting logs' : 'Export logs',
                  icon: Icons.download_outlined,
                  secondary: true,
                  onPressed: logExportBusy
                      ? null
                      : () => _confirmExportLogs(controller),
                ),
                ZentorButton(
                  label: supportBundleExportBusy
                      ? 'Exporting bundle'
                      : 'Export support bundle',
                  icon: Icons.inventory_2_outlined,
                  secondary: true,
                  onPressed: supportBundleExportBusy
                      ? null
                      : () => _confirmExportSupportBundle(controller),
                ),
                ZentorButton(
                  label: 'Reset configuration',
                  icon: Icons.restart_alt,
                  secondary: true,
                  onPressed: configurationResetControlsBusy
                      ? null
                      : () => _confirmResetConfiguration(controller),
                ),
              ],
            ),
          ],
        ),
      ],
    );
  }

  List<String> _splitPathLines(String raw) => raw
      .split(RegExp(r'[\r\n]+'))
      .map((line) => line.trim())
      .where((line) => line.isNotEmpty)
      .toList();

  Future<void> _confirmProtectionMode(
    ZentorController controller,
    ProtectionMode mode,
  ) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Change protection mode?'),
        content: Text(
          'This changes Avorax Guard behavior and local protection policy.\n\nSelected mode: ${mode.label}\n${mode.description}',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Change'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    final saved = await controller.setProtectionMode(mode, confirmed: true);
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          saved
              ? 'Protection mode changed.'
              : 'Unable to change protection mode. See the error banner.',
        ),
      ),
    );
  }

  Future<bool> _saveDeveloperOverride(
    ZentorController controller, {
    required bool enabled,
  }) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(
          enabled
              ? 'Save developer cloud override?'
              : 'Disable developer cloud override?',
        ),
        content: Text(
          enabled
              ? 'Avorax will use these developer cloud endpoint and client credentials from local settings instead of the build configuration.'
              : 'Avorax will stop using the locally saved developer cloud endpoint and client credentials and return to the build configuration.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: Text(enabled ? 'Save override' : 'Disable override'),
          ),
        ],
      ),
    );
    if (confirmed != true) return false;
    final saved = await controller.saveDeveloperCloudOverride(
      enabled: enabled,
      apiBaseUrl: _endpoint.text,
      projectId: _projectId.text,
      publicClientKey: _publicKey.text,
      confirmed: true,
    );
    if (!mounted) return saved;
    final message = switch ((enabled, saved)) {
      (true, true) => 'Developer cloud override saved.',
      (true, false) =>
        'Unable to save developer override. See the error banner.',
      (false, true) => 'Developer cloud override disabled.',
      (false, false) =>
        'Unable to disable developer override. See the error banner.',
    };
    ScaffoldMessenger.of(
      context,
    ).showSnackBar(SnackBar(content: Text(message)));
    return saved;
  }

  Future<void> _confirmRansomwareGuardSettings(
    ZentorController controller,
  ) async {
    final protectedRoots = _splitPathLines(_ransomwareProtectedRoots.text);
    final trustedProcesses = _splitPathLines(_ransomwareTrustedProcesses.text);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Save ransomware protection settings?'),
        content: const Text(
          'This updates ransomware protected folders and the trusted process allowlist. Trusted processes can modify protected files without ransomware-guard alerts, so only add backup or sync tools you trust.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    final saved = await controller.updateRansomwareGuardSettings(
      protectedRoots: protectedRoots,
      trustedProcesses: trustedProcesses,
      confirmed: true,
    );
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          saved
              ? 'Ransomware protection settings saved.'
              : 'Unable to save ransomware protection settings. See the error banner.',
        ),
      ),
    );
  }

  Future<void> _confirmScheduledQuickScanSettings(
    ZentorController controller, {
    required bool enabled,
    required int intervalHours,
  }) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Change scheduled quick scan?'),
        content: Text(
          enabled
              ? 'Avorax will run recurring detect-only quick scans every $intervalHours hour(s) while the app is open. It will not create a Windows scheduled task or quarantine automatically.'
              : 'Avorax will stop the recurring in-app quick scan schedule. Manual scans remain available.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Change'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    final saved = await controller.updateScheduledQuickScanSettings(
      enabled: enabled,
      intervalHours: intervalHours,
      confirmed: true,
    );
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          saved
              ? 'Scheduled quick scan settings saved.'
              : 'Unable to save scheduled quick scan settings. See the error banner.',
        ),
      ),
    );
  }

  Future<void> _confirmExportLogs(ZentorController controller) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Export logs?'),
        content: const Text(
          'This writes local Avorax event history to a file. The export can include file paths, protection actions, update diagnostics, and error details.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Export'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await _exportLogs(controller, confirmed: true);
  }

  Future<void> _confirmExportSupportBundle(ZentorController controller) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Export support bundle?'),
        content: const Text(
          'This writes a local diagnostic JSON file with Avorax status summaries and event history. It does not include file contents or quarantine payloads, but events can include local paths and error details.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Export'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await _exportSupportBundle(controller, confirmed: true);
  }

  Future<void> _exportLogs(
    ZentorController controller, {
    bool confirmed = false,
  }) async {
    try {
      final path = await controller.exportLogs(confirmed: confirmed);
      if (!mounted) return;
      if (path == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Unable to export logs. See the error banner.'),
          ),
        );
        return;
      }
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('Logs exported to $path')));
    } on Object catch (error) {
      if (!mounted) return;
      final details = _boundedSettingsDiagnostic(error);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Unable to export logs: $details')),
      );
    }
  }

  Future<void> _exportSupportBundle(
    ZentorController controller, {
    bool confirmed = false,
  }) async {
    try {
      final path = await controller.exportSupportBundle(confirmed: confirmed);
      if (!mounted) return;
      if (path == null) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text(
              'Unable to export support bundle. See the error banner.',
            ),
          ),
        );
        return;
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Support bundle exported to $path')),
      );
    } on Object catch (error) {
      if (!mounted) return;
      final details = _boundedSettingsDiagnostic(error);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Unable to export support bundle: $details')),
      );
    }
  }

  Future<void> _confirmResetConfiguration(ZentorController controller) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Reset configuration?'),
        content: const Text(
          'This resets local Avorax settings back to defaults. Security event logs are kept.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(context).pop(true),
            child: const Text('Reset'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    final reset = await controller.resetConfiguration(confirmed: true);
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          reset
              ? 'Configuration reset.'
              : 'Unable to reset configuration. See the error banner.',
        ),
      ),
    );
  }
}

String _settingsProtectionStatusLabel(ZentorState state) {
  if (_settingsEngineNeedsAttention(state)) return 'Attention needed';
  return state.protectionStatus.label;
}

bool _settingsEngineNeedsAttention(ZentorState state) {
  return state.malwareEngineStatus != MalwareEngineStatus.available ||
      state.nativeEngineStatus != 'ready' ||
      (state.lastEngineError?.trim().isNotEmpty ?? false);
}

String _nativeEngineLabel(ZentorState state) {
  if (state.lastEngineError?.trim().isNotEmpty ?? false) {
    return 'Attention needed';
  }
  return switch (state.nativeEngineStatus) {
    'ready' => 'Ready',
    'error' => 'Error',
    'unavailable' => 'Unavailable',
    _ => 'Unknown',
  };
}

String _ipcModeLabel(String ipcMode) => switch (ipcMode) {
  'stdio' => 'Local stdio',
  'unknown' => 'Unknown',
  _ => 'Unknown',
};

String _networkExposureLabel(bool? networkExposed) => switch (networkExposed) {
  true => 'Yes',
  false => 'No',
  null => 'Unknown',
};

String _selfTestLabel(bool? passed) => switch (passed) {
  true => 'Passed',
  false => 'Failed',
  null => 'Unknown',
};

String _optionalPathLabel(String? value) {
  final trimmed = value?.trim();
  if (trimmed == null || trimmed.isEmpty) return 'Unknown';
  return trimmed;
}

String _enginePathsCheckedLabel(List<String> paths) {
  final reportedPaths = paths
      .map((path) => path.trim())
      .where((path) => path.isNotEmpty)
      .toList(growable: false);
  final visiblePaths = reportedPaths.take(4).toList(growable: false);
  if (visiblePaths.isEmpty) return 'Unknown';
  final hiddenCount = reportedPaths.length - visiblePaths.length;
  final suffix = hiddenCount > 0 ? ' (+$hiddenCount more)' : '';
  return '${visiblePaths.join(' | ')}$suffix';
}

String _nativePackagedCountLabel({
  required int count,
  required ZentorState state,
  required String noun,
}) {
  final engineDiagnosticVisible =
      state.lastEngineError?.trim().isNotEmpty ?? false;
  if (count > 0 ||
      (state.nativeEngineStatus == 'ready' && !engineDiagnosticVisible)) {
    return '$count packaged $noun loaded';
  }
  return 'Unknown';
}

String _featureSchemaLabel(String value) {
  final trimmed = value.trim();
  if (trimmed.isEmpty || trimmed.toLowerCase() == 'unavailable') {
    return 'Unavailable';
  }
  return trimmed;
}

String _rollbackSupportLabel(bool? supported) {
  if (supported == true) return 'Available';
  if (supported == false) return 'Unavailable';
  return 'Unknown';
}

String _nativeMlLabel(String status) => switch (status) {
  'loaded' => 'Loaded',
  'developmentModel' => 'Development model',
  'modelMissing' => 'Missing',
  'error' => 'Error',
  _ => 'Unavailable',
};

String _nativeMlProductionReadyLabel(ZentorState state) {
  if (state.nativeMlProductionReady) return 'Yes';
  if (state.nativeMlStatus == 'developmentModel') {
    return 'Development model loaded; not production-ready';
  }
  if (state.nativeMlStatus == 'loaded') return 'Loaded; not production-ready';
  return 'No';
}

String _reputationLabel(String status) => switch (status) {
  'available' => 'Available',
  'unavailable' => 'Unavailable',
  'disabled' => 'Disabled',
  'unknown' => 'Unknown',
  'error' => 'Error',
  _ => 'Unavailable',
};

String _serviceLabel(String status) => switch (status) {
  'running' => 'Running',
  'stopped' => 'Stopped',
  'missing' => 'Missing',
  'installed' => 'Installed',
  'unsupported' => 'Unsupported',
  'unknown' => 'Unknown',
  'error' => 'Error',
  _ => 'Unavailable',
};

String _serviceBoundaryLabel(CoreServiceBoundaryHealth health) =>
    switch (health.status) {
      CoreServiceBoundaryStatus.notChecked => 'Not checked',
      CoreServiceBoundaryStatus.unsupported => 'Unsupported on this platform',
      CoreServiceBoundaryStatus.unavailable => 'Unavailable',
      CoreServiceBoundaryStatus.degraded =>
        'Authenticated; native engine degraded',
      CoreServiceBoundaryStatus.ready => 'Authenticated and ready',
    };

String _guardLabel(String status) => switch (status) {
  'running' => 'Running',
  'stopped' => 'Stopped',
  'missing' => 'Missing',
  'installed' => 'Installed',
  'unknown' => 'Unknown',
  'off' => 'Off',
  'blockConfirmedThreats' => 'Block confirmed threats',
  'monitorOnly' => 'Monitor only',
  'aggressive' => 'Aggressive',
  _ => 'Unavailable',
};

String _driverLabel(String status) => switch (status) {
  'running' => 'Running',
  'stopped' => 'Stopped',
  'installed' => 'Installed',
  'missing' => 'Missing',
  'unknown' => 'Unknown',
  'testSigned' => 'Test-signed',
  'blockedByOs' => 'Blocked by OS',
  _ => 'Unavailable',
};

class _Section extends StatelessWidget {
  const _Section({required this.title, required this.children});

  final String title;
  final List<Widget> children;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: ZentorPanel(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Semantics(
              header: true,
              label: 'Settings section, $title',
              child: ExcludeSemantics(
                child: Text(
                  title,
                  style: Theme.of(context).textTheme.titleLarge,
                ),
              ),
            ),
            const SizedBox(height: 14),
            ...children,
          ],
        ),
      ),
    );
  }
}

class _ValueRow extends StatelessWidget {
  const _ValueRow(this.label, this.value);

  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 180,
            child: Text(
              label,
              style: const TextStyle(color: ZentorColors.textSecondary),
            ),
          ),
          Expanded(child: Text(value, overflow: TextOverflow.ellipsis)),
        ],
      ),
    );
  }
}
