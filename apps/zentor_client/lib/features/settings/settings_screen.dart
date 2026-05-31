import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';
import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../app/theme/zentor_colors.dart';
import '../../core/updates/update_service.dart';
import '../../shared/widgets/zentor_button.dart';
import '../../shared/widgets/zentor_status_card.dart';
import '../../shared/widgets/zentor_text_field.dart';

class SettingsScreen extends ConsumerStatefulWidget {
  const SettingsScreen({super.key});

  @override
  ConsumerState<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends ConsumerState<SettingsScreen> {
  late final TextEditingController _endpoint;
  late final TextEditingController _projectId;
  late final TextEditingController _publicKey;
  bool _developerOptions = false;

  @override
  void initState() {
    super.initState();
    final config = ref.read(zentorControllerProvider).config;
    _endpoint = TextEditingController(text: config.apiBaseUrl);
    _projectId = TextEditingController(text: config.projectId);
    _publicKey = TextEditingController(text: config.publicClientKey);
    _developerOptions = config.developerOverrideEnabled;
  }

  @override
  void dispose() {
    _endpoint.dispose();
    _projectId.dispose();
    _publicKey.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final state = ref.watch(zentorControllerProvider);
    final controller = ref.read(zentorControllerProvider.notifier);
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
                  label: 'Test Cloud Connection',
                  icon: Icons.cloud_sync_outlined,
                  secondary: true,
                  onPressed: controller.testCloudConnection,
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
              _ValueRow(
                'Update package',
                state.updateInfo!.assetName ?? 'No package available',
              ),
            ],
            if (state.updateError != null)
              _ValueRow('Last check', state.updateError!),
            const Text(
              'Avorax checks GitHub Releases and installs Windows updates from inside the app using the signed MSI package. Windows may ask for administrator approval.',
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
                  onPressed: state.updateStatus == UpdateStatus.checking
                      ? null
                      : controller.unawaitedCheckForUpdates,
                ),
                if (state.updateStatus == UpdateStatus.updateAvailable ||
                    state.updateStatus == UpdateStatus.installing)
                  ZentorButton(
                    label: state.updateStatus == UpdateStatus.installing
                        ? 'Starting update'
                        : 'Install update',
                    icon: Icons.system_update_alt_outlined,
                    onPressed: state.updateStatus == UpdateStatus.installing
                        ? null
                        : controller.installUpdateInApp,
                  ),
              ],
            ),
          ],
        ),
        _Section(
          title: 'Protection',
          children: [
            _ValueRow('Antivirus', state.protectionStatus.label),
            _ValueRow('Profile', state.config.protectionMode.label),
            DropdownButtonFormField<ProtectionMode>(
              initialValue: state.config.protectionMode,
              dropdownColor: ZentorColors.elevatedSurface,
              decoration: const InputDecoration(labelText: 'Protection mode'),
              items: ProtectionMode.values
                  .where((mode) => mode != ProtectionMode.off)
                  .map(
                    (mode) =>
                        DropdownMenuItem(value: mode, child: Text(mode.label)),
                  )
                  .toList(),
              onChanged: (mode) {
                if (mode != null) controller.setProtectionMode(mode);
              },
            ),
            const SizedBox(height: 8),
            Text(
              state.config.protectionMode == ProtectionMode.lockdown
                  ? 'Lockdown blocks unknown apps until you approve an exact file hash. This gives stronger prevention but may interrupt installers, developer tools, installers and scripts.'
                  : state.config.protectionMode.description,
              style: const TextStyle(
                color: ZentorColors.textSecondary,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 10),
            _ValueRow('Guard mode', _guardLabel(state.guardStatus)),
            _ValueRow('Driver status', _driverLabel(state.driverStatus)),
            if (state.protectionSelfTestResult != null)
              _ValueRow('Last self-test', state.protectionSelfTestResult!),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                ZentorButton(
                  label: 'Run Protection Self-Test',
                  icon: Icons.verified_user_outlined,
                  secondary: true,
                  onPressed: state.loading
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
          ],
        ),
        _Section(
          title: 'Avorax Native Engine',
          children: [
            _ValueRow('Engine status', state.malwareEngineStatus.label),
            _ValueRow('Native status', state.nativeEngineStatus),
            _ValueRow(
              'Native signatures',
              '${state.nativeSignatureCount} packaged signatures loaded',
            ),
            _ValueRow(
              'Native rules',
              '${state.nativeRuleCount} packaged rules loaded',
            ),
            _ValueRow(
              'Compatibility engines',
              state.compatibilityEnginesEnabled ? 'Enabled' : 'Disabled',
            ),
            ZentorButton(
              label: 'Check engine',
              icon: Icons.health_and_safety_outlined,
              secondary: true,
              onPressed: controller.unawaitedCheckMalwareEngine,
            ),
          ],
        ),
        _Section(
          title: 'Native ML',
          children: [
            _ValueRow('Model status', state.nativeMlStatus),
            _ValueRow(
              'Model version',
              state.nativeMlModelVersion ?? 'Not loaded',
            ),
            const _ValueRow('Feature schema', 'zne-features-v1'),
            _ValueRow(
              'Production-ready',
              state.nativeMlStatus == 'loaded' ? 'Yes' : 'No',
            ),
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
              'Restores from Avorax Recovery Vault when a protected copy exists.',
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
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text('Developer options'),
              subtitle: const Text(
                'Cloud settings are normally managed by the Avorax build configuration.',
                style: TextStyle(color: ZentorColors.textSecondary),
              ),
              value: _developerOptions,
              onChanged: (value) => setState(() => _developerOptions = value),
            ),
            if (_developerOptions) ...[
              ZentorTextField(controller: _endpoint, label: 'API endpoint'),
              const SizedBox(height: 12),
              ZentorTextField(controller: _projectId, label: 'Project ID'),
              const SizedBox(height: 12),
              ZentorTextField(
                controller: _publicKey,
                label: 'Public Client Key',
              ),
              const SizedBox(height: 12),
              ZentorButton(
                label: 'Save developer override',
                icon: Icons.save_outlined,
                onPressed: () => controller.saveDeveloperCloudOverride(
                  enabled: _developerOptions,
                  apiBaseUrl: _endpoint.text,
                  projectId: _projectId.text,
                  publicClientKey: _publicKey.text,
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
                  label: 'Export logs',
                  icon: Icons.download_outlined,
                  secondary: true,
                  onPressed: controller.exportLogs,
                ),
                ZentorButton(
                  label: 'Reset configuration',
                  icon: Icons.restart_alt,
                  secondary: true,
                  onPressed: controller.resetConfiguration,
                ),
              ],
            ),
          ],
        ),
      ],
    );
  }
}

String _guardLabel(String status) => switch (status) {
  'running' => 'Running',
  'stopped' => 'Stopped',
  'installed' => 'Installed',
  'blockConfirmedThreats' => 'Block confirmed threats',
  'monitorOnly' => 'Monitor only',
  'aggressive' => 'Aggressive',
  _ => 'Off',
};

String _driverLabel(String status) => switch (status) {
  'running' => 'Running',
  'installed' => 'Installed',
  'testSigned' => 'Test-signed',
  'blockedByOs' => 'Blocked by OS',
  _ => 'Missing',
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
            Text(title, style: Theme.of(context).textTheme.titleLarge),
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
