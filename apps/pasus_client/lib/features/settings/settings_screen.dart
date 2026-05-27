import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:go_router/go_router.dart';

import '../../app/app_state.dart';
import '../../app/theme/pasus_colors.dart';
import '../../shared/widgets/pasus_button.dart';
import '../../shared/widgets/pasus_status_card.dart';
import '../../shared/widgets/pasus_text_field.dart';

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
    final config = ref.read(pasusControllerProvider).config;
    _endpoint = TextEditingController(text: config.apiBaseUrl);
    _projectId = TextEditingController(text: config.projectId);
    _publicKey = TextEditingController(text: config.publicGameKey);
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
    final state = ref.watch(pasusControllerProvider);
    final controller = ref.read(pasusControllerProvider.notifier);
    return Column(
      children: [
        _Section(
          title: 'General',
          children: const [
            _ValueRow('App', 'Pasus'),
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
                PasusButton(
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
          title: 'Protection',
          children: [
            _ValueRow('Antivirus', state.protectionStatus.label),
            _ValueRow('Guard mode', _guardLabel(state.guardStatus)),
            _ValueRow('Driver status', _driverLabel(state.driverStatus)),
            if (state.protectionSelfTestResult != null)
              _ValueRow('Last self-test', state.protectionSelfTestResult!),
            Wrap(
              spacing: 12,
              runSpacing: 12,
              children: [
                PasusButton(
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
            _ValueRow(
              'Gaming',
              state.config.gameConfig.gameName.isEmpty
                  ? 'Optional'
                  : state.config.gameConfig.gameName,
            ),
          ],
        ),
        _Section(
          title: 'Malware engine',
          children: [
            _ValueRow('Engine status', state.malwareEngineStatus.label),
            const _ValueRow('Provider', 'ClamAV through Pasus local core'),
            _ValueRow(
              'YARA rules',
              state.yaraStatus == 'available'
                  ? '${state.yaraRuleCount} packaged rules loaded'
                  : 'Rules unavailable',
            ),
            PasusButton(
              label: 'Check engine',
              icon: Icons.health_and_safety_outlined,
              secondary: true,
              onPressed: controller.unawaitedCheckMalwareEngine,
            ),
          ],
        ),
        _Section(
          title: 'AI Engine',
          children: [
            _ValueRow('Model status', state.aiModelInfo.status.label),
            _ValueRow('Model version', state.aiModelInfo.modelVersion),
            _ValueRow('Feature schema', state.aiModelInfo.featureSchemaVersion),
            _ValueRow(
              'Production-ready',
              state.aiModelInfo.productionReady ? 'Yes' : 'No',
            ),
            _ValueRow('Last inference test', state.aiModelInfo.message),
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
              'Labels are saved locally for export. Pasus does not retrain itself silently.',
            ),
          ],
        ),
        _Section(
          title: 'Ransomware protection',
          children: const [
            _ValueRow('Mode', 'Block confirmed behavior'),
            _ValueRow(
              'Recovery',
              'Restores from Pasus Recovery Vault when a protected copy exists.',
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
            PasusButton(
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
                'Cloud settings are normally managed by the Pasus build configuration.',
                style: TextStyle(color: PasusColors.textSecondary),
              ),
              value: _developerOptions,
              onChanged: (value) => setState(() => _developerOptions = value),
            ),
            if (_developerOptions) ...[
              PasusTextField(controller: _endpoint, label: 'API endpoint'),
              const SizedBox(height: 12),
              PasusTextField(controller: _projectId, label: 'Project ID'),
              const SizedBox(height: 12),
              PasusTextField(controller: _publicKey, label: 'Public Game Key'),
              const SizedBox(height: 12),
              PasusButton(
                label: 'Save developer override',
                icon: Icons.save_outlined,
                onPressed: () => controller.saveDeveloperCloudOverride(
                  enabled: _developerOptions,
                  apiBaseUrl: _endpoint.text,
                  projectId: _projectId.text,
                  publicGameKey: _publicKey.text,
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
                PasusButton(
                  label: 'Export logs',
                  icon: Icons.download_outlined,
                  secondary: true,
                  onPressed: controller.exportLogs,
                ),
                PasusButton(
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
      child: PasusPanel(
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
              style: const TextStyle(color: PasusColors.textSecondary),
            ),
          ),
          Expanded(child: Text(value, overflow: TextOverflow.ellipsis)),
        ],
      ),
    );
  }
}
