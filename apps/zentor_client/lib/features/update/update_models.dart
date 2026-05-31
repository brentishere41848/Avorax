import '../../core/updates/update_service.dart';

class UpdateViewModel {
  const UpdateViewModel({
    required this.status,
    required this.currentVersion,
    this.latestVersion,
    this.channel,
    this.packageName,
    this.releaseNotes,
    this.rollbackSupported = false,
    this.error,
  });

  final UpdateStatus status;
  final String currentVersion;
  final String? latestVersion;
  final String? channel;
  final String? packageName;
  final String? releaseNotes;
  final bool rollbackSupported;
  final String? error;
}
