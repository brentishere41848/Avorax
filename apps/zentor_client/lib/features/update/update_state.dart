import '../../app/app_state.dart';
import 'update_models.dart';

UpdateViewModel updateViewModelFromState(ZentorState state) {
  final update = state.updateInfo;
  return UpdateViewModel(
    status: state.updateStatus,
    currentVersion: state.currentAppVersion,
    latestVersion: update?.latestVersion,
    channel: update?.channel,
    packageName: update?.packageName,
    releaseNotes: update?.releaseNotes,
    rollbackSupported: update?.rollbackSupported ?? false,
    error: state.updateError,
  );
}
