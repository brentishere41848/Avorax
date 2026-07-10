import 'package:zentor_protocol/zentor_protocol.dart';

import '../../app/app_state.dart';
import '../../core/updates/update_service.dart';

bool updateMutationOperationInProgress(ZentorState state) =>
    _updateMutationStatusInProgress(state.updateStatus);

bool _updateMutationStatusInProgress(UpdateStatus status) => {
  UpdateStatus.downloading,
  UpdateStatus.verifying,
  UpdateStatus.installing,
  UpdateStatus.rollingBack,
}.contains(status);

bool updateMutationBlockedByActiveWork(ZentorState state) {
  final protectionActiveOrChanging =
      state.protectionOperationInFlight ||
      state.protectionSelfTestInFlight ||
      state.config.realtimeProtectionEnabled ||
      {
        ProtectionStatus.starting,
        ProtectionStatus.localOnly,
        ProtectionStatus.protected,
        ProtectionStatus.partiallyProtected,
        ProtectionStatus.stopping,
      }.contains(state.protectionStatus) ||
      state.realtimeWatcherMode != 'off' ||
      state.realtimeWatchedPaths.isNotEmpty ||
      state.watchPollLoopStatus != 'off';

  return protectionActiveOrChanging ||
      state.scanStartInFlight ||
      state.scanStatus == ScanStatus.running ||
      state.scanTargetSelectionInFlight ||
      state.scanCancelInFlight ||
      state.securitySettingsActionInFlight ||
      state.configurationResetInFlight ||
      state.serviceActionInFlight ||
      state.developerCloudOverrideInFlight ||
      state.protectedAppActionInFlight ||
      state.quarantineActionInFlight ||
      state.allowlistActionInFlight ||
      state.detectionFeedbackInFlight;
}
