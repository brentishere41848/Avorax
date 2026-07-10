import '../../app/app_state.dart';

extension UpdateControllerCommands on ZentorController {
  Future<void> checkForInAppUpdate() => unawaitedCheckForUpdates();

  Future<void> downloadVerifyAndInstallUpdate({bool confirmed = false}) =>
      installUpdateInApp(confirmed: confirmed);
}
