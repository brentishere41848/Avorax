class AppRegistryEntry {
  const AppRegistryEntry({
    required this.appId,
    required this.displayName,
    required this.processNames,
    required this.executableNames,
    this.launcherIds = const [],
    this.expectedBuildHashes = const [],
    this.allowedPathHints = const [],
    this.protectionProfile = 'standard',
  });

  final String appId;
  final String displayName;
  final List<String> processNames;
  final List<String> executableNames;
  final List<String> launcherIds;
  final List<String> expectedBuildHashes;
  final List<String> allowedPathHints;
  final String protectionProfile;
}

class AppRegistry {
  const AppRegistry();

  List<AppRegistryEntry> get entries => const [];
}
