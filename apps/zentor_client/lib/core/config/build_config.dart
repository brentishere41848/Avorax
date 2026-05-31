const zentorApiBaseUrl = String.fromEnvironment(
  'ZENTOR_API_BASE_URL',
  defaultValue: 'http://127.0.0.1:8000',
);
const avoraxApiBaseUrl = String.fromEnvironment(
  'AVORAX_API_BASE_URL',
  defaultValue: zentorApiBaseUrl,
);

const zentorProjectId = String.fromEnvironment(
  'ZENTOR_PROJECT_ID',
  defaultValue: 'avorax-default',
);
const avoraxProjectId = String.fromEnvironment(
  'AVORAX_PROJECT_ID',
  defaultValue: zentorProjectId,
);

const zentorPublicClientKey = String.fromEnvironment(
  'ZENTOR_PUBLIC_CLIENT_KEY',
  defaultValue: 'avorax-public-client',
);
const avoraxPublicClientKey = String.fromEnvironment(
  'AVORAX_PUBLIC_CLIENT_KEY',
  defaultValue: zentorPublicClientKey,
);

const zentorUpdatesRepoOwner = String.fromEnvironment(
  'ZENTOR_UPDATES_REPO_OWNER',
  defaultValue: 'brentishere41848',
);
const avoraxUpdatesRepoOwner = String.fromEnvironment(
  'AVORAX_UPDATES_REPO_OWNER',
  defaultValue: zentorUpdatesRepoOwner,
);

const zentorUpdatesRepoName = String.fromEnvironment(
  'ZENTOR_UPDATES_REPO_NAME',
  defaultValue: 'Avorax',
);
const avoraxUpdatesRepoName = String.fromEnvironment(
  'AVORAX_UPDATES_REPO_NAME',
  defaultValue: zentorUpdatesRepoName,
);
const avoraxUpdateFeedUrl = String.fromEnvironment(
  'AVORAX_UPDATE_FEED_URL',
  defaultValue: '',
);
const avoraxUpdateChannel = String.fromEnvironment(
  'AVORAX_UPDATE_CHANNEL',
  defaultValue: 'dev',
);

const zentorAppVersion = String.fromEnvironment(
  'ZENTOR_APP_VERSION',
  defaultValue: '0.1.15',
);
const avoraxAppVersion = String.fromEnvironment(
  'AVORAX_APP_VERSION',
  defaultValue: zentorAppVersion,
);

class BuildConfig {
  const BuildConfig({
    this.apiBaseUrl = avoraxApiBaseUrl,
    this.projectId = avoraxProjectId,
    this.publicClientKey = avoraxPublicClientKey,
    this.updatesRepoOwner = avoraxUpdatesRepoOwner,
    this.updatesRepoName = avoraxUpdatesRepoName,
    this.updateFeedUrl = avoraxUpdateFeedUrl,
    this.updateChannel = avoraxUpdateChannel,
    this.appVersion = avoraxAppVersion,
  });

  final String apiBaseUrl;
  final String projectId;
  final String publicClientKey;
  final String updatesRepoOwner;
  final String updatesRepoName;
  final String updateFeedUrl;
  final String updateChannel;
  final String appVersion;
}
