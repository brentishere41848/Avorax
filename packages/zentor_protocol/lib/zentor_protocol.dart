enum CloudStatus {
  checking,
  disabled,
  online,
  offline,
  misconfigured;

  String get label => switch (this) {
    CloudStatus.checking => 'Cloud: Checking',
    CloudStatus.disabled => 'Cloud: Disabled',
    CloudStatus.online => 'Cloud: Online',
    CloudStatus.offline => 'Cloud: Offline',
    CloudStatus.misconfigured => 'Cloud: Misconfigured',
  };
}

enum ProtectionStatus {
  idle,
  starting,
  localOnly,
  protected,
  partiallyProtected,
  stopping,
  error;

  String get label => switch (this) {
    ProtectionStatus.idle => 'Protection Idle',
    ProtectionStatus.starting => 'Starting',
    ProtectionStatus.localOnly => 'Local Protection Active',
    ProtectionStatus.protected => 'Verified Protection Active',
    ProtectionStatus.partiallyProtected => 'Driver Self-Test Required',
    ProtectionStatus.stopping => 'Stopping',
    ProtectionStatus.error => 'Protection Error',
  };
}

enum ProtectionMode {
  off,
  monitorOnly,
  balanced,
  blockConfirmedThreats,
  lockdown,
  developerMode;

  String get label => switch (this) {
    ProtectionMode.off => 'Off',
    ProtectionMode.monitorOnly => 'Monitor Only',
    ProtectionMode.balanced => 'Balanced Protection',
    ProtectionMode.blockConfirmedThreats => 'Block Confirmed Threats',
    ProtectionMode.lockdown => 'Lockdown Protection',
    ProtectionMode.developerMode => 'Developer Mode',
  };

  String get description => switch (this) {
    ProtectionMode.off => 'Protection decisions are disabled.',
    ProtectionMode.monitorOnly => 'Unknown apps are logged and monitored.',
    ProtectionMode.balanced =>
      'Blocks confirmed threats and reviews suspicious apps.',
    ProtectionMode.blockConfirmedThreats =>
      'Automatically stops and quarantines confirmed threats only.',
    ProtectionMode.lockdown =>
      'Blocks unknown apps until an exact hash is approved.',
    ProtectionMode.developerMode =>
      'Reduces interruption for developer tools while still stopping confirmed threats.',
  };
}

enum AppDetectionStatus {
  idle,
  scanning,
  detected,
  notFound,
  manual;

  String get label => switch (this) {
    AppDetectionStatus.idle => 'App Detection Idle',
    AppDetectionStatus.scanning => 'Scanning Known Locations',
    AppDetectionStatus.detected => 'App Detected',
    AppDetectionStatus.notFound => 'No Supported App Found',
    AppDetectionStatus.manual => 'Manual App',
  };
}

enum AppVerificationStatus {
  notConfigured,
  pending,
  verified,
  mismatch,
  failed;

  String get label => switch (this) {
    AppVerificationStatus.notConfigured => 'Not Verified',
    AppVerificationStatus.pending => 'Pending',
    AppVerificationStatus.verified => 'Verified',
    AppVerificationStatus.mismatch => 'Update Required',
    AppVerificationStatus.failed => 'Verification Failed',
  };
}

enum MalwareEngineStatus {
  checking,
  available,
  unavailable,
  signaturesOutdated,
  error;

  String get label => switch (this) {
    MalwareEngineStatus.checking => 'Checking Engine',
    MalwareEngineStatus.available => 'Malware Engine Available',
    MalwareEngineStatus.unavailable => 'Malware Engine Unavailable',
    MalwareEngineStatus.signaturesOutdated => 'Signatures Outdated',
    MalwareEngineStatus.error => 'Engine Error',
  };
}

enum AiModelStatus {
  active,
  developmentModel,
  modelMissing,
  error;

  String get label => switch (this) {
    AiModelStatus.active => 'Local AI Active',
    AiModelStatus.developmentModel => 'Development model',
    AiModelStatus.modelMissing => 'Model missing',
    AiModelStatus.error => 'AI error',
  };
}

class AiModelInfo {
  const AiModelInfo({
    this.status = AiModelStatus.modelMissing,
    this.modelVersion = 'unavailable',
    this.featureSchemaVersion = 'unavailable',
    this.productionReady = false,
    this.message = 'Local AI model is missing.',
  });

  final AiModelStatus status;
  final String modelVersion;
  final String featureSchemaVersion;
  final bool productionReady;
  final String message;
}

enum ScanStatus {
  idle,
  running,
  clean,
  infected,
  completedWithErrors,
  engineUnavailable,
  cancelled,
  failed;

  String get label => switch (this) {
    ScanStatus.idle => 'Scan Idle',
    ScanStatus.running => 'Scan Running',
    ScanStatus.clean => 'Clean',
    ScanStatus.infected => 'Threat Detected',
    ScanStatus.completedWithErrors => 'Completed With Errors',
    ScanStatus.engineUnavailable => 'Engine Unavailable',
    ScanStatus.cancelled => 'Cancelled',
    ScanStatus.failed => 'Scan Failed',
  };
}

enum ScanActionMode {
  detectOnly,
  autoQuarantineConfirmedOnly,
  autoQuarantineAllDetections;

  String get label => switch (this) {
    ScanActionMode.detectOnly => 'Detect only',
    ScanActionMode.autoQuarantineConfirmedOnly =>
      'Auto-quarantine confirmed threats',
    ScanActionMode.autoQuarantineAllDetections =>
      'Legacy confirmed-only quarantine',
  };
}

enum ScanJobStatus {
  queued,
  running,
  paused,
  cancelled,
  completed,
  failed;

  String get label => switch (this) {
    ScanJobStatus.queued => 'Queued',
    ScanJobStatus.running => 'Running',
    ScanJobStatus.paused => 'Paused',
    ScanJobStatus.cancelled => 'Cancelled',
    ScanJobStatus.completed => 'Completed',
    ScanJobStatus.failed => 'Failed',
  };
}

enum ScanKind {
  quick,
  full,
  custom;

  String get label => switch (this) {
    ScanKind.quick => 'Quick Scan',
    ScanKind.full => 'Full Scan',
    ScanKind.custom => 'Custom Scan',
  };
}

enum DetectionType {
  signature,
  yara,
  heuristic,
  localAi,
  behavior,
  ransomwareGuard,
  suspiciousBehavior,
  reputation,
  unknown;

  String get label => switch (this) {
    DetectionType.signature => 'Signature',
    DetectionType.yara => 'YARA',
    DetectionType.heuristic => 'Heuristic',
    DetectionType.localAi => 'Local AI',
    DetectionType.behavior => 'Behavior',
    DetectionType.ransomwareGuard => 'Ransomware Guard',
    DetectionType.suspiciousBehavior => 'Suspicious behavior',
    DetectionType.reputation => 'Reputation',
    DetectionType.unknown => 'Unknown',
  };
}

enum RiskVerdict {
  clean,
  likelyClean,
  unknown,
  suspicious,
  probableMalware,
  confirmedMalware;

  String get label => switch (this) {
    RiskVerdict.clean => 'Clean',
    RiskVerdict.likelyClean => 'Likely clean',
    RiskVerdict.unknown => 'Review suggested',
    RiskVerdict.suspicious => 'Review suggested',
    RiskVerdict.probableMalware => 'Probable malware',
    RiskVerdict.confirmedMalware => 'Confirmed threat',
  };
}

enum RiskSeverity { info, low, medium, high, critical }

enum RiskReasonSource {
  staticFeature,
  signature,
  yara,
  heuristic,
  aiModel,
  behavior,
  userLabel,
  allowlist,
  cloudOptional,
}

class RiskReason {
  const RiskReason({
    required this.id,
    required this.title,
    required this.detail,
    required this.weight,
    required this.severity,
    required this.source,
  });

  final String id;
  final String title;
  final String detail;
  final int weight;
  final RiskSeverity severity;
  final RiskReasonSource source;
}

class RiskScore {
  const RiskScore({
    required this.score,
    required this.verdict,
    required this.confidence,
    required this.reasons,
    required this.recommendedAction,
    required this.enginesUsed,
  });

  final int score;
  final RiskVerdict verdict;
  final ThreatConfidence confidence;
  final List<RiskReason> reasons;
  final RecommendedAction recommendedAction;
  final List<DetectionType> enginesUsed;
}

enum ThreatCategory {
  trojan,
  ransomware,
  spyware,
  infostealer,
  adware,
  worm,
  keylogger,
  miner,
  rootkitIndicator,
  potentiallyUnwantedApp,
  suspiciousDownloader,
  suspiciousScript,
  maliciousMacro,
  exploitDropper,
  credentialTheftIndicator,
  persistenceIndicator,
  securityTamperIndicator,
  unknown;

  String get label => switch (this) {
    ThreatCategory.trojan => 'Potential Trojan',
    ThreatCategory.ransomware => 'Potential ransomware',
    ThreatCategory.spyware => 'Potential spyware',
    ThreatCategory.infostealer => 'Potential infostealer',
    ThreatCategory.adware => 'Potential adware',
    ThreatCategory.worm => 'Potential worm',
    ThreatCategory.keylogger => 'Potential keylogger',
    ThreatCategory.miner => 'Potential miner',
    ThreatCategory.rootkitIndicator => 'Rootkit indicator',
    ThreatCategory.potentiallyUnwantedApp => 'Potentially unwanted app',
    ThreatCategory.suspiciousDownloader => 'Suspicious downloader',
    ThreatCategory.suspiciousScript => 'Suspicious script',
    ThreatCategory.maliciousMacro => 'Malicious macro indicator',
    ThreatCategory.exploitDropper => 'Exploit dropper indicator',
    ThreatCategory.credentialTheftIndicator => 'Credential theft indicator',
    ThreatCategory.persistenceIndicator => 'Persistence indicator',
    ThreatCategory.securityTamperIndicator => 'Security tamper indicator',
    ThreatCategory.unknown => 'Possible malware',
  };
}

enum ThreatConfidence {
  low,
  medium,
  high,
  confirmed;

  String get label => switch (this) {
    ThreatConfidence.low => 'Low',
    ThreatConfidence.medium => 'Medium',
    ThreatConfidence.high => 'High',
    ThreatConfidence.confirmed => 'Confirmed',
  };
}

enum RecommendedAction {
  quarantine,
  review,
  allowlist,
  delete;

  String get label => switch (this) {
    RecommendedAction.quarantine => 'Quarantine',
    RecommendedAction.review => 'Review',
    RecommendedAction.allowlist => 'Allowlist',
    RecommendedAction.delete => 'Delete',
  };
}

enum ThreatResultStatus {
  detected,
  quarantined,
  ignored,
  restored,
  deleted,
  allowlisted;

  String get label => switch (this) {
    ThreatResultStatus.detected => 'Detected',
    ThreatResultStatus.quarantined => 'Quarantined',
    ThreatResultStatus.ignored => 'Ignored',
    ThreatResultStatus.restored => 'Restored',
    ThreatResultStatus.deleted => 'Deleted',
    ThreatResultStatus.allowlisted => 'Allowlisted',
  };
}

enum QuarantineItemStatus {
  quarantined,
  restored,
  deleted;

  String get label => switch (this) {
    QuarantineItemStatus.quarantined => 'Quarantined',
    QuarantineItemStatus.restored => 'Restored',
    QuarantineItemStatus.deleted => 'Deleted',
  };
}

enum AllowlistEntryType {
  file,
  folder,
  app,
  executable,
  hash;

  String get label => switch (this) {
    AllowlistEntryType.file => 'File',
    AllowlistEntryType.folder => 'Folder',
    AllowlistEntryType.app => 'App',
    AllowlistEntryType.executable => 'Executable',
    AllowlistEntryType.hash => 'Hash',
  };
}

class ZentorConfig {
  const ZentorConfig({
    this.apiBaseUrl = '',
    this.projectId = '',
    this.publicClientKey = '',
    this.developerOverrideEnabled = false,
    this.onboardingComplete = false,
    this.protectedAppConfig = const ProtectedAppConfig(),
    this.scanPaths = const [],
    this.realtimeProtectionEnabled = false,
    this.protectionMode = ProtectionMode.balanced,
    this.ransomwareProtectedRoots = const [],
    this.ransomwareTrustedProcesses = const [],
    this.scheduledQuickScanEnabled = false,
    this.scheduledQuickScanIntervalHours = 24,
  });

  final String apiBaseUrl;
  final String projectId;
  final String publicClientKey;
  final bool developerOverrideEnabled;
  final bool onboardingComplete;
  final ProtectedAppConfig protectedAppConfig;
  final List<String> scanPaths;
  final bool realtimeProtectionEnabled;
  final ProtectionMode protectionMode;
  final List<String> ransomwareProtectedRoots;
  final List<String> ransomwareTrustedProcesses;
  final bool scheduledQuickScanEnabled;
  final int scheduledQuickScanIntervalHours;

  static const maxConfigStringListEntries = 128;
  static const maxConfigStringListEntryLength = 1024;
  static const maxCloudEndpointLength = 2048;
  static const maxCloudProjectIdLength = 256;
  static const maxCloudPublicClientKeyLength = 512;
  static const minScheduledQuickScanIntervalHours = 1;
  static const maxScheduledQuickScanIntervalHours = 168;
  static final _cloudControlTextPattern = RegExp(r'[\x00-\x1F\x7F]');
  static final _configStringListControlPattern = RegExp(r'[\x00-\x1F\x7F]');

  bool get hasCloudConfiguration =>
      apiBaseUrl.trim().isNotEmpty &&
      projectId.trim().isNotEmpty &&
      publicClientKey.trim().isNotEmpty;

  List<String> validateCloudConfiguration() {
    final errors = <String>[];
    final rawEndpoint = apiBaseUrl;
    final rawProject = projectId;
    final rawPublicKey = publicClientKey;
    final endpoint = apiBaseUrl.trim();
    final project = projectId.trim();
    final publicKey = publicClientKey.trim();
    final parsed = Uri.tryParse(endpoint);
    if (endpoint.isEmpty) {
      errors.add(
        'Cloud settings are managed by your Avorax build configuration.',
      );
    } else if (_cloudControlTextPattern.hasMatch(rawEndpoint)) {
      errors.add(
        'Avorax Cloud endpoint contains unsupported control characters.',
      );
    } else if (endpoint.length > maxCloudEndpointLength) {
      errors.add('Avorax Cloud endpoint is too long.');
    } else if (parsed == null ||
        !parsed.hasScheme ||
        parsed.host.isEmpty ||
        (parsed.scheme != 'https' && parsed.scheme != 'http')) {
      errors.add('Avorax Cloud endpoint must be an absolute URL.');
    }
    if (project.isEmpty || publicKey.isEmpty) {
      errors.add('Avorax Cloud build configuration is incomplete.');
    } else {
      if (_cloudControlTextPattern.hasMatch(rawProject)) {
        errors.add(
          'Avorax Cloud project ID contains unsupported control characters.',
        );
      }
      if (project.length > maxCloudProjectIdLength) {
        errors.add('Avorax Cloud project ID is too long.');
      }
      if (_cloudControlTextPattern.hasMatch(rawPublicKey)) {
        errors.add(
          'Avorax Cloud public client key contains unsupported control characters.',
        );
      }
      if (publicKey.length > maxCloudPublicClientKeyLength) {
        errors.add('Avorax Cloud public client key is too long.');
      }
    }
    return errors;
  }

  ZentorConfig copyWith({
    String? apiBaseUrl,
    String? projectId,
    String? publicClientKey,
    bool? developerOverrideEnabled,
    bool? onboardingComplete,
    ProtectedAppConfig? protectedAppConfig,
    List<String>? scanPaths,
    bool? realtimeProtectionEnabled,
    ProtectionMode? protectionMode,
    List<String>? ransomwareProtectedRoots,
    List<String>? ransomwareTrustedProcesses,
    bool? scheduledQuickScanEnabled,
    int? scheduledQuickScanIntervalHours,
  }) {
    return ZentorConfig(
      apiBaseUrl: apiBaseUrl ?? this.apiBaseUrl,
      projectId: projectId ?? this.projectId,
      publicClientKey: publicClientKey ?? this.publicClientKey,
      developerOverrideEnabled:
          developerOverrideEnabled ?? this.developerOverrideEnabled,
      onboardingComplete: onboardingComplete ?? this.onboardingComplete,
      protectedAppConfig: protectedAppConfig ?? this.protectedAppConfig,
      scanPaths: scanPaths ?? this.scanPaths,
      realtimeProtectionEnabled:
          realtimeProtectionEnabled ?? this.realtimeProtectionEnabled,
      protectionMode: protectionMode ?? this.protectionMode,
      ransomwareProtectedRoots:
          ransomwareProtectedRoots ?? this.ransomwareProtectedRoots,
      ransomwareTrustedProcesses:
          ransomwareTrustedProcesses ?? this.ransomwareTrustedProcesses,
      scheduledQuickScanEnabled:
          scheduledQuickScanEnabled ?? this.scheduledQuickScanEnabled,
      scheduledQuickScanIntervalHours:
          scheduledQuickScanIntervalHours ??
          this.scheduledQuickScanIntervalHours,
    );
  }

  Map<String, Object?> toJson() => {
    'apiBaseUrl': apiBaseUrl,
    'projectId': projectId,
    'publicClientKey': publicClientKey,
    'developerOverrideEnabled': developerOverrideEnabled,
    'onboardingComplete': onboardingComplete,
    'protectedAppConfig': protectedAppConfig.toJson(),
    'scanPaths': scanPaths,
    'realtimeProtectionEnabled': realtimeProtectionEnabled,
    'protectionMode': protectionMode.name,
    'ransomwareProtectedRoots': ransomwareProtectedRoots,
    'ransomwareTrustedProcesses': ransomwareTrustedProcesses,
    'scheduledQuickScanEnabled': scheduledQuickScanEnabled,
    'scheduledQuickScanIntervalHours': scheduledQuickScanIntervalHours,
  };

  factory ZentorConfig.fromJson(Map<String, Object?> json) {
    final appJson = json['protectedAppConfig'];
    return ZentorConfig(
      apiBaseUrl: _optionalBoundedConfigString(
        json,
        'apiBaseUrl',
        maxCloudEndpointLength,
      ),
      projectId: _optionalBoundedConfigString(
        json,
        'projectId',
        maxCloudProjectIdLength,
      ),
      publicClientKey: _optionalBoundedConfigString(
        json,
        'publicClientKey',
        maxCloudPublicClientKeyLength,
      ),
      developerOverrideEnabled: _optionalBool(json, 'developerOverrideEnabled'),
      onboardingComplete: _optionalBool(json, 'onboardingComplete'),
      protectedAppConfig: _optionalProtectedAppConfig(appJson),
      scanPaths: _optionalStringList(json, 'scanPaths'),
      realtimeProtectionEnabled: _optionalBool(
        json,
        'realtimeProtectionEnabled',
      ),
      protectionMode: _optionalProtectionMode(json['protectionMode']),
      ransomwareProtectedRoots: _optionalStringList(
        json,
        'ransomwareProtectedRoots',
      ),
      ransomwareTrustedProcesses: _optionalStringList(
        json,
        'ransomwareTrustedProcesses',
      ),
      scheduledQuickScanEnabled: _optionalBool(
        json,
        'scheduledQuickScanEnabled',
      ),
      scheduledQuickScanIntervalHours: _optionalIntInRange(
        json,
        'scheduledQuickScanIntervalHours',
        min: minScheduledQuickScanIntervalHours,
        max: maxScheduledQuickScanIntervalHours,
        defaultValue: 24,
      ),
    );
  }

  static bool _optionalBool(Map<String, Object?> json, String key) {
    final value = json[key];
    if (value == null) return false;
    if (value is bool) return value;
    throw FormatException('Config field $key must be a boolean.');
  }

  static int _optionalIntInRange(
    Map<String, Object?> json,
    String key, {
    required int min,
    required int max,
    required int defaultValue,
  }) {
    final value = json[key];
    if (value == null) return defaultValue;
    if (value is! int) {
      throw FormatException('Config field $key must be an integer.');
    }
    if (value < min || value > max) {
      throw FormatException('Config field $key must be between $min and $max.');
    }
    return value;
  }

  static String _optionalBoundedConfigString(
    Map<String, Object?> json,
    String key,
    int maxLength,
  ) {
    final value = json[key];
    if (value == null) return '';
    if (value is! String) {
      throw FormatException('Config field $key must be a string.');
    }
    if (_cloudControlTextPattern.hasMatch(value)) {
      throw FormatException(
        'Config field $key must not contain control characters.',
      );
    }
    final trimmed = value.trim();
    if (trimmed.length > maxLength) {
      throw FormatException(
        'Config field $key must be at most $maxLength characters.',
      );
    }
    return trimmed;
  }

  static ProtectedAppConfig _optionalProtectedAppConfig(Object? value) {
    if (value == null) return const ProtectedAppConfig();
    if (value is Map<String, Object?>) {
      return ProtectedAppConfig.fromJson(value);
    }
    throw const FormatException(
      'Config field protectedAppConfig must be a JSON object.',
    );
  }

  static ProtectionMode _optionalProtectionMode(Object? value) {
    if (value == null) return ProtectionMode.balanced;
    if (value is! String) {
      throw const FormatException(
        'Config field protectionMode must be a string.',
      );
    }
    for (final mode in ProtectionMode.values) {
      if (mode.name == value) return mode;
    }
    throw FormatException(
      'Config field protectionMode is not supported: $value',
    );
  }

  static List<String> _optionalStringList(
    Map<String, Object?> json,
    String key,
  ) {
    final value = json[key];
    if (value == null) return const [];
    if (value is! List) {
      throw FormatException('Config field $key must be a list of strings.');
    }
    final strings = <String>[];
    for (final item in value) {
      if (item is! String) {
        throw FormatException('Config field $key must be a list of strings.');
      }
      if (_configStringListControlPattern.hasMatch(item)) {
        throw FormatException(
          'Config field $key entries must not contain control characters.',
        );
      }
      final trimmed = item.trim();
      if (trimmed.isEmpty) {
        throw FormatException(
          'Config field $key entries must be non-empty strings.',
        );
      }
      if (trimmed.length > maxConfigStringListEntryLength) {
        throw FormatException(
          'Config field $key entries must be at most '
          '$maxConfigStringListEntryLength characters.',
        );
      }
      strings.add(trimmed);
      if (strings.length > maxConfigStringListEntries) {
        throw FormatException(
          'Config field $key must contain at most '
          '$maxConfigStringListEntries entries.',
        );
      }
    }
    return strings;
  }
}

class ProtectedAppConfig {
  const ProtectedAppConfig({
    this.appId = '',
    this.appName = '',
    this.appPath = '',
    this.expectedBuildHash = '',
    this.lastCalculatedHash = '',
    this.platform = '',
    this.source = '',
    this.protectionProfile = 'standard',
  });

  final String appId;
  final String appName;
  final String appPath;
  final String expectedBuildHash;
  final String lastCalculatedHash;
  final String platform;
  final String source;
  final String protectionProfile;

  static const maxProtectedAppTextLength = 512;
  static const maxProtectedAppPathLength = 2048;
  static final _sha256Pattern = RegExp(r'^[a-fA-F0-9]{64}$');
  static final _protectedAppControlTextPattern = RegExp(r'[\x00-\x1F\x7F]');

  bool get isConfigured =>
      appName.trim().isNotEmpty && appPath.trim().isNotEmpty;

  ProtectedAppConfig copyWith({
    String? appId,
    String? appName,
    String? appPath,
    String? expectedBuildHash,
    String? lastCalculatedHash,
    String? platform,
    String? source,
    String? protectionProfile,
  }) {
    return ProtectedAppConfig(
      appId: appId ?? this.appId,
      appName: appName ?? this.appName,
      appPath: appPath ?? this.appPath,
      expectedBuildHash: expectedBuildHash ?? this.expectedBuildHash,
      lastCalculatedHash: lastCalculatedHash ?? this.lastCalculatedHash,
      platform: platform ?? this.platform,
      source: source ?? this.source,
      protectionProfile: protectionProfile ?? this.protectionProfile,
    );
  }

  ProtectedAppConfig normalized() => ProtectedAppConfig.fromJson(toJson());

  Map<String, Object?> toJson() => {
    'appId': appId,
    'appName': appName,
    'appPath': appPath,
    'expectedBuildHash': expectedBuildHash,
    'lastCalculatedHash': lastCalculatedHash,
    'platform': platform,
    'source': source,
    'protectionProfile': protectionProfile,
  };

  factory ProtectedAppConfig.fromJson(Map<String, Object?> json) =>
      ProtectedAppConfig(
        appId: _optionalBoundedString(json, 'appId'),
        appName: _optionalBoundedString(json, 'appName'),
        appPath: _optionalBoundedString(
          json,
          'appPath',
          maxLength: maxProtectedAppPathLength,
        ),
        expectedBuildHash: _optionalSha256(json, 'expectedBuildHash'),
        lastCalculatedHash: _optionalSha256(json, 'lastCalculatedHash'),
        platform: _optionalBoundedString(json, 'platform'),
        source: _optionalBoundedString(json, 'source'),
        protectionProfile: _optionalNonEmptyBoundedString(
          json,
          'protectionProfile',
          defaultValue: 'standard',
        ),
      );

  static String _optionalBoundedString(
    Map<String, Object?> json,
    String key, {
    int maxLength = maxProtectedAppTextLength,
    String defaultValue = '',
  }) {
    final value = json[key];
    if (value == null) return defaultValue;
    if (value is! String) {
      throw FormatException('Protected app field $key must be a string.');
    }
    if (_protectedAppControlTextPattern.hasMatch(value)) {
      throw FormatException(
        'Protected app field $key must not contain control characters.',
      );
    }
    final trimmed = value.trim();
    if (trimmed.isEmpty) return '';
    if (trimmed.length > maxLength) {
      throw FormatException(
        'Protected app field $key must be at most $maxLength characters.',
      );
    }
    return trimmed;
  }

  static String _optionalNonEmptyBoundedString(
    Map<String, Object?> json,
    String key, {
    int maxLength = maxProtectedAppTextLength,
    required String defaultValue,
  }) {
    final value = _optionalBoundedString(
      json,
      key,
      maxLength: maxLength,
      defaultValue: defaultValue,
    );
    if (value.isEmpty) {
      throw FormatException(
        'Protected app field $key must be non-empty when present.',
      );
    }
    return value;
  }

  static String _optionalSha256(Map<String, Object?> json, String key) {
    final value = _optionalBoundedString(json, key, maxLength: 64);
    if (value.isEmpty) return '';
    if (!_sha256Pattern.hasMatch(value)) {
      throw FormatException(
        'Protected app field $key must be an empty value or SHA-256 hex.',
      );
    }
    return value.toLowerCase();
  }
}

class DetectedApp {
  const DetectedApp({
    required this.appId,
    required this.displayName,
    required this.path,
    required this.source,
    this.buildHash = '',
    this.protectionProfile = 'standard',
  });

  final String appId;
  final String displayName;
  final String path;
  final String source;
  final String buildHash;
  final String protectionProfile;

  ProtectedAppConfig toProtectedAppConfig() => ProtectedAppConfig(
    appId: appId,
    appName: displayName,
    appPath: path,
    lastCalculatedHash: buildHash,
    source: source,
    protectionProfile: protectionProfile,
  ).normalized();
}

class ProtectionRun {
  const ProtectionRun({
    required this.protectionRunId,
    required this.startedAt,
    this.expiresAt,
  });

  final String protectionRunId;
  final DateTime startedAt;
  final DateTime? expiresAt;
}

class HeartbeatStatus {
  const HeartbeatStatus({
    this.lastSentAt,
    this.lastError,
    this.inFlight = false,
  });

  final DateTime? lastSentAt;
  final String? lastError;
  final bool inFlight;

  HeartbeatStatus copyWith({
    DateTime? lastSentAt,
    String? lastError,
    bool? inFlight,
    bool clearError = false,
  }) {
    return HeartbeatStatus(
      lastSentAt: lastSentAt ?? this.lastSentAt,
      lastError: clearError ? null : lastError ?? this.lastError,
      inFlight: inFlight ?? this.inFlight,
    );
  }
}

class DeviceIntegritySummary {
  const DeviceIntegritySummary({
    required this.platform,
    required this.appVersion,
    required this.osVersion,
    required this.deviceIdentifierHashStatus,
    required this.localCoreStatus,
    required this.permissionsStatus,
    this.hostName = 'Unknown',
    this.userName = 'Unknown',
    this.executablePath = 'Unknown',
    this.workingDirectory = 'Unknown',
    this.systemArchitecture = 'Unknown',
    this.processorCount = 0,
    this.totalPhysicalMemory = 'Unknown',
    this.serviceStates = const {},
  });

  final String platform;
  final String appVersion;
  final String osVersion;
  final String deviceIdentifierHashStatus;
  final String localCoreStatus;
  final String permissionsStatus;
  final String hostName;
  final String userName;
  final String executablePath;
  final String workingDirectory;
  final String systemArchitecture;
  final int processorCount;
  final String totalPhysicalMemory;
  final Map<String, String> serviceStates;
}

class LocalEvent {
  const LocalEvent({
    required this.id,
    required this.type,
    required this.message,
    required this.createdAt,
    this.details,
    this.category = 'app',
    this.severity = 'info',
  });

  final String id;
  final String type;
  final String message;
  final DateTime createdAt;
  final String? details;
  final String category;
  final String severity;

  static const maxIdLength = 128;
  static const maxTypeLength = 96;
  static const maxMessageLength = 320;
  static const maxDetailsLength = 4096;
  static const maxCategoryLength = 64;
  static const maxSeverityLength = 32;
  static const maxTimestampLength = 64;
  static const allowedCategories = {
    'app',
    'protection',
    'scan',
    'settings',
    'update',
    'quarantine',
  };
  static const allowedSeverities = {'info', 'warning', 'error'};
  static final _eventControlTextPattern = RegExp(r'[\x00-\x1F\x7F]');

  Map<String, Object?> toJson() => {
    'id': id,
    'type': type,
    'message': message,
    'createdAt': createdAt.toIso8601String(),
    'details': details,
    'category': category,
    'severity': severity,
  };

  factory LocalEvent.fromJson(Map<String, Object?> json) => LocalEvent(
    id: _requiredEventString(json, 'id', maxIdLength),
    type: _requiredEventString(json, 'type', maxTypeLength),
    message: _requiredEventString(json, 'message', maxMessageLength),
    createdAt: _requiredEventDateTime(json, 'createdAt'),
    details: _optionalEventString(json, 'details', maxDetailsLength),
    category: _optionalEventAllowedString(
      json,
      'category',
      maxCategoryLength,
      allowedCategories,
      'app',
    ),
    severity: _optionalEventAllowedString(
      json,
      'severity',
      maxSeverityLength,
      allowedSeverities,
      'info',
    ),
  );

  static String _requiredEventString(
    Map<String, Object?> json,
    String key,
    int maxLength,
  ) {
    final value = _optionalEventString(json, key, maxLength);
    if (value == null || value.isEmpty) {
      throw FormatException(
        'Local event field $key must be a non-empty string.',
      );
    }
    return value;
  }

  static String? _optionalEventString(
    Map<String, Object?> json,
    String key,
    int maxLength,
  ) {
    final value = json[key];
    if (value == null) return null;
    if (value is! String) {
      throw FormatException('Local event field $key must be a string.');
    }
    _rejectEventControlText(key, value);
    final trimmed = value.trim();
    if (trimmed.length > maxLength) {
      throw FormatException(
        'Local event field $key must be at most $maxLength characters.',
      );
    }
    return trimmed;
  }

  static DateTime _requiredEventDateTime(
    Map<String, Object?> json,
    String key,
  ) {
    final value = json[key];
    if (value == null) {
      throw FormatException('Local event field $key must be a string.');
    }
    if (value is! String) {
      throw FormatException('Local event field $key must be a string.');
    }
    _rejectEventControlText(key, value);
    final trimmed = value.trim();
    if (trimmed.length > maxTimestampLength) {
      throw FormatException(
        'Local event field $key must be at most $maxTimestampLength characters.',
      );
    }
    final parsed = DateTime.tryParse(trimmed);
    if (parsed == null) {
      throw FormatException(
        'Local event field $key must be a valid timestamp.',
      );
    }
    return parsed;
  }

  static String _optionalEventAllowedString(
    Map<String, Object?> json,
    String key,
    int maxLength,
    Set<String> allowed,
    String fallback,
  ) {
    final value = _optionalEventString(json, key, maxLength);
    if (value == null) return fallback;
    if (!allowed.contains(value)) {
      throw FormatException(
        'Local event field $key must be one of: ${allowed.join(', ')}.',
      );
    }
    return value;
  }

  static void _rejectEventControlText(String key, String value) {
    if (_eventControlTextPattern.hasMatch(value)) {
      throw FormatException(
        'Local event field $key must not contain control characters.',
      );
    }
  }
}

class ScanResult {
  const ScanResult({
    required this.status,
    required this.scannedPath,
    required this.sha256,
    required this.engine,
    required this.scannedAt,
    required this.durationMs,
    this.signatureName,
    this.threatName,
    this.rawEngineSummary,
  });

  final ScanStatus status;
  final String scannedPath;
  final String sha256;
  final String engine;
  final DateTime scannedAt;
  final int durationMs;
  final String? signatureName;
  final String? threatName;
  final String? rawEngineSummary;
}

class ThreatResult {
  const ThreatResult({
    required this.id,
    required this.path,
    required this.fileName,
    required this.sha256,
    required this.sizeBytes,
    required this.detectionType,
    required this.threatCategory,
    required this.threatName,
    required this.confidence,
    required this.engine,
    required this.detectedAt,
    required this.recommendedAction,
    required this.status,
    required this.riskScore,
    this.reasonSummary = '',
    this.quarantineId,
    this.quarantinePath,
    this.quarantineActionTaken,
  });

  final String id;
  final String path;
  final String fileName;
  final String sha256;
  final int sizeBytes;
  final DetectionType detectionType;
  final ThreatCategory threatCategory;
  final String threatName;
  final ThreatConfidence confidence;
  final String engine;
  final DateTime detectedAt;
  final RecommendedAction recommendedAction;
  final ThreatResultStatus status;
  final RiskScore riskScore;
  final String reasonSummary;
  final String? quarantineId;
  final String? quarantinePath;
  final String? quarantineActionTaken;

  ThreatResult copyWith({
    RecommendedAction? recommendedAction,
    ThreatResultStatus? status,
    String? quarantineId,
    String? quarantinePath,
    String? quarantineActionTaken,
  }) {
    return ThreatResult(
      id: id,
      path: path,
      fileName: fileName,
      sha256: sha256,
      sizeBytes: sizeBytes,
      detectionType: detectionType,
      threatCategory: threatCategory,
      threatName: threatName,
      confidence: confidence,
      engine: engine,
      detectedAt: detectedAt,
      recommendedAction: recommendedAction ?? this.recommendedAction,
      status: status ?? this.status,
      riskScore: riskScore,
      reasonSummary: reasonSummary,
      quarantineId: quarantineId ?? this.quarantineId,
      quarantinePath: quarantinePath ?? this.quarantinePath,
      quarantineActionTaken:
          quarantineActionTaken ?? this.quarantineActionTaken,
    );
  }
}

class ScanReport {
  const ScanReport({
    required this.status,
    required this.kind,
    required this.actionMode,
    required this.filesScanned,
    required this.threatsFound,
    required this.skippedFiles,
    required this.elapsedMs,
    required this.threats,
    this.foldersScanned = 0,
    this.bytesScanned = 0,
    this.totalFilesEstimated,
    this.totalBytesEstimated,
    this.suspiciousFound = 0,
    this.quarantinedFiles = 0,
    this.permissionDeniedCount = 0,
    this.progress,
    this.currentPath,
    this.message,
    this.scanErrors = const [],
  });

  final ScanStatus status;
  final ScanKind kind;
  final ScanActionMode actionMode;
  final int filesScanned;
  final int foldersScanned;
  final int bytesScanned;
  final int? totalFilesEstimated;
  final int? totalBytesEstimated;
  final int threatsFound;
  final int suspiciousFound;
  final int quarantinedFiles;
  final int skippedFiles;
  final int permissionDeniedCount;
  final int elapsedMs;
  final String? currentPath;
  final String? message;
  final List<String> scanErrors;
  final List<ThreatResult> threats;
  final ScanProgress? progress;
}

class ScanProgress {
  const ScanProgress({
    required this.jobId,
    required this.scanType,
    required this.status,
    required this.filesScanned,
    required this.foldersScanned,
    required this.bytesScanned,
    required this.threatsFound,
    required this.suspiciousFound,
    required this.skippedFiles,
    required this.permissionDeniedCount,
    required this.startedAt,
    required this.updatedAt,
    required this.elapsedSeconds,
    this.currentPath,
    this.totalFilesEstimated,
    this.totalBytesEstimated,
    this.estimatedRemainingSeconds,
    this.progressPercent,
  });

  final String jobId;
  final ScanKind scanType;
  final ScanJobStatus status;
  final String? currentPath;
  final int filesScanned;
  final int foldersScanned;
  final int bytesScanned;
  final int? totalFilesEstimated;
  final int? totalBytesEstimated;
  final int threatsFound;
  final int suspiciousFound;
  final int skippedFiles;
  final int permissionDeniedCount;
  final DateTime startedAt;
  final DateTime updatedAt;
  final int elapsedSeconds;
  final int? estimatedRemainingSeconds;
  final double? progressPercent;

  String get etaLabel => estimatedRemainingSeconds == null
      ? 'ETA: calculating...'
      : 'ETA: ${_formatSeconds(estimatedRemainingSeconds!)}';

  static String _formatSeconds(int seconds) {
    if (seconds < 60) return '${seconds}s';
    final minutes = seconds ~/ 60;
    final remainder = seconds % 60;
    if (minutes < 60) return '${minutes}m ${remainder}s';
    final hours = minutes ~/ 60;
    return '${hours}h ${minutes % 60}m';
  }
}

class QuarantineRecord {
  const QuarantineRecord({
    required this.quarantineId,
    required this.originalPath,
    required this.quarantinePath,
    required this.sha256,
    required this.fileSize,
    required this.detectionName,
    required this.engine,
    required this.quarantinedAt,
    required this.status,
    required this.source,
    required this.blockedBeforeExecution,
    required this.processStarted,
    required this.actionTaken,
    this.userNote,
  });

  final String quarantineId;
  final String originalPath;
  final String quarantinePath;
  final String sha256;
  final int fileSize;
  final String detectionName;
  final String engine;
  final DateTime quarantinedAt;
  final QuarantineItemStatus status;
  final String? userNote;
  final String source;
  final bool blockedBeforeExecution;
  final bool processStarted;
  final String actionTaken;
}

class AllowlistEntry {
  const AllowlistEntry({
    required this.id,
    required this.type,
    required this.path,
    required this.reason,
    required this.createdAt,
    this.sha256,
    this.createdBy = 'local_user',
    this.active = true,
  });

  final String id;
  final AllowlistEntryType type;
  final String path;
  final String? sha256;
  final String reason;
  final DateTime createdAt;
  final String createdBy;
  final bool active;
}
