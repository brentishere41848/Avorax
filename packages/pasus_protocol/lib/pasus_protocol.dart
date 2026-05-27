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
    ProtectionStatus.protected => 'Protected',
    ProtectionStatus.partiallyProtected => 'Partially Protected',
    ProtectionStatus.stopping => 'Stopping',
    ProtectionStatus.error => 'Protection Error',
  };
}

enum GameDetectionStatus {
  idle,
  scanning,
  detected,
  notFound,
  manual;

  String get label => switch (this) {
    GameDetectionStatus.idle => 'Game Detection Idle',
    GameDetectionStatus.scanning => 'Scanning Known Locations',
    GameDetectionStatus.detected => 'Game Detected',
    GameDetectionStatus.notFound => 'No Supported Game Found',
    GameDetectionStatus.manual => 'Manual Game',
  };
}

enum GameVerificationStatus {
  notConfigured,
  pending,
  verified,
  mismatch,
  failed;

  String get label => switch (this) {
    GameVerificationStatus.notConfigured => 'Not Verified',
    GameVerificationStatus.pending => 'Pending',
    GameVerificationStatus.verified => 'Verified',
    GameVerificationStatus.mismatch => 'Update Required',
    GameVerificationStatus.failed => 'Verification Failed',
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
    this.featureSchemaVersion = '1.0.0',
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
      'Auto-quarantine all detections',
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
    RiskVerdict.suspicious => 'Suspicious',
    RiskVerdict.probableMalware => 'Probable Malware',
    RiskVerdict.confirmedMalware => 'Confirmed Threat',
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
  adware,
  worm,
  keylogger,
  miner,
  potentiallyUnwantedApp,
  unknown;

  String get label => switch (this) {
    ThreatCategory.trojan => 'Potential Trojan',
    ThreatCategory.ransomware => 'Potential ransomware',
    ThreatCategory.spyware => 'Potential spyware',
    ThreatCategory.adware => 'Potential adware',
    ThreatCategory.worm => 'Potential worm',
    ThreatCategory.keylogger => 'Potential keylogger',
    ThreatCategory.miner => 'Potential miner',
    ThreatCategory.potentiallyUnwantedApp => 'Potentially unwanted app',
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

class PasusConfig {
  const PasusConfig({
    this.apiBaseUrl = '',
    this.projectId = '',
    this.publicGameKey = '',
    this.developerOverrideEnabled = false,
    this.onboardingComplete = false,
    this.gameConfig = const GameConfig(),
    this.scanPaths = const [],
    this.realtimeProtectionEnabled = false,
  });

  final String apiBaseUrl;
  final String projectId;
  final String publicGameKey;
  final bool developerOverrideEnabled;
  final bool onboardingComplete;
  final GameConfig gameConfig;
  final List<String> scanPaths;
  final bool realtimeProtectionEnabled;

  bool get hasCloudConfiguration =>
      apiBaseUrl.trim().isNotEmpty &&
      projectId.trim().isNotEmpty &&
      publicGameKey.trim().isNotEmpty;

  List<String> validateCloudConfiguration() {
    final errors = <String>[];
    final parsed = Uri.tryParse(apiBaseUrl.trim());
    if (apiBaseUrl.trim().isEmpty) {
      errors.add(
        'Cloud settings are managed by your Pasus build configuration.',
      );
    } else if (parsed == null || !parsed.hasScheme || parsed.host.isEmpty) {
      errors.add('Pasus Cloud endpoint must be an absolute URL.');
    }
    if (projectId.trim().isEmpty || publicGameKey.trim().isEmpty) {
      errors.add('Pasus Cloud build configuration is incomplete.');
    }
    return errors;
  }

  PasusConfig copyWith({
    String? apiBaseUrl,
    String? projectId,
    String? publicGameKey,
    bool? developerOverrideEnabled,
    bool? onboardingComplete,
    GameConfig? gameConfig,
    List<String>? scanPaths,
    bool? realtimeProtectionEnabled,
  }) {
    return PasusConfig(
      apiBaseUrl: apiBaseUrl ?? this.apiBaseUrl,
      projectId: projectId ?? this.projectId,
      publicGameKey: publicGameKey ?? this.publicGameKey,
      developerOverrideEnabled:
          developerOverrideEnabled ?? this.developerOverrideEnabled,
      onboardingComplete: onboardingComplete ?? this.onboardingComplete,
      gameConfig: gameConfig ?? this.gameConfig,
      scanPaths: scanPaths ?? this.scanPaths,
      realtimeProtectionEnabled:
          realtimeProtectionEnabled ?? this.realtimeProtectionEnabled,
    );
  }

  Map<String, Object?> toJson() => {
    'apiBaseUrl': apiBaseUrl,
    'projectId': projectId,
    'publicGameKey': publicGameKey,
    'developerOverrideEnabled': developerOverrideEnabled,
    'onboardingComplete': onboardingComplete,
    'gameConfig': gameConfig.toJson(),
    'scanPaths': scanPaths,
    'realtimeProtectionEnabled': realtimeProtectionEnabled,
  };

  factory PasusConfig.fromJson(Map<String, Object?> json) {
    final gameJson = json['gameConfig'];
    final scanPathsJson = json['scanPaths'];
    return PasusConfig(
      apiBaseUrl: json['apiBaseUrl'] as String? ?? '',
      projectId: json['projectId'] as String? ?? '',
      publicGameKey: json['publicGameKey'] as String? ?? '',
      developerOverrideEnabled:
          json['developerOverrideEnabled'] as bool? ?? false,
      onboardingComplete: json['onboardingComplete'] as bool? ?? false,
      gameConfig: gameJson is Map<String, Object?>
          ? GameConfig.fromJson(gameJson)
          : const GameConfig(),
      scanPaths: scanPathsJson is List
          ? scanPathsJson.whereType<String>().toList()
          : const [],
      realtimeProtectionEnabled:
          json['realtimeProtectionEnabled'] as bool? ?? false,
    );
  }
}

class GameConfig {
  const GameConfig({
    this.gameId = '',
    this.gameName = '',
    this.gamePath = '',
    this.expectedBuildHash = '',
    this.lastCalculatedHash = '',
    this.platform = '',
    this.source = '',
    this.protectionProfile = 'standard',
  });

  final String gameId;
  final String gameName;
  final String gamePath;
  final String expectedBuildHash;
  final String lastCalculatedHash;
  final String platform;
  final String source;
  final String protectionProfile;

  bool get isConfigured =>
      gameName.trim().isNotEmpty && gamePath.trim().isNotEmpty;

  GameConfig copyWith({
    String? gameId,
    String? gameName,
    String? gamePath,
    String? expectedBuildHash,
    String? lastCalculatedHash,
    String? platform,
    String? source,
    String? protectionProfile,
  }) {
    return GameConfig(
      gameId: gameId ?? this.gameId,
      gameName: gameName ?? this.gameName,
      gamePath: gamePath ?? this.gamePath,
      expectedBuildHash: expectedBuildHash ?? this.expectedBuildHash,
      lastCalculatedHash: lastCalculatedHash ?? this.lastCalculatedHash,
      platform: platform ?? this.platform,
      source: source ?? this.source,
      protectionProfile: protectionProfile ?? this.protectionProfile,
    );
  }

  Map<String, Object?> toJson() => {
    'gameId': gameId,
    'gameName': gameName,
    'gamePath': gamePath,
    'expectedBuildHash': expectedBuildHash,
    'lastCalculatedHash': lastCalculatedHash,
    'platform': platform,
    'source': source,
    'protectionProfile': protectionProfile,
  };

  factory GameConfig.fromJson(Map<String, Object?> json) => GameConfig(
    gameId: json['gameId'] as String? ?? '',
    gameName: json['gameName'] as String? ?? '',
    gamePath: json['gamePath'] as String? ?? '',
    expectedBuildHash: json['expectedBuildHash'] as String? ?? '',
    lastCalculatedHash: json['lastCalculatedHash'] as String? ?? '',
    platform: json['platform'] as String? ?? '',
    source: json['source'] as String? ?? '',
    protectionProfile: json['protectionProfile'] as String? ?? 'standard',
  );
}

class DetectedGame {
  const DetectedGame({
    required this.gameId,
    required this.displayName,
    required this.path,
    required this.source,
    this.buildHash = '',
    this.protectionProfile = 'standard',
  });

  final String gameId;
  final String displayName;
  final String path;
  final String source;
  final String buildHash;
  final String protectionProfile;

  GameConfig toGameConfig() => GameConfig(
    gameId: gameId,
    gameName: displayName,
    gamePath: path,
    lastCalculatedHash: buildHash,
    source: source,
    protectionProfile: protectionProfile,
  );
}

class ProtectionSession {
  const ProtectionSession({
    required this.sessionId,
    required this.startedAt,
    this.expiresAt,
  });

  final String sessionId;
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
  });

  final String platform;
  final String appVersion;
  final String osVersion;
  final String deviceIdentifierHashStatus;
  final String localCoreStatus;
  final String permissionsStatus;
}

class LocalEvent {
  const LocalEvent({
    required this.id,
    required this.type,
    required this.message,
    required this.createdAt,
    this.details,
  });

  final String id;
  final String type;
  final String message;
  final DateTime createdAt;
  final String? details;

  Map<String, Object?> toJson() => {
    'id': id,
    'type': type,
    'message': message,
    'createdAt': createdAt.toIso8601String(),
    'details': details,
  };

  factory LocalEvent.fromJson(Map<String, Object?> json) => LocalEvent(
    id: json['id'] as String? ?? '',
    type: json['type'] as String? ?? 'unknown',
    message: json['message'] as String? ?? '',
    createdAt:
        DateTime.tryParse(json['createdAt'] as String? ?? '') ??
        DateTime.fromMillisecondsSinceEpoch(0),
    details: json['details'] as String?,
  );
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

  ThreatResult copyWith({
    RecommendedAction? recommendedAction,
    ThreatResultStatus? status,
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
    this.userNote,
    this.source = 'scanner',
    this.blockedBeforeExecution = false,
    this.processStarted = false,
    this.actionTaken = 'quarantined',
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
