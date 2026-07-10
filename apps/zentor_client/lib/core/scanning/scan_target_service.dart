import 'dart:io';

enum ScanPlatform { windows, macos, linux, other }

class ScanTargetService {
  const ScanTargetService();

  ScanTargetPlan quickScanTargetPlan({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) {
    final env = environment ?? Platform.environment;
    final activePlatform = platform ?? _currentPlatform();
    final home = _firstEnvironmentPath(env, const [
      'HOME',
      'USERPROFILE',
    ], activePlatform);
    final targets = <String>{};
    final limitations = <String>[];
    void addIfPresent(String? path) {
      if (path == null || path.trim().isEmpty) return;
      final probe = _pathExistsOrNeedsCoreValidation(path, 'quick scan target');
      if (probe.include) targets.add(path);
      final limitation = probe.limitation;
      if (limitation != null) limitations.add(limitation);
    }

    if (home != null) {
      addIfPresent(_join(home, 'Downloads', activePlatform));
      addIfPresent(_join(home, 'Desktop', activePlatform));
    }

    switch (activePlatform) {
      case ScanPlatform.windows:
        addIfPresent(_environmentPath(env, 'TEMP', activePlatform));
        addIfPresent(_environmentPath(env, 'TMP', activePlatform));
        final appData = _environmentPath(env, 'APPDATA', activePlatform);
        addIfPresent(
          appData == null
              ? null
              : _join(
                  appData,
                  r'Microsoft\Windows\Start Menu\Programs\Startup',
                  activePlatform,
                ),
        );
        final localAppData = _environmentPath(
          env,
          'LOCALAPPDATA',
          activePlatform,
        );
        addIfPresent(
          localAppData == null
              ? null
              : _join(localAppData, 'Temp', activePlatform),
        );
      case ScanPlatform.macos:
        addIfPresent('/tmp');
        addIfPresent(
          home == null
              ? null
              : _join(home, 'Library/LaunchAgents', activePlatform),
        );
        addIfPresent('/Library/LaunchAgents');
      case ScanPlatform.linux:
        addIfPresent('/tmp');
        addIfPresent(
          home == null
              ? null
              : _join(home, '.config/autostart', activePlatform),
        );
        addIfPresent(
          home == null ? null : _join(home, '.local/bin', activePlatform),
        );
      case ScanPlatform.other:
        addIfPresent(_environmentPath(env, 'TMPDIR', activePlatform));
    }
    final paths = targets.toList()..sort();
    return ScanTargetPlan(paths, limitations);
  }

  List<String> quickScanTargets({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => quickScanTargetPlan(environment: environment, platform: platform).paths;

  ScanTargetPlan fullScanRootPlan({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) {
    final env = environment ?? Platform.environment;
    final activePlatform = platform ?? _currentPlatform();
    final limitations = <String>[];
    void addRootIfPresent(Set<String> roots, String path) {
      final probe = _directoryExistsOrNeedsCoreValidation(
        path,
        'full scan root',
      );
      if (probe.include) roots.add(path);
      final limitation = probe.limitation;
      if (limitation != null) limitations.add(limitation);
    }

    switch (activePlatform) {
      case ScanPlatform.windows:
        final roots = <String>{};
        for (var code = 'A'.codeUnitAt(0); code <= 'Z'.codeUnitAt(0); code++) {
          addRootIfPresent(roots, '${String.fromCharCode(code)}:\\');
        }
        final paths = roots.toList()..sort();
        return ScanTargetPlan(paths, limitations);
      case ScanPlatform.macos:
        final home = _environmentPath(env, 'HOME', activePlatform);
        final roots = <String>{};
        if (home != null) addRootIfPresent(roots, home);
        addRootIfPresent(roots, '/Applications');
        addRootIfPresent(roots, '/Users');
        final paths = roots.toList()..sort();
        return ScanTargetPlan(paths, limitations);
      case ScanPlatform.linux:
        final home = _environmentPath(env, 'HOME', activePlatform);
        final roots = <String>{};
        if (home != null) addRootIfPresent(roots, home);
        addRootIfPresent(roots, '/opt');
        addRootIfPresent(roots, '/usr/local');
        final paths = roots.toList()..sort();
        return ScanTargetPlan(paths, limitations);
      case ScanPlatform.other:
        final home = _firstEnvironmentPath(env, const [
          'HOME',
          'USERPROFILE',
        ], activePlatform);
        final roots = <String>{};
        if (home != null) addRootIfPresent(roots, home);
        final paths = roots.toList()..sort();
        return ScanTargetPlan(paths, limitations);
    }
  }

  List<String> fullScanRoots({
    Map<String, String>? environment,
    ScanPlatform? platform,
  }) => fullScanRootPlan(environment: environment, platform: platform).paths;

  _ScanTargetProbe _pathExistsOrNeedsCoreValidation(String path, String label) {
    try {
      return _ScanTargetProbe(
        FileSystemEntity.typeSync(path, followLinks: false) !=
            FileSystemEntityType.notFound,
      );
    } on Object catch (error) {
      return _ScanTargetProbe(
        true,
        _scanTargetProbeLimitation(label, path, error),
      );
    }
  }

  _ScanTargetProbe _directoryExistsOrNeedsCoreValidation(
    String path,
    String label,
  ) {
    try {
      final type = FileSystemEntity.typeSync(path, followLinks: false);
      return _ScanTargetProbe(
        type == FileSystemEntityType.directory ||
            type == FileSystemEntityType.link,
      );
    } on Object catch (error) {
      return _ScanTargetProbe(
        true,
        _scanTargetProbeLimitation(label, path, error),
      );
    }
  }

  String _scanTargetProbeLimitation(String label, String path, Object error) {
    final details = _boundedScanTargetDiagnostic(error);
    return 'Unable to inspect $label $path before Core validation: $details';
  }

  String _boundedScanTargetDiagnostic(Object error) {
    final normalized = error
        .toString()
        .replaceAll(RegExp(r'[\x00-\x1F\x7F]+'), ' ')
        .replaceAll(RegExp(r'\s{2,}'), ' ')
        .trim();
    if (normalized.isEmpty) return 'unknown inspection error';
    if (normalized.length <= 240) return normalized;
    return '${normalized.substring(0, 240)}...';
  }

  String? _firstEnvironmentPath(
    Map<String, String> env,
    List<String> keys,
    ScanPlatform platform,
  ) {
    for (final key in keys) {
      final value = _environmentPath(env, key, platform);
      if (value != null) return value;
    }
    return null;
  }

  String? _environmentPath(
    Map<String, String> env,
    String key,
    ScanPlatform platform,
  ) {
    final value = env[key]?.trim();
    if (value == null || value.isEmpty) return null;
    if (value.contains('\u0000')) return null;
    if (_hasParentTraversal(value)) return null;
    return _isAbsoluteLocalPath(value, platform) ? value : null;
  }

  bool _hasParentTraversal(String path) {
    return path
        .replaceAll(r'\', '/')
        .split('/')
        .any((segment) => segment == '..');
  }

  bool _isAbsoluteLocalPath(String path, ScanPlatform platform) {
    switch (platform) {
      case ScanPlatform.windows:
        final normalized = path.replaceAll('/', r'\');
        if (normalized.startsWith(r'\\')) return false;
        return RegExp(r'^[A-Za-z]:\\').hasMatch(normalized);
      case ScanPlatform.macos:
      case ScanPlatform.linux:
        return (path.startsWith('/') && !path.startsWith('//')) ||
            _isCurrentHostAbsoluteLocalPath(path);
      case ScanPlatform.other:
        if (path.startsWith('//') || path.startsWith(r'\\')) return false;
        return path.startsWith('/') ||
            RegExp(r'^[A-Za-z]:[\\/]').hasMatch(path);
    }
  }

  bool _isCurrentHostAbsoluteLocalPath(String path) {
    if (Platform.isWindows) {
      final normalized = path.replaceAll('/', r'\');
      if (normalized.startsWith(r'\\')) return false;
      return RegExp(r'^[A-Za-z]:\\').hasMatch(normalized);
    }
    return false;
  }

  ScanPlatform _currentPlatform() {
    if (Platform.isWindows) return ScanPlatform.windows;
    if (Platform.isMacOS) return ScanPlatform.macos;
    if (Platform.isLinux) return ScanPlatform.linux;
    return ScanPlatform.other;
  }

  String _join(String base, String child, ScanPlatform platform) {
    final separator = _separatorFor(platform);
    final normalizedChild = child.replaceAll(RegExp(r'[/\\]+'), separator);
    return base.endsWith('/') || base.endsWith('\\')
        ? '$base$normalizedChild'
        : '$base$separator$normalizedChild';
  }

  String _separatorFor(ScanPlatform platform) {
    return platform == ScanPlatform.windows ? r'\' : '/';
  }
}

class ScanTargetPlan {
  const ScanTargetPlan(this.paths, this.limitations);

  final List<String> paths;
  final List<String> limitations;
}

class _ScanTargetProbe {
  const _ScanTargetProbe(this.include, [this.limitation]);

  final bool include;
  final String? limitation;
}
