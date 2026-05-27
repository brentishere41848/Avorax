import 'dart:io';

class ScanTargetService {
  const ScanTargetService();

  List<String> quickScanTargets({Map<String, String>? environment}) {
    final env = environment ?? Platform.environment;
    final home = env['HOME'] ?? env['USERPROFILE'];
    final targets = <String>{};
    void addIfPresent(String? path) {
      if (path == null || path.trim().isEmpty) return;
      if (FileSystemEntity.typeSync(path) != FileSystemEntityType.notFound) {
        targets.add(path);
      }
    }

    if (home != null) {
      addIfPresent(_join(home, 'Downloads'));
      addIfPresent(_join(home, 'Desktop'));
    }

    if (Platform.isWindows) {
      addIfPresent(env['TEMP']);
      addIfPresent(env['TMP']);
      final appData = env['APPDATA'];
      addIfPresent(
        appData == null
            ? null
            : _join(appData, r'Microsoft\Windows\Start Menu\Programs\Startup'),
      );
      final localAppData = env['LOCALAPPDATA'];
      addIfPresent(localAppData == null ? null : _join(localAppData, 'Temp'));
    } else if (Platform.isMacOS) {
      addIfPresent('/tmp');
      addIfPresent(home == null ? null : _join(home, 'Library/LaunchAgents'));
      addIfPresent('/Library/LaunchAgents');
    } else if (Platform.isLinux) {
      addIfPresent('/tmp');
      addIfPresent(home == null ? null : _join(home, '.config/autostart'));
      addIfPresent(home == null ? null : _join(home, '.local/bin'));
    }
    return targets.toList()..sort();
  }

  List<String> fullScanRoots({Map<String, String>? environment}) {
    final env = environment ?? Platform.environment;
    if (Platform.isWindows) {
      final roots = <String>{};
      for (var code = 'A'.codeUnitAt(0); code <= 'Z'.codeUnitAt(0); code++) {
        final root = '${String.fromCharCode(code)}:\\';
        if (Directory(root).existsSync()) roots.add(root);
      }
      return roots.toList()..sort();
    }
    if (Platform.isMacOS) {
      final home = env['HOME'];
      return [
        if (home != null && Directory(home).existsSync()) home,
        if (Directory('/Applications').existsSync()) '/Applications',
        if (Directory('/Users').existsSync()) '/Users',
      ];
    }
    final home = env['HOME'];
    return [
      if (home != null && Directory(home).existsSync()) home,
      if (Directory('/opt').existsSync()) '/opt',
      if (Directory('/usr/local').existsSync()) '/usr/local',
    ];
  }

  String _join(String base, String child) {
    final normalizedChild = child
        .replaceAll('/', Platform.pathSeparator)
        .replaceAll('\\', Platform.pathSeparator);
    return base.endsWith(Platform.pathSeparator)
        ? '$base$normalizedChild'
        : '$base${Platform.pathSeparator}$normalizedChild';
  }
}
