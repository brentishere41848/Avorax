import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:pasus_client/core/scanning/scan_target_service.dart';

void main() {
  test('quick scan selects common user risk locations', () {
    final root = Directory.systemTemp.createTempSync('pasus-quick-');
    addTearDown(() => root.deleteSync(recursive: true));
    Directory('${root.path}${Platform.pathSeparator}Downloads').createSync();
    Directory('${root.path}${Platform.pathSeparator}Desktop').createSync();

    final targets = const ScanTargetService().quickScanTargets(
      environment: {'HOME': root.path, 'USERPROFILE': root.path},
    );

    expect(targets.any((path) => path.endsWith('Downloads')), isTrue);
    expect(targets.any((path) => path.endsWith('Desktop')), isTrue);
  });

  test('quick scan avoids broad launcher and applications trees', () {
    final root = Directory.systemTemp.createTempSync('pasus-quick-scope-');
    addTearDown(() => root.deleteSync(recursive: true));
    final appData = Directory('${root.path}${Platform.pathSeparator}AppData');
    final startMenu = Directory(
      '${appData.path}${Platform.pathSeparator}Microsoft'
      '${Platform.pathSeparator}Windows${Platform.pathSeparator}Start Menu',
    );
    final startup = Directory(
      '${startMenu.path}${Platform.pathSeparator}Programs'
      '${Platform.pathSeparator}Startup',
    );
    startMenu.createSync(recursive: true);
    startup.createSync(recursive: true);

    final targets = const ScanTargetService().quickScanTargets(
      environment: {
        'HOME': root.path,
        'USERPROFILE': root.path,
        'APPDATA': appData.path,
      },
    );

    expect(targets, contains(startup.path));
    expect(targets, isNot(contains(startMenu.path)));
  });

  test('full scan roots include accessible home area', () {
    final root = Directory.systemTemp.createTempSync('pasus-full-');
    addTearDown(() => root.deleteSync(recursive: true));

    final roots = const ScanTargetService().fullScanRoots(
      environment: {'HOME': root.path, 'USERPROFILE': root.path},
    );

    if (Platform.isWindows) {
      expect(roots.any((path) => path.endsWith(r':\')), isTrue);
    } else {
      expect(roots, contains(root.path));
    }
  });
}
