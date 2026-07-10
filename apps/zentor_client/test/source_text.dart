import 'dart:io';

String normalizeSourceText(String source) {
  return source.replaceAll('\r\n', '\n').replaceAll('\r', '\n');
}

String readNormalizedSource(String path) {
  return normalizeSourceText(File(path).readAsStringSync());
}
