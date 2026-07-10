import 'package:flutter_test/flutter_test.dart';

import 'source_text.dart';

void main() {
  test('source text normalization handles Windows and legacy newlines', () {
    expect(
      normalizeSourceText('first\r\nsecond\rthird'),
      'first\nsecond\nthird',
    );
  });
}
