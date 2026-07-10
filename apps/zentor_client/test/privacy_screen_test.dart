import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:zentor_client/app/theme/zentor_theme.dart';
import 'package:zentor_client/features/privacy/privacy_screen.dart';

void main() {
  testWidgets(
    'privacy policy point list states visible limits and non-behaviors',
    (tester) async {
      tester.view.physicalSize = const Size(1200, 1800);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);

      await tester.pumpWidget(
        MaterialApp(theme: ZentorTheme.dark(), home: const PrivacyScreen()),
      );

      expect(find.text('Privacy-first by design'), findsOneWidget);
      expect(find.byIcon(Icons.check_circle_outline), findsNWidgets(11));
      for (final point in PrivacyScreen.points) {
        expect(find.text(point), findsOneWidget);
      }
      expect(find.textContaining('does not steal credentials'), findsOneWidget);
      expect(
        find.textContaining('does not read browser cookies'),
        findsOneWidget,
      );
      expect(
        find.textContaining('does not hide from the user'),
        findsOneWidget,
      );
      expect(
        find.textContaining('does not silently install kernel drivers'),
        findsOneWidget,
      );
      expect(find.textContaining('never permanently deletes'), findsOneWidget);
    },
  );
}
