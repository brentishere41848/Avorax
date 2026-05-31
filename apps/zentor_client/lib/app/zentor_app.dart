import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'router.dart';
import 'theme/zentor_theme.dart';

class ZentorApp extends ConsumerWidget {
  const ZentorApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final router = ref.watch(routerProvider);
    return MaterialApp.router(
      title: 'Avorax',
      debugShowCheckedModeBanner: false,
      theme: ZentorTheme.dark(),
      routerConfig: router,
    );
  }
}
