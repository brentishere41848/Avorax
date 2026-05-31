# API Configuration

Avorax uses build-time Avorax Cloud configuration for optional cloud features. Local scanning does not require this configuration.

```dart
const zentorApiBaseUrl = String.fromEnvironment(
  'AVORAX_API_BASE_URL',
  defaultValue: 'http://127.0.0.1:8000',
);

const zentorProjectId = String.fromEnvironment(
  'AVORAX_PROJECT_ID',
  defaultValue: 'avorax-default',
);

const zentorPublicClientKey = String.fromEnvironment(
  'AVORAX_PUBLIC_CLIENT_KEY',
  defaultValue: 'avorax-public-client',
);
```

Run with custom values:

```powershell
flutter run -d windows `
  --dart-define=AVORAX_API_BASE_URL=https://YOUR_API_HERE `
  --dart-define=AVORAX_PROJECT_ID=YOUR_PROJECT_ID `
  --dart-define=AVORAX_PUBLIC_CLIENT_KEY=YOUR_PUBLIC_CLIENT_KEY
```

The app does not require a cloud health check before scanning. Cloud checks are user-initiated from settings or future cloud update/reporting flows.

- Success shows `Cloud: Online`.
- Failure shows `Cloud: Offline`.
- Disabled shows `Cloud: Disabled`.
- Failure does not block local scanning, quarantine, or protection controls.

Manual editing is hidden in `Settings > Advanced > Developer options`.
