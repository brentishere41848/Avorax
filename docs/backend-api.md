# Backend API

Avorax includes a Rust Axum backend in `services/api`.

## Start Everything

```powershell
cd C:\Users\Brent\CodexProjects\Avorax
docker compose -f infra/docker-compose.yml up --build
```

API URL:

```text
http://127.0.0.1:8000
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/v1/health
```

## Connect Flutter

```powershell
cd apps/zentor_client
flutter run -d windows `
  --dart-define=AVORAX_API_BASE_URL=http://127.0.0.1:8000 `
  --dart-define=AVORAX_PROJECT_ID=avorax-default `
  --dart-define=AVORAX_PUBLIC_CLIENT_KEY=avorax-public-client
```

## Auth

Protected endpoints require:

```text
Authorization: Bearer avorax-public-client
```

API keys are stored as SHA-256 hashes in Postgres.

## Database

Migrations are in `infra/migrations`. The initial schema creates:

- `projects`
- `api_keys`
- `devices`
- `devices`
- `protectionRuns`
- `protected_app_builds`
- `events`
- `detections`
- `risk_scores`
- `bans`
- `appeals`
- `audit_logs`

Compose exposes the API on `127.0.0.1:8000`, Postgres on `localhost:15432`, and Redis on `localhost:16379` to avoid conflicts with existing local services.
