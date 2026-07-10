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

The local Compose stack enables the development seed explicitly with `AVORAX_ENABLE_DEV_SEED=true`. Direct Cargo runs must set that flag plus `AVORAX_DEV_PROJECT_ID` and `AVORAX_DEV_PUBLIC_CLIENT_KEY` when they need the documented local key; production deployments should create real projects/keys instead of enabling the dev seed.

`POST /v1/projects` is fail-closed until an authenticated provisioning workflow exists. It does not issue bearer keys to unauthenticated callers.

The Flutter client uses hyphenated protection-run routes:

- `POST /v1/protection-runs`
- `POST /v1/protection-runs/{session_id}/heartbeat`
- `POST /v1/protection-runs/{session_id}/events`
- `POST /v1/protection-runs/{session_id}/end`

The API keeps legacy underscore route aliases for compatibility. Protection-run creation returns both `protection_run_id` and `session_id`; current Flutter clients read `protection_run_id`.

Request `project_id` fields accept either the authenticated project UUID string or the authenticated project slug such as `avorax-default`. A request body cannot select a different project than the bearer token authorizes.

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

Request bodies and nested event payloads are bounded. Detection reports accept the current Flutter aggregate `detections` array, validate detection count and SHA-256/hash/text fields, and continue to accept the older single-detection shape for compatibility.
