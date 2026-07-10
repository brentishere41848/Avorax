# Avorax API

Rust Axum backend for local Avorax development.

## Run With Docker Compose

```powershell
cd C:\Users\Brent\CodexProjects\Avorax
docker compose -f infra/docker-compose.yml up --build
```

The Compose API listens on `http://127.0.0.1:8000`.

```powershell
Invoke-RestMethod http://127.0.0.1:8000/v1/health
```

The compose stack starts:

- PostgreSQL on `localhost:15432`
- Redis on `localhost:16379`
- Avorax API on `127.0.0.1:8000`

## Development Seed

On startup, the API creates a local development project and API key:

```text
AVORAX_ENABLE_DEV_SEED=true
AVORAX_DEV_PROJECT_ID=avorax-default
AVORAX_DEV_PUBLIC_CLIENT_KEY=avorax-public-client
```

Use the key as:

```text
Authorization: Bearer avorax-public-client
```

## Run With Cargo

Start Postgres and Redis:

```powershell
cd C:\Users\Brent\CodexProjects\Avorax
docker compose -f infra/docker-compose.yml up postgres redis
```

Run the API:

```powershell
cd services/api
$env:DATABASE_URL="postgres://zentor:zentor@localhost:15432/zentor"
$env:REDIS_URL="redis://localhost:16379"
$env:AVORAX_ENABLE_DEV_SEED="true"
$env:AVORAX_DEV_PROJECT_ID="avorax-default"
$env:AVORAX_DEV_PUBLIC_CLIENT_KEY="avorax-public-client"
cargo run
```

When running with Cargo directly, the API listens on `http://127.0.0.1:8000` unless you set `AVORAX_API_BIND_ADDR`.

## Endpoints

- `GET /v1/health`
- `POST /v1/projects` (disabled until an authenticated provisioning workflow exists)
- `POST /v1/devices`
- `POST /v1/protection-runs`
- `POST /v1/protection-runs/{session_id}/heartbeat`
- `POST /v1/protection-runs/{session_id}/events`
- `POST /v1/protection-runs/{session_id}/end`
- `GET /v1/devices/{device_id}/risk`
- `POST /v1/bans`
- `POST /v1/detections`
- `POST /v1/quarantine`
- `GET /v1/audit-logs`

## Safety

The API stores only protection-related session, event, risk, detection, quarantine metadata, and audit data. It does not receive raw personal files or credentials from the client.

The API also keeps legacy underscore protection-run routes for compatibility, but the Flutter client uses the documented hyphenated routes. Request bodies are size-limited and route handlers validate string, hash, token, event-batch, and JSON payload bounds before inserting records. Project creation is not open over the public API; local development uses the explicit dev seed and production projects must be provisioned out of band until an authenticated admin workflow exists.
