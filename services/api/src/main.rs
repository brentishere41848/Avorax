use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::{serve, Router};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Pool, Postgres};
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

mod auth;
mod config;
mod error;
mod models;
mod routes;

use auth::hash_api_key;
use config::ApiConfig;

const MAX_API_BODY_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: Option<Arc<redis::Client>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    load_local_dotenv()?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("zentor_api=info".parse()?))
        .init();

    let config = ApiConfig::from_env()?;
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;
    run_migrations(&db).await?;
    if let Some(dev_seed) = &config.dev_seed {
        seed_dev_project(
            &db,
            &dev_seed.dev_project_id,
            &dev_seed.dev_public_client_key,
        )
        .await?;
    }
    let redis = Some(Arc::new(
        redis::Client::open(config.redis_url.clone()).context("invalid Redis URL")?,
    ));
    let state = AppState { db, redis };
    let app = router(state);
    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!("Avorax API listening on {}", config.bind_addr);
    serve(listener, app).await?;
    Ok(())
}

fn load_local_dotenv() -> anyhow::Result<()> {
    let dotenv_path = Path::new(".env");
    if dotenv_path
        .try_exists()
        .context("failed to inspect .env file")?
    {
        dotenvy::from_path(dotenv_path).context("failed to load .env file")?;
    }
    Ok(())
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(routes::health))
        .route("/v1/projects", post(routes::create_project))
        .route("/v1/devices", post(routes::register_device))
        .route("/v1/protection_runs", post(routes::create_session))
        .route("/v1/protection-runs", post(routes::create_session))
        .route(
            "/v1/protection_runs/{session_id}/heartbeat",
            post(routes::heartbeat),
        )
        .route(
            "/v1/protection-runs/{session_id}/heartbeat",
            post(routes::heartbeat),
        )
        .route(
            "/v1/protection_runs/{session_id}/events",
            post(routes::ingest_events),
        )
        .route(
            "/v1/protection-runs/{session_id}/events",
            post(routes::ingest_events),
        )
        .route(
            "/v1/protection_runs/{session_id}/end",
            post(routes::end_session),
        )
        .route(
            "/v1/protection-runs/{session_id}/end",
            post(routes::end_session),
        )
        .route("/v1/devices/{device_id}/risk", get(routes::device_risk))
        .route("/v1/bans", post(routes::create_ban))
        .route("/v1/detections", post(routes::report_detection))
        .route("/v1/quarantine", post(routes::upload_quarantine_metadata))
        .route("/v1/audit-logs", get(routes::audit_logs))
        .layer(DefaultBodyLimit::max(MAX_API_BODY_BYTES))
        .layer(CorsLayer::new())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn run_migrations(db: &Pool<Postgres>) -> anyhow::Result<()> {
    let migrations_dir = Path::new("../../infra/migrations");
    if !migrations_dir.try_exists().with_context(|| {
        format!(
            "failed to inspect migrations directory: {}",
            migrations_dir.display()
        )
    })? {
        anyhow::bail!(
            "migrations directory not found: {}",
            migrations_dir.display()
        );
    }
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(migrations_dir).with_context(|| {
        format!(
            "failed to read migrations directory: {}",
            migrations_dir.display()
        )
    })? {
        let path = entry
            .with_context(|| {
                format!(
                    "failed to read migrations directory entry under {}",
                    migrations_dir.display()
                )
            })?
            .path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("sql") {
            entries.push(path);
        }
    }
    entries.sort();
    for path in entries {
        let sql = std::fs::read_to_string(&path)?;
        for statement in sql.split(';') {
            let statement = statement.trim();
            if statement.is_empty() {
                continue;
            }
            sqlx::query(statement).execute(db).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    fn test_app() -> Router {
        let db = PgPoolOptions::new()
            .connect_lazy("postgres://avorax:avorax@127.0.0.1:15432/avorax_test")
            .expect("lazy test pool");
        router(AppState { db, redis: None })
    }

    #[test]
    fn api_router_does_not_use_permissive_cors() {
        let source = include_str!("main.rs");
        assert!(source.contains("CorsLayer::new()"));
        let permissive_cors = ["CorsLayer", "::permissive()"].concat();
        assert!(!source.contains(&permissive_cors));
    }

    #[test]
    fn api_router_supports_flutter_cloud_routes_and_body_limit() {
        let source = include_str!("main.rs");
        assert!(source.contains("/v1/protection-runs"));
        assert!(source.contains("/v1/protection-runs/{session_id}/heartbeat"));
        assert!(source.contains("DefaultBodyLimit::max(MAX_API_BODY_BYTES)"));
        let old_session_param = ["/", ":session_id"].concat();
        let old_device_param = ["/", ":device_id"].concat();
        assert!(!source.contains(&old_session_param));
        assert!(!source.contains(&old_device_param));
    }

    #[tokio::test]
    async fn cors_preflight_does_not_grant_permissive_browser_access() {
        let response = test_app()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/v1/protection-runs")
                    .header(header::ORIGIN, "https://example.invalid")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("preflight response");

        assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_ne!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&header::HeaderValue::from_static("*"))
        );
        assert_ne!(
            response.headers().get(header::ACCESS_CONTROL_ALLOW_METHODS),
            Some(&header::HeaderValue::from_static("*"))
        );
    }
}

async fn seed_dev_project(db: &PgPool, project_slug: &str, public_key: &str) -> anyhow::Result<()> {
    let project_id = uuid::Uuid::new_v4();
    let key_id = uuid::Uuid::new_v4();
    let key_hash = hash_api_key(public_key);
    sqlx::query(
        "insert into projects (id, name, slug)
         values ($1, 'Avorax Local Dev', $2)
         on conflict (slug) do nothing",
    )
    .bind(project_id)
    .bind(project_slug)
    .execute(db)
    .await?;
    let row: (uuid::Uuid,) = sqlx::query_as("select id from projects where slug = $1")
        .bind(project_slug)
        .fetch_one(db)
        .await?;
    sqlx::query(
        "insert into api_keys (id, project_id, name, key_hash)
         values ($1, $2, 'Local dev public key', $3)
         on conflict (key_hash) do nothing",
    )
    .bind(key_id)
    .bind(row.0)
    .bind(key_hash)
    .execute(db)
    .await?;
    Ok(())
}
