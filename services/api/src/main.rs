use std::path::Path;
use std::sync::Arc;

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

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub redis: Option<Arc<redis::Client>>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("zentor_api=info".parse()?))
        .init();

    let config = ApiConfig::from_env()?;
    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&config.database_url)
        .await?;
    run_migrations(&db).await?;
    seed_dev_project(&db, &config.dev_project_id, &config.dev_public_client_key).await?;
    let redis = redis::Client::open(config.redis_url.clone())
        .ok()
        .map(Arc::new);
    let state = AppState { db, redis };
    let app = router(state);
    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!("Avorax API listening on {}", config.bind_addr);
    serve(listener, app).await?;
    Ok(())
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/health", get(routes::health))
        .route("/v1/projects", post(routes::create_project))
        .route("/v1/devices", post(routes::register_device))
        .route("/v1/protection_runs", post(routes::create_session))
        .route(
            "/v1/protection_runs/:session_id/heartbeat",
            post(routes::heartbeat),
        )
        .route(
            "/v1/protection_runs/:session_id/events",
            post(routes::ingest_events),
        )
        .route("/v1/protection_runs/:session_id/end", post(routes::end_session))
        .route("/v1/devices/:device_id/risk", get(routes::device_risk))
        .route("/v1/bans", post(routes::create_ban))
        .route("/v1/detections", post(routes::report_detection))
        .route("/v1/quarantine", post(routes::upload_quarantine_metadata))
        .route("/v1/audit-logs", get(routes::audit_logs))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn run_migrations(db: &Pool<Postgres>) -> anyhow::Result<()> {
    let migrations_dir = Path::new("../../infra/migrations");
    if !migrations_dir.exists() {
        anyhow::bail!(
            "migrations directory not found: {}",
            migrations_dir.display()
        );
    }
    let mut entries = std::fs::read_dir(migrations_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sql"))
        .collect::<Vec<_>>();
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
