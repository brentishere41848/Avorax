use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::{hash_api_key, ApiAuth};
use crate::error::{ApiError, ApiResult};
use crate::models::*;
use crate::AppState;

pub async fn health(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    sqlx::query("select 1").execute(&state.db).await?;
    Ok(Json(json!({
        "status": "ok",
        "service": "zentor-api",
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

pub async fn create_project(
    State(state): State<AppState>,
    Json(request): Json<CreateProjectRequest>,
) -> ApiResult<Json<ProjectResponse>> {
    let name = request.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("project name is required".to_string()));
    }
    let project_id = Uuid::new_v4();
    let slug = request
        .slug
        .unwrap_or_else(|| name.to_lowercase().replace(' ', "-"));
    let public_client_key = format!("pk_zentor_{}", Uuid::new_v4().simple());
    let key_hash = hash_api_key(&public_client_key);
    let mut tx = state.db.begin().await?;
    sqlx::query("insert into projects (id, name, slug) values ($1, $2, $3)")
        .bind(project_id)
        .bind(name)
        .bind(&slug)
        .execute(&mut *tx)
        .await?;
    sqlx::query("insert into api_keys (id, project_id, name, key_hash) values ($1, $2, $3, $4)")
        .bind(Uuid::new_v4())
        .bind(project_id)
        .bind("Default public client key")
        .bind(key_hash)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit(
        &state,
        Some(project_id),
        None,
        "project_created",
        json!({"name": name, "slug": slug}),
    )
    .await?;
    Ok(Json(ProjectResponse {
        project_id,
        name: name.to_string(),
        slug,
        public_client_key,
    }))
}

pub async fn register_device(
    State(state): State<AppState>,
    auth: ApiAuth,
    Json(request): Json<RegisterDeviceRequest>,
) -> ApiResult<Json<DeviceResponse>> {
    let project_id = if request.project_id == auth.project_id {
        request.project_id
    } else {
        auth.project_id
    };
    let device_id = Uuid::new_v4();
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>)>(
        "insert into devices (id, project_id, external_device_id, display_name)
         values ($1, $2, $3, $4)
         on conflict (project_id, external_device_id)
         do update set display_name = excluded.display_name
         returning id, project_id, external_device_id, display_name",
    )
    .bind(device_id)
    .bind(project_id)
    .bind(request.external_device_id)
    .bind(request.display_name)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(DeviceResponse {
        device_id: row.0,
        project_id: row.1,
        external_device_id: row.2,
        display_name: row.3,
    }))
}

pub async fn create_session(
    State(state): State<AppState>,
    auth: ApiAuth,
    Json(request): Json<CreateSessionRequest>,
) -> ApiResult<Json<SessionResponse>> {
    if request.nonce.trim().is_empty() {
        return Err(ApiError::BadRequest("nonce is required".to_string()));
    }
    let session_id = Uuid::new_v4();
    let project_id = request.project_id.unwrap_or(auth.project_id);
    if project_id != auth.project_id {
        return Err(ApiError::Unauthorized);
    }
    let started_at = Utc::now();
    sqlx::query(
        "insert into protection_runs
         (id, project_id, device_id, platform, client_version, file_hash, device_fingerprint_hash, nonce, started_at, expires_at, status)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active')",
    )
    .bind(session_id)
    .bind(project_id)
    .bind(request.device_id)
    .bind(request.platform)
    .bind(request.client_version)
    .bind(request.file_hash)
    .bind(request.device_fingerprint_hash)
    .bind(request.nonce)
    .bind(started_at)
    .bind(request.expires_at)
    .execute(&state.db)
    .await?;
    audit(
        &state,
        Some(project_id),
        request.device_id,
        "protection_session_created",
        json!({"session_id": session_id}),
    )
    .await?;
    Ok(Json(SessionResponse {
        session_id,
        started_at,
        expires_at: request.expires_at,
    }))
}

pub async fn heartbeat(
    State(state): State<AppState>,
    auth: ApiAuth,
    Path(session_id): Path<Uuid>,
    Json(request): Json<HeartbeatRequest>,
) -> ApiResult<Json<Value>> {
    if let Some(body_session_id) = request.session_id {
        if body_session_id != session_id {
            return Err(ApiError::BadRequest("session_id mismatch".to_string()));
        }
    }
    let session_project = session_project(&state, session_id).await?;
    if session_project != auth.project_id {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query(
        "insert into events (id, project_id, session_id, event_type, payload)
         values ($1,$2,$3,'heartbeat',$4)",
    )
    .bind(Uuid::new_v4())
    .bind(auth.project_id)
    .bind(session_id)
    .bind(json!({
        "monotonic_time": request.monotonic_time,
        "client_timestamp": request.client_timestamp,
        "signed_payload": request.signed_payload,
        "environment": request.environment,
    }))
    .execute(&state.db)
    .await?;
    sqlx::query("update protection_runs set last_heartbeat_at = now() where id = $1")
        .bind(session_id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn ingest_events(
    State(state): State<AppState>,
    auth: ApiAuth,
    Path(session_id): Path<Uuid>,
    Json(events): Json<Vec<SecurityEventRequest>>,
) -> ApiResult<Json<Value>> {
    let session_project = session_project(&state, session_id).await?;
    if session_project != auth.project_id {
        return Err(ApiError::Unauthorized);
    }
    let mut inserted = 0usize;
    for event in events {
        let (event_type, payload) = match event {
            SecurityEventRequest::FileScanEvent { payload } => ("file_scan_event", payload),
            SecurityEventRequest::ProtectionDecisionEvent { payload } => {
                ("protection_decision_event", payload)
            }
            SecurityEventRequest::QuarantineEvent { payload } => ("quarantine_event", payload),
            SecurityEventRequest::AllowlistEvent { payload } => ("allowlist_event", payload),
            SecurityEventRequest::ServiceHealthEvent { payload } => ("service_health_event", payload),
        };
        sqlx::query(
            "insert into events (id, project_id, session_id, event_type, payload)
             values ($1,$2,$3,$4,$5)",
        )
        .bind(Uuid::new_v4())
        .bind(auth.project_id)
        .bind(session_id)
        .bind(event_type)
        .bind(payload)
        .execute(&state.db)
        .await?;
        inserted += 1;
    }
    Ok(Json(json!({"inserted": inserted})))
}

pub async fn end_session(
    State(state): State<AppState>,
    auth: ApiAuth,
    Path(session_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let session_project = session_project(&state, session_id).await?;
    if session_project != auth.project_id {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query("update protection_runs set status = 'ended', ended_at = now() where id = $1")
        .bind(session_id)
        .execute(&state.db)
        .await?;
    audit(
        &state,
        Some(auth.project_id),
        None,
        "protection_session_ended",
        json!({"session_id": session_id}),
    )
    .await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn device_risk(
    State(state): State<AppState>,
    auth: ApiAuth,
    Path(device_id): Path<Uuid>,
) -> ApiResult<Json<RiskResponse>> {
    let row = sqlx::query_as::<_, (Option<i32>, Option<String>, Option<Value>)>(
        "select score, severity, reasons from risk_scores
         where project_id = $1 and device_id = $2 order by calculated_at desc limit 1",
    )
    .bind(auth.project_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    let (score, severity, reasons) = match row {
        Some((score, severity, reasons)) => (
            score.unwrap_or(0),
            severity.unwrap_or_else(|| "info".to_string()),
            reasons
                .and_then(|value| serde_json::from_value(value).ok())
                .unwrap_or_else(Vec::new),
        ),
        None => (0, "info".to_string(), Vec::new()),
    };
    Ok(Json(RiskResponse {
        device_id,
        score,
        severity,
        reasons,
    }))
}

pub async fn create_ban(
    State(state): State<AppState>,
    auth: ApiAuth,
    Json(request): Json<CreateBanRequest>,
) -> ApiResult<Json<Value>> {
    let allowed = [
        "clean",
        "suspicious",
        "review_required",
        "confirmed",
        "appealed",
        "revoked",
    ];
    if !allowed.contains(&request.status.as_str()) {
        return Err(ApiError::BadRequest("invalid ban status".to_string()));
    }
    let ban_id = Uuid::new_v4();
    sqlx::query(
        "insert into bans (id, project_id, device_id, status, reason)
         values ($1,$2,$3,$4,$5)",
    )
    .bind(ban_id)
    .bind(auth.project_id)
    .bind(request.device_id)
    .bind(request.status)
    .bind(request.reason)
    .execute(&state.db)
    .await?;
    audit(
        &state,
        Some(auth.project_id),
        Some(request.device_id),
        "ban_status_changed",
        json!({"ban_id": ban_id}),
    )
    .await?;
    Ok(Json(json!({"ban_id": ban_id})))
}

pub async fn report_detection(
    State(state): State<AppState>,
    auth: ApiAuth,
    Json(request): Json<DetectionReportRequest>,
) -> ApiResult<Json<Value>> {
    let project_id = request.project_id.unwrap_or(auth.project_id);
    if project_id != auth.project_id {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query(
        "insert into detections (id, project_id, rule_id, severity, risk_delta, reasons, evidence)
         values ($1,$2,'malware_detection','high',70,$3,$4)",
    )
    .bind(Uuid::new_v4())
    .bind(project_id)
    .bind(json!([request
        .threat_name
        .clone()
        .unwrap_or_else(|| "Threat detected".to_string())]))
    .bind(json!({
        "scanned_path_hash": request.scanned_path_hash,
        "engine": request.engine,
        "threat_name": request.threat_name,
        "detected_at": request.detected_at,
    }))
    .execute(&state.db)
    .await?;
    audit(
        &state,
        Some(project_id),
        None,
        "automated_detection_reported",
        json!({"engine": request.engine}),
    )
    .await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn upload_quarantine_metadata(
    State(state): State<AppState>,
    auth: ApiAuth,
    Json(request): Json<QuarantineMetadataRequest>,
) -> ApiResult<Json<Value>> {
    let project_id = request.project_id.unwrap_or(auth.project_id);
    if project_id != auth.project_id {
        return Err(ApiError::Unauthorized);
    }
    sqlx::query(
        "insert into events (id, project_id, event_type, payload)
         values ($1,$2,'quarantine_metadata',$3)",
    )
    .bind(Uuid::new_v4())
    .bind(project_id)
    .bind(json!({
        "quarantine_id": request.quarantine_id,
        "sha256": request.sha256,
        "detection_name": request.detection_name,
        "engine": request.engine,
        "quarantined_at": request.quarantined_at,
        "status": request.status,
    }))
    .execute(&state.db)
    .await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn audit_logs(State(state): State<AppState>, auth: ApiAuth) -> ApiResult<Json<Value>> {
    let rows = sqlx::query_as::<_, (Uuid, String, Value, chrono::DateTime<Utc>)>(
        "select id, action, metadata, created_at from audit_logs
         where project_id = $1 order by created_at desc limit 100",
    )
    .bind(auth.project_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "audit_logs": rows.into_iter().map(|row| json!({
            "id": row.0,
            "action": row.1,
            "metadata": row.2,
            "created_at": row.3,
        })).collect::<Vec<_>>()
    })))
}

async fn session_project(state: &AppState, session_id: Uuid) -> ApiResult<Uuid> {
    sqlx::query_as::<_, (Uuid,)>("select project_id from protection_runs where id = $1")
        .bind(session_id)
        .fetch_optional(&state.db)
        .await?
        .map(|row| row.0)
        .ok_or(ApiError::NotFound)
}

async fn audit(
    state: &AppState,
    project_id: Option<Uuid>,
    device_id: Option<Uuid>,
    action: &str,
    metadata: Value,
) -> ApiResult<()> {
    sqlx::query(
        "insert into audit_logs (id, project_id, device_id, actor_type, action, metadata)
         values ($1,$2,$3,'system',$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(project_id)
    .bind(device_id)
    .bind(action)
    .bind(metadata)
    .execute(&state.db)
    .await?;
    Ok(())
}
