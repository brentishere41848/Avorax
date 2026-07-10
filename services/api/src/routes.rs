use axum::extract::{Path, State};
use axum::Json;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::auth::ApiAuth;
use crate::error::{ApiError, ApiResult};
use crate::models::*;
use crate::AppState;

const MAX_API_NAME_CHARS: usize = 256;
const MAX_API_SLUG_CHARS: usize = 128;
const MAX_API_ID_CHARS: usize = 256;
const MAX_API_PLATFORM_CHARS: usize = 64;
const MAX_API_ENGINE_CHARS: usize = 128;
const MAX_API_STATUS_CHARS: usize = 64;
const MAX_API_REASON_CHARS: usize = 1024;
const MAX_API_NONCE_CHARS: usize = 128;
const MAX_API_SIGNED_PAYLOAD_CHARS: usize = 2048;
const MAX_API_JSON_VALUE_BYTES: usize = 16 * 1024;
const MAX_API_EVENTS_PER_BATCH: usize = 128;
const MAX_API_DETECTIONS_PER_REPORT: usize = 256;
const MAX_API_SESSION_TTL_HOURS: i64 = 24;
const MAX_API_CLIENT_CLOCK_SKEW_MINUTES: i64 = 10;
const MAX_API_EVIDENCE_AGE_DAYS: i64 = 30;

#[derive(Debug)]
struct NormalizedDetection {
    path_hash: String,
    engine: String,
    threat_name: Option<String>,
    detected_at: chrono::DateTime<Utc>,
    details: Value,
}

#[derive(Debug)]
struct SessionContext {
    project_id: Uuid,
    status: String,
    expires_at: DateTime<Utc>,
}

pub async fn health(State(state): State<AppState>) -> ApiResult<Json<Value>> {
    sqlx::query("select 1").execute(&state.db).await?;
    Ok(Json(json!({
        "status": "ok",
        "service": "avorax-api",
        "version": env!("CARGO_PKG_VERSION"),
    })))
}

pub async fn create_project(
    State(_state): State<AppState>,
    Json(_request): Json<CreateProjectRequest>,
) -> ApiResult<Json<ProjectResponse>> {
    Err(ApiError::Forbidden(
        "project creation is disabled; provision projects during deployment".to_string(),
    ))
}

pub async fn register_device(
    State(state): State<AppState>,
    auth: ApiAuth,
    Json(request): Json<RegisterDeviceRequest>,
) -> ApiResult<Json<DeviceResponse>> {
    let project_id =
        authenticated_project_from_request(&state, auth.project_id, Some(&request.project_id))
            .await?;
    let external_device_id = bounded_text(
        &request.external_device_id,
        "external_device_id",
        MAX_API_ID_CHARS,
    )?;
    let display_name =
        optional_bounded_text(request.display_name, "display_name", MAX_API_NAME_CHARS)?;
    let device_id = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    let row = sqlx::query_as::<_, (Uuid, Uuid, String, Option<String>)>(
        "insert into devices (id, project_id, external_device_id, display_name)
         values ($1, $2, $3, $4)
         on conflict (project_id, external_device_id)
         do update set display_name = excluded.display_name
         returning id, project_id, external_device_id, display_name",
    )
    .bind(device_id)
    .bind(project_id)
    .bind(external_device_id)
    .bind(display_name)
    .fetch_one(&mut *tx)
    .await?;
    let audit_result = sqlx::query(
        "insert into audit_logs (id, project_id, device_id, actor_type, action, metadata)
         values ($1,$2,$3,'system',$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(Option::<Uuid>::Some(row.1))
    .bind(Option::<Uuid>::Some(row.0))
    .bind("device_registered")
    .bind(json!({"display_name_present": row.3.is_some()}))
    .execute(&mut *tx)
    .await?;
    if audit_result.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "device registration audit insert did not affect exactly one row".to_string(),
        ));
    }
    tx.commit().await?;
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
    let platform = bounded_text(&request.platform, "platform", MAX_API_PLATFORM_CHARS)?;
    let client_version =
        optional_bounded_text(request.client_version, "client_version", MAX_API_NAME_CHARS)?;
    let file_hash = optional_sha256(request.file_hash, "file_hash")?;
    let device_fingerprint_hash = optional_bounded_text(
        request.device_fingerprint_hash,
        "device_fingerprint_hash",
        MAX_API_ID_CHARS,
    )?;
    let nonce = bounded_text(&request.nonce, "nonce", MAX_API_NONCE_CHARS)?;
    let session_id = Uuid::new_v4();
    let project_id =
        authenticated_project_from_request(&state, auth.project_id, request.project_id.as_deref())
            .await?;
    let started_at = Utc::now();
    let max_expires_at = started_at + ChronoDuration::hours(MAX_API_SESSION_TTL_HOURS);
    if request.expires_at <= started_at {
        return Err(ApiError::BadRequest(
            "expires_at must be in the future".to_string(),
        ));
    }
    if request.expires_at > max_expires_at {
        return Err(ApiError::BadRequest(format!(
            "expires_at exceeds maximum session lifetime of {MAX_API_SESSION_TTL_HOURS} hours"
        )));
    }
    if let Some(device_id) = request.device_id {
        ensure_device_in_project(&state, device_id, project_id).await?;
    }
    let mut tx = state.db.begin().await?;
    let session_result = sqlx::query(
        "insert into protection_runs
         (id, project_id, device_id, platform, client_version, file_hash, device_fingerprint_hash, nonce, started_at, expires_at, status)
         values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active')",
    )
    .bind(session_id)
    .bind(project_id)
    .bind(request.device_id)
    .bind(platform)
    .bind(client_version)
    .bind(file_hash)
    .bind(device_fingerprint_hash)
    .bind(nonce)
    .bind(started_at)
    .bind(request.expires_at)
    .execute(&mut *tx)
    .await?;
    if session_result.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "protection session insert did not affect exactly one row".to_string(),
        ));
    }
    let audit_result = sqlx::query(
        "insert into audit_logs (id, project_id, device_id, actor_type, action, metadata)
         values ($1,$2,$3,'system',$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(Option::<Uuid>::Some(project_id))
    .bind(request.device_id)
    .bind("protection_session_created")
    .bind(json!({"session_id": session_id}))
    .execute(&mut *tx)
    .await?;
    if audit_result.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "protection session audit insert did not affect exactly one row".to_string(),
        ));
    }
    tx.commit().await?;
    Ok(Json(SessionResponse {
        protection_run_id: session_id,
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
    active_session_project(&state, session_id, auth.project_id).await?;
    let signed_payload = bounded_text(
        &request.signed_payload,
        "signed_payload",
        MAX_API_SIGNED_PAYLOAD_CHARS,
    )?;
    validate_json_value_size(&request.environment, "environment")?;
    let client_timestamp =
        validate_client_evidence_timestamp(request.client_timestamp, "client_timestamp")?;
    let mut tx = state.db.begin().await?;
    let heartbeat_result = sqlx::query(
        "update protection_runs set last_heartbeat_at = now()
         where id = $1 and project_id = $2 and status = 'active' and expires_at > now()",
    )
    .bind(session_id)
    .bind(auth.project_id)
    .execute(&mut *tx)
    .await?;
    if heartbeat_result.rows_affected() != 1 {
        return Err(ApiError::BadRequest(
            "protection session is not active or has expired".to_string(),
        ));
    }
    let event_result = sqlx::query(
        "insert into events (id, project_id, session_id, event_type, payload)
         values ($1,$2,$3,'heartbeat',$4)",
    )
    .bind(Uuid::new_v4())
    .bind(auth.project_id)
    .bind(session_id)
    .bind(json!({
        "monotonic_time": request.monotonic_time,
        "client_timestamp": client_timestamp,
        "signed_payload": signed_payload,
        "environment": request.environment,
    }))
    .execute(&mut *tx)
    .await?;
    if event_result.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "heartbeat event insert did not affect exactly one row".to_string(),
        ));
    }
    tx.commit().await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn ingest_events(
    State(state): State<AppState>,
    auth: ApiAuth,
    Path(session_id): Path<Uuid>,
    Json(events): Json<Vec<SecurityEventRequest>>,
) -> ApiResult<Json<Value>> {
    active_session_project(&state, session_id, auth.project_id).await?;
    if events.is_empty() {
        return Err(ApiError::BadRequest(
            "event batch must contain at least one event".to_string(),
        ));
    }
    if events.len() > MAX_API_EVENTS_PER_BATCH {
        return Err(ApiError::BadRequest(format!(
            "event batch exceeds {MAX_API_EVENTS_PER_BATCH} events"
        )));
    }
    let mut normalized_events = Vec::with_capacity(events.len());
    for event in events {
        let (event_type, payload) = match event {
            SecurityEventRequest::FileScanEvent { payload } => ("file_scan_event", payload),
            SecurityEventRequest::ProtectionDecisionEvent { payload } => {
                ("protection_decision_event", payload)
            }
            SecurityEventRequest::QuarantineEvent { payload } => ("quarantine_event", payload),
            SecurityEventRequest::AllowlistEvent { payload } => ("allowlist_event", payload),
            SecurityEventRequest::ServiceHealthEvent { payload } => {
                ("service_health_event", payload)
            }
        };
        validate_json_value_size(&payload, event_type)?;
        normalized_events.push((event_type, payload));
    }
    let mut tx = state.db.begin().await?;
    let mut inserted = 0usize;
    for (event_type, payload) in normalized_events {
        let result = sqlx::query(
            "insert into events (id, project_id, session_id, event_type, payload)
             values ($1,$2,$3,$4,$5)",
        )
        .bind(Uuid::new_v4())
        .bind(auth.project_id)
        .bind(session_id)
        .bind(event_type)
        .bind(payload)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() != 1 {
            return Err(ApiError::Internal(
                "event insert did not affect exactly one row".to_string(),
            ));
        }
        inserted += 1;
    }
    tx.commit().await?;
    Ok(Json(json!({"inserted": inserted})))
}

pub async fn end_session(
    State(state): State<AppState>,
    auth: ApiAuth,
    Path(session_id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let session = session_context(&state, session_id).await?;
    if session.project_id != auth.project_id {
        return Err(ApiError::Unauthorized);
    }
    if session.status != "active" {
        return Err(ApiError::BadRequest(
            "protection session is not active".to_string(),
        ));
    }
    let mut tx = state.db.begin().await?;
    let result = sqlx::query(
        "update protection_runs set status = 'ended', ended_at = now() where id = $1 and status = 'active'",
    )
        .bind(session_id)
        .execute(&mut *tx)
        .await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::BadRequest(
            "protection session is not active".to_string(),
        ));
    }
    let audit_result = sqlx::query(
        "insert into audit_logs (id, project_id, device_id, actor_type, action, metadata)
         values ($1,$2,$3,'system',$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(Option::<Uuid>::Some(auth.project_id))
    .bind(Option::<Uuid>::None)
    .bind("protection_session_ended")
    .bind(json!({"session_id": session_id}))
    .execute(&mut *tx)
    .await?;
    if audit_result.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "end-session audit insert did not affect exactly one row".to_string(),
        ));
    }
    tx.commit().await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn device_risk(
    State(state): State<AppState>,
    auth: ApiAuth,
    Path(device_id): Path<Uuid>,
) -> ApiResult<Json<RiskResponse>> {
    ensure_device_in_project(&state, device_id, auth.project_id).await?;
    let row = sqlx::query_as::<_, (Option<i32>, Option<String>, Option<Value>)>(
        "select score, severity, reasons from risk_scores
         where project_id = $1 and device_id = $2 order by calculated_at desc limit 1",
    )
    .bind(auth.project_id)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    let (score, severity, reasons) = match row {
        Some((score, severity, reasons)) => {
            let score = score
                .ok_or_else(|| ApiError::Internal("stored risk score is missing".to_string()))?;
            let severity = severity
                .ok_or_else(|| ApiError::Internal("stored risk severity is missing".to_string()))?;
            let reasons = match reasons {
                Some(value) => serde_json::from_value(value).map_err(|_| {
                    ApiError::Internal("stored risk reasons are invalid".to_string())
                })?,
                None => Vec::new(),
            };
            (score, severity, reasons)
        }
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
    let status = bounded_text(&request.status, "ban status", MAX_API_STATUS_CHARS)?;
    if !allowed.contains(&status.as_str()) {
        return Err(ApiError::BadRequest("invalid ban status".to_string()));
    }
    let reason = bounded_text(&request.reason, "ban reason", MAX_API_REASON_CHARS)?;
    ensure_device_in_project(&state, request.device_id, auth.project_id).await?;
    let ban_id = Uuid::new_v4();
    let mut tx = state.db.begin().await?;
    let ban_result = sqlx::query(
        "insert into bans (id, project_id, device_id, status, reason)
         values ($1,$2,$3,$4,$5)",
    )
    .bind(ban_id)
    .bind(auth.project_id)
    .bind(request.device_id)
    .bind(status)
    .bind(reason)
    .execute(&mut *tx)
    .await?;
    if ban_result.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "ban insert did not affect exactly one row".to_string(),
        ));
    }
    let audit_result = sqlx::query(
        "insert into audit_logs (id, project_id, device_id, actor_type, action, metadata)
         values ($1,$2,$3,'system',$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(Option::<Uuid>::Some(auth.project_id))
    .bind(Option::<Uuid>::Some(request.device_id))
    .bind("ban_status_changed")
    .bind(json!({"ban_id": ban_id}))
    .execute(&mut *tx)
    .await?;
    if audit_result.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "ban audit insert did not affect exactly one row".to_string(),
        ));
    }
    tx.commit().await?;
    Ok(Json(json!({"ban_id": ban_id})))
}

pub async fn report_detection(
    State(state): State<AppState>,
    auth: ApiAuth,
    Json(request): Json<DetectionReportRequest>,
) -> ApiResult<Json<Value>> {
    let project_id =
        authenticated_project_from_request(&state, auth.project_id, request.project_id.as_deref())
            .await?;
    let detections = normalized_detections(request)?;
    let mut tx = state.db.begin().await?;
    for detection in &detections {
        let detection_result = sqlx::query(
            "insert into detections (id, project_id, rule_id, severity, risk_delta, reasons, evidence)
             values ($1,$2,'malware_detection','high',70,$3,$4)",
        )
        .bind(Uuid::new_v4())
        .bind(project_id)
        .bind(json!([detection
            .threat_name
            .clone()
            .unwrap_or_else(|| "Threat detected".to_string())]))
        .bind(json!({
            "scanned_path_hash": &detection.path_hash,
            "engine": &detection.engine,
            "threat_name": &detection.threat_name,
            "detected_at": detection.detected_at,
            "details": &detection.details,
        }))
        .execute(&mut *tx)
        .await?;
        if detection_result.rows_affected() != 1 {
            return Err(ApiError::Internal(
                "detection insert did not affect exactly one row".to_string(),
            ));
        }
    }
    let audit_result = sqlx::query(
        "insert into audit_logs (id, project_id, device_id, actor_type, action, metadata)
         values ($1,$2,$3,'system',$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(Option::<Uuid>::Some(project_id))
    .bind(Option::<Uuid>::None)
    .bind("automated_detection_reported")
    .bind(json!({"detection_count": detections.len()}))
    .execute(&mut *tx)
    .await?;
    if audit_result.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "detection audit insert did not affect exactly one row".to_string(),
        ));
    }
    tx.commit().await?;
    Ok(Json(json!({"ok": true})))
}

pub async fn upload_quarantine_metadata(
    State(state): State<AppState>,
    auth: ApiAuth,
    Json(request): Json<QuarantineMetadataRequest>,
) -> ApiResult<Json<Value>> {
    let project_id =
        authenticated_project_from_request(&state, auth.project_id, request.project_id.as_deref())
            .await?;
    let quarantine_id = bounded_token(&request.quarantine_id, "quarantine_id", MAX_API_ID_CHARS)?;
    let sha256 = required_sha256(&request.sha256, "sha256")?;
    let detection_name = bounded_text(
        &request.detection_name,
        "detection_name",
        MAX_API_NAME_CHARS,
    )?;
    let engine = bounded_text(&request.engine, "engine", MAX_API_ENGINE_CHARS)?;
    let status = bounded_text(&request.status, "status", MAX_API_STATUS_CHARS)?;
    let action_taken = bounded_text(&request.action_taken, "action_taken", MAX_API_STATUS_CHARS)?;
    let quarantined_at =
        validate_client_evidence_timestamp(request.quarantined_at, "quarantined_at")?;
    if !quarantine_action_matches_status(&action_taken, &status) {
        return Err(ApiError::BadRequest(
            "quarantine action_taken does not match status".to_string(),
        ));
    }
    let source = bounded_text(&request.source, "source", MAX_API_STATUS_CHARS)?;
    if source != "scanner" {
        return Err(ApiError::BadRequest(
            "unsupported quarantine source".to_string(),
        ));
    }
    if request.blocked_before_execution || request.process_started {
        return Err(ApiError::BadRequest(
            "scanner quarantine metadata cannot claim execution-state evidence".to_string(),
        ));
    }
    let payload = json!({
        "quarantine_id": quarantine_id,
        "sha256": sha256,
        "detection_name": detection_name,
        "engine": engine,
        "quarantined_at": quarantined_at,
        "status": status,
        "action_taken": action_taken,
        "source": source,
        "blocked_before_execution": request.blocked_before_execution,
        "process_started": request.process_started,
    });
    validate_json_value_size(&payload, "quarantine_metadata")?;
    let result = sqlx::query(
        "insert into events (id, project_id, event_type, payload)
         values ($1,$2,'quarantine_metadata',$3)",
    )
    .bind(Uuid::new_v4())
    .bind(project_id)
    .bind(payload)
    .execute(&state.db)
    .await?;
    if result.rows_affected() != 1 {
        return Err(ApiError::Internal(
            "quarantine metadata event insert did not affect exactly one row".to_string(),
        ));
    }
    Ok(Json(json!({"ok": true})))
}

fn quarantine_action_matches_status(action_taken: &str, status: &str) -> bool {
    match status {
        "quarantined" => action_taken == "quarantined",
        "restored" => action_taken == "restored",
        "deleted" => action_taken == "deleted",
        _ => false,
    }
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

fn normalized_detections(request: DetectionReportRequest) -> ApiResult<Vec<NormalizedDetection>> {
    if let Some(items) = request.detections {
        if items.is_empty() {
            return Err(ApiError::BadRequest(
                "detection report must contain at least one detection".to_string(),
            ));
        }
        if items.len() > MAX_API_DETECTIONS_PER_REPORT {
            return Err(ApiError::BadRequest(format!(
                "detection report exceeds {MAX_API_DETECTIONS_PER_REPORT} detections"
            )));
        }
        let mut normalized = Vec::with_capacity(items.len());
        for item in items {
            let path_hash = required_sha256(&item.path_hash, "path_hash")?;
            let engine = bounded_text(&item.engine, "engine", MAX_API_ENGINE_CHARS)?;
            let threat_name = Some(bounded_text(
                &item.threat_name,
                "threat_name",
                MAX_API_NAME_CHARS,
            )?);
            let detection_type =
                optional_bounded_text(item.detection_type, "detection_type", MAX_API_STATUS_CHARS)?;
            let threat_category = optional_bounded_text(
                item.threat_category,
                "threat_category",
                MAX_API_STATUS_CHARS,
            )?;
            let confidence =
                optional_bounded_text(item.confidence, "confidence", MAX_API_STATUS_CHARS)?;
            let status = optional_bounded_text(item.status, "status", MAX_API_STATUS_CHARS)?;
            let detected_at = match item.detected_at {
                Some(detected_at) => {
                    validate_client_evidence_timestamp(detected_at, "detected_at")?
                }
                None => Utc::now(),
            };
            normalized.push(NormalizedDetection {
                path_hash,
                engine,
                threat_name,
                detected_at,
                details: json!({
                    "detection_type": detection_type,
                    "threat_category": threat_category,
                    "confidence": confidence,
                    "status": status,
                }),
            });
        }
        return Ok(normalized);
    }

    let path_hash = required_sha256(
        &request
            .scanned_path_hash
            .ok_or_else(|| ApiError::BadRequest("scanned_path_hash is required".to_string()))?,
        "scanned_path_hash",
    )?;
    let engine = bounded_text(
        &request
            .engine
            .ok_or_else(|| ApiError::BadRequest("engine is required".to_string()))?,
        "engine",
        MAX_API_ENGINE_CHARS,
    )?;
    let threat_name =
        optional_bounded_text(request.threat_name, "threat_name", MAX_API_NAME_CHARS)?;
    let detected_at = request
        .detected_at
        .ok_or_else(|| ApiError::BadRequest("detected_at is required".to_string()))?;
    let detected_at = validate_client_evidence_timestamp(detected_at, "detected_at")?;
    Ok(vec![NormalizedDetection {
        path_hash,
        engine,
        threat_name,
        detected_at,
        details: json!({"legacy_payload": true}),
    }])
}

fn bounded_text(value: &str, field: &str, max_chars: usize) -> ApiResult<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ApiError::BadRequest(format!("{field} is required")));
    }
    if trimmed.contains('\0') {
        return Err(ApiError::BadRequest(format!("{field} contains NUL")));
    }
    if trimmed.chars().count() > max_chars {
        return Err(ApiError::BadRequest(format!(
            "{field} exceeds {max_chars} characters"
        )));
    }
    Ok(trimmed.to_string())
}

fn optional_bounded_text(
    value: Option<String>,
    field: &str,
    max_chars: usize,
) -> ApiResult<Option<String>> {
    value
        .map(|value| bounded_text(&value, field, max_chars))
        .transpose()
}

fn bounded_slug(value: &str) -> ApiResult<String> {
    let slug = bounded_text(value, "slug", MAX_API_SLUG_CHARS)?;
    if !slug
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_')
    {
        return Err(ApiError::BadRequest(
            "slug must contain only lowercase ASCII letters, digits, hyphen, or underscore"
                .to_string(),
        ));
    }
    Ok(slug)
}

fn bounded_token(value: &str, field: &str, max_chars: usize) -> ApiResult<String> {
    let token = bounded_text(value, field, max_chars)?;
    if !token
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(ApiError::BadRequest(format!(
            "{field} must contain only ASCII letters, digits, hyphen, or underscore"
        )));
    }
    Ok(token)
}

fn required_sha256(value: &str, field: &str) -> ApiResult<String> {
    let hash = bounded_text(value, field, 64)?;
    if hash.len() != 64 || !hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest(format!(
            "{field} must be a 64-character SHA-256 hex value"
        )));
    }
    Ok(hash.to_ascii_lowercase())
}

fn optional_sha256(value: Option<String>, field: &str) -> ApiResult<Option<String>> {
    value
        .map(|value| required_sha256(&value, field))
        .transpose()
}

fn validate_json_value_size(value: &Value, field: &str) -> ApiResult<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| ApiError::BadRequest(format!("{field} is not valid JSON")))?;
    if bytes.len() > MAX_API_JSON_VALUE_BYTES {
        return Err(ApiError::BadRequest(format!(
            "{field} exceeds {MAX_API_JSON_VALUE_BYTES} bytes"
        )));
    }
    Ok(())
}

fn validate_client_evidence_timestamp(
    value: DateTime<Utc>,
    field: &str,
) -> ApiResult<DateTime<Utc>> {
    let now = Utc::now();
    let max_future = now + ChronoDuration::minutes(MAX_API_CLIENT_CLOCK_SKEW_MINUTES);
    if value > max_future {
        return Err(ApiError::BadRequest(format!(
            "{field} is too far in the future"
        )));
    }
    let min_past = now - ChronoDuration::days(MAX_API_EVIDENCE_AGE_DAYS);
    if value < min_past {
        return Err(ApiError::BadRequest(format!("{field} is too old")));
    }
    Ok(value)
}

async fn authenticated_project_from_request(
    state: &AppState,
    auth_project_id: Uuid,
    requested_project_id: Option<&str>,
) -> ApiResult<Uuid> {
    let Some(requested_project_id) = requested_project_id else {
        return Ok(auth_project_id);
    };
    let requested = bounded_text(requested_project_id, "project_id", MAX_API_ID_CHARS)?;
    if requested == auth_project_id.to_string() {
        return Ok(auth_project_id);
    }
    if Uuid::parse_str(&requested).is_ok() {
        return Err(ApiError::Unauthorized);
    }
    let slug = bounded_slug(&requested)?;
    let row = sqlx::query_as::<_, (Uuid,)>("select id from projects where id = $1 and slug = $2")
        .bind(auth_project_id)
        .bind(slug)
        .fetch_optional(&state.db)
        .await?;
    if row.is_some() {
        Ok(auth_project_id)
    } else {
        Err(ApiError::Unauthorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_hash() -> String {
        "a".repeat(64)
    }

    #[test]
    fn normalized_detections_accepts_flutter_aggregate_payload() {
        let request = DetectionReportRequest {
            project_id: None,
            scanned_path_hash: None,
            engine: None,
            threat_name: None,
            detected_at: None,
            detections: Some(vec![DetectionReportItem {
                path_hash: valid_hash(),
                engine: "native".to_string(),
                threat_name: "EICAR-Test-File".to_string(),
                detection_type: Some("malware".to_string()),
                threat_category: Some("test".to_string()),
                confidence: Some("confirmed".to_string()),
                status: Some("detected".to_string()),
                detected_at: None,
            }]),
        };
        let normalized = normalized_detections(request).expect("aggregate payload");
        assert_eq!(normalized.len(), 1);
        assert_eq!(normalized[0].engine, "native");
        assert_eq!(normalized[0].path_hash, valid_hash());
    }

    #[test]
    fn normalized_detections_rejects_empty_aggregate_payload() {
        let request = DetectionReportRequest {
            project_id: None,
            scanned_path_hash: None,
            engine: None,
            threat_name: None,
            detected_at: None,
            detections: Some(Vec::new()),
        };
        let error = normalized_detections(request).expect_err("empty report must fail");
        assert!(error
            .to_string()
            .contains("detection report must contain at least one detection"));
    }

    #[test]
    fn normalized_detections_rejects_oversized_aggregate_payload() {
        let request = DetectionReportRequest {
            project_id: None,
            scanned_path_hash: None,
            engine: None,
            threat_name: None,
            detected_at: None,
            detections: Some(
                (0..=MAX_API_DETECTIONS_PER_REPORT)
                    .map(|_| DetectionReportItem {
                        path_hash: valid_hash(),
                        engine: "native".to_string(),
                        threat_name: "EICAR-Test-File".to_string(),
                        detection_type: None,
                        threat_category: None,
                        confidence: None,
                        status: None,
                        detected_at: None,
                    })
                    .collect(),
            ),
        };
        let error = normalized_detections(request).expect_err("oversized report must fail");
        assert!(error.to_string().contains("detection report exceeds"));
    }

    #[test]
    fn normalized_detections_rejects_empty_before_count_bound_source_marker() {
        let source = include_str!("routes.rs");
        let normalized_source = &source[source
            .find("fn normalized_detections")
            .expect("normalized_detections")
            ..source.find("fn bounded_text").expect("bounded_text")];

        assert!(normalized_source.contains("if items.is_empty()"));
        assert!(normalized_source.contains("detection report must contain at least one detection"));
        assert!(
            normalized_source.find("if items.is_empty()")
                < normalized_source.find("items.len() > MAX_API_DETECTIONS_PER_REPORT")
        );
    }

    #[test]
    fn device_registration_uses_transaction_for_device_and_audit_source_marker() {
        let source = include_str!("routes.rs");
        let device_source = &source[source
            .find("pub async fn register_device")
            .expect("register_device")
            ..source
                .find("pub async fn create_session")
                .expect("create_session")];

        assert!(device_source.contains("let mut tx = state.db.begin().await?"));
        assert!(device_source.contains("insert into devices"));
        assert!(device_source.contains("insert into audit_logs"));
        assert!(device_source.contains("device_registered"));
        assert!(device_source.contains("display_name_present"));
        assert!(device_source.contains(".fetch_one(&mut *tx)"));
        assert!(device_source.contains(".execute(&mut *tx)"));
        assert!(device_source.contains("tx.commit().await?"));
        assert!(
            device_source.find("let mut tx = state.db.begin().await?")
                < device_source.find("insert into devices")
        );
        assert!(
            device_source.find("insert into devices")
                < device_source.find("insert into audit_logs")
        );
        assert!(
            device_source.find("tx.commit().await?") < device_source.find("Ok(Json(DeviceResponse")
        );
    }

    #[test]
    fn device_registration_requires_audit_insert_ack_before_response_source_marker() {
        let source = include_str!("routes.rs");
        let device_source = &source[source
            .find("pub async fn register_device")
            .expect("register_device")
            ..source
                .find("pub async fn create_session")
                .expect("create_session")];

        assert!(device_source.contains("let audit_result = sqlx::query("));
        assert!(device_source.contains("audit_result.rows_affected() != 1"));
        assert!(device_source
            .contains("device registration audit insert did not affect exactly one row"));
        assert!(
            device_source.find("let audit_result = sqlx::query(")
                < device_source.find("audit_result.rows_affected() != 1")
        );
        assert!(
            device_source.find("audit_result.rows_affected() != 1")
                < device_source.find("tx.commit().await?")
        );
        assert!(
            device_source.find("tx.commit().await?") < device_source.find("Ok(Json(DeviceResponse")
        );
    }

    #[test]
    fn api_json_payload_limit_rejects_large_values() {
        let large = Value::String("x".repeat(MAX_API_JSON_VALUE_BYTES + 1));
        let error = validate_json_value_size(&large, "environment").expect_err("large JSON");
        assert!(error.to_string().contains("environment exceeds"));
    }

    #[test]
    fn client_evidence_timestamp_rejects_outside_window() {
        let future = Utc::now() + ChronoDuration::minutes(MAX_API_CLIENT_CLOCK_SKEW_MINUTES + 1);
        let old = Utc::now() - ChronoDuration::days(MAX_API_EVIDENCE_AGE_DAYS + 1);

        let future_error = validate_client_evidence_timestamp(future, "detected_at")
            .expect_err("future evidence must fail");
        assert!(future_error
            .to_string()
            .contains("detected_at is too far in the future"));

        let old_error = validate_client_evidence_timestamp(old, "quarantined_at")
            .expect_err("old evidence must fail");
        assert!(old_error.to_string().contains("quarantined_at is too old"));
    }

    #[test]
    fn client_evidence_timestamps_are_bounded_source_marker() {
        let source = include_str!("routes.rs");
        assert!(source.contains("const MAX_API_CLIENT_CLOCK_SKEW_MINUTES: i64 = 10"));
        assert!(source.contains("const MAX_API_EVIDENCE_AGE_DAYS: i64 = 30"));
        assert!(source.contains(
            "validate_client_evidence_timestamp(request.client_timestamp, \"client_timestamp\")"
        ));
        assert!(source.contains("validate_client_evidence_timestamp(detected_at, \"detected_at\")"));
        assert!(source.contains(
            "validate_client_evidence_timestamp(request.quarantined_at, \"quarantined_at\")"
        ));
        assert!(source.contains("value > max_future"));
        assert!(source.contains("value < min_past"));
    }

    #[test]
    fn event_ingest_rejects_empty_batches_source_marker() {
        let source = include_str!("routes.rs");
        let ingest_start = source
            .find("pub async fn ingest_events")
            .expect("ingest_events");
        let ingest_end = source
            .find("pub async fn end_session")
            .expect("end_session");
        let ingest_source = &source[ingest_start..ingest_end];
        assert!(ingest_source.contains("if events.is_empty()"));
        assert!(ingest_source.contains("event batch must contain at least one event"));
        assert!(
            ingest_source.find("if events.is_empty()")
                < ingest_source.find("if events.len() > MAX_API_EVENTS_PER_BATCH")
        );
        assert!(
            ingest_source.contains("let mut normalized_events = Vec::with_capacity(events.len())")
        );
        assert!(ingest_source.contains("normalized_events.push((event_type, payload))"));
        assert!(ingest_source.contains("let mut tx = state.db.begin().await?"));
        assert!(ingest_source.contains("for (event_type, payload) in normalized_events"));
        assert!(ingest_source.contains(".execute(&mut *tx)"));
        assert!(ingest_source.contains("tx.commit().await?"));
        assert!(
            ingest_source.find("validate_json_value_size")
                < ingest_source.find("insert into events")
        );
        assert!(
            ingest_source.find("let mut tx = state.db.begin().await?")
                < ingest_source.find("insert into events")
        );
        assert!(
            ingest_source.find("tx.commit().await?")
                < ingest_source.find("Ok(Json(json!({\"inserted\": inserted})))")
        );
    }

    #[test]
    fn event_ingest_requires_insert_ack_before_counting_source_marker() {
        let source = include_str!("routes.rs");
        let ingest_source = &source[source
            .find("pub async fn ingest_events")
            .expect("ingest_events")
            ..source
                .find("pub async fn end_session")
                .expect("end_session")];

        assert!(ingest_source.contains("let result = sqlx::query("));
        assert!(ingest_source.contains("result.rows_affected() != 1"));
        assert!(ingest_source.contains("event insert did not affect exactly one row"));
        assert!(
            ingest_source.find("let result = sqlx::query(")
                < ingest_source.find("result.rows_affected() != 1")
        );
        assert!(
            ingest_source.find("result.rows_affected() != 1") < ingest_source.find("inserted += 1")
        );
        assert!(ingest_source.find("inserted += 1") < ingest_source.find("tx.commit().await?"));
    }

    #[test]
    fn session_expiry_is_bounded_source_marker() {
        let source = include_str!("routes.rs");
        let session_start = source
            .find("pub async fn create_session")
            .expect("create_session");
        let heartbeat_start = source.find("pub async fn heartbeat").expect("heartbeat");
        let session_source = &source[session_start..heartbeat_start];
        assert!(source.contains("const MAX_API_SESSION_TTL_HOURS: i64 = 24"));
        assert!(session_source.contains("ChronoDuration::hours(MAX_API_SESSION_TTL_HOURS)"));
        assert!(session_source.contains("request.expires_at <= started_at"));
        assert!(session_source.contains("expires_at must be in the future"));
        assert!(session_source.contains("request.expires_at > max_expires_at"));
        assert!(session_source.contains("expires_at exceeds maximum session lifetime"));
        assert!(
            session_source.find("request.expires_at <= started_at")
                < session_source.find("insert into protection_runs")
        );
    }

    #[test]
    fn session_device_id_requires_project_match_source_marker() {
        let source = include_str!("routes.rs");
        let session_source = &source[source
            .find("pub async fn create_session")
            .expect("create_session")
            ..source.find("pub async fn heartbeat").expect("heartbeat")];

        assert!(session_source.contains("if let Some(device_id) = request.device_id"));
        assert!(session_source
            .contains("ensure_device_in_project(&state, device_id, project_id).await?"));
        assert!(
            session_source.find("ensure_device_in_project")
                < session_source.find("insert into protection_runs")
        );
    }

    #[test]
    fn session_creation_uses_transaction_for_run_and_audit_source_marker() {
        let source = include_str!("routes.rs");
        let session_source = &source[source
            .find("pub async fn create_session")
            .expect("create_session")
            ..source.find("pub async fn heartbeat").expect("heartbeat")];

        assert!(session_source.contains("let mut tx = state.db.begin().await?"));
        assert!(session_source.contains("insert into protection_runs"));
        assert!(session_source.contains("insert into audit_logs"));
        assert!(session_source.contains("protection_session_created"));
        assert!(session_source.contains(".execute(&mut *tx)"));
        assert!(session_source.contains("tx.commit().await?"));
        assert!(
            session_source.find("let mut tx = state.db.begin().await?")
                < session_source.find("insert into protection_runs")
        );
        assert!(
            session_source.find("insert into protection_runs")
                < session_source.find("insert into audit_logs")
        );
        assert!(
            session_source.find("tx.commit().await?")
                < session_source.find("Ok(Json(SessionResponse")
        );
        assert!(!session_source.contains("audit("));
    }

    #[test]
    fn session_creation_requires_insert_acks_before_response_source_marker() {
        let source = include_str!("routes.rs");
        let session_source = &source[source
            .find("pub async fn create_session")
            .expect("create_session")
            ..source.find("pub async fn heartbeat").expect("heartbeat")];

        assert!(session_source.contains("let session_result = sqlx::query("));
        assert!(session_source.contains("session_result.rows_affected() != 1"));
        assert!(session_source.contains("protection session insert did not affect exactly one row"));
        assert!(session_source.contains("let audit_result = sqlx::query("));
        assert!(session_source.contains("audit_result.rows_affected() != 1"));
        assert!(session_source
            .contains("protection session audit insert did not affect exactly one row"));
        assert!(
            session_source.find("let session_result = sqlx::query(")
                < session_source.find("session_result.rows_affected() != 1")
        );
        assert!(
            session_source.find("session_result.rows_affected() != 1")
                < session_source.find("let audit_result = sqlx::query(")
        );
        assert!(
            session_source.find("audit_result.rows_affected() != 1")
                < session_source.find("tx.commit().await?")
        );
        assert!(
            session_source.find("tx.commit().await?")
                < session_source.find("Ok(Json(SessionResponse")
        );
    }

    #[test]
    fn session_writes_require_active_unexpired_sessions_source_marker() {
        let source = include_str!("routes.rs");
        let heartbeat_source = &source[source.find("pub async fn heartbeat").expect("heartbeat")
            ..source.find("pub async fn ingest_events").expect("ingest")];
        let ingest_source = &source[source.find("pub async fn ingest_events").expect("ingest")
            ..source.find("pub async fn end_session").expect("end")];
        let end_source = &source[source.find("pub async fn end_session").expect("end")
            ..source.find("pub async fn device_risk").expect("risk")];
        let helper_source = &source[source
            .find("async fn active_session_project")
            .expect("active helper")..];

        assert!(heartbeat_source
            .contains("active_session_project(&state, session_id, auth.project_id)"));
        assert!(
            ingest_source.contains("active_session_project(&state, session_id, auth.project_id)")
        );
        assert!(helper_source.contains("session.project_id != auth_project_id"));
        assert!(
            helper_source.find("session.project_id != auth_project_id")
                < helper_source.find("session.status != \"active\"")
        );
        assert!(helper_source.contains("session.status != \"active\""));
        assert!(helper_source.contains("session.expires_at <= Utc::now()"));
        assert!(helper_source.contains("protection session has expired"));
        assert!(end_source.contains("session_context(&state, session_id)"));
        assert!(end_source.contains("session.status != \"active\""));
        assert!(end_source.contains("where id = $1 and status = 'active'"));
        assert!(end_source.contains("result.rows_affected() != 1"));
        assert!(end_source.contains("let mut tx = state.db.begin().await?"));
        assert!(end_source.contains("insert into audit_logs"));
        assert!(end_source.contains("protection_session_ended"));
        assert!(end_source.contains("let audit_result = sqlx::query("));
        assert!(end_source.contains("audit_result.rows_affected() != 1"));
        assert!(end_source.contains("end-session audit insert did not affect exactly one row"));
        assert!(end_source.contains(".execute(&mut *tx)"));
        assert!(end_source.contains("tx.commit().await?"));
        assert!(
            end_source.find("let mut tx = state.db.begin().await?")
                < end_source.find("update protection_runs set status = 'ended'")
        );
        assert!(
            end_source.find("result.rows_affected() != 1")
                < end_source.find("insert into audit_logs")
        );
        assert!(
            end_source.find("audit_result.rows_affected() != 1")
                < end_source.find("tx.commit().await?")
        );
        assert!(
            end_source.find("tx.commit().await?")
                < end_source.find("Ok(Json(json!({\"ok\": true})))")
        );
        assert!(!end_source.contains("audit("));
    }

    #[test]
    fn heartbeat_requires_active_update_ack_before_event_insert_source_marker() {
        let source = include_str!("routes.rs");
        let heartbeat_source = &source[source.find("pub async fn heartbeat").expect("heartbeat")
            ..source.find("pub async fn ingest_events").expect("ingest")];

        assert!(heartbeat_source.contains(
            "where id = $1 and project_id = $2 and status = 'active' and expires_at > now()"
        ));
        assert!(heartbeat_source.contains("heartbeat_result.rows_affected() != 1"));
        assert!(heartbeat_source.contains("protection session is not active or has expired"));
        assert!(heartbeat_source.contains("let mut tx = state.db.begin().await?"));
        assert!(heartbeat_source.contains(".execute(&mut *tx)"));
        assert!(heartbeat_source.contains("tx.commit().await?"));
        assert!(
            heartbeat_source.find("heartbeat_result.rows_affected() != 1")
                < heartbeat_source.find("insert into events")
        );
        assert!(
            heartbeat_source.find("let mut tx = state.db.begin().await?")
                < heartbeat_source.find("update protection_runs set last_heartbeat_at")
        );
        assert!(
            heartbeat_source.find("tx.commit().await?")
                < heartbeat_source.find("Ok(Json(json!({\"ok\": true})))")
        );
        assert!(!heartbeat_source
            .contains("update protection_runs set last_heartbeat_at = now() where id = $1"));
    }

    #[test]
    fn heartbeat_requires_event_insert_ack_before_success_source_marker() {
        let source = include_str!("routes.rs");
        let heartbeat_source = &source[source.find("pub async fn heartbeat").expect("heartbeat")
            ..source.find("pub async fn ingest_events").expect("ingest")];

        assert!(heartbeat_source.contains("let event_result = sqlx::query("));
        assert!(heartbeat_source.contains("event_result.rows_affected() != 1"));
        assert!(heartbeat_source.contains("heartbeat event insert did not affect exactly one row"));
        assert!(
            heartbeat_source.find("heartbeat_result.rows_affected() != 1")
                < heartbeat_source.find("let event_result = sqlx::query(")
        );
        assert!(
            heartbeat_source.find("let event_result = sqlx::query(")
                < heartbeat_source.find("event_result.rows_affected() != 1")
        );
        assert!(
            heartbeat_source.find("event_result.rows_affected() != 1")
                < heartbeat_source.find("tx.commit().await?")
        );
        assert!(
            heartbeat_source.find("tx.commit().await?")
                < heartbeat_source.find("Ok(Json(json!({\"ok\": true})))")
        );
    }

    #[test]
    fn ban_creation_requires_device_project_match_source_marker() {
        let source = include_str!("routes.rs");
        let ban_source = &source[source.find("pub async fn create_ban").expect("create_ban")
            ..source
                .find("pub async fn report_detection")
                .expect("report_detection")];
        let helper_source = &source[source
            .find("async fn ensure_device_in_project")
            .expect("device project helper")..];

        assert!(ban_source.contains(
            "ensure_device_in_project(&state, request.device_id, auth.project_id).await?"
        ));
        assert!(ban_source.contains("insert into bans"));
        assert!(ban_source.contains("let mut tx = state.db.begin().await?"));
        assert!(ban_source.contains("insert into audit_logs"));
        assert!(ban_source.contains("ban_status_changed"));
        assert!(ban_source.contains(".execute(&mut *tx)"));
        assert!(ban_source.contains("tx.commit().await?"));
        assert!(ban_source.find("ensure_device_in_project") < ban_source.find("insert into bans"));
        assert!(
            ban_source.find("let mut tx = state.db.begin().await?")
                < ban_source.find("insert into bans")
        );
        assert!(ban_source.find("insert into bans") < ban_source.find("insert into audit_logs"));
        assert!(
            ban_source.find("tx.commit().await?")
                < ban_source.find("Ok(Json(json!({\"ban_id\": ban_id})))")
        );
        assert!(!ban_source.contains("audit("));
        assert!(helper_source.contains("select 1 from devices where id = $1 and project_id = $2"));
        assert!(helper_source.contains(".ok_or(ApiError::NotFound)"));
    }

    #[test]
    fn ban_creation_requires_insert_acks_before_response_source_marker() {
        let source = include_str!("routes.rs");
        let ban_source = &source[source.find("pub async fn create_ban").expect("create_ban")
            ..source
                .find("pub async fn report_detection")
                .expect("report_detection")];

        assert!(ban_source.contains("let ban_result = sqlx::query("));
        assert!(ban_source.contains("ban_result.rows_affected() != 1"));
        assert!(ban_source.contains("ban insert did not affect exactly one row"));
        assert!(ban_source.contains("let audit_result = sqlx::query("));
        assert!(ban_source.contains("audit_result.rows_affected() != 1"));
        assert!(ban_source.contains("ban audit insert did not affect exactly one row"));
        assert!(
            ban_source.find("let ban_result = sqlx::query(")
                < ban_source.find("ban_result.rows_affected() != 1")
        );
        assert!(
            ban_source.find("ban_result.rows_affected() != 1")
                < ban_source.find("let audit_result = sqlx::query(")
        );
        assert!(
            ban_source.find("audit_result.rows_affected() != 1")
                < ban_source.find("tx.commit().await?")
        );
        assert!(
            ban_source.find("tx.commit().await?")
                < ban_source.find("Ok(Json(json!({\"ban_id\": ban_id})))")
        );
    }

    #[test]
    fn device_risk_requires_device_project_match_before_default_source_marker() {
        let source = include_str!("routes.rs");
        let risk_source = &source[source
            .find("pub async fn device_risk")
            .expect("device_risk")
            ..source.find("pub async fn create_ban").expect("create_ban")];

        assert!(risk_source
            .contains("ensure_device_in_project(&state, device_id, auth.project_id).await?"));
        assert!(risk_source.contains("None => (0, \"info\".to_string(), Vec::new())"));
        assert!(
            risk_source.find("ensure_device_in_project")
                < risk_source.find("None => (0, \"info\".to_string(), Vec::new())")
        );
    }

    #[test]
    fn detection_report_uses_transaction_for_rows_and_audit_source_marker() {
        let source = include_str!("routes.rs");
        let detection_source = &source[source
            .find("pub async fn report_detection")
            .expect("report_detection")
            ..source
                .find("pub async fn upload_quarantine_metadata")
                .expect("upload_quarantine_metadata")];

        assert!(detection_source.contains("let mut tx = state.db.begin().await?"));
        assert!(detection_source.contains("insert into detections"));
        assert!(detection_source.contains("insert into audit_logs"));
        assert!(detection_source.contains(".execute(&mut *tx)"));
        assert!(detection_source.contains("tx.commit().await?"));
        assert!(
            detection_source.find("let mut tx = state.db.begin().await?")
                < detection_source.find("insert into detections")
        );
        assert!(
            detection_source.find("insert into detections")
                < detection_source.find("insert into audit_logs")
        );
        assert!(
            detection_source.find("tx.commit().await?")
                < detection_source.find("Ok(Json(json!({\"ok\": true})))")
        );
        assert!(!detection_source.contains("audit("));
    }

    #[test]
    fn detection_report_requires_insert_acks_before_success_source_marker() {
        let source = include_str!("routes.rs");
        let detection_source = &source[source
            .find("pub async fn report_detection")
            .expect("report_detection")
            ..source
                .find("pub async fn upload_quarantine_metadata")
                .expect("upload_quarantine_metadata")];

        assert!(detection_source.contains("let detection_result = sqlx::query("));
        assert!(detection_source.contains("detection_result.rows_affected() != 1"));
        assert!(detection_source.contains("detection insert did not affect exactly one row"));
        assert!(detection_source.contains("let audit_result = sqlx::query("));
        assert!(detection_source.contains("audit_result.rows_affected() != 1"));
        assert!(detection_source.contains("detection audit insert did not affect exactly one row"));
        assert!(
            detection_source.find("let detection_result = sqlx::query(")
                < detection_source.find("detection_result.rows_affected() != 1")
        );
        assert!(
            detection_source.find("detection_result.rows_affected() != 1")
                < detection_source.find("let audit_result = sqlx::query(")
        );
        assert!(
            detection_source.find("audit_result.rows_affected() != 1")
                < detection_source.find("tx.commit().await?")
        );
        assert!(
            detection_source.find("tx.commit().await?")
                < detection_source.find("Ok(Json(json!({\"ok\": true})))")
        );
    }

    #[test]
    fn quarantine_metadata_evidence_contract_source_marker() {
        let models = include_str!("models.rs");
        let routes = include_str!("routes.rs");
        let request_start = models
            .find("pub struct QuarantineMetadataRequest")
            .expect("quarantine request model");
        assert!(models[..request_start].contains("#[serde(deny_unknown_fields)]"));
        assert!(models.contains("pub action_taken: String"));
        assert!(models.contains("pub source: String"));
        assert!(models.contains("pub blocked_before_execution: bool"));
        assert!(models.contains("pub process_started: bool"));
        assert!(routes.contains("quarantine_action_matches_status(&action_taken, &status)"));
        assert!(routes.contains("source != \"scanner\""));
        assert!(routes.contains("request.blocked_before_execution || request.process_started"));
        assert!(routes.contains("\"action_taken\": action_taken"));
        assert!(routes.contains("\"source\": source"));
        assert!(routes.contains("\"blocked_before_execution\": request.blocked_before_execution"));
        assert!(routes.contains("\"process_started\": request.process_started"));
    }

    #[test]
    fn quarantine_metadata_payload_size_is_bounded_before_insert_source_marker() {
        let source = include_str!("routes.rs");
        let quarantine_source = &source[source
            .find("pub async fn upload_quarantine_metadata")
            .expect("upload_quarantine_metadata")
            ..source
                .find("fn quarantine_action_matches_status")
                .expect("quarantine_action_matches_status")];

        assert!(quarantine_source.contains("let payload = json!({"));
        assert!(quarantine_source
            .contains("validate_json_value_size(&payload, \"quarantine_metadata\")?"));
        assert!(quarantine_source.contains("insert into events"));
        assert!(quarantine_source.contains(".bind(payload)"));
        assert!(!quarantine_source.contains(".bind(json!({"));
        assert!(
            quarantine_source.find("let payload = json!({")
                < quarantine_source.find("validate_json_value_size")
        );
        assert!(
            quarantine_source.find("validate_json_value_size")
                < quarantine_source.find("insert into events")
        );
        assert!(
            quarantine_source.find("insert into events") < quarantine_source.find(".bind(payload)")
        );
    }

    #[test]
    fn quarantine_metadata_requires_insert_ack_before_success_source_marker() {
        let source = include_str!("routes.rs");
        let quarantine_source = &source[source
            .find("pub async fn upload_quarantine_metadata")
            .expect("upload_quarantine_metadata")
            ..source
                .find("fn quarantine_action_matches_status")
                .expect("quarantine_action_matches_status")];

        assert!(quarantine_source.contains("let result = sqlx::query("));
        assert!(quarantine_source.contains("result.rows_affected() != 1"));
        assert!(quarantine_source
            .contains("quarantine metadata event insert did not affect exactly one row"));
        assert!(
            quarantine_source.find("let result = sqlx::query(")
                < quarantine_source.find("result.rows_affected() != 1")
        );
        assert!(
            quarantine_source.find("result.rows_affected() != 1")
                < quarantine_source.find("Ok(Json(json!({\"ok\": true})))")
        );
    }

    #[test]
    fn project_id_models_accept_client_slug_strings() {
        let models = include_str!("models.rs");
        assert!(models.contains("pub project_id: Option<String>"));
        assert!(models.contains("pub project_id: String"));
    }

    #[test]
    fn project_id_resolver_rejects_mismatched_uuid_source_marker() {
        let source = include_str!("routes.rs");
        assert!(source.contains("requested == auth_project_id.to_string()"));
        assert!(source.contains("Uuid::parse_str(&requested).is_ok()"));
        assert!(source.contains("select id from projects where id = $1 and slug = $2"));
    }

    #[test]
    fn project_creation_endpoint_is_fail_closed_source_marker() {
        let source = include_str!("routes.rs");
        assert!(source.contains("project creation is disabled"));
        let key_issuance_marker = ["public_client_key", " = format!"].concat();
        assert!(!source.contains(&key_issuance_marker));
    }

    #[test]
    fn routes_do_not_keep_unused_audit_helper_source_marker() {
        let source = include_str!("routes.rs");
        let async_marker = ["async fn ", "audit("].concat();
        let fn_marker = ["fn ", "audit("].concat();
        assert!(!source.contains(&async_marker));
        assert!(!source.contains(&fn_marker));
    }
}

async fn session_context(state: &AppState, session_id: Uuid) -> ApiResult<SessionContext> {
    sqlx::query_as::<_, (Uuid, String, DateTime<Utc>)>(
        "select project_id, status, expires_at from protection_runs where id = $1",
    )
    .bind(session_id)
    .fetch_optional(&state.db)
    .await?
    .map(|row| SessionContext {
        project_id: row.0,
        status: row.1,
        expires_at: row.2,
    })
    .ok_or(ApiError::NotFound)
}

async fn active_session_project(
    state: &AppState,
    session_id: Uuid,
    auth_project_id: Uuid,
) -> ApiResult<Uuid> {
    let session = session_context(state, session_id).await?;
    if session.project_id != auth_project_id {
        return Err(ApiError::Unauthorized);
    }
    if session.status != "active" {
        return Err(ApiError::BadRequest(
            "protection session is not active".to_string(),
        ));
    }
    if session.expires_at <= Utc::now() {
        return Err(ApiError::BadRequest(
            "protection session has expired".to_string(),
        ));
    }
    Ok(session.project_id)
}

async fn ensure_device_in_project(
    state: &AppState,
    device_id: Uuid,
    project_id: Uuid,
) -> ApiResult<()> {
    sqlx::query_as::<_, (i32,)>("select 1 from devices where id = $1 and project_id = $2")
        .bind(device_id)
        .bind(project_id)
        .fetch_optional(&state.db)
        .await?
        .map(|_| ())
        .ok_or(ApiError::NotFound)
}
