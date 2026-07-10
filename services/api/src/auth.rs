use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;

const MAX_API_KEY_CHARS: usize = 256;

#[derive(Debug, Clone)]
pub struct ApiAuth {
    pub project_id: Uuid,
}

#[async_trait]
impl FromRequestParts<AppState> for ApiAuth {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Some(header) = parts.headers.get(axum::http::header::AUTHORIZATION) else {
            return Err((StatusCode::UNAUTHORIZED, "missing authorization"));
        };
        let Ok(value) = header.to_str() else {
            return Err((StatusCode::UNAUTHORIZED, "invalid authorization"));
        };
        let token = bearer_token(value)?;
        authenticate_key(&state.db, token)
            .await
            .map(|project_id| ApiAuth { project_id })
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid api key"))
    }
}

fn bearer_token(value: &str) -> Result<&str, (StatusCode, &'static str)> {
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err((StatusCode::UNAUTHORIZED, "invalid authorization"));
    };
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_API_KEY_CHARS {
        return Err((StatusCode::UNAUTHORIZED, "invalid authorization"));
    }
    if !token
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err((StatusCode::UNAUTHORIZED, "invalid authorization"));
    }
    Ok(token)
}

pub async fn authenticate_key(pool: &PgPool, token: &str) -> sqlx::Result<Uuid> {
    let key_hash = hash_api_key(token);
    let row: (Uuid,) = sqlx::query_as(
        "select project_id from api_keys where key_hash = $1 and revoked_at is null limit 1",
    )
    .bind(key_hash)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub fn hash_api_key(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_rejects_empty_or_oversized_values_before_hashing() {
        assert!(bearer_token("Bearer ").is_err());
        let oversized = format!("Bearer {}", "a".repeat(MAX_API_KEY_CHARS + 1));
        assert!(bearer_token(&oversized).is_err());
    }

    #[test]
    fn bearer_token_accepts_documented_dev_key_shape() {
        assert_eq!(
            bearer_token("Bearer avorax-public-client").expect("token"),
            "avorax-public-client"
        );
        assert_eq!(
            bearer_token("Bearer pk_avorax_0123456789abcdef").expect("token"),
            "pk_avorax_0123456789abcdef"
        );
    }
}
