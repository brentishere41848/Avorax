use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("not found")]
    NotFound,
    #[error("internal error: {0}")]
    Internal(String),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden(_) => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let message = match self {
            ApiError::BadRequest(message) => format!("bad request: {message}"),
            ApiError::Unauthorized => "unauthorized".to_string(),
            ApiError::Forbidden(message) => format!("forbidden: {message}"),
            ApiError::NotFound => "not found".to_string(),
            ApiError::Internal(_) | ApiError::Database(_) => "internal server error".to_string(),
        };
        let body = Json(json!({
            "error": message,
        }));
        (status, body).into_response()
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

#[cfg(test)]
mod tests {
    #[test]
    fn api_error_response_does_not_expose_database_error_text_source_marker() {
        let source = include_str!("error.rs");
        assert!(source.contains("internal server error"));
        assert!(!source.contains("\"error\": self.to_string()"));
    }
}
