use crate::service::error::{ServiceError, ServiceErrorKind};
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use common_http_server_rs::ApiResponse;
use serde_json::Value;

fn status_code_for(kind: ServiceErrorKind) -> StatusCode {
    match kind {
        ServiceErrorKind::BadRequest => StatusCode::BAD_REQUEST,
        ServiceErrorKind::NotFound => StatusCode::NOT_FOUND,
        ServiceErrorKind::Conflict => StatusCode::CONFLICT,
        ServiceErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let status = status_code_for(self.kind());
        ApiResponse::<Value>::error_with_status(self.message().to_string(), status).into_response()
    }
}
