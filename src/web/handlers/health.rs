use std::sync::Arc;

use axum::{Json, extract::State};
use serde::Serialize;

use crate::{config::AppConfig, web::response::ApiResponse};

#[derive(Debug, Serialize)]
pub struct HealthPayload {
    pub status: &'static str,
    pub service: &'static str,
}

pub async fn healthz(State(_config): State<Arc<AppConfig>>) -> Json<ApiResponse<HealthPayload>> {
    Json(ApiResponse::ok(HealthPayload {
        status: "ok",
        service: "some-snippets",
    }))
}
