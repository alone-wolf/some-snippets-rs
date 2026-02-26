pub(crate) mod collection_handler;
mod error_mapper;
pub(crate) mod file_handler;
pub(crate) mod health_handler;
pub(crate) mod resource_handler;

use axum::{
    Router,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use common_http_server_rs::ApiResponse;
use sea_orm::DatabaseConnection;
use serde::Serialize;
use std::{path::PathBuf, sync::Arc};

pub(crate) fn api_v1_router(db: Arc<DatabaseConnection>, file_storage_dir: Arc<PathBuf>) -> Router {
    Router::new()
        .merge(collection_handler::router(db.clone()))
        .merge(file_handler::router(db.clone(), file_storage_dir))
        .merge(resource_handler::router(db))
}

pub(super) fn success_response<T: Serialize>(status: StatusCode, data: T) -> Response {
    ApiResponse {
        success: true,
        data: Some(data),
        error: None,
        request_id: None,
        status_code: Some(status.as_u16()),
    }
    .into_response()
}
