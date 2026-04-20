use axum::{Json, extract::State, http::HeaderMap};

use crate::{
    app::state::AppState,
    error::AppResult,
    modules::{
        auth::permission::Permission, file::repository::FileMetadataRepository,
        file::service::FileService,
    },
    web::{
        dto::file_metadata::FileMetadataResponse, middleware::authz::require_permission,
        response::ApiResponse,
    },
};

pub async fn list_file_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Vec<FileMetadataResponse>>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = FileService::new(FileMetadataRepository::new(state.db.clone()));
    let items = service
        .list_all()
        .await?
        .into_iter()
        .map(FileMetadataResponse::from)
        .collect();
    Ok(Json(ApiResponse::ok(items)))
}
