use crate::handler::success_response;
use crate::service::error::ServiceError;
use crate::service::file_service::{FileService, UploadRequest};
use axum::{Router, extract::Multipart, http::StatusCode, response::Response, routing::post};
use sea_orm::DatabaseConnection;
use std::{path::PathBuf, sync::Arc};

async fn parse_upload_file(mut multipart: Multipart) -> Result<UploadRequest, ServiceError> {
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| ServiceError::bad_request(format!("invalid multipart payload: {error}")))?
    {
        let field_name = field.name().map(str::to_owned).unwrap_or_default();
        if field_name != "file" {
            continue;
        }

        let original_filename = field
            .file_name()
            .map(str::to_owned)
            .unwrap_or_else(|| "upload.bin".to_string());
        let mime_type = field.content_type().map(str::to_owned);
        let bytes = field.bytes().await.map_err(|error| {
            ServiceError::bad_request(format!("failed to read upload: {error}"))
        })?;

        return Ok(UploadRequest {
            original_filename,
            mime_type,
            bytes: bytes.to_vec(),
        });
    }

    Err(ServiceError::bad_request("missing multipart field `file`"))
}

pub(crate) fn router(db: Arc<DatabaseConnection>, storage_dir: Arc<PathBuf>) -> Router {
    let service = FileService::new(db, storage_dir);
    Router::new().route(
        "/files/upload",
        post(move |multipart: Multipart| upload_file(service.clone(), multipart)),
    )
}

async fn upload_file(service: FileService, multipart: Multipart) -> Result<Response, ServiceError> {
    let upload = parse_upload_file(multipart).await?;
    let created = service.upload(upload).await?;
    Ok(success_response(StatusCode::CREATED, created))
}
