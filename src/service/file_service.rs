use crate::entity::{FileActiveModel, FileModel};
use crate::repository::file_repository::FileRepository;
use crate::service::error::{ServiceError, map_db_error};
use chrono::Utc;
use sea_orm::{ActiveValue::Set, DatabaseConnection};
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
use uuid::Uuid;

pub(crate) struct UploadRequest {
    pub(crate) original_filename: String,
    pub(crate) mime_type: Option<String>,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone)]
pub(crate) struct FileService {
    db: Arc<DatabaseConnection>,
    storage_dir: Arc<PathBuf>,
}

impl FileService {
    pub(crate) fn new(db: Arc<DatabaseConnection>, storage_dir: Arc<PathBuf>) -> Self {
        Self { db, storage_dir }
    }

    pub(crate) async fn upload(&self, upload: UploadRequest) -> Result<FileModel, ServiceError> {
        if upload.bytes.is_empty() {
            return Err(ServiceError::bad_request("uploaded file is empty"));
        }

        let file_uuid = Uuid::new_v4().simple().to_string();
        let target_path = self.storage_dir.join(&file_uuid);
        let target_path_display = target_path.to_string_lossy().to_string();

        tokio::fs::write(&target_path, &upload.bytes)
            .await
            .map_err(|error| {
                ServiceError::internal(format!("failed to persist uploaded file: {error}"))
            })?;

        let byte_size = i32::try_from(upload.bytes.len()).map_err(|_| {
            ServiceError::bad_request("uploaded file is too large to fit into byte_size")
        })?;
        let sha256 = format!("{:x}", Sha256::digest(&upload.bytes));

        let active_model = FileActiveModel {
            file_uuid: Set(Some(file_uuid)),
            storage_path: Set(target_path_display),
            original_filename: Set(upload.original_filename),
            mime_type: Set(upload.mime_type),
            byte_size: Set(Some(byte_size)),
            sha256: Set(Some(sha256)),
            created_at: Set(Utc::now().into()),
            ..Default::default()
        };

        match FileRepository::insert(self.db.as_ref(), active_model).await {
            Ok(model) => Ok(model),
            Err(error) => {
                let _ = tokio::fs::remove_file(&target_path).await;
                Err(map_db_error(error))
            }
        }
    }
}
