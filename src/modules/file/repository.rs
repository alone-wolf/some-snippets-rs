use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};

use crate::{
    error::{AppError, AppResult},
    storage::db::entities::file_metadata,
};

#[derive(Clone)]
pub struct FileMetadataRepository {
    db: DatabaseConnection,
}

#[derive(Debug, Clone)]
pub struct CreateFileMetadataParams {
    pub node_id: i64,
    pub file_uuid: String,
    pub bucket: String,
    pub object_key: String,
    pub filename: String,
    pub mime_type: Option<String>,
    pub size_bytes: i64,
    pub checksum: Option<String>,
    pub meta_json: Option<serde_json::Value>,
}

impl FileMetadataRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_node_id(&self, node_id: i64) -> AppResult<file_metadata::Model> {
        file_metadata::Entity::find()
            .filter(file_metadata::Column::NodeId.eq(node_id))
            .one(&self.db)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("file metadata for node {node_id}")))
    }

    pub async fn find_by_node_ids(&self, node_ids: &[i64]) -> AppResult<Vec<file_metadata::Model>> {
        file_metadata::Entity::find()
            .filter(file_metadata::Column::NodeId.is_in(node_ids.iter().copied()))
            .all(&self.db)
            .await
            .map_err(AppError::from)
    }

    pub async fn list_all(&self) -> AppResult<Vec<file_metadata::Model>> {
        file_metadata::Entity::find()
            .order_by_desc(file_metadata::Column::Id)
            .all(&self.db)
            .await
            .map_err(AppError::from)
    }

    pub async fn create(
        &self,
        params: CreateFileMetadataParams,
    ) -> AppResult<file_metadata::Model> {
        file_metadata::ActiveModel {
            node_id: Set(params.node_id),
            file_uuid: Set(params.file_uuid),
            bucket: Set(params.bucket),
            object_key: Set(params.object_key),
            filename: Set(params.filename),
            mime_type: Set(params.mime_type),
            size_bytes: Set(params.size_bytes),
            checksum: Set(params.checksum),
            meta_json: Set(params.meta_json),
            ..Default::default()
        }
        .insert(&self.db)
        .await
        .map_err(AppError::from)
    }

    pub async fn update(
        &self,
        existing: file_metadata::Model,
        input: crate::modules::file::model::FileMetadataInput,
    ) -> AppResult<file_metadata::Model> {
        let mut active: file_metadata::ActiveModel = existing.into();
        active.bucket = Set(input.bucket);
        active.object_key = Set(input.object_key);
        active.filename = Set(input.filename);
        active.mime_type = Set(input.mime_type);
        active.size_bytes = Set(input.size_bytes);
        active.checksum = Set(input.checksum);
        active.meta_json = Set(input.meta);
        active.updated_at = Set(chrono::Utc::now());
        active.update(&self.db).await.map_err(AppError::from)
    }
}
