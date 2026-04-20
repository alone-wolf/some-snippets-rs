use uuid::Uuid;

use crate::{
    error::AppResult,
    modules::file::{
        model::FileMetadataInput,
        repository::{CreateFileMetadataParams, FileMetadataRepository},
    },
};

#[derive(Clone)]
pub struct FileService {
    repo: FileMetadataRepository,
}

impl FileService {
    pub fn new(repo: FileMetadataRepository) -> Self {
        Self { repo }
    }

    pub async fn create_for_node(
        &self,
        node_id: i64,
        input: FileMetadataInput,
    ) -> AppResult<crate::storage::db::entities::file_metadata::Model> {
        self.repo
            .create(CreateFileMetadataParams {
                node_id,
                file_uuid: Uuid::new_v4().to_string(),
                bucket: input.bucket,
                object_key: input.object_key,
                filename: input.filename,
                mime_type: input.mime_type,
                size_bytes: input.size_bytes,
                checksum: input.checksum,
                meta_json: input.meta,
            })
            .await
    }

    pub async fn update(
        &self,
        node_id: i64,
        input: FileMetadataInput,
    ) -> AppResult<crate::storage::db::entities::file_metadata::Model> {
        let existing = self.repo.find_by_node_id(node_id).await?;
        self.repo.update(existing, input).await
    }

    pub async fn clone_to_node(
        &self,
        source_node_id: i64,
        target_node_id: i64,
        override_input: FileMetadataInput,
    ) -> AppResult<crate::storage::db::entities::file_metadata::Model> {
        let existing = self.repo.find_by_node_id(source_node_id).await?;
        self.repo
            .create(CreateFileMetadataParams {
                node_id: target_node_id,
                file_uuid: Uuid::new_v4().to_string(),
                bucket: override_input.bucket,
                object_key: override_input.object_key,
                filename: override_input.filename,
                mime_type: override_input.mime_type.or(existing.mime_type),
                size_bytes: override_input.size_bytes,
                checksum: override_input.checksum.or(existing.checksum),
                meta_json: override_input.meta.or(existing.meta_json),
            })
            .await
    }

    pub fn repo(&self) -> &FileMetadataRepository {
        &self.repo
    }

    pub async fn list_all(
        &self,
    ) -> AppResult<Vec<crate::storage::db::entities::file_metadata::Model>> {
        self.repo.list_all().await
    }
}
