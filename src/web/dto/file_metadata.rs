use serde::Serialize;

use crate::storage::db::entities::file_metadata;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadataResponse {
    pub id: i64,
    pub node_id: i64,
    pub file_uuid: String,
    pub bucket: String,
    pub object_key: String,
    pub filename: String,
    pub mime_type: Option<String>,
    pub size_bytes: i64,
    pub checksum: Option<String>,
    pub meta: Option<serde_json::Value>,
}

impl From<file_metadata::Model> for FileMetadataResponse {
    fn from(value: file_metadata::Model) -> Self {
        Self {
            id: value.id,
            node_id: value.node_id,
            file_uuid: value.file_uuid,
            bucket: value.bucket,
            object_key: value.object_key,
            filename: value.filename,
            mime_type: value.mime_type,
            size_bytes: value.size_bytes,
            checksum: value.checksum,
            meta: value.meta_json,
        }
    }
}
