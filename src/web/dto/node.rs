use serde::{Deserialize, Serialize};

use crate::{modules::node::model::NodeWithFile, storage::db::entities::nodes};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateNodeRequest {
    pub kind: String,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub file: Option<FilePayload>,
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateNodeRequest {
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub file: Option<FilePayload>,
    #[serde(default)]
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilePayload {
    pub filename: String,
    pub bucket: String,
    pub object_key: String,
    #[serde(default)]
    pub mime_type: Option<String>,
    pub size_bytes: i64,
    #[serde(default)]
    pub checksum: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeResponse {
    pub id: i64,
    pub content_id: i64,
    pub uuid: String,
    pub version: i32,
    pub kind: String,
    pub lifecycle_state: String,
    pub text: Option<String>,
    pub prev_node_id: Option<i64>,
    pub meta: Option<serde_json::Value>,
    pub created_by: String,
    pub updated_by: String,
    pub file: Option<FilePayload>,
}

impl From<NodeWithFile> for NodeResponse {
    fn from(value: NodeWithFile) -> Self {
        Self {
            id: value.node.id,
            content_id: value.node.content_id,
            uuid: value.node.uuid,
            version: value.node.version,
            kind: value.node.kind,
            lifecycle_state: value.node.lifecycle_state,
            text: value.node.text_content,
            prev_node_id: value.node.prev_node_id,
            meta: value.node.meta_json,
            created_by: value.node.created_by,
            updated_by: value.node.updated_by,
            file: value.file_metadata.map(|file| FilePayload {
                filename: file.filename,
                bucket: file.bucket,
                object_key: file.object_key,
                mime_type: file.mime_type,
                size_bytes: file.size_bytes,
                checksum: file.checksum,
            }),
        }
    }
}

impl From<nodes::Model> for NodeResponse {
    fn from(value: nodes::Model) -> Self {
        Self {
            id: value.id,
            content_id: value.content_id,
            uuid: value.uuid,
            version: value.version,
            kind: value.kind,
            lifecycle_state: value.lifecycle_state,
            text: value.text_content,
            prev_node_id: value.prev_node_id,
            meta: value.meta_json,
            created_by: value.created_by,
            updated_by: value.updated_by,
            file: None,
        }
    }
}
