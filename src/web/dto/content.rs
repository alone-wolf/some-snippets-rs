use serde::{Deserialize, Serialize};

use crate::{
    storage::{
        db::entities::{content_versions, contents},
        snapshot::{latest::LatestSnapshot, version::VersionSnapshot},
    },
    web::dto::draft::DraftSnapshot,
};

#[derive(Debug, Clone, Deserialize)]
pub struct CreateContentRequest {
    pub slug: String,
    pub title: String,
    pub status: String,
    #[serde(default)]
    pub schema_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateContentRequest {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub schema_id: Option<Option<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateVersionRequest {
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RollbackRequest {
    pub version: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentResponse {
    pub id: i64,
    pub collection_id: i64,
    pub slug: String,
    pub title: String,
    pub status: String,
    pub schema_id: Option<String>,
    pub draft_snapshot_key: Option<String>,
    pub latest_snapshot_key: Option<String>,
    pub latest_version: i32,
    pub created_by: String,
    pub updated_by: String,
}

impl From<contents::Model> for ContentResponse {
    fn from(value: contents::Model) -> Self {
        Self {
            id: value.id,
            collection_id: value.collection_id,
            slug: value.slug,
            title: value.title,
            status: value.status,
            schema_id: value.schema_id,
            draft_snapshot_key: value.draft_snapshot_key,
            latest_snapshot_key: value.latest_snapshot_key,
            latest_version: value.latest_version,
            created_by: value.created_by,
            updated_by: value.updated_by,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentVersionResponse {
    pub version: i32,
    pub label: Option<String>,
    pub snapshot_key: String,
    pub snapshot_checksum: String,
    pub created_by: String,
}

impl From<content_versions::Model> for ContentVersionResponse {
    fn from(value: content_versions::Model) -> Self {
        Self {
            version: value.version,
            label: value.label,
            snapshot_key: value.snapshot_key,
            snapshot_checksum: value.snapshot_checksum,
            created_by: value.created_by,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentSnapshotsResponse {
    pub draft: DraftSnapshot,
    pub latest: Option<LatestSnapshot>,
    pub versions: Vec<ContentVersionResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionSnapshotResponse {
    pub snapshot: VersionSnapshot,
}
