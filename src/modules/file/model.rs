use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadataInput {
    pub filename: String,
    pub bucket: String,
    pub object_key: String,
    #[serde(default)]
    pub mime_type: Option<String>,
    pub size_bytes: i64,
    #[serde(default)]
    pub checksum: Option<String>,
    #[serde(default)]
    pub meta: Option<Value>,
}
