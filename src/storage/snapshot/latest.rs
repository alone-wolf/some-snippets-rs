use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::version::FileSnapshot;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct LatestSnapshot {
    pub content_id: String,
    pub state: SnapshotState,
    pub version: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub nodes: Vec<NodeSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotState {
    Latest,
    Version,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct NodeSnapshot {
    pub node_id: i64,
    pub uuid: String,
    pub version: i32,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}
