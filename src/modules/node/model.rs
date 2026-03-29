use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::storage::db::entities::{file_metadata, nodes};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Text,
    File,
}

impl NodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::File => "file",
        }
    }
}

impl TryFrom<&str> for NodeKind {
    type Error = crate::error::AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "text" => Ok(Self::Text),
            "file" => Ok(Self::File),
            other => Err(crate::error::AppError::Validation(format!(
                "unsupported node kind: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeLifecycleState {
    DraftOnly,
    Committed,
}

impl NodeLifecycleState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DraftOnly => "draft_only",
            Self::Committed => "committed",
        }
    }
}

impl TryFrom<&str> for NodeLifecycleState {
    type Error = crate::error::AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "draft_only" => Ok(Self::DraftOnly),
            "committed" => Ok(Self::Committed),
            other => Err(crate::error::AppError::Validation(format!(
                "unsupported lifecycle state: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextNodeInput {
    pub text: String,
    #[serde(default)]
    pub meta: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileNodeInput {
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

#[derive(Debug, Clone)]
pub struct NodeWithFile {
    pub node: nodes::Model,
    pub file_metadata: Option<file_metadata::Model>,
}
