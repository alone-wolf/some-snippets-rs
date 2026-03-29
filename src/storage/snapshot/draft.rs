use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DraftSnapshot {
    pub content_id: String,
    pub state: DraftState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub nodes: Vec<DraftNodeRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DraftState {
    Draft,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DraftNodeRef {
    pub node_id: i64,
}

impl DraftSnapshot {
    pub fn empty(content_id: i64) -> Self {
        Self {
            content_id: content_id.to_string(),
            state: DraftState::Draft,
            label: Some("draft".to_owned()),
            nodes: Vec::new(),
        }
    }
}
