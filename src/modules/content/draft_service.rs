use std::{collections::HashMap, sync::Arc};

use sea_orm::DatabaseConnection;

use crate::{
    error::{AppError, AppResult},
    modules::content::repository::ContentRepository,
    storage::{
        db::entities::contents,
        object_store::{ObjectStore, get_json, put_json},
        snapshot::{
            draft::{DraftNodeRef, DraftSnapshot},
            path::draft_snapshot_key,
        },
    },
};

#[derive(Clone)]
pub struct DraftService {
    content_repo: ContentRepository,
    object_store: Arc<dyn ObjectStore>,
}

impl DraftService {
    pub fn new(db: DatabaseConnection, object_store: Arc<dyn ObjectStore>) -> Self {
        Self {
            content_repo: ContentRepository::new(db),
            object_store,
        }
    }

    pub async fn load(&self, content: &contents::Model) -> AppResult<DraftSnapshot> {
        match &content.draft_snapshot_key {
            Some(key) => get_json(
                self.object_store.as_ref(),
                self.object_store.default_bucket(),
                key,
            )
            .await
            .or_else(|_| Ok(DraftSnapshot::empty(content.id))),
            None => Ok(DraftSnapshot::empty(content.id)),
        }
    }

    pub async fn write(
        &self,
        content: contents::Model,
        snapshot: &DraftSnapshot,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let key = draft_snapshot_key(content.id);
        put_json(
            self.object_store.as_ref(),
            self.object_store.default_bucket(),
            &key,
            snapshot,
        )
        .await?;

        self.content_repo
            .set_draft_snapshot_key(content, key, actor)
            .await
    }

    pub async fn add_node(
        &self,
        content: contents::Model,
        node_id: i64,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let mut draft = self.load(&content).await?;
        draft.nodes.push(DraftNodeRef { node_id });
        self.write(content, &draft, actor).await
    }

    pub async fn remove_node(
        &self,
        content: contents::Model,
        node_id: i64,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let mut draft = self.load(&content).await?;
        let previous_len = draft.nodes.len();
        draft.nodes.retain(|entry| entry.node_id != node_id);
        if draft.nodes.len() == previous_len {
            return Err(AppError::NotFound(format!(
                "node {node_id} not found in draft for content {}",
                content.id
            )));
        }

        self.write(content, &draft, actor).await
    }

    pub async fn replace_node(
        &self,
        content: contents::Model,
        old_node_id: i64,
        new_node_id: i64,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let mut draft = self.load(&content).await?;
        let mut replaced = false;
        for node in &mut draft.nodes {
            if node.node_id == old_node_id {
                node.node_id = new_node_id;
                replaced = true;
            }
        }
        if !replaced {
            return Err(AppError::NotFound(format!(
                "node {old_node_id} not found in draft for content {}",
                content.id
            )));
        }

        self.write(content, &draft, actor).await
    }

    pub async fn reorder(
        &self,
        content: contents::Model,
        node_ids: Vec<i64>,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let existing = self.load(&content).await?;
        let existing_map =
            HashMap::<i64, ()>::from_iter(existing.nodes.iter().map(|item| (item.node_id, ())));
        for node_id in &node_ids {
            if !existing_map.contains_key(node_id) {
                return Err(AppError::Validation(format!(
                    "node {node_id} does not exist in current draft"
                )));
            }
        }

        let snapshot = DraftSnapshot {
            content_id: content.id.to_string(),
            state: crate::storage::snapshot::draft::DraftState::Draft,
            label: Some("draft".to_owned()),
            nodes: node_ids
                .into_iter()
                .map(|node_id| DraftNodeRef { node_id })
                .collect(),
        };
        self.write(content, &snapshot, actor).await
    }
}
