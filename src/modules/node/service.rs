use std::{collections::HashMap, sync::Arc};

use sea_orm::DatabaseConnection;
use uuid::Uuid;

use crate::{
    error::{AppError, AppResult},
    modules::{
        content::{draft_service::DraftService, repository::ContentRepository},
        file::{
            model::FileMetadataInput, repository::FileMetadataRepository, service::FileService,
        },
        node::{
            model::{FileNodeInput, NodeKind, NodeLifecycleState, NodeWithFile, TextNodeInput},
            repository::{CreateNodeParams, NodeRepository},
        },
    },
    storage::{db::entities::nodes, object_store::ObjectStore},
};

#[derive(Debug, Clone)]
pub struct NodeEditResult {
    pub old_node: nodes::Model,
    pub new_node: nodes::Model,
    pub copy_on_write: bool,
}

#[derive(Clone)]
pub struct NodeService {
    content_repo: ContentRepository,
    node_repo: NodeRepository,
    file_service: FileService,
    draft_service: DraftService,
}

impl NodeService {
    pub fn new(db: DatabaseConnection, object_store: Arc<dyn ObjectStore>) -> Self {
        let file_repo = FileMetadataRepository::new(db.clone());

        Self {
            content_repo: ContentRepository::new(db.clone()),
            node_repo: NodeRepository::new(db.clone()),
            file_service: FileService::new(file_repo),
            draft_service: DraftService::new(db, object_store),
        }
    }

    pub async fn create_text_node(
        &self,
        content_id: i64,
        input: TextNodeInput,
        actor: &str,
    ) -> AppResult<nodes::Model> {
        let content = self.content_repo.get(content_id).await?;
        let node = self
            .node_repo
            .create(CreateNodeParams {
                content_id,
                uuid: Uuid::new_v4().to_string(),
                version: 0,
                kind: NodeKind::Text,
                lifecycle_state: NodeLifecycleState::DraftOnly,
                text_content: Some(input.text),
                prev_node_id: None,
                meta_json: input.meta,
                actor: actor.to_owned(),
            })
            .await?;

        self.draft_service.add_node(content, node.id, actor).await?;
        Ok(node)
    }

    pub async fn create_file_node(
        &self,
        content_id: i64,
        input: FileNodeInput,
        actor: &str,
    ) -> AppResult<NodeWithFile> {
        let content = self.content_repo.get(content_id).await?;
        let node = self
            .node_repo
            .create(CreateNodeParams {
                content_id,
                uuid: Uuid::new_v4().to_string(),
                version: 0,
                kind: NodeKind::File,
                lifecycle_state: NodeLifecycleState::DraftOnly,
                text_content: None,
                prev_node_id: None,
                meta_json: input.meta.clone(),
                actor: actor.to_owned(),
            })
            .await?;

        let file_metadata = self
            .file_service
            .create_for_node(
                node.id,
                FileMetadataInput {
                    filename: input.filename,
                    bucket: input.bucket,
                    object_key: input.object_key,
                    mime_type: input.mime_type,
                    size_bytes: input.size_bytes,
                    checksum: input.checksum,
                    meta: input.meta,
                },
            )
            .await?;

        self.draft_service.add_node(content, node.id, actor).await?;

        Ok(NodeWithFile {
            node,
            file_metadata: Some(file_metadata),
        })
    }

    pub async fn get_node_with_file(&self, node_id: i64) -> AppResult<NodeWithFile> {
        let node = self.node_repo.find_by_id(node_id).await?;
        let kind = NodeKind::try_from(node.kind.as_str())?;
        let file_metadata = if matches!(kind, NodeKind::File) {
            Some(self.file_service.repo().find_by_node_id(node.id).await?)
        } else {
            None
        };

        Ok(NodeWithFile {
            node,
            file_metadata,
        })
    }

    pub async fn get_lineage_version(&self, uuid: &str, version: i32) -> AppResult<NodeWithFile> {
        let node = self.node_repo.find_by_uuid_version(uuid, version).await?;
        self.get_node_with_file(node.id).await
    }

    pub async fn update_text_node(
        &self,
        node_id: i64,
        input: TextNodeInput,
        actor: &str,
    ) -> AppResult<NodeEditResult> {
        let existing = self.node_repo.find_by_id(node_id).await?;
        let content = self.content_repo.get(existing.content_id).await?;
        if NodeKind::try_from(existing.kind.as_str())? != NodeKind::Text {
            return Err(AppError::Validation(format!(
                "node {node_id} is not a text node"
            )));
        }

        let state = NodeLifecycleState::try_from(existing.lifecycle_state.as_str())?;
        match state {
            NodeLifecycleState::DraftOnly => {
                let updated = self
                    .node_repo
                    .update_text(existing.clone(), input.text, input.meta, actor)
                    .await?;
                Ok(NodeEditResult {
                    old_node: existing,
                    new_node: updated,
                    copy_on_write: false,
                })
            }
            NodeLifecycleState::Committed => {
                let replacement = self
                    .node_repo
                    .create(CreateNodeParams {
                        content_id: existing.content_id,
                        uuid: existing.uuid.clone(),
                        version: existing.version + 1,
                        kind: NodeKind::Text,
                        lifecycle_state: NodeLifecycleState::DraftOnly,
                        text_content: Some(input.text),
                        prev_node_id: Some(existing.id),
                        meta_json: input.meta,
                        actor: actor.to_owned(),
                    })
                    .await?;

                self.draft_service
                    .replace_node(content, existing.id, replacement.id, actor)
                    .await?;

                Ok(NodeEditResult {
                    old_node: existing,
                    new_node: replacement,
                    copy_on_write: true,
                })
            }
        }
    }

    pub async fn update_file_node(
        &self,
        node_id: i64,
        input: FileNodeInput,
        actor: &str,
    ) -> AppResult<NodeEditResult> {
        let existing = self.node_repo.find_by_id(node_id).await?;
        let content = self.content_repo.get(existing.content_id).await?;
        if NodeKind::try_from(existing.kind.as_str())? != NodeKind::File {
            return Err(AppError::Validation(format!(
                "node {node_id} is not a file node"
            )));
        }

        let file_input = FileMetadataInput {
            filename: input.filename,
            bucket: input.bucket,
            object_key: input.object_key,
            mime_type: input.mime_type,
            size_bytes: input.size_bytes,
            checksum: input.checksum,
            meta: input.meta.clone(),
        };

        let state = NodeLifecycleState::try_from(existing.lifecycle_state.as_str())?;
        match state {
            NodeLifecycleState::DraftOnly => {
                let updated = self
                    .node_repo
                    .update_meta(existing.clone(), input.meta, actor)
                    .await?;
                let _ = self.file_service.update(existing.id, file_input).await?;

                Ok(NodeEditResult {
                    old_node: existing,
                    new_node: updated,
                    copy_on_write: false,
                })
            }
            NodeLifecycleState::Committed => {
                let replacement = self
                    .node_repo
                    .create(CreateNodeParams {
                        content_id: existing.content_id,
                        uuid: existing.uuid.clone(),
                        version: existing.version + 1,
                        kind: NodeKind::File,
                        lifecycle_state: NodeLifecycleState::DraftOnly,
                        text_content: None,
                        prev_node_id: Some(existing.id),
                        meta_json: input.meta,
                        actor: actor.to_owned(),
                    })
                    .await?;

                let _ = self
                    .file_service
                    .clone_to_node(existing.id, replacement.id, file_input)
                    .await?;

                self.draft_service
                    .replace_node(content, existing.id, replacement.id, actor)
                    .await?;

                Ok(NodeEditResult {
                    old_node: existing,
                    new_node: replacement,
                    copy_on_write: true,
                })
            }
        }
    }

    pub async fn batch_load_with_files(&self, node_ids: &[i64]) -> AppResult<Vec<NodeWithFile>> {
        let nodes = self.node_repo.find_by_ids(node_ids).await?;
        let metadata = self.file_service.repo().find_by_node_ids(node_ids).await?;
        let metadata_map: HashMap<i64, _> = metadata
            .into_iter()
            .map(|item| (item.node_id, item))
            .collect();

        let mut ordered = Vec::with_capacity(node_ids.len());
        let node_map: HashMap<i64, _> = nodes.into_iter().map(|node| (node.id, node)).collect();
        for node_id in node_ids {
            let node = node_map
                .get(node_id)
                .cloned()
                .ok_or_else(|| AppError::NotFound(format!("node {node_id}")))?;
            ordered.push(NodeWithFile {
                file_metadata: metadata_map.get(node_id).cloned(),
                node,
            });
        }

        Ok(ordered)
    }

    pub async fn mark_committed(&self, node_ids: &[i64], actor: &str) -> AppResult<()> {
        self.node_repo
            .update_lifecycle(node_ids, NodeLifecycleState::Committed, actor)
            .await
    }

    pub async fn restore_text_node(
        &self,
        content_id: i64,
        uuid: String,
        version: i32,
        text: String,
        meta: Option<serde_json::Value>,
        actor: &str,
    ) -> AppResult<NodeWithFile> {
        let node = self
            .node_repo
            .create(CreateNodeParams {
                content_id,
                uuid,
                version,
                kind: NodeKind::Text,
                lifecycle_state: NodeLifecycleState::Committed,
                text_content: Some(text),
                prev_node_id: None,
                meta_json: meta,
                actor: actor.to_owned(),
            })
            .await?;

        Ok(NodeWithFile {
            node,
            file_metadata: None,
        })
    }

    pub async fn restore_file_node(
        &self,
        content_id: i64,
        uuid: String,
        version: i32,
        input: FileNodeInput,
        actor: &str,
    ) -> AppResult<NodeWithFile> {
        let node = self
            .node_repo
            .create(CreateNodeParams {
                content_id,
                uuid,
                version,
                kind: NodeKind::File,
                lifecycle_state: NodeLifecycleState::Committed,
                text_content: None,
                prev_node_id: None,
                meta_json: input.meta.clone(),
                actor: actor.to_owned(),
            })
            .await?;

        let file_metadata = self
            .file_service
            .create_for_node(
                node.id,
                FileMetadataInput {
                    filename: input.filename,
                    bucket: input.bucket,
                    object_key: input.object_key,
                    mime_type: input.mime_type,
                    size_bytes: input.size_bytes,
                    checksum: input.checksum,
                    meta: input.meta,
                },
            )
            .await?;

        Ok(NodeWithFile {
            node,
            file_metadata: Some(file_metadata),
        })
    }
}
