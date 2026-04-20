use std::sync::Arc;

use sea_orm::{ActiveModelTrait, DatabaseConnection, Set};

use crate::{
    error::{AppError, AppResult},
    modules::{
        content::{draft_service::DraftService, repository::ContentRepository},
        node::{model::NodeWithFile, service::NodeService},
    },
    storage::{
        db::entities::{collections, content_versions, contents},
        object_store::ObjectStore,
        snapshot::{
            checksum::sha256_hex,
            draft::DraftSnapshot,
            latest::{LatestSnapshot, NodeSnapshot, SnapshotState},
            path::{latest_snapshot_key, version_snapshot_key},
            rollback::VersionSnapshot as RollbackSnapshot,
            version::{FileSnapshot, VersionNodeSnapshot, VersionSnapshot, VersionState},
        },
    },
};

#[derive(Clone)]
pub struct ContentService {
    content_repo: ContentRepository,
    draft_service: DraftService,
    node_service: NodeService,
    object_store: Arc<dyn ObjectStore>,
}

#[derive(Debug, Clone)]
pub struct CreateCollectionInput {
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub visibility: String,
}

#[derive(Debug, Clone)]
pub struct CreateContentInput {
    pub collection_id: i64,
    pub slug: String,
    pub title: String,
    pub status: String,
    pub schema_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateCollectionInput {
    pub slug: Option<String>,
    pub name: Option<String>,
    pub description: Option<Option<String>>,
    pub visibility: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpdateContentInput {
    pub title: Option<String>,
    pub status: Option<String>,
    pub schema_id: Option<Option<String>>,
}

impl ContentService {
    pub fn new(db: DatabaseConnection, object_store: Arc<dyn ObjectStore>) -> Self {
        Self {
            content_repo: ContentRepository::new(db.clone()),
            draft_service: DraftService::new(db.clone(), Arc::clone(&object_store)),
            node_service: NodeService::new(db, Arc::clone(&object_store)),
            object_store,
        }
    }

    pub async fn create_collection(
        &self,
        input: CreateCollectionInput,
        actor: &str,
    ) -> AppResult<collections::Model> {
        let slug = input.slug.trim();
        let name = input.name.trim();
        let visibility = input.visibility.trim();

        if slug.is_empty() {
            return Err(AppError::Validation(
                "collection slug is required".to_owned(),
            ));
        }
        if name.is_empty() {
            return Err(AppError::Validation(
                "collection name is required".to_owned(),
            ));
        }
        if visibility.is_empty() {
            return Err(AppError::Validation(
                "collection visibility is required".to_owned(),
            ));
        }

        if self.content_repo.collection_slug_exists(slug).await? {
            return Err(AppError::Conflict(format!(
                "collection slug already exists: {slug}"
            )));
        }

        self.content_repo
            .create_collection(
                slug.to_owned(),
                name.to_owned(),
                input.description.map(|value| value.trim().to_owned()),
                visibility.to_owned(),
                actor,
            )
            .await
    }

    pub async fn create_content(
        &self,
        input: CreateContentInput,
        actor: &str,
    ) -> AppResult<contents::Model> {
        self.content_repo
            .ensure_collection_exists(input.collection_id)
            .await?;

        let content = self
            .content_repo
            .create(
                input.collection_id,
                input.slug,
                input.title,
                input.status,
                input.schema_id,
                actor,
            )
            .await?;

        self.draft_service
            .write(content.clone(), &DraftSnapshot::empty(content.id), actor)
            .await
    }

    pub async fn update_collection(
        &self,
        collection_id: i64,
        input: UpdateCollectionInput,
    ) -> AppResult<collections::Model> {
        let collection = self
            .content_repo
            .ensure_collection_exists(collection_id)
            .await?;

        let slug = match input.slug {
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(AppError::Validation(
                        "collection slug is required".to_owned(),
                    ));
                }
                if trimmed != collection.slug
                    && self
                        .content_repo
                        .collection_slug_exists_except(collection_id, trimmed)
                        .await?
                {
                    return Err(AppError::Conflict(format!(
                        "collection slug already exists: {trimmed}"
                    )));
                }
                Some(trimmed.to_owned())
            }
            None => None,
        };

        let name = match input.name {
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(AppError::Validation(
                        "collection name is required".to_owned(),
                    ));
                }
                Some(trimmed.to_owned())
            }
            None => None,
        };

        let visibility = match input.visibility {
            Some(value) => {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    return Err(AppError::Validation(
                        "collection visibility is required".to_owned(),
                    ));
                }
                Some(trimmed.to_owned())
            }
            None => None,
        };

        let description = input.description.map(|value| {
            value.and_then(|item| {
                let trimmed = item.trim().to_owned();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
        });

        self.content_repo
            .update_collection(collection, slug, name, description, visibility)
            .await
    }

    pub async fn get_content(&self, content_id: i64) -> AppResult<contents::Model> {
        self.content_repo.get(content_id).await
    }

    pub async fn list_collections(&self) -> AppResult<Vec<collections::Model>> {
        self.content_repo.list_collections().await
    }

    pub async fn list_contents(&self, collection_id: i64) -> AppResult<Vec<contents::Model>> {
        self.content_repo
            .ensure_collection_exists(collection_id)
            .await?;
        self.content_repo.list_by_collection(collection_id).await
    }

    pub async fn list_all_contents(&self) -> AppResult<Vec<contents::Model>> {
        self.content_repo.list_all_contents().await
    }

    pub async fn update_content(
        &self,
        content_id: i64,
        input: UpdateContentInput,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let content = self.content_repo.get(content_id).await?;
        self.content_repo
            .update(content, input.title, input.status, input.schema_id, actor)
            .await
    }

    pub async fn get_draft_snapshot(&self, content_id: i64) -> AppResult<DraftSnapshot> {
        let content = self.content_repo.get(content_id).await?;
        self.draft_service.load(&content).await
    }

    pub async fn reorder_draft(
        &self,
        content_id: i64,
        node_ids: Vec<i64>,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let content = self.content_repo.get(content_id).await?;
        self.draft_service.reorder(content, node_ids, actor).await
    }

    pub async fn commit_latest(&self, content_id: i64, actor: &str) -> AppResult<LatestSnapshot> {
        let content = self.content_repo.get(content_id).await?;
        let draft = self.draft_service.load(&content).await?;
        let node_ids: Vec<_> = draft.nodes.iter().map(|item| item.node_id).collect();
        let nodes = self.node_service.batch_load_with_files(&node_ids).await?;
        let snapshot = LatestSnapshot {
            content_id: content.id.to_string(),
            state: SnapshotState::Latest,
            version: content.latest_version,
            label: Some("latest".to_owned()),
            nodes: compose_node_snapshots(nodes),
        };

        let key = latest_snapshot_key(content.id);
        let payload = serde_json::to_vec_pretty(&snapshot)?;
        self.object_store
            .put_bytes(self.object_store.default_bucket(), &key, payload)
            .await?;

        self.content_repo
            .set_latest_snapshot_key(content, key, actor)
            .await?;
        self.node_service.mark_committed(&node_ids, actor).await?;

        Ok(snapshot)
    }

    pub async fn get_latest_snapshot(&self, content_id: i64) -> AppResult<LatestSnapshot> {
        let content = self.content_repo.get(content_id).await?;
        let key = content.latest_snapshot_key.ok_or_else(|| {
            AppError::NotFound(format!("latest snapshot for content {content_id}"))
        })?;
        let bytes = self
            .object_store
            .get_bytes(self.object_store.default_bucket(), &key)
            .await?;
        serde_json::from_slice(&bytes).map_err(AppError::from)
    }

    pub async fn create_version(
        &self,
        content_id: i64,
        label: Option<String>,
        actor: &str,
    ) -> AppResult<VersionSnapshot> {
        let content = self.content_repo.get(content_id).await?;
        let latest = self.get_latest_snapshot(content_id).await?;
        let next_version = self.content_repo.next_version(&content).await?;

        if self
            .content_repo
            .version_exists(content_id, next_version)
            .await?
        {
            return Err(AppError::Conflict(format!(
                "content version already exists: {content_id}:{next_version}"
            )));
        }

        let snapshot = VersionSnapshot {
            content_id: latest.content_id,
            state: VersionState::Version,
            version: next_version,
            label: label.clone(),
            nodes: latest
                .nodes
                .into_iter()
                .map(|node| VersionNodeSnapshot {
                    node_id: node.node_id,
                    uuid: node.uuid,
                    version: node.version,
                    kind: node.kind,
                    text: node.text,
                    file: node.file,
                    meta: node.meta,
                })
                .collect(),
        };

        let bytes = serde_json::to_vec_pretty(&snapshot)?;
        let key = version_snapshot_key(content_id, next_version);
        self.object_store
            .put_bytes(self.object_store.default_bucket(), &key, bytes.clone())
            .await?;

        let checksum = sha256_hex(&bytes);
        let db = self.content_repo.db();
        content_versions::ActiveModel {
            content_id: Set(content_id),
            version: Set(next_version),
            label: Set(label),
            snapshot_key: Set(key.clone()),
            snapshot_checksum: Set(checksum),
            created_by: Set(actor.to_owned()),
            meta_json: Set(None),
            ..Default::default()
        }
        .insert(db)
        .await?;

        self.content_repo
            .set_latest_version(content, next_version, actor)
            .await?;

        Ok(snapshot)
    }

    pub async fn list_versions(&self, content_id: i64) -> AppResult<Vec<content_versions::Model>> {
        self.content_repo.list_versions(content_id).await
    }

    pub async fn get_version_snapshot(
        &self,
        content_id: i64,
        version: i32,
    ) -> AppResult<VersionSnapshot> {
        let version_meta = self.content_repo.get_version(content_id, version).await?;
        let bytes = self
            .object_store
            .get_bytes(
                self.object_store.default_bucket(),
                &version_meta.snapshot_key,
            )
            .await?;
        serde_json::from_slice(&bytes).map_err(AppError::from)
    }

    pub async fn rollback_to_version(
        &self,
        content_id: i64,
        version: i32,
        actor: &str,
    ) -> AppResult<DraftSnapshot> {
        let content = self.content_repo.get(content_id).await?;
        let snapshot: RollbackSnapshot = self.get_version_snapshot(content_id, version).await?;
        let mut node_refs = Vec::with_capacity(snapshot.nodes.len());

        for node in snapshot.nodes {
            let restored = match self.node_service.get_node_with_file(node.node_id).await {
                Ok(existing) => existing,
                Err(_) => match self
                    .node_service
                    .get_lineage_version(&node.uuid, node.version)
                    .await
                {
                    Ok(existing) => existing,
                    Err(_) => self.restore_snapshot_node(content_id, node, actor).await?,
                },
            };

            node_refs.push(crate::storage::snapshot::draft::DraftNodeRef {
                node_id: restored.node.id,
            });
        }

        let draft = DraftSnapshot {
            content_id: content.id.to_string(),
            state: crate::storage::snapshot::draft::DraftState::Draft,
            label: Some("draft".to_owned()),
            nodes: node_refs,
        };

        self.draft_service.write(content, &draft, actor).await?;
        Ok(draft)
    }

    async fn restore_snapshot_node(
        &self,
        content_id: i64,
        node: VersionNodeSnapshot,
        actor: &str,
    ) -> AppResult<NodeWithFile> {
        let kind = node.kind.as_str();
        match kind {
            "text" => {
                self.node_service
                    .restore_text_node(
                        content_id,
                        node.uuid,
                        node.version,
                        node.text.unwrap_or_default(),
                        node.meta,
                        actor,
                    )
                    .await
            }
            "file" => {
                let file = node
                    .file
                    .ok_or_else(|| AppError::Validation("file snapshot is missing".to_owned()))?;
                self.node_service
                    .restore_file_node(
                        content_id,
                        node.uuid,
                        node.version,
                        crate::modules::node::model::FileNodeInput {
                            filename: file.filename,
                            bucket: file.bucket,
                            object_key: file.object_key,
                            mime_type: file.mime_type,
                            size_bytes: file.size_bytes,
                            checksum: file.checksum,
                            meta: node.meta,
                        },
                        actor,
                    )
                    .await
            }
            other => Err(AppError::Validation(format!(
                "unsupported rollback node kind: {other}"
            ))),
        }
    }
}

fn compose_node_snapshots(nodes: Vec<NodeWithFile>) -> Vec<NodeSnapshot> {
    nodes
        .into_iter()
        .map(|item| NodeSnapshot {
            node_id: item.node.id,
            uuid: item.node.uuid,
            version: item.node.version,
            kind: item.node.kind,
            text: item.node.text_content,
            file: item.file_metadata.map(|file| FileSnapshot {
                filename: file.filename,
                bucket: file.bucket,
                object_key: file.object_key,
                mime_type: file.mime_type,
                size_bytes: file.size_bytes,
                checksum: file.checksum,
            }),
            meta: item.node.meta_json,
        })
        .collect()
}
