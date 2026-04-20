use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, Set,
};

use crate::{
    error::{AppError, AppResult},
    modules::node::model::{NodeKind, NodeLifecycleState},
    storage::db::entities::nodes,
};

#[derive(Clone)]
pub struct NodeRepository {
    db: DatabaseConnection,
}

#[derive(Debug, Clone)]
pub struct CreateNodeParams {
    pub content_id: i64,
    pub uuid: String,
    pub version: i32,
    pub kind: NodeKind,
    pub lifecycle_state: NodeLifecycleState,
    pub text_content: Option<String>,
    pub prev_node_id: Option<i64>,
    pub meta_json: Option<serde_json::Value>,
    pub actor: String,
}

impl NodeRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn find_by_id(&self, node_id: i64) -> AppResult<nodes::Model> {
        nodes::Entity::find_by_id(node_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("node {node_id}")))
    }

    pub async fn find_by_uuid_version(&self, uuid: &str, version: i32) -> AppResult<nodes::Model> {
        nodes::Entity::find()
            .filter(nodes::Column::Uuid.eq(uuid.to_owned()))
            .filter(nodes::Column::Version.eq(version))
            .one(&self.db)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("node lineage {uuid}:{version}")))
    }

    pub async fn find_by_ids(&self, node_ids: &[i64]) -> AppResult<Vec<nodes::Model>> {
        nodes::Entity::find()
            .filter(nodes::Column::Id.is_in(node_ids.iter().copied()))
            .all(&self.db)
            .await
            .map_err(AppError::from)
    }

    pub async fn list_all(&self) -> AppResult<Vec<nodes::Model>> {
        nodes::Entity::find()
            .order_by_desc(nodes::Column::Id)
            .all(&self.db)
            .await
            .map_err(AppError::from)
    }

    pub async fn create(&self, params: CreateNodeParams) -> AppResult<nodes::Model> {
        nodes::ActiveModel {
            content_id: Set(params.content_id),
            uuid: Set(params.uuid),
            version: Set(params.version),
            kind: Set(params.kind.as_str().to_owned()),
            lifecycle_state: Set(params.lifecycle_state.as_str().to_owned()),
            text_content: Set(params.text_content),
            prev_node_id: Set(params.prev_node_id),
            meta_json: Set(params.meta_json),
            created_by: Set(params.actor.clone()),
            updated_by: Set(params.actor),
            ..Default::default()
        }
        .insert(&self.db)
        .await
        .map_err(AppError::from)
    }

    pub async fn update_text(
        &self,
        node: nodes::Model,
        text: String,
        meta: Option<serde_json::Value>,
        actor: &str,
    ) -> AppResult<nodes::Model> {
        let mut active: nodes::ActiveModel = node.into();
        active.text_content = Set(Some(text));
        active.meta_json = Set(meta);
        active.updated_by = Set(actor.to_owned());
        active.updated_at = Set(chrono::Utc::now());
        active.update(&self.db).await.map_err(AppError::from)
    }

    pub async fn update_meta(
        &self,
        node: nodes::Model,
        meta: Option<serde_json::Value>,
        actor: &str,
    ) -> AppResult<nodes::Model> {
        let mut active: nodes::ActiveModel = node.into();
        active.meta_json = Set(meta);
        active.updated_by = Set(actor.to_owned());
        active.updated_at = Set(chrono::Utc::now());
        active.update(&self.db).await.map_err(AppError::from)
    }

    pub async fn update_lifecycle(
        &self,
        node_ids: &[i64],
        lifecycle_state: NodeLifecycleState,
        actor: &str,
    ) -> AppResult<()> {
        let now = chrono::Utc::now();
        nodes::Entity::update_many()
            .col_expr(
                nodes::Column::LifecycleState,
                sea_orm::sea_query::Expr::value(lifecycle_state.as_str()),
            )
            .col_expr(
                nodes::Column::UpdatedBy,
                sea_orm::sea_query::Expr::value(actor),
            )
            .col_expr(
                nodes::Column::UpdatedAt,
                sea_orm::sea_query::Expr::value(now),
            )
            .filter(nodes::Column::Id.is_in(node_ids.iter().copied()))
            .exec(&self.db)
            .await?;

        Ok(())
    }

    pub async fn latest_lineage_version(&self, uuid: &str) -> AppResult<Option<nodes::Model>> {
        nodes::Entity::find()
            .filter(nodes::Column::Uuid.eq(uuid.to_owned()))
            .order_by_desc(nodes::Column::Version)
            .one(&self.db)
            .await
            .map_err(AppError::from)
    }
}
