use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, Set,
};

use crate::{
    error::{AppError, AppResult},
    storage::db::entities::{collections, content_versions, contents},
};

#[derive(Clone)]
pub struct ContentRepository {
    db: DatabaseConnection,
}

impl ContentRepository {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn ensure_collection_exists(
        &self,
        collection_id: i64,
    ) -> AppResult<collections::Model> {
        collections::Entity::find_by_id(collection_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("collection {collection_id}")))
    }

    pub async fn list_collections(&self) -> AppResult<Vec<collections::Model>> {
        collections::Entity::find()
            .order_by_asc(collections::Column::Name)
            .all(&self.db)
            .await
            .map_err(AppError::from)
    }

    pub async fn collection_slug_exists(&self, slug: &str) -> AppResult<bool> {
        collections::Entity::find()
            .filter(collections::Column::Slug.eq(slug))
            .count(&self.db)
            .await
            .map(|count| count > 0)
            .map_err(AppError::from)
    }

    pub async fn collection_slug_exists_except(
        &self,
        collection_id: i64,
        slug: &str,
    ) -> AppResult<bool> {
        collections::Entity::find()
            .filter(collections::Column::Slug.eq(slug))
            .filter(collections::Column::Id.ne(collection_id))
            .count(&self.db)
            .await
            .map(|count| count > 0)
            .map_err(AppError::from)
    }

    pub async fn create_collection(
        &self,
        slug: String,
        name: String,
        description: Option<String>,
        visibility: String,
        actor: &str,
    ) -> AppResult<collections::Model> {
        let model = collections::ActiveModel {
            slug: Set(slug),
            name: Set(name),
            description: Set(description),
            visibility: Set(visibility),
            owner_id: Set(actor.to_owned()),
            config_json: Set(None),
            ..Default::default()
        };

        model.insert(&self.db).await.map_err(AppError::from)
    }

    pub async fn update_collection(
        &self,
        collection: collections::Model,
        slug: Option<String>,
        name: Option<String>,
        description: Option<Option<String>>,
        visibility: Option<String>,
    ) -> AppResult<collections::Model> {
        let mut active: collections::ActiveModel = collection.into();
        if let Some(value) = slug {
            active.slug = Set(value);
        }
        if let Some(value) = name {
            active.name = Set(value);
        }
        if let Some(value) = description {
            active.description = Set(value);
        }
        if let Some(value) = visibility {
            active.visibility = Set(value);
        }
        active.updated_at = Set(chrono::Utc::now());
        active.update(&self.db).await.map_err(AppError::from)
    }

    pub async fn list_by_collection(&self, collection_id: i64) -> AppResult<Vec<contents::Model>> {
        contents::Entity::find()
            .filter(contents::Column::CollectionId.eq(collection_id))
            .order_by_asc(contents::Column::Id)
            .all(&self.db)
            .await
            .map_err(AppError::from)
    }

    pub async fn list_all_contents(&self) -> AppResult<Vec<contents::Model>> {
        contents::Entity::find()
            .order_by_desc(contents::Column::Id)
            .all(&self.db)
            .await
            .map_err(AppError::from)
    }

    pub async fn create(
        &self,
        collection_id: i64,
        slug: String,
        title: String,
        status: String,
        schema_id: Option<String>,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let model = contents::ActiveModel {
            collection_id: Set(collection_id),
            slug: Set(slug),
            title: Set(title),
            status: Set(status),
            schema_id: Set(schema_id),
            draft_snapshot_key: Set(None),
            latest_snapshot_key: Set(None),
            latest_version: Set(0),
            created_by: Set(actor.to_owned()),
            updated_by: Set(actor.to_owned()),
            ..Default::default()
        };

        model.insert(&self.db).await.map_err(AppError::from)
    }

    pub async fn get(&self, content_id: i64) -> AppResult<contents::Model> {
        contents::Entity::find_by_id(content_id)
            .one(&self.db)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("content {content_id}")))
    }

    pub async fn update(
        &self,
        content: contents::Model,
        title: Option<String>,
        status: Option<String>,
        schema_id: Option<Option<String>>,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let mut active: contents::ActiveModel = content.into();
        if let Some(value) = title {
            active.title = Set(value);
        }
        if let Some(value) = status {
            active.status = Set(value);
        }
        if let Some(value) = schema_id {
            active.schema_id = Set(value);
        }
        active.updated_by = Set(actor.to_owned());
        active.updated_at = Set(chrono::Utc::now());
        active.update(&self.db).await.map_err(AppError::from)
    }

    pub async fn set_draft_snapshot_key(
        &self,
        content: contents::Model,
        key: String,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let mut active: contents::ActiveModel = content.into();
        active.draft_snapshot_key = Set(Some(key));
        active.updated_by = Set(actor.to_owned());
        active.updated_at = Set(chrono::Utc::now());
        active.update(&self.db).await.map_err(AppError::from)
    }

    pub async fn set_latest_snapshot_key(
        &self,
        content: contents::Model,
        key: String,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let mut active: contents::ActiveModel = content.into();
        active.latest_snapshot_key = Set(Some(key));
        active.updated_by = Set(actor.to_owned());
        active.updated_at = Set(chrono::Utc::now());
        active.update(&self.db).await.map_err(AppError::from)
    }

    pub async fn set_latest_version(
        &self,
        content: contents::Model,
        version: i32,
        actor: &str,
    ) -> AppResult<contents::Model> {
        let mut active: contents::ActiveModel = content.into();
        active.latest_version = Set(version);
        active.updated_by = Set(actor.to_owned());
        active.updated_at = Set(chrono::Utc::now());
        active.update(&self.db).await.map_err(AppError::from)
    }

    pub async fn next_version(&self, content: &contents::Model) -> AppResult<i32> {
        let latest = content_versions::Entity::find()
            .filter(content_versions::Column::ContentId.eq(content.id))
            .order_by_desc(content_versions::Column::Version)
            .one(&self.db)
            .await?;

        Ok(latest
            .map(|item| item.version + 1)
            .unwrap_or(content.latest_version + 1))
    }

    pub async fn list_versions(&self, content_id: i64) -> AppResult<Vec<content_versions::Model>> {
        content_versions::Entity::find()
            .filter(content_versions::Column::ContentId.eq(content_id))
            .order_by_asc(content_versions::Column::Version)
            .all(&self.db)
            .await
            .map_err(AppError::from)
    }

    pub async fn version_exists(&self, content_id: i64, version: i32) -> AppResult<bool> {
        content_versions::Entity::find()
            .filter(content_versions::Column::ContentId.eq(content_id))
            .filter(content_versions::Column::Version.eq(version))
            .count(&self.db)
            .await
            .map(|count| count > 0)
            .map_err(AppError::from)
    }

    pub async fn get_version(
        &self,
        content_id: i64,
        version: i32,
    ) -> AppResult<content_versions::Model> {
        content_versions::Entity::find()
            .filter(content_versions::Column::ContentId.eq(content_id))
            .filter(content_versions::Column::Version.eq(version))
            .one(&self.db)
            .await?
            .ok_or_else(|| AppError::NotFound(format!("content version {content_id}:{version}")))
    }

    pub fn db(&self) -> &DatabaseConnection {
        &self.db
    }
}
