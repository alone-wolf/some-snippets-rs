use std::sync::Arc;

use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, Set};
use some_snippets::{
    modules::{
        content::service::{ContentService, CreateContentInput},
        node::service::NodeService,
    },
    storage::{
        db::entities::collections,
        object_store::{ObjectStore, local::LocalObjectStore},
    },
};
use some_snippets_migration::MigratorTrait;
use tempfile::TempDir;

pub struct TestContext {
    pub _tempdir: TempDir,
    pub _db: DatabaseConnection,
    pub _object_store: Arc<dyn ObjectStore>,
    pub content_service: ContentService,
    pub node_service: NodeService,
    pub collection_id: i64,
}

impl TestContext {
    pub async fn create_content(
        &self,
        slug: &str,
        title: &str,
    ) -> Result<some_snippets::storage::db::entities::contents::Model, Box<dyn std::error::Error>>
    {
        self.content_service
            .create_content(
                CreateContentInput {
                    collection_id: self.collection_id,
                    slug: slug.to_owned(),
                    title: title.to_owned(),
                    status: "draft".to_owned(),
                    schema_id: None,
                },
                "tester",
            )
            .await
            .map_err(Into::into)
    }
}

pub async fn setup() -> Result<TestContext, Box<dyn std::error::Error>> {
    let tempdir = tempfile::tempdir()?;
    let db_path = tempdir.path().join("app.db");
    let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
    let db = Database::connect(&db_url).await?;
    some_snippets_migration::Migrator::up(&db, None).await?;

    let object_store = LocalObjectStore::new(
        tempdir.path().join("object-store"),
        "content-assets".to_owned(),
    )
    .await?;

    let collection = collections::ActiveModel {
        slug: Set("test-collection".to_owned()),
        name: Set("Test Collection".to_owned()),
        description: Set(Some("integration fixture".to_owned())),
        visibility: Set("private".to_owned()),
        owner_id: Set("tester".to_owned()),
        config_json: Set(None),
        ..Default::default()
    }
    .insert(&db)
    .await?;

    Ok(TestContext {
        content_service: ContentService::new(db.clone(), Arc::clone(&object_store)),
        node_service: NodeService::new(db.clone(), Arc::clone(&object_store)),
        collection_id: collection.id,
        _db: db,
        _object_store: object_store,
        _tempdir: tempdir,
    })
}
