use crate::crud::single_table_crud_router;
use crate::persistence::{
    CollectionActiveModel, CollectionEntity, FileActiveModel, FileEntity, HistoryActiveModel,
    HistoryEntity, NodeActiveModel, NodeEntity, SnippetActiveModel, SnippetEntity, TagActiveModel,
    TagEntity, TextActiveModel, TextEntity,
};
use axum::{Json, Router, routing::get};
use common_http_server_rs::{AppBuilder, AppConfig, Server, ServerConfig};
use migration::{Migrator, MigratorTrait};
use sea_orm::{Database, DatabaseConnection};
use serde::Serialize;
use std::sync::Arc;

#[derive(Debug, Serialize)]
struct PingResponse {
    success: bool,
    message: &'static str,
}

async fn ping() -> Json<PingResponse> {
    Json(PingResponse {
        success: true,
        message: "pong",
    })
}

macro_rules! mount_crud_resources {
    ($app_builder:expr, $db:expr, [$(($path:literal, $resource:literal, $entity:ty, $active_model:ty)),+ $(,)?]) => {{
        let app_builder = $app_builder;
        $(
            let app_builder = app_builder.nest(
                $path,
                single_table_crud_router::<$entity, $active_model>($db.clone(), $resource),
            );
        )+
        app_builder
    }};
}

fn build_server(db: Arc<DatabaseConnection>) -> Server {
    let app_config = AppConfig::new()
        .with_logging(true)
        .with_tracing(true)
        .with_cors(true);

    let api_v1_router = mount_crud_resources!(
        Router::new(),
        db,
        [
            (
                "/collections",
                "collection",
                CollectionEntity,
                CollectionActiveModel
            ),
            ("/files", "file", FileEntity, FileActiveModel),
            ("/histories", "history", HistoryEntity, HistoryActiveModel),
            ("/nodes", "node", NodeEntity, NodeActiveModel),
            ("/snippets", "snippet", SnippetEntity, SnippetActiveModel),
            ("/tags", "tag", TagEntity, TagActiveModel),
            ("/texts", "text", TextEntity, TextActiveModel),
        ]
    );
    let app_builder = AppBuilder::new(app_config)
        .route("/ping", get(ping))
        .nest("/api/v1", api_v1_router);

    let server_config = ServerConfig::new(3000).with_host("127.0.0.1");

    Server::new(server_config, app_builder)
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://snippets.db?mode=rwc".to_string());

    let migration_db = migration::sea_orm::Database::connect(&database_url).await?;
    Migrator::up(&migration_db, None).await?;

    let db = Database::connect(&database_url).await?;

    build_server(Arc::new(db)).start().await
}
