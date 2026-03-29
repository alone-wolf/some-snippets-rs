pub mod state;

use std::path::Path;

use axum::Router;
use sea_orm::Database;
use some_snippets_migration::MigratorTrait;
use tokio::fs;
use tower_http::trace::TraceLayer;

use crate::{config::AppConfig, storage::object_store::local::LocalObjectStore, web};

use self::state::AppState;

pub fn init_tracing(config: &AppConfig) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(config.server.log_filter.clone()));

    tracing_subscriber::fmt().with_env_filter(filter).init();
}

pub async fn build_state(config: AppConfig) -> crate::error::AppResult<AppState> {
    ensure_database_parent_dir(&config.database.url).await?;
    let db = Database::connect(&config.database.url).await?;

    if config.database.auto_migrate {
        some_snippets_migration::Migrator::up(&db, None).await?;
    }

    let object_store = LocalObjectStore::new(
        config.object_store.root_dir.clone(),
        config.object_store.default_bucket.clone(),
    )
    .await?;

    Ok(AppState::new(config, db, object_store))
}

pub fn build_router(state: AppState) -> Router {
    web::router::build_router()
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

async fn ensure_database_parent_dir(database_url: &str) -> crate::error::AppResult<()> {
    let Some(path) = sqlite_file_path(database_url) else {
        return Ok(());
    };

    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent).await?;
    }

    Ok(())
}

fn sqlite_file_path(database_url: &str) -> Option<&Path> {
    if !database_url.starts_with("sqlite://") {
        return None;
    }

    let raw = database_url
        .trim_start_matches("sqlite://")
        .split('?')
        .next()
        .unwrap_or_default();

    if raw.is_empty() || raw == ":memory:" {
        return None;
    }

    Some(Path::new(raw))
}
