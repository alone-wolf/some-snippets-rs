use crate::handler::{api_v1_router, health_handler::ping};
use axum::routing::get;
use common_http_server_rs::{AppBuilder, AppConfig, Server, ServerConfig};
use migration::{Migrator, MigratorTrait};
use sea_orm::{Database, DatabaseConnection};
use std::{io, path::PathBuf, sync::Arc};

fn build_server(db: Arc<DatabaseConnection>, file_storage_dir: Arc<PathBuf>) -> Server {
    let app_config = AppConfig::new()
        .with_logging(true)
        .with_tracing(true)
        .with_cors(true);

    let app_builder = AppBuilder::new(app_config)
        .route("/ping", get(ping))
        .nest("/api/v1", api_v1_router(db, file_storage_dir));

    let server_config = ServerConfig::new(3000).with_host("127.0.0.1");

    Server::new(server_config, app_builder)
}

fn sanitize_sqlite_url(database_url: String) -> String {
    let is_sqlite = database_url.starts_with("sqlite://") || database_url.starts_with("sqlite:");
    if !is_sqlite {
        return database_url;
    }

    let mut parts = database_url.splitn(2, '?');
    let base = parts.next().unwrap_or_default();
    let Some(query) = parts.next() else {
        return database_url;
    };

    let filtered: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let key = pair.split('=').next().unwrap_or_default();
            !key.eq_ignore_ascii_case("foreign_keys")
        })
        .collect();

    if filtered.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", filtered.join("&"))
    }
}

fn init_file_storage_dir() -> Result<Arc<PathBuf>, io::Error> {
    let configured = std::env::var("FILE_STORAGE_DIR").unwrap_or_else(|_| "uploads".to_string());
    let path = PathBuf::from(configured);

    if path.exists() {
        if !path.is_dir() {
            return Err(io::Error::other(format!(
                "FILE_STORAGE_DIR is not a directory: {}",
                path.display()
            )));
        }
    } else {
        std::fs::create_dir_all(&path).map_err(|error| {
            io::Error::other(format!(
                "failed to create FILE_STORAGE_DIR {}: {error}",
                path.display()
            ))
        })?;
    }

    match path.canonicalize() {
        Ok(resolved) => Ok(Arc::new(resolved)),
        Err(_) => Ok(Arc::new(path)),
    }
}

pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let file_storage_dir = init_file_storage_dir()?;

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite://snippets.db?mode=rwc".to_string());
    let database_url = sanitize_sqlite_url(database_url);

    let migration_db = migration::sea_orm::Database::connect(&database_url).await?;
    Migrator::up(&migration_db, None).await?;

    let db = Database::connect(&database_url).await?;

    build_server(Arc::new(db), file_storage_dir).start().await
}
