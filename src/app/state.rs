use std::sync::Arc;

use axum::extract::FromRef;
use sea_orm::DatabaseConnection;

use crate::{config::AppConfig, storage::object_store::ObjectStore};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: DatabaseConnection,
    pub object_store: Arc<dyn ObjectStore>,
}

impl AppState {
    pub fn new(
        config: AppConfig,
        db: DatabaseConnection,
        object_store: Arc<dyn ObjectStore>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            db,
            object_store,
        }
    }
}

impl FromRef<AppState> for Arc<AppConfig> {
    fn from_ref(input: &AppState) -> Self {
        Arc::clone(&input.config)
    }
}

impl FromRef<AppState> for DatabaseConnection {
    fn from_ref(input: &AppState) -> Self {
        input.db.clone()
    }
}

impl FromRef<AppState> for Arc<dyn ObjectStore> {
    fn from_ref(input: &AppState) -> Self {
        Arc::clone(&input.object_store)
    }
}
