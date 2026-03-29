use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use tokio::fs;

use crate::{
    error::{AppError, AppResult},
    storage::object_store::{DynObjectStore, ObjectStore},
};

#[derive(Debug, Clone)]
pub struct LocalObjectStore {
    root_dir: PathBuf,
    default_bucket: String,
}

impl LocalObjectStore {
    pub async fn new(root_dir: PathBuf, default_bucket: String) -> AppResult<DynObjectStore> {
        fs::create_dir_all(root_dir.join(&default_bucket))
            .await
            .map_err(AppError::storage)?;

        Ok(Arc::new(Self {
            root_dir,
            default_bucket,
        }))
    }

    fn object_path(&self, bucket: &str, key: &str) -> PathBuf {
        self.root_dir.join(bucket).join(key)
    }
}

#[async_trait]
impl ObjectStore for LocalObjectStore {
    async fn put_bytes(&self, bucket: &str, key: &str, bytes: Vec<u8>) -> AppResult<()> {
        let path = self.object_path(bucket, key);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(AppError::storage)?;
        }

        fs::write(path, bytes).await.map_err(AppError::storage)
    }

    async fn get_bytes(&self, bucket: &str, key: &str) -> AppResult<Vec<u8>> {
        fs::read(self.object_path(bucket, key))
            .await
            .map_err(AppError::storage)
    }

    fn default_bucket(&self) -> &str {
        &self.default_bucket
    }

    fn root_dir(&self) -> PathBuf {
        self.root_dir.clone()
    }
}
