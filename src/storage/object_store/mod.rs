pub mod local;

use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use serde::{Serialize, de::DeserializeOwned};

use crate::error::{AppError, AppResult};

#[async_trait]
pub trait ObjectStore: Send + Sync {
    async fn put_bytes(&self, bucket: &str, key: &str, bytes: Vec<u8>) -> AppResult<()>;
    async fn get_bytes(&self, bucket: &str, key: &str) -> AppResult<Vec<u8>>;

    fn default_bucket(&self) -> &str;
    fn root_dir(&self) -> PathBuf;
}

pub type DynObjectStore = Arc<dyn ObjectStore>;

pub async fn put_json<T>(
    store: &(dyn ObjectStore + Send + Sync),
    bucket: &str,
    key: &str,
    value: &T,
) -> AppResult<()>
where
    T: Serialize + Send + Sync,
{
    let payload = serde_json::to_vec_pretty(value)?;
    store.put_bytes(bucket, key, payload).await
}

pub async fn get_json<T>(
    store: &(dyn ObjectStore + Send + Sync),
    bucket: &str,
    key: &str,
) -> AppResult<T>
where
    T: DeserializeOwned + Send,
{
    let bytes = store.get_bytes(bucket, key).await?;
    serde_json::from_slice(&bytes).map_err(AppError::from)
}
