use crate::entity::{CollectionActiveModel, CollectionEntity};
use crate::repository::collection_repository::CollectionRepository;
use crate::repository::resource_repository::ResourceRepository;
use crate::service::common::{
    merge_payload_with_existing, payload_as_object_mut, resolve_pagination,
};
use crate::service::error::{ServiceError, map_db_error};
use chrono::Utc;
use sea_orm::{DatabaseConnection, TransactionTrait};
use serde_json::Value;
use std::sync::Arc;

fn collection_not_found(key: &str) -> ServiceError {
    ServiceError::not_found(format!("collection with key={key} was not found"))
}

fn sanitize_collection_payload(payload: &mut Value, is_update: bool) -> Result<(), ServiceError> {
    let object = payload_as_object_mut(payload)?;
    object.remove("id");
    object.remove("created_at");
    object.remove("updated_at");

    if !is_update && !object.contains_key("label") {
        return Err(ServiceError::bad_request("missing required field `label`"));
    }
    if !is_update && !object.contains_key("key") {
        return Err(ServiceError::bad_request("missing required field `key`"));
    }

    for required in ["label", "key"] {
        if let Some(value) = object.get(required) {
            let Some(text) = value.as_str() else {
                return Err(ServiceError::bad_request(format!(
                    "field `{required}` must be a non-empty string"
                )));
            };
            let trimmed = text.trim();
            if trimmed.is_empty() {
                return Err(ServiceError::bad_request(format!(
                    "field `{required}` must be a non-empty string"
                )));
            }
            object.insert(required.to_string(), Value::String(trimmed.to_string()));
        }
    }

    if let Some(description) = object.get("description")
        && !description.is_null()
        && !description.is_string()
    {
        return Err(ServiceError::bad_request(
            "field `description` must be a string or null",
        ));
    }

    let now = Utc::now().to_rfc3339();
    if !is_update {
        object.insert("created_at".to_string(), Value::String(now.clone()));
    }
    object.insert("updated_at".to_string(), Value::String(now));
    Ok(())
}

fn validate_collection_payload(payload: &Value) -> Result<(), ServiceError> {
    let Some(object) = payload.as_object() else {
        return Err(ServiceError::bad_request(
            "request payload must be a JSON object",
        ));
    };

    for required in ["label", "key"] {
        let Some(value) = object.get(required) else {
            return Err(ServiceError::bad_request(format!(
                "missing required field `{required}`"
            )));
        };
        let Some(text) = value.as_str() else {
            return Err(ServiceError::bad_request(format!(
                "field `{required}` must be a non-empty string"
            )));
        };
        if text.trim().is_empty() {
            return Err(ServiceError::bad_request(format!(
                "field `{required}` must be a non-empty string"
            )));
        }
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct CollectionService {
    db: Arc<DatabaseConnection>,
}

impl CollectionService {
    pub(crate) fn new(db: Arc<DatabaseConnection>) -> Self {
        Self { db }
    }

    pub(crate) async fn list(
        &self,
        page: Option<u64>,
        page_size: Option<u64>,
    ) -> Result<Value, ServiceError> {
        let (page, page_size, offset) = resolve_pagination(page, page_size)?;

        let records = ResourceRepository::list_records::<CollectionEntity, _>(
            self.db.as_ref(),
            page_size,
            offset,
        )
        .await
        .map_err(map_db_error)?;

        Ok(serde_json::json!({
            "items": records,
            "page": page,
            "page_size": page_size,
        }))
    }

    pub(crate) async fn create(&self, mut payload: Value) -> Result<Value, ServiceError> {
        let txn = self.db.begin().await.map_err(map_db_error)?;
        sanitize_collection_payload(&mut payload, false)?;
        validate_collection_payload(&payload)?;

        let created = ResourceRepository::insert_from_json_and_reload::<
            CollectionEntity,
            CollectionActiveModel,
            _,
        >(&txn, payload)
        .await
        .map_err(map_db_error)?
        .ok_or_else(|| ServiceError::internal("failed to reload newly created collection"))?;

        txn.commit().await.map_err(map_db_error)?;
        Ok(created)
    }

    pub(crate) async fn get(&self, key: &str) -> Result<Value, ServiceError> {
        let record = CollectionRepository::find_json_by_key(self.db.as_ref(), key)
            .await
            .map_err(map_db_error)?;

        record.ok_or_else(|| collection_not_found(key))
    }

    pub(crate) async fn update(
        &self,
        key: &str,
        mut payload: Value,
    ) -> Result<Value, ServiceError> {
        let txn = self.db.begin().await.map_err(map_db_error)?;
        let existing = CollectionRepository::find_model_by_key(&txn, key)
            .await
            .map_err(map_db_error)?;

        let Some(existing) = existing else {
            return Err(collection_not_found(key));
        };

        sanitize_collection_payload(&mut payload, true)?;
        let existing_payload = serde_json::to_value(&existing).map_err(|error| {
            ServiceError::internal(format!("failed to serialize existing collection: {error}"))
        })?;
        let merged_payload = merge_payload_with_existing(
            existing_payload,
            &payload,
            "failed to serialize existing collection as JSON object",
        )?;
        validate_collection_payload(&merged_payload)?;

        ResourceRepository::update_from_json::<CollectionEntity, CollectionActiveModel, _>(
            &txn, existing, payload,
        )
        .await
        .map_err(map_db_error)?;

        let updated_key = merged_payload
            .get("key")
            .and_then(|value| value.as_str())
            .unwrap_or(key)
            .to_string();

        let updated = CollectionRepository::find_json_by_key(&txn, &updated_key)
            .await
            .map_err(map_db_error)?
            .ok_or_else(|| collection_not_found(&updated_key))?;

        txn.commit().await.map_err(map_db_error)?;
        Ok(updated)
    }

    pub(crate) async fn delete(&self, key: &str) -> Result<(), ServiceError> {
        let txn = self.db.begin().await.map_err(map_db_error)?;
        let existing = CollectionRepository::find_model_by_key(&txn, key)
            .await
            .map_err(map_db_error)?;
        let Some(existing) = existing else {
            return Err(collection_not_found(key));
        };

        let rows_affected =
            ResourceRepository::delete_by_id::<CollectionEntity, _>(&txn, existing.id)
                .await
                .map_err(map_db_error)?;
        if rows_affected == 0 {
            return Err(collection_not_found(key));
        }

        txn.commit().await.map_err(map_db_error)?;
        Ok(())
    }
}
