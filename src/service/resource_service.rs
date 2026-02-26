use crate::entity::{CollectionEntity, FileEntity, HistoryEntity, SnippetEntity, TextEntity};
use crate::repository::resource_repository::ResourceRepository;
use crate::service::error::{ServiceError, map_db_error};
use chrono::Utc;
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, ConnectionTrait, DatabaseConnection, EntityTrait,
    IntoActiveModel, Iterable, PrimaryKeyToColumn, PrimaryKeyTrait, TransactionTrait, TryIntoModel,
};
use serde_json::Value;
use std::{marker::PhantomData, sync::Arc};

#[derive(Clone, Copy)]
pub(crate) enum TimestampPolicy {
    CreatedOnly,
    CreatedAndUpdated,
}

#[derive(Clone, Copy)]
pub(crate) enum ReferencePolicy {
    None,
    Snippet,
    History,
    Node,
}

impl TimestampPolicy {
    fn has_created_at(self) -> bool {
        matches!(self, Self::CreatedOnly | Self::CreatedAndUpdated)
    }

    fn has_updated_at(self) -> bool {
        matches!(self, Self::CreatedAndUpdated)
    }
}

fn resource_not_found(resource_name: &'static str, id: i32) -> ServiceError {
    ServiceError::not_found(format!("{resource_name} with id={id} was not found"))
}

fn strip_id_key(payload: &mut Value) {
    if let Some(object) = payload.as_object_mut() {
        object.remove("id");
    }
}

fn apply_server_timestamps(payload: &mut Value, policy: TimestampPolicy, is_update: bool) {
    if let Some(object) = payload.as_object_mut() {
        object.remove("created_at");
        object.remove("updated_at");

        let now = Utc::now().to_rfc3339();
        if policy.has_created_at() && !is_update {
            object.insert("created_at".to_string(), Value::String(now.clone()));
        }
        if policy.has_updated_at() {
            object.insert("updated_at".to_string(), Value::String(now));
        }
    }
}

fn parse_i32_field(
    payload: &Value,
    field_name: &'static str,
    required: bool,
) -> Result<Option<i32>, ServiceError> {
    let Some(object) = payload.as_object() else {
        return Err(ServiceError::bad_request(
            "request payload must be a JSON object",
        ));
    };

    let value = object.get(field_name);
    if value.is_none() {
        if required {
            return Err(ServiceError::bad_request(format!(
                "missing required field `{field_name}`"
            )));
        }
        return Ok(None);
    }

    match value {
        Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => {
            let raw = number.as_i64().ok_or_else(|| {
                ServiceError::bad_request(format!("field `{field_name}` must be a valid integer"))
            })?;
            let id = i32::try_from(raw).map_err(|_| {
                ServiceError::bad_request(format!("field `{field_name}` is out of i32 range"))
            })?;
            Ok(Some(id))
        }
        Some(_) => Err(ServiceError::bad_request(format!(
            "field `{field_name}` must be an integer or null"
        ))),
        None => Ok(None),
    }
}

fn parse_optional_string_field(
    payload: &Value,
    field_name: &'static str,
) -> Result<Option<String>, ServiceError> {
    let Some(object) = payload.as_object() else {
        return Err(ServiceError::bad_request(
            "request payload must be a JSON object",
        ));
    };

    match object.get(field_name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(ServiceError::bad_request(format!(
            "field `{field_name}` must be a string"
        ))),
    }
}

async fn ensure_reference_exists<E, C>(
    db: &C,
    id: i32,
    field_name: &'static str,
) -> Result<(), ServiceError>
where
    E: EntityTrait,
    C: ConnectionTrait,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    let exists = ResourceRepository::find_model_by_id::<E, _>(db, id)
        .await
        .map_err(map_db_error)?
        .is_some();

    if !exists {
        return Err(ServiceError::bad_request(format!(
            "invalid `{field_name}`: referenced record {id} not found"
        )));
    }

    Ok(())
}

async fn validate_references(
    db: &impl ConnectionTrait,
    payload: &Value,
    reference_policy: ReferencePolicy,
) -> Result<(), ServiceError> {
    match reference_policy {
        ReferencePolicy::None => Ok(()),
        ReferencePolicy::Snippet => {
            let connection_id = parse_i32_field(payload, "connection_id", true)?;
            if let Some(connection_id) = connection_id {
                ensure_reference_exists::<CollectionEntity, _>(db, connection_id, "connection_id")
                    .await?;
            }

            let current_history_id = parse_i32_field(payload, "current_history_id", false)?;
            if let Some(current_history_id) = current_history_id {
                ensure_reference_exists::<HistoryEntity, _>(
                    db,
                    current_history_id,
                    "current_history_id",
                )
                .await?;
            }

            Ok(())
        }
        ReferencePolicy::History => {
            let snippet_id = parse_i32_field(payload, "snippet_id", true)?;
            if let Some(snippet_id) = snippet_id {
                ensure_reference_exists::<SnippetEntity, _>(db, snippet_id, "snippet_id").await?;
            }

            Ok(())
        }
        ReferencePolicy::Node => {
            let snippet_id = parse_i32_field(payload, "snippet_id", true)?;
            if let Some(snippet_id) = snippet_id {
                ensure_reference_exists::<SnippetEntity, _>(db, snippet_id, "snippet_id").await?;
            }

            let text_id = parse_i32_field(payload, "text_id", false)?;
            if let Some(text_id) = text_id {
                ensure_reference_exists::<TextEntity, _>(db, text_id, "text_id").await?;
            }

            let file_id = parse_i32_field(payload, "file_id", false)?;
            if let Some(file_id) = file_id {
                ensure_reference_exists::<FileEntity, _>(db, file_id, "file_id").await?;
            }

            let kind = parse_optional_string_field(payload, "kind")?
                .ok_or_else(|| ServiceError::bad_request("missing required field `kind`"))?;
            validate_node_kind(kind.as_str(), text_id, file_id)?;

            Ok(())
        }
    }
}

fn validate_node_kind(
    kind: &str,
    text_id: Option<i32>,
    file_id: Option<i32>,
) -> Result<(), ServiceError> {
    match kind {
        "text" => {
            if file_id.is_some() {
                return Err(ServiceError::bad_request(
                    "`kind=text` cannot be combined with `file_id`",
                ));
            }
            if text_id.is_none() {
                return Err(ServiceError::bad_request(
                    "`kind=text` requires a non-null `text_id`",
                ));
            }
            Ok(())
        }
        "file" => {
            if text_id.is_some() {
                return Err(ServiceError::bad_request(
                    "`kind=file` cannot be combined with `text_id`",
                ));
            }
            if file_id.is_none() {
                return Err(ServiceError::bad_request(
                    "`kind=file` requires a non-null `file_id`",
                ));
            }
            Ok(())
        }
        _ => Err(ServiceError::bad_request(
            "field `kind` must be either `text` or `file`",
        )),
    }
}

fn merge_payload_with_existing(
    mut existing_payload: Value,
    update_payload: &Value,
) -> Result<Value, ServiceError> {
    let Some(existing_object) = existing_payload.as_object_mut() else {
        return Err(ServiceError::internal(
            "failed to serialize existing record as JSON object",
        ));
    };

    let Some(update_object) = update_payload.as_object() else {
        return Err(ServiceError::bad_request(
            "request payload must be a JSON object",
        ));
    };

    for (key, value) in update_object {
        existing_object.insert(key.clone(), value.clone());
    }

    Ok(existing_payload)
}

#[derive(Clone)]
pub(crate) struct ResourceService<E, A> {
    db: Arc<DatabaseConnection>,
    resource_name: &'static str,
    timestamp_policy: TimestampPolicy,
    reference_policy: ReferencePolicy,
    _marker: PhantomData<fn() -> (E, A)>,
}

impl<E, A> ResourceService<E, A> {
    pub(crate) fn new(
        db: Arc<DatabaseConnection>,
        resource_name: &'static str,
        timestamp_policy: TimestampPolicy,
        reference_policy: ReferencePolicy,
    ) -> Self {
        Self {
            db,
            resource_name,
            timestamp_policy,
            reference_policy,
            _marker: PhantomData,
        }
    }
}

impl<E, A> ResourceService<E, A>
where
    E: EntityTrait + Send + Sync + 'static,
    A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send + 'static,
    E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    E::PrimaryKey: Iterable + PrimaryKeyToColumn<Column = E::Column>,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    pub(crate) async fn list(
        &self,
        page: Option<u64>,
        page_size: Option<u64>,
    ) -> Result<Value, ServiceError> {
        let page_size = page_size.unwrap_or(20).clamp(1, 200);
        let page = page.unwrap_or(1).max(1);
        let offset = (page - 1).checked_mul(page_size).ok_or_else(|| {
            ServiceError::bad_request("page and page_size combination is too large")
        })?;

        let records = ResourceRepository::list_records::<E, _>(self.db.as_ref(), page_size, offset)
            .await
            .map_err(map_db_error)?;

        Ok(serde_json::json!({
            "items": records,
            "page": page,
            "page_size": page_size,
        }))
    }

    pub(crate) async fn get(&self, id: i32) -> Result<Value, ServiceError> {
        let record = ResourceRepository::find_json_by_id::<E, _>(self.db.as_ref(), id)
            .await
            .map_err(map_db_error)?;

        record.ok_or_else(|| resource_not_found(self.resource_name, id))
    }

    pub(crate) async fn create(&self, mut payload: Value) -> Result<Value, ServiceError> {
        let txn = self.db.begin().await.map_err(map_db_error)?;

        strip_id_key(&mut payload);
        apply_server_timestamps(&mut payload, self.timestamp_policy, false);
        validate_references(&txn, &payload, self.reference_policy).await?;

        let created = ResourceRepository::insert_from_json_and_reload::<E, A, _>(&txn, payload)
            .await
            .map_err(map_db_error)?;

        let Some(created) = created else {
            return Err(ServiceError::internal(format!(
                "failed to reload newly created {}",
                self.resource_name
            )));
        };

        txn.commit().await.map_err(map_db_error)?;

        Ok(created)
    }

    pub(crate) async fn update(&self, id: i32, mut payload: Value) -> Result<Value, ServiceError> {
        let txn = self.db.begin().await.map_err(map_db_error)?;

        let existing = ResourceRepository::find_model_by_id::<E, _>(&txn, id)
            .await
            .map_err(map_db_error)?;

        let Some(existing) = existing else {
            return Err(resource_not_found(self.resource_name, id));
        };

        let existing_payload = serde_json::to_value(&existing).map_err(|error| {
            ServiceError::internal(format!("failed to serialize existing record: {error}"))
        })?;

        strip_id_key(&mut payload);
        apply_server_timestamps(&mut payload, self.timestamp_policy, true);

        let merged_payload = merge_payload_with_existing(existing_payload, &payload)?;
        validate_references(&txn, &merged_payload, self.reference_policy).await?;

        ResourceRepository::update_from_json::<E, A, _>(&txn, existing, payload)
            .await
            .map_err(map_db_error)?;

        let updated = ResourceRepository::find_json_by_id::<E, _>(&txn, id)
            .await
            .map_err(map_db_error)?;

        let Some(updated) = updated else {
            return Err(resource_not_found(self.resource_name, id));
        };

        txn.commit().await.map_err(map_db_error)?;
        Ok(updated)
    }

    pub(crate) async fn delete(&self, id: i32) -> Result<(), ServiceError> {
        let txn = self.db.begin().await.map_err(map_db_error)?;

        let existing = ResourceRepository::find_model_by_id::<E, _>(&txn, id)
            .await
            .map_err(map_db_error)?;
        if existing.is_none() {
            return Err(resource_not_found(self.resource_name, id));
        }

        let rows_affected = ResourceRepository::delete_by_id::<E, _>(&txn, id)
            .await
            .map_err(map_db_error)?;
        if rows_affected == 0 {
            return Err(resource_not_found(self.resource_name, id));
        }

        txn.commit().await.map_err(map_db_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::validate_node_kind;
    use crate::service::error::ServiceErrorKind;

    #[test]
    fn validates_text_kind_requires_text_id() {
        let error =
            validate_node_kind("text", None, None).expect_err("text kind must require text_id");
        assert_eq!(error.kind(), ServiceErrorKind::BadRequest);
    }

    #[test]
    fn validates_file_kind_requires_file_id() {
        let error =
            validate_node_kind("file", None, None).expect_err("file kind must require file_id");
        assert_eq!(error.kind(), ServiceErrorKind::BadRequest);
    }

    #[test]
    fn validates_kind_and_reference_match() {
        let error =
            validate_node_kind("file", Some(1), None).expect_err("file kind cannot point to text");
        assert_eq!(error.kind(), ServiceErrorKind::BadRequest);
    }

    #[test]
    fn accepts_valid_kind_payloads() {
        validate_node_kind("text", Some(1), None).expect("text payload should be valid");
        validate_node_kind("file", None, Some(1)).expect("file payload should be valid");
    }
}
