use crate::service::error::ServiceError;
use serde_json::{Map, Value};

pub(crate) fn payload_as_object_mut(
    payload: &mut Value,
) -> Result<&mut Map<String, Value>, ServiceError> {
    payload
        .as_object_mut()
        .ok_or_else(|| ServiceError::bad_request("request payload must be a JSON object"))
}

pub(crate) fn payload_as_object(payload: &Value) -> Result<&Map<String, Value>, ServiceError> {
    payload
        .as_object()
        .ok_or_else(|| ServiceError::bad_request("request payload must be a JSON object"))
}

pub(crate) fn merge_payload_with_existing(
    mut existing_payload: Value,
    update_payload: &Value,
    internal_error_message: &'static str,
) -> Result<Value, ServiceError> {
    let existing_object = existing_payload
        .as_object_mut()
        .ok_or_else(|| ServiceError::internal(internal_error_message))?;
    let update_object = payload_as_object(update_payload)?;

    for (key, value) in update_object {
        existing_object.insert(key.clone(), value.clone());
    }

    Ok(existing_payload)
}

pub(crate) fn resolve_pagination(
    page: Option<u64>,
    page_size: Option<u64>,
) -> Result<(u64, u64, u64), ServiceError> {
    let page_size = page_size.unwrap_or(20).clamp(1, 200);
    let page = page.unwrap_or(1).max(1);
    let offset = (page - 1)
        .checked_mul(page_size)
        .ok_or_else(|| ServiceError::bad_request("page and page_size combination is too large"))?;
    Ok((page, page_size, offset))
}
