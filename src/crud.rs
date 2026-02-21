use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use common_http_server_rs::ApiResponse;
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, IntoActiveModel,
    PrimaryKeyTrait, QuerySelect, TryIntoModel,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct ListQuery {
    page: Option<u64>,
    page_size: Option<u64>,
}

#[derive(Debug)]
struct ApiHttpError {
    status: StatusCode,
    message: String,
}

impl ApiHttpError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn not_found(resource_name: &'static str, id: i32) -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            format!("{resource_name} with id={id} was not found"),
        )
    }
}

impl IntoResponse for ApiHttpError {
    fn into_response(self) -> Response {
        ApiResponse::<Value>::error_with_status(self.message, self.status).into_response()
    }
}

fn map_db_error(error: DbErr) -> ApiHttpError {
    match error {
        DbErr::RecordNotFound(message) => ApiHttpError::new(StatusCode::NOT_FOUND, message),
        DbErr::Json(message) | DbErr::Type(message) => {
            ApiHttpError::new(StatusCode::BAD_REQUEST, message)
        }
        other => ApiHttpError::new(StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
    }
}

fn success_response<T: Serialize>(status: StatusCode, data: T) -> Response {
    ApiResponse {
        success: true,
        data: Some(data),
        error: None,
        request_id: None,
        status_code: Some(status.as_u16()),
    }
    .into_response()
}

fn strip_id_key(payload: &mut Value) {
    if let Some(object) = payload.as_object_mut() {
        object.remove("id");
    }
}

pub(crate) fn single_table_crud_router<E, A>(
    db: Arc<DatabaseConnection>,
    resource_name: &'static str,
) -> Router
where
    E: EntityTrait + Send + Sync + 'static,
    A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send + 'static,
    E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    let list_db = db.clone();
    let create_db = db.clone();
    let get_db = db.clone();
    let update_db = db.clone();
    let delete_db = db;

    Router::new()
        .route(
            "/",
            get(move |query: Query<ListQuery>| {
                list_records::<E>(list_db.clone(), resource_name, query)
            })
            .post(move |Json(payload): Json<Value>| {
                create_record::<E, A>(create_db.clone(), resource_name, payload)
            }),
        )
        .route(
            "/:id",
            get(move |Path(id): Path<i32>| get_record::<E>(get_db.clone(), resource_name, id))
                .put(move |Path(id): Path<i32>, Json(payload): Json<Value>| {
                    update_record::<E, A>(update_db.clone(), resource_name, id, payload)
                })
                .delete(move |Path(id): Path<i32>| {
                    delete_record::<E>(delete_db.clone(), resource_name, id)
                }),
        )
}

async fn list_records<E>(
    db: Arc<DatabaseConnection>,
    _resource_name: &'static str,
    Query(query): Query<ListQuery>,
) -> Result<Response, ApiHttpError>
where
    E: EntityTrait,
{
    let page_size = query.page_size.unwrap_or(20).clamp(1, 200);
    let page = query.page.unwrap_or(1).max(1);
    let offset = (page - 1).checked_mul(page_size).ok_or_else(|| {
        ApiHttpError::new(
            StatusCode::BAD_REQUEST,
            "page and page_size combination is too large",
        )
    })?;

    let records = E::find()
        .limit(page_size)
        .offset(offset)
        .into_json()
        .all(db.as_ref())
        .await
        .map_err(map_db_error)?;

    let response = serde_json::json!({
        "items": records,
        "page": page,
        "page_size": page_size,
    });

    Ok(success_response(StatusCode::OK, response))
}

async fn get_record<E>(
    db: Arc<DatabaseConnection>,
    resource_name: &'static str,
    id: i32,
) -> Result<Response, ApiHttpError>
where
    E: EntityTrait,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    let record = E::find_by_id(id)
        .into_json()
        .one(db.as_ref())
        .await
        .map_err(map_db_error)?;

    let Some(record) = record else {
        return Err(ApiHttpError::not_found(resource_name, id));
    };

    Ok(success_response(StatusCode::OK, record))
}

async fn create_record<E, A>(
    db: Arc<DatabaseConnection>,
    resource_name: &'static str,
    mut payload: Value,
) -> Result<Response, ApiHttpError>
where
    E: EntityTrait,
    A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send,
    E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    strip_id_key(&mut payload);

    let active_model = A::from_json(payload).map_err(map_db_error)?;

    let insert_result = E::insert(active_model)
        .exec(db.as_ref())
        .await
        .map_err(map_db_error)?;

    let created = E::find_by_id(insert_result.last_insert_id)
        .into_json()
        .one(db.as_ref())
        .await
        .map_err(map_db_error)?;

    let Some(created) = created else {
        return Err(ApiHttpError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to reload newly created {resource_name}"),
        ));
    };

    Ok(success_response(StatusCode::CREATED, created))
}

async fn update_record<E, A>(
    db: Arc<DatabaseConnection>,
    resource_name: &'static str,
    id: i32,
    mut payload: Value,
) -> Result<Response, ApiHttpError>
where
    E: EntityTrait,
    A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send,
    E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de>,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    let existing = E::find_by_id(id)
        .one(db.as_ref())
        .await
        .map_err(map_db_error)?;

    let Some(existing) = existing else {
        return Err(ApiHttpError::not_found(resource_name, id));
    };

    strip_id_key(&mut payload);

    let mut active_model = existing.into_active_model();
    active_model.set_from_json(payload).map_err(map_db_error)?;

    active_model
        .update(db.as_ref())
        .await
        .map_err(map_db_error)?;

    let updated = E::find_by_id(id)
        .into_json()
        .one(db.as_ref())
        .await
        .map_err(map_db_error)?;

    let Some(updated) = updated else {
        return Err(ApiHttpError::not_found(resource_name, id));
    };

    Ok(success_response(StatusCode::OK, updated))
}

async fn delete_record<E>(
    db: Arc<DatabaseConnection>,
    resource_name: &'static str,
    id: i32,
) -> Result<Response, ApiHttpError>
where
    E: EntityTrait,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    let result = E::delete_by_id(id)
        .exec(db.as_ref())
        .await
        .map_err(map_db_error)?;

    if result.rows_affected == 0 {
        return Err(ApiHttpError::not_found(resource_name, id));
    }

    Ok(StatusCode::NO_CONTENT.into_response())
}
