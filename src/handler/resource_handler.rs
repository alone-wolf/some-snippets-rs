use crate::entity::{
    FileActiveModel, FileEntity, HistoryActiveModel, HistoryEntity, NodeActiveModel, NodeEntity,
    SnippetActiveModel, SnippetEntity, TagActiveModel, TagEntity, TextActiveModel, TextEntity,
};
use crate::handler::success_response;
use crate::service::error::ServiceError;
use crate::service::resource_service::{ReferencePolicy, ResourceService, TimestampPolicy};
use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use sea_orm::{
    ActiveModelBehavior, ActiveModelTrait, DatabaseConnection, EntityTrait, IntoActiveModel,
    Iterable, PrimaryKeyToColumn, PrimaryKeyTrait, TryIntoModel,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct ListQuery {
    page: Option<u64>,
    page_size: Option<u64>,
}

macro_rules! mount_resources {
    ($router:expr, $db:expr, [$(($path:literal, $resource:literal, $entity:ty, $active_model:ty, $timestamp_policy:expr, $reference_policy:expr)),+ $(,)?]) => {{
        let router = $router;
        $(
            let router = router.merge(
                single_resource_router::<$entity, $active_model>(
                    $db.clone(),
                    $path,
                    $resource,
                    $timestamp_policy,
                    $reference_policy,
                ),
            );
        )+
        router
    }};
}

pub(crate) fn router(db: Arc<DatabaseConnection>) -> Router {
    mount_resources!(
        Router::new(),
        db,
        [
            (
                "/files",
                "file",
                FileEntity,
                FileActiveModel,
                TimestampPolicy::CreatedOnly,
                ReferencePolicy::None
            ),
            (
                "/histories",
                "history",
                HistoryEntity,
                HistoryActiveModel,
                TimestampPolicy::CreatedAndUpdated,
                ReferencePolicy::History
            ),
            (
                "/nodes",
                "node",
                NodeEntity,
                NodeActiveModel,
                TimestampPolicy::CreatedOnly,
                ReferencePolicy::Node
            ),
            (
                "/snippets",
                "snippet",
                SnippetEntity,
                SnippetActiveModel,
                TimestampPolicy::CreatedAndUpdated,
                ReferencePolicy::Snippet
            ),
            (
                "/tags",
                "tag",
                TagEntity,
                TagActiveModel,
                TimestampPolicy::CreatedOnly,
                ReferencePolicy::None
            ),
            (
                "/texts",
                "text",
                TextEntity,
                TextActiveModel,
                TimestampPolicy::CreatedOnly,
                ReferencePolicy::None
            ),
        ]
    )
}

fn single_resource_router<E, A>(
    db: Arc<DatabaseConnection>,
    base_path: &'static str,
    resource_name: &'static str,
    timestamp_policy: TimestampPolicy,
    reference_policy: ReferencePolicy,
) -> Router
where
    E: EntityTrait + Send + Sync + 'static,
    A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send + 'static,
    E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    E::PrimaryKey: Iterable + PrimaryKeyToColumn<Column = E::Column>,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    let service =
        ResourceService::<E, A>::new(db, resource_name, timestamp_policy, reference_policy);

    let list_service = service.clone();
    let create_service = service.clone();
    let get_service = service.clone();
    let update_service = service.clone();
    let delete_service = service;

    let detail_path = format!("{base_path}/{{id}}");

    Router::new()
        .route(
            base_path,
            get(move |query: Query<ListQuery>| list_records(list_service.clone(), query)).post(
                move |Json(payload): Json<Value>| create_record(create_service.clone(), payload),
            ),
        )
        .route(
            detail_path.as_str(),
            get(move |Path(id): Path<i32>| get_record(get_service.clone(), id))
                .put(move |Path(id): Path<i32>, Json(payload): Json<Value>| {
                    update_record(update_service.clone(), id, payload)
                })
                .delete(move |Path(id): Path<i32>| delete_record(delete_service.clone(), id)),
        )
}

async fn list_records<E, A>(
    service: ResourceService<E, A>,
    Query(query): Query<ListQuery>,
) -> Result<Response, ServiceError>
where
    E: EntityTrait + Send + Sync + 'static,
    A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send + 'static,
    E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    E::PrimaryKey: Iterable + PrimaryKeyToColumn<Column = E::Column>,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    let data = service.list(query.page, query.page_size).await?;
    Ok(success_response(StatusCode::OK, data))
}

async fn get_record<E, A>(service: ResourceService<E, A>, id: i32) -> Result<Response, ServiceError>
where
    E: EntityTrait + Send + Sync + 'static,
    A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send + 'static,
    E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    E::PrimaryKey: Iterable + PrimaryKeyToColumn<Column = E::Column>,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    let data = service.get(id).await?;
    Ok(success_response(StatusCode::OK, data))
}

async fn create_record<E, A>(
    service: ResourceService<E, A>,
    payload: Value,
) -> Result<Response, ServiceError>
where
    E: EntityTrait + Send + Sync + 'static,
    A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send + 'static,
    E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    E::PrimaryKey: Iterable + PrimaryKeyToColumn<Column = E::Column>,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    let data = service.create(payload).await?;
    Ok(success_response(StatusCode::CREATED, data))
}

async fn update_record<E, A>(
    service: ResourceService<E, A>,
    id: i32,
    payload: Value,
) -> Result<Response, ServiceError>
where
    E: EntityTrait + Send + Sync + 'static,
    A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send + 'static,
    E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    E::PrimaryKey: Iterable + PrimaryKeyToColumn<Column = E::Column>,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    let data = service.update(id, payload).await?;
    Ok(success_response(StatusCode::OK, data))
}

async fn delete_record<E, A>(
    service: ResourceService<E, A>,
    id: i32,
) -> Result<Response, ServiceError>
where
    E: EntityTrait + Send + Sync + 'static,
    A: ActiveModelTrait<Entity = E> + ActiveModelBehavior + TryIntoModel<E::Model> + Send + 'static,
    E::Model: IntoActiveModel<A> + serde::Serialize + for<'de> serde::Deserialize<'de> + Send,
    E::PrimaryKey: Iterable + PrimaryKeyToColumn<Column = E::Column>,
    i32: Into<<E::PrimaryKey as PrimaryKeyTrait>::ValueType>,
{
    service.delete(id).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
