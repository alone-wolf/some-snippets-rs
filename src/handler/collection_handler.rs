use crate::handler::success_response;
use crate::service::collection_service::CollectionService;
use crate::service::error::ServiceError;
use axum::{
    Json, Router,
    extract::{Path, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use sea_orm::DatabaseConnection;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct ListQuery {
    page: Option<u64>,
    page_size: Option<u64>,
}

pub(crate) fn router(db: Arc<DatabaseConnection>) -> Router {
    let service = CollectionService::new(db);
    let list_service = service.clone();
    let create_service = service.clone();
    let get_service = service.clone();
    let update_service = service.clone();
    let delete_service = service;

    Router::new()
        .route(
            "/collections",
            get(move |query: Query<ListQuery>| list_collections(list_service.clone(), query)).post(
                move |Json(payload): Json<Value>| {
                    create_collection(create_service.clone(), payload)
                },
            ),
        )
        .route(
            "/collections/{key}",
            get(move |Path(key): Path<String>| get_collection(get_service.clone(), key))
                .put(move |Path(key): Path<String>, Json(payload): Json<Value>| {
                    update_collection(update_service.clone(), key, payload)
                })
                .delete(move |Path(key): Path<String>| {
                    delete_collection(delete_service.clone(), key)
                }),
        )
}

async fn list_collections(
    service: CollectionService,
    Query(query): Query<ListQuery>,
) -> Result<Response, ServiceError> {
    let data = service.list(query.page, query.page_size).await?;
    Ok(success_response(StatusCode::OK, data))
}

async fn create_collection(
    service: CollectionService,
    payload: Value,
) -> Result<Response, ServiceError> {
    let data = service.create(payload).await?;
    Ok(success_response(StatusCode::CREATED, data))
}

async fn get_collection(service: CollectionService, key: String) -> Result<Response, ServiceError> {
    let data = service.get(&key).await?;
    Ok(success_response(StatusCode::OK, data))
}

async fn update_collection(
    service: CollectionService,
    key: String,
    payload: Value,
) -> Result<Response, ServiceError> {
    let data = service.update(&key, payload).await?;
    Ok(success_response(StatusCode::OK, data))
}

async fn delete_collection(
    service: CollectionService,
    key: String,
) -> Result<Response, ServiceError> {
    service.delete(&key).await?;
    Ok(StatusCode::NO_CONTENT.into_response())
}
