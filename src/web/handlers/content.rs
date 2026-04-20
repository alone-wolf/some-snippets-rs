use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};

use crate::{
    app::state::AppState,
    error::AppResult,
    modules::{
        auth::permission::Permission,
        content::service::{
            ContentService, CreateCollectionInput, CreateContentInput, UpdateCollectionInput,
            UpdateContentInput,
        },
    },
    web::{
        dto::content::{
            CollectionResponse, ContentResponse, ContentVersionResponse, CreateCollectionRequest,
            CreateContentRequest, CreateVersionRequest, ReorderDraftRequest, RollbackRequest,
            UpdateCollectionRequest, UpdateContentRequest, VersionSnapshotResponse,
        },
        middleware::authz::require_permission,
        response::ApiResponse,
    },
};

pub async fn create_collection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateCollectionRequest>,
) -> AppResult<(StatusCode, Json<ApiResponse<CollectionResponse>>)> {
    let user = require_permission(&state, &headers, Permission::ContentUpdate)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let collection = service
        .create_collection(
            CreateCollectionInput {
                slug: payload.slug,
                name: payload.name,
                description: payload.description,
                visibility: payload.visibility,
            },
            &user.user_id,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(CollectionResponse::from(collection))),
    ))
}

pub async fn list_collections(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Vec<CollectionResponse>>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let collections = service
        .list_collections()
        .await?
        .into_iter()
        .map(CollectionResponse::from)
        .collect();
    Ok(Json(ApiResponse::ok(collections)))
}

pub async fn update_collection(
    State(state): State<AppState>,
    Path(collection_id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<UpdateCollectionRequest>,
) -> AppResult<Json<ApiResponse<CollectionResponse>>> {
    let _user = require_permission(&state, &headers, Permission::ContentUpdate)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let collection = service
        .update_collection(
            collection_id,
            UpdateCollectionInput {
                slug: payload.slug,
                name: payload.name,
                description: payload.description,
                visibility: payload.visibility,
            },
        )
        .await?;
    Ok(Json(ApiResponse::ok(CollectionResponse::from(collection))))
}

pub async fn list_contents(
    State(state): State<AppState>,
    Path(collection_id): Path<i64>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Vec<ContentResponse>>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let contents = service
        .list_contents(collection_id)
        .await?
        .into_iter()
        .map(ContentResponse::from)
        .collect();
    Ok(Json(ApiResponse::ok(contents)))
}

pub async fn list_all_contents(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Vec<ContentResponse>>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let contents = service
        .list_all_contents()
        .await?
        .into_iter()
        .map(ContentResponse::from)
        .collect();
    Ok(Json(ApiResponse::ok(contents)))
}

pub async fn create_content(
    State(state): State<AppState>,
    Path(collection_id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<CreateContentRequest>,
) -> AppResult<(StatusCode, Json<ApiResponse<ContentResponse>>)> {
    let user = require_permission(&state, &headers, Permission::ContentUpdate)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let content = service
        .create_content(
            CreateContentInput {
                collection_id,
                slug: payload.slug,
                title: payload.title,
                status: payload.status,
                schema_id: payload.schema_id,
            },
            &user.user_id,
        )
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse::ok(ContentResponse::from(content))),
    ))
}

pub async fn get_content(
    State(state): State<AppState>,
    Path(content_id): Path<i64>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<ContentResponse>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let content = service.get_content(content_id).await?;
    Ok(Json(ApiResponse::ok(ContentResponse::from(content))))
}

pub async fn update_content(
    State(state): State<AppState>,
    Path(content_id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<UpdateContentRequest>,
) -> AppResult<Json<ApiResponse<ContentResponse>>> {
    let user = require_permission(&state, &headers, Permission::ContentUpdate)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let content = service
        .update_content(
            content_id,
            UpdateContentInput {
                title: payload.title,
                status: payload.status,
                schema_id: payload.schema_id,
            },
            &user.user_id,
        )
        .await?;
    Ok(Json(ApiResponse::ok(ContentResponse::from(content))))
}

pub async fn commit_latest(
    State(state): State<AppState>,
    Path(content_id): Path<i64>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<crate::storage::snapshot::latest::LatestSnapshot>>> {
    let user = require_permission(&state, &headers, Permission::ContentCommitLatest)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let snapshot = service.commit_latest(content_id, &user.user_id).await?;
    Ok(Json(ApiResponse::ok(snapshot)))
}

pub async fn create_version(
    State(state): State<AppState>,
    Path(content_id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<CreateVersionRequest>,
) -> AppResult<Json<ApiResponse<crate::storage::snapshot::version::VersionSnapshot>>> {
    let user = require_permission(&state, &headers, Permission::ContentCreateVersion)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let snapshot = service
        .create_version(content_id, payload.label, &user.user_id)
        .await?;
    Ok(Json(ApiResponse::ok(snapshot)))
}

pub async fn rollback(
    State(state): State<AppState>,
    Path(content_id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<RollbackRequest>,
) -> AppResult<Json<ApiResponse<crate::storage::snapshot::draft::DraftSnapshot>>> {
    let user = require_permission(&state, &headers, Permission::ContentRollback)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let draft = service
        .rollback_to_version(content_id, payload.version, &user.user_id)
        .await?;
    Ok(Json(ApiResponse::ok(draft)))
}

pub async fn get_draft(
    State(state): State<AppState>,
    Path(content_id): Path<i64>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<crate::storage::snapshot::draft::DraftSnapshot>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let draft = service.get_draft_snapshot(content_id).await?;
    Ok(Json(ApiResponse::ok(draft)))
}

pub async fn reorder_draft(
    State(state): State<AppState>,
    Path(content_id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<ReorderDraftRequest>,
) -> AppResult<Json<ApiResponse<ContentResponse>>> {
    let user = require_permission(&state, &headers, Permission::ContentUpdate)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let content = service
        .reorder_draft(content_id, payload.node_ids, &user.user_id)
        .await?;
    Ok(Json(ApiResponse::ok(ContentResponse::from(content))))
}

pub async fn get_latest(
    State(state): State<AppState>,
    Path(content_id): Path<i64>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<crate::storage::snapshot::latest::LatestSnapshot>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let latest = service.get_latest_snapshot(content_id).await?;
    Ok(Json(ApiResponse::ok(latest)))
}

pub async fn list_versions(
    State(state): State<AppState>,
    Path(content_id): Path<i64>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Vec<ContentVersionResponse>>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let versions = service
        .list_versions(content_id)
        .await?
        .into_iter()
        .map(ContentVersionResponse::from)
        .collect();
    Ok(Json(ApiResponse::ok(versions)))
}

pub async fn get_version(
    State(state): State<AppState>,
    Path((content_id, version)): Path<(i64, i32)>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<VersionSnapshotResponse>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = ContentService::new(state.db.clone(), state.object_store.clone());
    let snapshot = service.get_version_snapshot(content_id, version).await?;
    Ok(Json(ApiResponse::ok(VersionSnapshotResponse { snapshot })))
}
