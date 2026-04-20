use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};

use crate::{
    app::state::AppState,
    error::{AppError, AppResult},
    modules::{
        auth::permission::Permission,
        node::{
            model::{FileNodeInput, NodeKind, TextNodeInput},
            service::NodeService,
        },
    },
    web::{
        dto::node::{CreateNodeRequest, NodeResponse, UpdateNodeRequest},
        middleware::authz::require_permission,
        response::ApiResponse,
    },
};

pub async fn create_node(
    State(state): State<AppState>,
    Path(content_id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<CreateNodeRequest>,
) -> AppResult<(StatusCode, Json<ApiResponse<NodeResponse>>)> {
    let user = require_permission(&state, &headers, Permission::NodeCreate)?;
    let service = NodeService::new(state.db.clone(), state.object_store.clone());
    let response = match NodeKind::try_from(payload.kind.as_str())? {
        NodeKind::Text => {
            let node = service
                .create_text_node(
                    content_id,
                    TextNodeInput {
                        text: payload
                            .text
                            .ok_or_else(|| AppError::Validation("text is required".to_owned()))?,
                        meta: payload.meta,
                    },
                    &user.user_id,
                )
                .await?;
            NodeResponse::from(node)
        }
        NodeKind::File => {
            let file = payload
                .file
                .ok_or_else(|| AppError::Validation("file payload is required".to_owned()))?;
            let node = service
                .create_file_node(
                    content_id,
                    FileNodeInput {
                        filename: file.filename,
                        bucket: file.bucket,
                        object_key: file.object_key,
                        mime_type: file.mime_type,
                        size_bytes: file.size_bytes,
                        checksum: file.checksum,
                        meta: payload.meta,
                    },
                    &user.user_id,
                )
                .await?;
            NodeResponse::from(node)
        }
    };

    Ok((StatusCode::CREATED, Json(ApiResponse::ok(response))))
}

pub async fn update_node(
    State(state): State<AppState>,
    Path(node_id): Path<i64>,
    headers: HeaderMap,
    Json(payload): Json<UpdateNodeRequest>,
) -> AppResult<Json<ApiResponse<NodeResponse>>> {
    let user = require_permission(&state, &headers, Permission::NodeUpdate)?;
    let service = NodeService::new(state.db.clone(), state.object_store.clone());
    let existing = service.get_node_with_file(node_id).await?;
    let response = match NodeKind::try_from(existing.node.kind.as_str())? {
        NodeKind::Text => {
            let result = service
                .update_text_node(
                    node_id,
                    TextNodeInput {
                        text: payload
                            .text
                            .ok_or_else(|| AppError::Validation("text is required".to_owned()))?,
                        meta: payload.meta,
                    },
                    &user.user_id,
                )
                .await?;
            NodeResponse::from(result.new_node)
        }
        NodeKind::File => {
            let file = payload
                .file
                .ok_or_else(|| AppError::Validation("file payload is required".to_owned()))?;
            let result = service
                .update_file_node(
                    node_id,
                    FileNodeInput {
                        filename: file.filename,
                        bucket: file.bucket,
                        object_key: file.object_key,
                        mime_type: file.mime_type,
                        size_bytes: file.size_bytes,
                        checksum: file.checksum,
                        meta: payload.meta,
                    },
                    &user.user_id,
                )
                .await?;
            let current = service.get_node_with_file(result.new_node.id).await?;
            NodeResponse::from(current)
        }
    };

    Ok(Json(ApiResponse::ok(response)))
}

pub async fn get_node(
    State(state): State<AppState>,
    Path(node_id): Path<i64>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<NodeResponse>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = NodeService::new(state.db.clone(), state.object_store.clone());
    let node = service.get_node_with_file(node_id).await?;
    Ok(Json(ApiResponse::ok(NodeResponse::from(node))))
}

pub async fn get_lineage_version(
    State(state): State<AppState>,
    Path((uuid, version)): Path<(String, i32)>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<NodeResponse>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = NodeService::new(state.db.clone(), state.object_store.clone());
    let node = service.get_lineage_version(&uuid, version).await?;
    Ok(Json(ApiResponse::ok(NodeResponse::from(node))))
}

pub async fn list_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Vec<NodeResponse>>>> {
    let _user = require_permission(&state, &headers, Permission::ContentRead)?;
    let service = NodeService::new(state.db.clone(), state.object_store.clone());
    let items = service
        .list_all_with_files()
        .await?
        .into_iter()
        .map(NodeResponse::from)
        .collect();
    Ok(Json(ApiResponse::ok(items)))
}
