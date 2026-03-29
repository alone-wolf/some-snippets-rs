use axum::{
    Router,
    routing::{get, post},
};

use super::handlers::{content, health, node};

pub fn build_router() -> Router<crate::app::state::AppState> {
    Router::new()
        .route("/healthz", get(health::healthz))
        .route(
            "/collections/{collection_id}/contents",
            post(content::create_content),
        )
        .route(
            "/contents/{content_id}",
            get(content::get_content).patch(content::update_content),
        )
        .route("/contents/{content_id}/nodes", post(node::create_node))
        .route(
            "/nodes/{node_id}",
            get(node::get_node).patch(node::update_node),
        )
        .route(
            "/node-lineages/{uuid}/versions/{version}",
            get(node::get_lineage_version),
        )
        .route("/contents/{content_id}/commit", post(content::commit_latest))
        .route(
            "/contents/{content_id}/versions",
            post(content::create_version).get(content::list_versions),
        )
        .route("/contents/{content_id}/rollback", post(content::rollback))
        .route("/draft/contents/{content_id}", get(content::get_draft))
        .route("/latest/contents/{content_id}", get(content::get_latest))
        .route(
            "/versions/contents/{content_id}/{version}",
            get(content::get_version),
        )
}
