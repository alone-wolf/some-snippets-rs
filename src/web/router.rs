use axum::{
    Router,
    routing::{get, patch, post},
};
use tower_http::services::{ServeDir, ServeFile};

use super::handlers::{content, file_metadata, health, node};

pub fn build_router() -> Router<crate::app::state::AppState> {
    Router::new()
        .route("/healthz", get(health::healthz))
        .route(
            "/collections",
            get(content::list_collections).post(content::create_collection),
        )
        .route(
            "/collections/{collection_id}",
            patch(content::update_collection),
        )
        .route(
            "/collections/{collection_id}/contents",
            get(content::list_contents).post(content::create_content),
        )
        .route(
            "/contents/{content_id}",
            get(content::get_content).patch(content::update_content),
        )
        .route("/contents", get(content::list_all_contents))
        .route("/contents/{content_id}/nodes", post(node::create_node))
        .route("/nodes", get(node::list_nodes))
        .route(
            "/nodes/{node_id}",
            get(node::get_node).patch(node::update_node),
        )
        .route("/file-metadata", get(file_metadata::list_file_metadata))
        .route(
            "/node-lineages/{uuid}/versions/{version}",
            get(node::get_lineage_version),
        )
        .route(
            "/contents/{content_id}/commit",
            post(content::commit_latest),
        )
        .route(
            "/contents/{content_id}/versions",
            post(content::create_version).get(content::list_versions),
        )
        .route("/contents/{content_id}/rollback", post(content::rollback))
        .route(
            "/draft/contents/{content_id}",
            get(content::get_draft).patch(content::reorder_draft),
        )
        .route("/latest/contents/{content_id}", get(content::get_latest))
        .route(
            "/versions/contents/{content_id}/{version}",
            get(content::get_version),
        )
        .nest_service(
            "/app/assets",
            ServeDir::new("web-admin/dist/assets")
                .precompressed_br()
                .precompressed_gzip(),
        )
        .nest_service(
            "/app",
            ServeDir::new("web-admin/dist").fallback(ServeFile::new("web-admin/dist/index.html")),
        )
}
