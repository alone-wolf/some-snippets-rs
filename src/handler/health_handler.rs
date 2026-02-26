use axum::Json;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(crate) struct PingResponse {
    success: bool,
    message: &'static str,
}

pub(crate) async fn ping() -> Json<PingResponse> {
    Json(PingResponse {
        success: true,
        message: "pong",
    })
}
